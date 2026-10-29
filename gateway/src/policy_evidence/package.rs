//! Assemble a `policy-evidence.v1` package from what the admin endpoint
//! established about one publication.
//!
//! The package is an envelope around one report:
//!
//! ```json
//! {
//!   "schema_version": "policy-evidence.v1",
//!   "generated_at": "2026-10-28T12:00:00Z",
//!   "manifest": [{
//!     "name": "report",
//!     "media_type": "application/vnd.greengateway.policy-evidence-report+json",
//!     "schema_version": "policy-evidence-report.v1",
//!     "digest": "sha256:...",
//!     "size": 1234
//!   }],
//!   "report": { ... }
//! }
//! ```
//!
//! The manifest's `digest` is the ADR-0004 semantic digest of `report` and
//! its `size` the length of the report's RFC 8785 bytes, so a reader who
//! canonicalizes the report it received can check both. The package itself
//! is served as its RFC 8785 bytes. Everything a reader could rely on is in
//! the report; the envelope adds only when it was generated.
//!
//! Assembly is pure: it formats values and computes digests, and reads,
//! writes and logs nothing.

use serde_json::{json, Map, Value};

use super::{
    MAX_EVIDENCE_DIAGNOSTICS, MAX_PACKAGE_BYTES, PACKAGE_SCHEMA_VERSION, REDACTION_PROFILE,
    REPORT_MEDIA_TYPE, REPORT_SCHEMA_VERSION, TRUST_STATEMENT,
};
use crate::{
    canonical_json,
    policy_eval::{
        tools::{TOOL_CONTEXT_VERSION, TOOL_SEMANTICS_VERSION},
        CONTEXT_VERSION, HTTP_SEMANTICS_VERSION,
    },
    policy_replay::REPLAY_CONTEXT_SCHEMA_VERSION,
    policy_simulation::{
        run::{SimulationOutcome, MAX_ECHOED_POLICY_STRING_BYTES},
        Projection, TraceLevel,
    },
    policy_testing::{self, report::RunReport, runner::RunStatus},
    rbac::policy_document::PolicyDiagnostic,
};

/// The largest integer a report repeats from a history row: the I-JSON safe
/// range. A larger one is not a value the gateway recorded.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// The operations a history row records, as its diff summary's `action`
/// names them. Any other value is reported as `unrecognized`, never repeated.
const RECORDED_OPERATIONS: &[&str] = &[
    "imported_from_standalone",
    "policy_draft_published",
    "policy_replaced",
    "policy_rolled_back",
    "rule_created",
    "rule_deleted",
    "rule_updated",
    "rules_reordered",
];

/// The shadow-review transitions a bound rule change records.
const SHADOW_REVIEW_TRANSITIONS: &[&str] = &["disable", "promote"];

/// The identity of one policy document as the history holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyIdentity {
    pub(crate) schema_version: String,
    /// The policy ETag of the stored document: the compatibility binding
    /// every policy API already speaks.
    pub(crate) etag: String,
    /// The ADR-0004 semantic digest, for a document format with a normative
    /// normalization (policy v1); `None` otherwise.
    pub(crate) semantic_digest: Option<String>,
}

/// The history version a package is about, as it was recorded.
pub(crate) struct PublicationRecord {
    pub(crate) version: i64,
    /// When the history recorded it (RFC 3339, as stored).
    pub(crate) recorded_at: String,
    /// The row's diff summary. Only the members [`approval_view`] knows are
    /// read, and only in the shapes the gateway writes them in.
    pub(crate) diff_summary: Value,
    pub(crate) policy: PolicyIdentity,
}

/// The history version immediately before the publication.
pub(crate) struct PredecessorRecord {
    pub(crate) version: i64,
    pub(crate) policy: PolicyIdentity,
}

/// The publication revalidated by this build, as `POST .../policy/validate`
/// would judge it now.
pub(crate) struct ValidationOutcome {
    pub(crate) valid: bool,
    /// The document's own diagnostics, the deployment checks and the
    /// cross-resource findings, in that order.
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
    /// The resource snapshot the cross-resource checks read, as
    /// `POST .../policy/validate` reports it; `None` when the document did
    /// not parse and nothing was checked.
    pub(crate) resource_snapshot: Option<Value>,
}

/// The synthetic cases decided for the package.
pub(crate) struct SimulationEvidence {
    pub(crate) trace: TraceLevel,
    pub(crate) projections: Vec<Projection>,
    /// Whether every case was also decided under the predecessor, so results
    /// compare the publication with what it replaced.
    pub(crate) compared_with_predecessor: bool,
    pub(crate) outcome: SimulationOutcome,
}

/// A finished replay job of the caller's, bound to the publication.
pub(crate) struct ReplayEvidence {
    /// Whether the job's result is complete.
    pub(crate) complete: bool,
    /// Whether the active policy the job compared its candidate with is the
    /// publication's predecessor, so its impact comparison is the
    /// publication against what it replaced.
    pub(crate) compared_with_predecessor: bool,
    /// The job's section of the report, as the replay registry renders it.
    pub(crate) view: Value,
}

/// Everything a report is assembled from.
pub(crate) struct EvidenceInputs {
    pub(crate) request_digest: String,
    pub(crate) publication: PublicationRecord,
    pub(crate) predecessor: Option<PredecessorRecord>,
    pub(crate) validation: ValidationOutcome,
    pub(crate) tests: Option<RunReport>,
    pub(crate) simulation: Option<SimulationEvidence>,
    pub(crate) replay: Option<ReplayEvidence>,
}

/// An assembled package and what the endpoint records about it.
#[derive(Debug)]
pub(crate) struct EvidencePackage {
    /// The package's RFC 8785 bytes, exactly as served.
    pub(crate) bytes: Vec<u8>,
    pub(crate) report_digest: String,
    pub(crate) complete: bool,
    pub(crate) limitations: Vec<&'static str>,
}

/// Why no package was assembled. Neither is a partial package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PackageError {
    /// A value had no canonical form. Never expected for the values a report
    /// holds.
    Encoding,
    /// The package exceeds [`MAX_PACKAGE_BYTES`].
    TooLarge,
}

/// Assemble the package for `inputs`, stamped with `generated_at`.
pub(crate) fn assemble(
    inputs: EvidenceInputs,
    generated_at: &str,
) -> Result<EvidencePackage, PackageError> {
    let (report, limitations) = report(inputs)?;
    let complete = limitations.is_empty();
    let report_bytes =
        canonical_json::canonical_json_bytes(&report).map_err(|_| PackageError::Encoding)?;
    let report_digest =
        canonical_json::semantic_digest(REPORT_MEDIA_TYPE, REPORT_SCHEMA_VERSION, &report)
            .map_err(|_| PackageError::Encoding)?;
    if report_bytes.len() > MAX_PACKAGE_BYTES {
        return Err(PackageError::TooLarge);
    }
    let envelope = json!({
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "generated_at": generated_at,
        "manifest": [{
            "name": "report",
            "media_type": REPORT_MEDIA_TYPE,
            "schema_version": REPORT_SCHEMA_VERSION,
            "digest": report_digest,
            "size": report_bytes.len(),
        }],
        "report": report,
    });
    let bytes =
        canonical_json::canonical_json_bytes(&envelope).map_err(|_| PackageError::Encoding)?;
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(PackageError::TooLarge);
    }
    Ok(EvidencePackage {
        bytes,
        report_digest,
        complete,
        limitations,
    })
}

/// The report for `inputs` and its sorted limitation codes.
fn report(inputs: EvidenceInputs) -> Result<(Value, Vec<&'static str>), PackageError> {
    let EvidenceInputs {
        request_digest,
        publication,
        predecessor,
        validation,
        tests,
        simulation,
        replay,
    } = inputs;
    let mut limitations = Vec::new();

    if publication.policy.semantic_digest.is_none() {
        limitations.push("policy_semantic_digest_unavailable");
    }
    let (approval, recorded_base) = approval_view(&publication);
    let predecessor_check = match (&predecessor, recorded_base.as_deref()) {
        (None, _) => {
            limitations.push("predecessor_not_in_history");
            "no_predecessor"
        }
        (Some(_), None) => "no_recorded_base",
        (Some(predecessor), Some(base)) if predecessor.policy.etag == base => {
            "matches_recorded_base"
        }
        (Some(_), Some(_)) => {
            limitations.push("predecessor_differs_from_recorded_base");
            "differs_from_recorded_base"
        }
    };
    let publication_view = json!({
        "version": publication.version,
        "policy": identity_view(&publication.policy),
        "predecessor": predecessor.as_ref().map(|predecessor| json!({
            "version": predecessor.version,
            "policy": identity_view(&predecessor.policy),
        })),
        "predecessor_check": predecessor_check,
    });

    let validation_view = validation_view(&validation, &mut limitations)?;

    let tests_view = match &tests {
        None => {
            limitations.push("tests_not_included");
            json!({ "included": false })
        }
        Some(report) => {
            if matches!(report.status, RunStatus::Incomplete | RunStatus::Error) {
                limitations.push("tests_incomplete");
            }
            json!({
                "included": true,
                "results": policy_testing::report::to_json(report)
                    .map_err(|_| PackageError::Encoding)?,
            })
        }
    };

    let simulation_view = match simulation {
        None => {
            limitations.push("simulation_not_included");
            json!({ "included": false })
        }
        Some(simulation) => {
            let base = match (&predecessor, simulation.compared_with_predecessor) {
                (Some(predecessor), true) => json!({
                    "version": predecessor.version,
                    "etag": predecessor.policy.etag,
                }),
                (Some(_), false) => {
                    limitations.push("simulation_base_not_evaluable");
                    Value::Null
                }
                // Already reported as `predecessor_not_in_history`.
                (None, _) => Value::Null,
            };
            json!({
                "included": true,
                "mode": "synthetic",
                "trace": simulation.trace.as_str(),
                "projections": simulation
                    .projections
                    .iter()
                    .map(|projection| projection.as_str())
                    .collect::<Vec<_>>(),
                "base": base,
                "candidate": {
                    "version": publication.version,
                    "etag": publication.policy.etag,
                },
                "not_evaluated": policy_testing::NOT_EVALUATED,
                "summary": simulation.outcome.summary,
                "cases": simulation.outcome.cases,
            })
        }
    };

    let replay_view = match replay {
        None => {
            limitations.push("replay_not_included");
            json!({ "included": false })
        }
        Some(replay) => {
            if !replay.complete {
                limitations.push("replay_incomplete");
            }
            let predecessor_check = match (&predecessor, replay.compared_with_predecessor) {
                (Some(_), true) => "matches_predecessor",
                (Some(_), false) => {
                    limitations.push("replay_base_not_predecessor");
                    "differs_from_predecessor"
                }
                // Already reported as `predecessor_not_in_history`.
                (None, _) => "no_predecessor",
            };
            let mut view = replay.view;
            if let Some(members) = view.as_object_mut() {
                members.insert("predecessor_check".to_owned(), json!(predecessor_check));
            }
            view
        }
    };

    limitations.sort_unstable();
    limitations.dedup();
    let report = json!({
        "schema_version": REPORT_SCHEMA_VERSION,
        "redaction_profile": REDACTION_PROFILE,
        "gateway_version": env!("CARGO_PKG_VERSION"),
        "evaluator": {
            "http_semantics_version": HTTP_SEMANTICS_VERSION,
            "http_context_version": CONTEXT_VERSION,
            "tool_semantics_version": TOOL_SEMANTICS_VERSION,
            "tool_context_version": TOOL_CONTEXT_VERSION,
            "replay_context_version": REPLAY_CONTEXT_SCHEMA_VERSION,
        },
        "request_digest": request_digest,
        "publication": publication_view,
        "approval": approval,
        "validation": validation_view,
        "tests": tests_view,
        "simulation": simulation_view,
        "replay": replay_view,
        "completeness": if limitations.is_empty() { "complete" } else { "incomplete" },
        "limitations": limitations,
        "trust": {
            "signed": false,
            "statement": TRUST_STATEMENT,
        },
    });
    Ok((report, limitations))
}

fn identity_view(identity: &PolicyIdentity) -> Value {
    json!({
        "schema_version": identity.schema_version,
        "etag": identity.etag,
        "semantic_digest": identity.semantic_digest,
    })
}

fn validation_view(
    validation: &ValidationOutcome,
    limitations: &mut Vec<&'static str>,
) -> Result<Value, PackageError> {
    if validation
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.blocks.evidence)
    {
        limitations.push("validation_blocks_evidence");
    }
    let truncated = validation.diagnostics.len() > MAX_EVIDENCE_DIAGNOSTICS;
    if truncated {
        limitations.push("validation_diagnostics_truncated");
    }
    let listed =
        &validation.diagnostics[..validation.diagnostics.len().min(MAX_EVIDENCE_DIAGNOSTICS)];
    Ok(json!({
        // Judged now, by this build and this deployment's checks: the
        // history does not record what validation said at publication time.
        "basis": "revalidated_by_this_build",
        "valid": validation.valid,
        "diagnostics": serde_json::to_value(listed).map_err(|_| PackageError::Encoding)?,
        "diagnostics_truncated": truncated,
        "resource_snapshot": validation.resource_snapshot,
    }))
}

/// What the publication's history row records about the commit that made it,
/// and the base ETag it recorded the commit was made against, if any.
///
/// GreenGateway has no approval workflow beyond the authorized commit
/// itself, so this is the approval as recorded: when, by which operation, and
/// what that operation was bound to (the draft revision a publication was
/// reviewed as, or the shadow review a promotion or disable was justified
/// by). Only members the gateway writes are read, each only in the shape it
/// writes it in; anything else is left out rather than repeated. The actor is
/// withheld: a subject is often an email address, and the package carries no
/// identity. An authorized reader finds it under the same version in the
/// policy history.
fn approval_view(publication: &PublicationRecord) -> (Value, Option<String>) {
    let summary = publication.diff_summary.as_object();
    let member = |name: &str| summary.and_then(|summary| summary.get(name));
    let operation = match member("action").and_then(Value::as_str) {
        None => "not_recorded",
        Some(action) => RECORDED_OPERATIONS
            .iter()
            .find(|known| **known == action)
            .copied()
            .unwrap_or("unrecognized"),
    };
    let mut view = Map::new();
    view.insert("basis".to_owned(), json!("authorized_commit"));
    view.insert("recorded_at".to_owned(), json!(publication.recorded_at));
    view.insert("actor".to_owned(), json!("withheld"));
    view.insert("operation".to_owned(), json!(operation));
    let mut recorded_base = None;
    match operation {
        "policy_draft_published" => {
            let revision = member("draft_revision").and_then(safe_integer);
            let base_etag = member("base_etag").and_then(etag_shaped);
            if let (Some(revision), Some(base_etag)) = (revision, base_etag) {
                view.insert(
                    "draft".to_owned(),
                    json!({ "revision": revision, "base_etag": base_etag }),
                );
                recorded_base = Some(base_etag.to_owned());
            }
        }
        "policy_rolled_back" => {
            if let Some(target) = member("target_version").and_then(safe_integer) {
                view.insert("rollback_target_version".to_owned(), json!(target));
            }
        }
        "rule_created" | "rule_deleted" | "rule_updated" => {
            if let Some(rule_id) = member("rule_id").and_then(echoable_id) {
                view.insert("rule_id".to_owned(), json!(rule_id));
            }
            if let Some(review) = member("shadow_review").and_then(Value::as_object) {
                let transition = review
                    .get("transition")
                    .and_then(Value::as_str)
                    .filter(|transition| SHADOW_REVIEW_TRANSITIONS.contains(transition));
                let policy_etag = review.get("policy_etag").and_then(etag_shaped);
                let evidence_digest = review.get("evidence_digest").and_then(digest_shaped);
                if let (Some(transition), Some(policy_etag), Some(evidence_digest)) =
                    (transition, policy_etag, evidence_digest)
                {
                    view.insert(
                        "shadow_review".to_owned(),
                        json!({
                            "transition": transition,
                            "policy_etag": policy_etag,
                            "evidence_digest": evidence_digest,
                        }),
                    );
                    recorded_base = Some(policy_etag.to_owned());
                }
            }
        }
        _ => {}
    }
    (Value::Object(view), recorded_base)
}

fn safe_integer(value: &Value) -> Option<u64> {
    value.as_u64().filter(|value| *value <= MAX_SAFE_INTEGER)
}

/// `value` when it is a policy ETag as the gateway writes one:
/// `"sha256:<64 lowercase hex>"`, quotes included.
fn etag_shaped(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| {
        text.strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .is_some_and(is_sha256_digest)
    })
}

/// `value` when it is `sha256:<64 lowercase hex>`.
fn digest_shaped(value: &Value) -> Option<&str> {
    value.as_str().filter(|text| is_sha256_digest(text))
}

fn is_sha256_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// An authored element id short enough to repeat, as simulation results
/// bound them.
fn echoable_id(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= MAX_ECHOED_POLICY_STRING_BYTES)
}
