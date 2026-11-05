//! Assemble a `policy-evidence.v1` package from what the admin endpoint
//! established about one candidate: a publication or a draft.
//!
//! The package is an envelope around the artifacts its manifest names:
//!
//! ```json
//! {
//!   "schema_version": "policy-evidence.v1",
//!   "generated_at": "2026-10-28T12:00:00Z",
//!   "manifest": [
//!     {
//!       "name": "report",
//!       "media_type": "application/vnd.greengateway.policy-evidence-report+json",
//!       "schema_version": "policy-evidence-report.v1",
//!       "digest": "sha256:...",
//!       "size": 1234
//!     },
//!     { "name": "analysis", ... },
//!     { "name": "report_markdown", ... }
//!   ],
//!   "report": { ... },
//!   "analysis": { ... },
//!   "report_markdown": "# Policy evidence report\n..."
//! }
//! ```
//!
//! Each manifest entry names the envelope member of the same name. For a
//! JSON artifact (`report`, and `analysis` when the request asked for it) the
//! `digest` is the ADR-0004 semantic digest of that member and `size` the
//! length of its RFC 8785 bytes, so a reader who canonicalizes the member it
//! received can check both. `report_markdown` is a string; its `digest` is
//! the ADR-0004 source digest of its UTF-8 bytes and `size` their length. The
//! report also names the analysis artifact by the same entry, so the report
//! digest binds it; the Markdown is derived from the report and carries
//! nothing it lacks. The package itself is served as its RFC 8785 bytes.
//! Everything a reader could rely on is in the report; the envelope adds only
//! when it was generated.
//!
//! Assembly is pure: it formats values and computes digests, and reads,
//! writes and logs nothing.

use serde_json::{json, Map, Value};

use super::{
    markdown, ANALYSIS_MEDIA_TYPE, DRAFT_TRUST_STATEMENT, MARKDOWN_MEDIA_TYPE,
    MARKDOWN_SCHEMA_VERSION, MAX_EVIDENCE_DIAGNOSTICS, MAX_PACKAGE_BYTES, PACKAGE_SCHEMA_VERSION,
    REDACTION_PROFILE, REPORT_MEDIA_TYPE, REPORT_SCHEMA_VERSION, TRUST_STATEMENT,
};
use crate::{
    canonical_json,
    policy_analysis::RESULT_SCHEMA_VERSION as ANALYSIS_SCHEMA_VERSION,
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

/// The manifest names of the artifacts a package carries, in manifest order.
pub(crate) const REPORT_ARTIFACT: &str = "report";
pub(crate) const ANALYSIS_ARTIFACT: &str = "analysis";
pub(crate) const MARKDOWN_ARTIFACT: &str = "report_markdown";

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

/// The identity of one policy document as its authority holds it.
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

/// A server-side draft of the caller's, as the drafts store held it at the
/// draft ETag the request named.
pub(crate) struct DraftRecord {
    pub(crate) draft_id: String,
    pub(crate) revision: i64,
    /// The strong draft ETag the request pinned, which the draft still had.
    pub(crate) draft_etag: String,
    pub(crate) policy: PolicyIdentity,
    /// The live policy the draft is pinned to: what publishing it would
    /// replace, and so its predecessor wherever a report compares.
    pub(crate) base: PolicyIdentity,
}

/// What a package is about.
pub(crate) enum CandidateRecord {
    /// A version of the policy history and the version before it.
    Publication {
        record: PublicationRecord,
        predecessor: Option<PredecessorRecord>,
    },
    /// A draft, never presented as a publication.
    Draft(DraftRecord),
}

impl CandidateRecord {
    /// The report's `candidate_kind`.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Publication { .. } => "publication",
            Self::Draft(_) => "draft",
        }
    }

    /// The candidate's own document.
    pub(crate) fn policy(&self) -> &PolicyIdentity {
        match self {
            Self::Publication { record, .. } => &record.policy,
            Self::Draft(draft) => &draft.policy,
        }
    }

    /// Whether the report knows what the candidate replaces.
    fn has_predecessor(&self) -> bool {
        match self {
            Self::Publication { predecessor, .. } => predecessor.is_some(),
            Self::Draft(_) => true,
        }
    }
}

/// The candidate revalidated by this build, as `POST .../policy/validate`
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
    /// Whether every case was also decided under what the candidate replaces
    /// (a publication's predecessor, a draft's base), so results compare the
    /// candidate with it.
    pub(crate) compared_with_predecessor: bool,
    pub(crate) outcome: SimulationOutcome,
}

/// A finished replay job of the caller's, bound to the candidate.
pub(crate) struct ReplayEvidence {
    /// Whether the job's result is complete.
    pub(crate) complete: bool,
    /// Whether the active policy the job compared its candidate with is what
    /// the candidate replaces, so its impact comparison is the candidate's
    /// own.
    pub(crate) compared_with_predecessor: bool,
    /// The job's section of the report, as the replay registry renders it.
    pub(crate) view: Value,
}

/// The structural analyzer's results over the candidate.
pub(crate) struct AnalysisEvidence {
    /// The `policy-analysis-results.v1` document, as
    /// `policy_analysis::report::to_json` rendered it: findings, proof
    /// bases, suppression states, completeness and the bindings.
    pub(crate) results: Value,
}

/// Everything a package is assembled from.
pub(crate) struct EvidenceInputs {
    pub(crate) request_digest: String,
    pub(crate) candidate: CandidateRecord,
    pub(crate) validation: ValidationOutcome,
    pub(crate) tests: Option<RunReport>,
    pub(crate) simulation: Option<SimulationEvidence>,
    pub(crate) replay: Option<ReplayEvidence>,
    pub(crate) analysis: Option<AnalysisEvidence>,
}

/// An assembled package and what the endpoint records about it.
#[derive(Debug)]
pub(crate) struct EvidencePackage {
    /// The package's RFC 8785 bytes, exactly as served.
    pub(crate) bytes: Vec<u8>,
    pub(crate) report_digest: String,
    /// The analysis artifact's digest, when the package carries one.
    pub(crate) analysis_digest: Option<String>,
    /// The Markdown rendering's digest.
    pub(crate) markdown_digest: String,
    pub(crate) complete: bool,
    pub(crate) limitations: Vec<&'static str>,
}

/// Why no package was assembled. Neither is a partial package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PackageError {
    /// A value had no canonical form, the analysis results lacked a member
    /// the report repeats, or the Markdown template refused the report.
    /// Never expected for the values the endpoint hands over.
    Encoding,
    /// The package exceeds [`MAX_PACKAGE_BYTES`].
    TooLarge,
}

/// A JSON artifact as a manifest names it.
struct JsonArtifact {
    entry: Value,
    digest: String,
    /// The artifact's RFC 8785 bytes, which `entry` sizes and `digest` frames.
    bytes: Vec<u8>,
}

/// The manifest entry of a JSON artifact: its semantic digest and the length
/// of its RFC 8785 bytes.
fn json_artifact(
    name: &str,
    media_type: &str,
    schema_version: &str,
    value: &Value,
) -> Result<JsonArtifact, PackageError> {
    let bytes = canonical_json::canonical_json_bytes(value).map_err(|_| PackageError::Encoding)?;
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(PackageError::TooLarge);
    }
    let digest = canonical_json::semantic_digest(media_type, schema_version, value)
        .map_err(|_| PackageError::Encoding)?;
    Ok(JsonArtifact {
        entry: manifest_entry(name, media_type, schema_version, &digest, bytes.len()),
        digest,
        bytes,
    })
}

fn manifest_entry(
    name: &str,
    media_type: &str,
    schema_version: &str,
    digest: &str,
    size: usize,
) -> Value {
    json!({
        "name": name,
        "media_type": media_type,
        "schema_version": schema_version,
        "digest": digest,
        "size": size,
    })
}

/// Assemble the package for `inputs`, stamped with `generated_at`.
pub(crate) fn assemble(
    mut inputs: EvidenceInputs,
    generated_at: &str,
) -> Result<EvidencePackage, PackageError> {
    let analysis = match inputs.analysis.take() {
        None => None,
        Some(analysis) => {
            let artifact = json_artifact(
                ANALYSIS_ARTIFACT,
                ANALYSIS_MEDIA_TYPE,
                ANALYSIS_SCHEMA_VERSION,
                &analysis.results,
            )?;
            Some((analysis, artifact))
        }
    };
    let (report, limitations) = report(
        inputs,
        analysis
            .as_ref()
            .map(|(analysis, artifact)| (analysis, &artifact.entry)),
    )?;
    let complete = limitations.is_empty();
    let report_artifact = json_artifact(
        REPORT_ARTIFACT,
        REPORT_MEDIA_TYPE,
        REPORT_SCHEMA_VERSION,
        &report,
    )?;
    // Rendered from the report's own canonical bytes, and from nothing else.
    let rendered = markdown::render(&report_artifact.bytes).map_err(|_| PackageError::Encoding)?;
    let markdown_digest = canonical_json::source_digest(
        MARKDOWN_MEDIA_TYPE,
        MARKDOWN_SCHEMA_VERSION,
        rendered.as_bytes(),
    );
    let report_digest = report_artifact.digest;
    let mut manifest = vec![report_artifact.entry];
    let mut envelope = Map::new();
    let mut analysis_digest = None;
    if let Some((analysis, artifact)) = analysis {
        manifest.push(artifact.entry);
        envelope.insert(ANALYSIS_ARTIFACT.to_owned(), analysis.results);
        analysis_digest = Some(artifact.digest);
    }
    manifest.push(manifest_entry(
        MARKDOWN_ARTIFACT,
        MARKDOWN_MEDIA_TYPE,
        MARKDOWN_SCHEMA_VERSION,
        &markdown_digest,
        rendered.len(),
    ));
    envelope.insert("schema_version".to_owned(), json!(PACKAGE_SCHEMA_VERSION));
    envelope.insert("generated_at".to_owned(), json!(generated_at));
    envelope.insert("manifest".to_owned(), Value::Array(manifest));
    envelope.insert(REPORT_ARTIFACT.to_owned(), report);
    envelope.insert(MARKDOWN_ARTIFACT.to_owned(), Value::String(rendered));
    let bytes = canonical_json::canonical_json_bytes(&Value::Object(envelope))
        .map_err(|_| PackageError::Encoding)?;
    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(PackageError::TooLarge);
    }
    Ok(EvidencePackage {
        bytes,
        report_digest,
        analysis_digest,
        markdown_digest,
        complete,
        limitations,
    })
}

/// The report for `inputs` and its sorted limitation codes. `analysis` is the
/// analysis artifact and its manifest entry, which the report repeats.
fn report(
    inputs: EvidenceInputs,
    analysis: Option<(&AnalysisEvidence, &Value)>,
) -> Result<(Value, Vec<&'static str>), PackageError> {
    let EvidenceInputs {
        request_digest,
        candidate,
        validation,
        tests,
        simulation,
        replay,
        analysis: _,
    } = inputs;
    let mut limitations = Vec::new();

    if candidate.policy().semantic_digest.is_none() {
        limitations.push("policy_semantic_digest_unavailable");
    }
    let mut members = Map::new();
    match &candidate {
        CandidateRecord::Publication {
            record,
            predecessor,
        } => {
            let (approval, recorded_base) = approval_view(record);
            let predecessor_check = match (predecessor, recorded_base.as_deref()) {
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
            members.insert(
                "publication".to_owned(),
                json!({
                    "version": record.version,
                    "policy": identity_view(&record.policy),
                    "predecessor": predecessor.as_ref().map(|predecessor| json!({
                        "version": predecessor.version,
                        "policy": identity_view(&predecessor.policy),
                    })),
                    "predecessor_check": predecessor_check,
                }),
            );
            members.insert("approval".to_owned(), approval);
        }
        CandidateRecord::Draft(draft) => {
            // What the draft would replace is always known: the store
            // refuses a draft whose pinned base is not the live policy.
            members.insert(
                "draft".to_owned(),
                json!({
                    "draft_id": draft.draft_id,
                    "revision": draft.revision,
                    "draft_etag": draft.draft_etag,
                    "policy": identity_view(&draft.policy),
                    "base": { "source": "active", "policy": identity_view(&draft.base) },
                }),
            );
        }
    }

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
            let compared = simulation.compared_with_predecessor && candidate.has_predecessor();
            if candidate.has_predecessor() && !simulation.compared_with_predecessor {
                limitations.push("simulation_base_not_evaluable");
            }
            // A publication without a predecessor is already reported as
            // `predecessor_not_in_history`.
            let (base, candidate_view) = match &candidate {
                CandidateRecord::Publication {
                    record,
                    predecessor,
                } => (
                    predecessor
                        .as_ref()
                        .filter(|_| compared)
                        .map(|predecessor| {
                            json!({
                                "version": predecessor.version,
                                "etag": predecessor.policy.etag,
                            })
                        }),
                    json!({ "version": record.version, "etag": record.policy.etag }),
                ),
                CandidateRecord::Draft(draft) => (
                    compared.then(|| json!({ "etag": draft.base.etag })),
                    json!({ "draft_revision": draft.revision, "etag": draft.policy.etag }),
                ),
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
                "candidate": candidate_view,
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
            let predecessor_check = match (
                candidate.has_predecessor(),
                replay.compared_with_predecessor,
            ) {
                (true, true) => "matches_predecessor",
                (true, false) => {
                    limitations.push("replay_base_not_predecessor");
                    "differs_from_predecessor"
                }
                // Already reported as `predecessor_not_in_history`.
                (false, _) => "no_predecessor",
            };
            let mut view = replay.view;
            if let Some(members) = view.as_object_mut() {
                members.insert("predecessor_check".to_owned(), json!(predecessor_check));
            }
            view
        }
    };

    let analysis_view = analysis_view(analysis, &mut limitations)?;

    limitations.sort_unstable();
    limitations.dedup();
    members.insert("schema_version".to_owned(), json!(REPORT_SCHEMA_VERSION));
    members.insert("redaction_profile".to_owned(), json!(REDACTION_PROFILE));
    members.insert("candidate_kind".to_owned(), json!(candidate.kind()));
    members.insert(
        "gateway_version".to_owned(),
        json!(env!("CARGO_PKG_VERSION")),
    );
    members.insert(
        "evaluator".to_owned(),
        json!({
            "http_semantics_version": HTTP_SEMANTICS_VERSION,
            "http_context_version": CONTEXT_VERSION,
            "tool_semantics_version": TOOL_SEMANTICS_VERSION,
            "tool_context_version": TOOL_CONTEXT_VERSION,
            "replay_context_version": REPLAY_CONTEXT_SCHEMA_VERSION,
        }),
    );
    members.insert("request_digest".to_owned(), json!(request_digest));
    members.insert("validation".to_owned(), validation_view);
    members.insert("tests".to_owned(), tests_view);
    members.insert("simulation".to_owned(), simulation_view);
    members.insert("replay".to_owned(), replay_view);
    members.insert("analysis".to_owned(), analysis_view);
    members.insert(
        "completeness".to_owned(),
        json!(if limitations.is_empty() {
            "complete"
        } else {
            "incomplete"
        }),
    );
    members.insert("limitations".to_owned(), json!(limitations));
    members.insert(
        "trust".to_owned(),
        json!({
            "signed": false,
            "statement": match &candidate {
                CandidateRecord::Publication { .. } => TRUST_STATEMENT,
                CandidateRecord::Draft(_) => DRAFT_TRUST_STATEMENT,
            },
        }),
    );
    Ok((Value::Object(members), limitations))
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
        // history does not record what validation said at publication time,
        // and a draft's store judged it when it was saved.
        "basis": "revalidated_by_this_build",
        "valid": validation.valid,
        "diagnostics": serde_json::to_value(listed).map_err(|_| PackageError::Encoding)?,
        "diagnostics_truncated": truncated,
        "resource_snapshot": validation.resource_snapshot,
    }))
}

/// The report's analysis section: the analysis artifact's manifest entry,
/// so the report digest binds it, and what a reader gates on and reviews --
/// completeness, the analyzer's own limitations, whether the suppression
/// records were read, the counts, and each finding's code, fingerprint,
/// severity, proof basis, element and suppression state. Rationales,
/// remediations, lanes, details and patches stay in the artifact.
fn analysis_view(
    analysis: Option<(&AnalysisEvidence, &Value)>,
    limitations: &mut Vec<&'static str>,
) -> Result<Value, PackageError> {
    let Some((analysis, entry)) = analysis else {
        limitations.push("analysis_not_included");
        return Ok(json!({ "included": false }));
    };
    let results = &analysis.results;
    let member = |name: &str| results.get(name).ok_or(PackageError::Encoding);
    let complete = member("complete")?
        .as_bool()
        .ok_or(PackageError::Encoding)?;
    if !complete {
        limitations.push("analysis_incomplete");
    }
    let suppressions = member("suppressions")?;
    if !suppressions
        .get("available")
        .and_then(Value::as_bool)
        .ok_or(PackageError::Encoding)?
    {
        limitations.push("analysis_suppressions_unavailable");
    }
    let findings = member("findings")?
        .as_array()
        .ok_or(PackageError::Encoding)?
        .iter()
        .map(|finding| {
            let field = |name: &str| finding.get(name).cloned().ok_or(PackageError::Encoding);
            Ok(json!({
                "code": field("code")?,
                "fingerprint": field("fingerprint")?,
                "severity": field("severity")?,
                "proof_basis": field("proof_basis")?,
                "element": field("element")?,
                "suppression": field("suppression")?,
            }))
        })
        .collect::<Result<Vec<_>, PackageError>>()?;
    Ok(json!({
        "included": true,
        "artifact": entry,
        "analyzer": member("analyzer")?,
        "analyzed": member("analyzed")?,
        "complete": complete,
        "limitations": member("limitations")?,
        "suppressions": suppressions,
        "summary": member("summary")?,
        "findings": findings,
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
