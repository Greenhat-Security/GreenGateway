//! Stable renderings of an analysis: the authoritative JSON report and SARIF
//! 2.1.0 for code-scanning consumers.
//!
//! Both are derived from the same [`AnalysisOutcome`] and
//! [`SuppressionOutcome`] and are deterministic: the same policy, resources,
//! suppression records and analyzer version produce byte-identical output,
//! which is why neither carries a timestamp or a duration. (Whether a
//! suppression has ended is the store's judgement when it was read, so the
//! same records can read differently once one expires.) SARIF carries no
//! more than the JSON: codes, pointers, positions, element ids,
//! fingerprints, suppression ids and the bindings, never a path,
//! permission, role, caller or a suppression's reason.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::{
    suppression::{AppliedSuppression, SuppressionOutcome, SuppressionState},
    AnalysisError, AnalysisOutcome, CandidatePatch, Finding, FindingCode, ProofBasis, Severity,
    ANALYZER_VERSION, MAX_COMPARISONS, MAX_FINDINGS, RESULT_SCHEMA_VERSION,
};
use crate::policy_simulation::request::StoredCandidate;
use crate::{
    policy_eval::{
        tools::{TOOL_CONTEXT_VERSION, TOOL_SEMANTICS_VERSION},
        CONTEXT_VERSION, HTTP_SEMANTICS_VERSION,
    },
    rbac::policy_resources::PolicyResourceSnapshot,
};

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_NAME: &str = "greengateway-policy-analyzer";
/// What a patch's edits are: edits a `policy-simulation.v1` candidate takes.
const PATCH_FORMAT: &str = "policy-simulation.v1/edits";

/// What an analysis was run against, as the endpoint resolved it.
pub(crate) struct AnalysisBinding<'a> {
    pub(crate) request_digest: &'a str,
    /// The active policy's ETag, which the request pinned.
    pub(crate) base_etag: &'a str,
    /// Cluster mode: the security revision the base was read at.
    pub(crate) security_revision: Option<i64>,
    /// `active`, `edits`, `inline`, `draft` or `revision`.
    pub(crate) source: &'static str,
    /// The ETag of the analyzed document, which every position names.
    pub(crate) analyzed_etag: &'a str,
    /// The analyzed document's ADR-0004 semantic digest, for a document
    /// format that has one (policy v1).
    pub(crate) analyzed_semantic_digest: Option<&'a str>,
    pub(crate) edit_count: usize,
    /// The draft or history version the analyzed document was read as.
    pub(crate) stored: Option<&'a StoredCandidate>,
    pub(crate) mcp_alias_paths: usize,
    /// The resources the analysis was judged against: what a suppression
    /// binds besides the policy.
    pub(crate) resource_snapshot: &'a PolicyResourceSnapshot,
}

/// Counts only: no finding identity, so the summary is safe to audit.
pub(crate) fn summary(outcome: &AnalysisOutcome, suppressions: &SuppressionOutcome) -> Value {
    let mut by_severity = BTreeMap::new();
    let mut by_proof_basis = BTreeMap::new();
    let mut by_code = BTreeMap::new();
    for severity in [Severity::High, Severity::Medium, Severity::Low] {
        by_severity.insert(severity.as_str(), 0usize);
    }
    for basis in [
        ProofBasis::Proven,
        ProofBasis::Heuristic,
        ProofBasis::Inconclusive,
    ] {
        by_proof_basis.insert(basis.as_str(), 0usize);
    }
    for finding in &outcome.findings {
        *by_severity.entry(finding.severity.as_str()).or_default() += 1;
        *by_proof_basis
            .entry(finding.proof_basis.as_str())
            .or_default() += 1;
        *by_code.entry(finding.code.as_str()).or_insert(0usize) += 1;
    }
    json!({
        "findings": outcome.findings.len(),
        "patches": outcome
            .findings
            .iter()
            .filter(|finding| finding.patch.is_some())
            .count(),
        "by_severity": by_severity,
        "by_proof_basis": by_proof_basis,
        "by_code": by_code,
        "by_suppression_state": suppressions.counts(),
    })
}

fn suppressions_json(suppressions: &SuppressionOutcome) -> Value {
    json!({
        "available": suppressions.available,
        "records": suppressions.records,
    })
}

fn applied_suppression(
    suppressions: &SuppressionOutcome,
    index: usize,
) -> Option<&AppliedSuppression> {
    suppressions.applied.get(index).and_then(Option::as_ref)
}

/// A finding's suppression state: the state, the record that decided it
/// and, for a mismatched record, what it binds differently. Never the
/// record's reason.
fn suppression_json(applied: &AppliedSuppression) -> Value {
    let mut view = Map::new();
    view.insert("state".to_owned(), json!(applied.state.as_str()));
    view.insert("suppression_id".to_owned(), json!(applied.suppression_id));
    if applied.state == SuppressionState::Mismatched {
        view.insert(
            "mismatched".to_owned(),
            json!(applied
                .mismatched
                .iter()
                .map(|part| part.as_str())
                .collect::<Vec<_>>()),
        );
    }
    Value::Object(view)
}

/// The authoritative JSON report.
pub(crate) fn to_json(
    outcome: &AnalysisOutcome,
    binding: &AnalysisBinding<'_>,
    suppressions: &SuppressionOutcome,
) -> Result<Value, AnalysisError> {
    let findings = outcome
        .findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            finding_json(
                finding,
                binding.analyzed_etag,
                applied_suppression(suppressions, index),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut base = json!({ "source": "active", "etag": binding.base_etag });
    if let (Some(revision), Some(base)) = (binding.security_revision, base.as_object_mut()) {
        base.insert("security_revision".to_owned(), json!(revision));
    }
    let mut analyzed = json!({ "source": binding.source, "etag": binding.analyzed_etag });
    if let Some(analyzed) = analyzed.as_object_mut() {
        if binding.source == "edits" {
            analyzed.insert("edits".to_owned(), json!(binding.edit_count));
        }
        if let Some(stored) = binding.stored {
            stored.describe("", analyzed);
        }
    }
    if let (Some(digest), Some(analyzed)) =
        (binding.analyzed_semantic_digest, analyzed.as_object_mut())
    {
        analyzed.insert("semantic_digest".to_owned(), json!(digest));
    }
    let resource_snapshot = serde_json::to_value(binding.resource_snapshot)
        .map_err(|_| AnalysisError::Internal("resource_snapshot_unavailable"))?;
    Ok(json!({
        "schema_version": RESULT_SCHEMA_VERSION,
        "mode": "structural",
        "request_digest": binding.request_digest,
        "analyzer": analyzer_versions(),
        "base": base,
        "analyzed": analyzed,
        "resources": { "mcp_alias_paths": binding.mcp_alias_paths },
        "resource_snapshot": resource_snapshot,
        "complete": outcome.complete,
        "limitations": limitation_codes(outcome),
        "budget": {
            "comparisons": outcome.comparisons,
            "max_comparisons": MAX_COMPARISONS,
            "max_findings": MAX_FINDINGS,
        },
        "suppressions": suppressions_json(suppressions),
        "summary": summary(outcome, suppressions),
        "findings": findings,
    }))
}

fn analyzer_versions() -> Value {
    json!({
        "version": ANALYZER_VERSION,
        "http_semantics_version": HTTP_SEMANTICS_VERSION,
        "http_context_version": CONTEXT_VERSION,
        "tool_semantics_version": TOOL_SEMANTICS_VERSION,
        "tool_context_version": TOOL_CONTEXT_VERSION,
        "gateway_version": env!("CARGO_PKG_VERSION"),
    })
}

fn limitation_codes(outcome: &AnalysisOutcome) -> Vec<&'static str> {
    outcome
        .limitations
        .iter()
        .map(|limitation| limitation.as_str())
        .collect()
}

fn lanes(lanes: &[super::Lane]) -> Vec<&'static str> {
    lanes.iter().map(|lane| lane.as_str()).collect()
}

fn patch_json(patch: &CandidatePatch, analyzed_etag: &str) -> Value {
    json!({
        "format": PATCH_FORMAT,
        "applies_to_etag": analyzed_etag,
        "access_effect": patch.access_effect.as_str(),
        "edits": patch.edits,
    })
}

fn finding_json(
    finding: &Finding,
    analyzed_etag: &str,
    suppression: Option<&AppliedSuppression>,
) -> Result<Value, AnalysisError> {
    let mut view = Map::new();
    view.insert("code".to_owned(), json!(finding.code.as_str()));
    view.insert("fingerprint".to_owned(), json!(finding.fingerprint()?));
    view.insert("severity".to_owned(), json!(finding.severity.as_str()));
    view.insert(
        "proof_basis".to_owned(),
        json!(finding.proof_basis.as_str()),
    );
    view.insert("element".to_owned(), finding.element.to_json());
    if let Some(related) = &finding.related {
        view.insert("related".to_owned(), related.to_json());
    }
    view.insert(
        "never_decides_in".to_owned(),
        json!(lanes(&finding.never_decides_in)),
    );
    view.insert(
        "may_decide_in".to_owned(),
        json!(lanes(&finding.may_decide_in)),
    );
    view.insert("rationale".to_owned(), json!(finding.code.rationale()));
    view.insert("remediation".to_owned(), json!(finding.code.remediation()));
    view.insert("details".to_owned(), Value::Object(finding.details.clone()));
    if let Some(patch) = &finding.patch {
        view.insert("patch".to_owned(), patch_json(patch, analyzed_etag));
    }
    view.insert("limitations".to_owned(), json!(finding.limitations));
    view.insert(
        "suppression".to_owned(),
        suppression.map_or(Value::Null, suppression_json),
    );
    Ok(Value::Object(view))
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn sarif_rule_index(code: FindingCode) -> usize {
    FindingCode::ALL
        .iter()
        .position(|candidate| *candidate == code)
        .unwrap_or_default()
}

/// SARIF 2.1.0: one rule per finding code, in a fixed order, and one result
/// per finding. The run's properties carry the bindings, completeness and
/// counts, so a consumer can tell a clean complete analysis from an empty
/// file or an incomplete one.
///
/// A suppressed finding's result carries one `external`, `accepted`
/// suppression naming the record; every other result carries an empty
/// `suppressions` array, which SARIF reads as checked and not suppressed. An
/// expired or mismatched record is therefore never a SARIF suppression; its
/// state is in the result's properties. When the records could not be read
/// no result carries `suppressions` at all, SARIF's "not checked".
pub(crate) fn to_sarif(
    outcome: &AnalysisOutcome,
    binding: &AnalysisBinding<'_>,
    suppressions: &SuppressionOutcome,
) -> Result<Value, AnalysisError> {
    let rules = FindingCode::ALL
        .iter()
        .map(|code| {
            json!({
                "id": format!("policy-analysis/{}", code.as_str()),
                "name": code.as_str(),
                "shortDescription": { "text": code.rationale() },
                "help": { "text": code.remediation() },
            })
        })
        .collect::<Vec<_>>();
    let mut results = Vec::with_capacity(outcome.findings.len());
    for (index, finding) in outcome.findings.iter().enumerate() {
        let applied = applied_suppression(suppressions, index);
        let mut properties = Map::new();
        properties.insert("severity".to_owned(), json!(finding.severity.as_str()));
        properties.insert(
            "proof_basis".to_owned(),
            json!(finding.proof_basis.as_str()),
        );
        properties.insert(
            "never_decides_in".to_owned(),
            json!(lanes(&finding.never_decides_in)),
        );
        properties.insert(
            "may_decide_in".to_owned(),
            json!(lanes(&finding.may_decide_in)),
        );
        if let Some(related) = &finding.related {
            properties.insert("related".to_owned(), related.to_json());
        }
        properties.insert("details".to_owned(), Value::Object(finding.details.clone()));
        if let Some(patch) = &finding.patch {
            properties.insert("patch".to_owned(), patch_json(patch, binding.analyzed_etag));
        }
        properties.insert("limitations".to_owned(), json!(finding.limitations));
        if let Some(applied) = applied {
            properties.insert("suppression".to_owned(), suppression_json(applied));
        }
        let mut result = json!({
            "ruleId": format!("policy-analysis/{}", finding.code.as_str()),
            "ruleIndex": sarif_rule_index(finding.code),
            // A relation the evaluator did not confirm is for review, not a
            // failure the policy is proven to have.
            "kind": if finding.proof_basis == ProofBasis::Inconclusive { "review" } else { "fail" },
            "level": sarif_level(finding.severity),
            "message": { "text": finding.code.rationale() },
            "locations": [{
                "logicalLocations": [{
                    "name": finding
                        .element
                        .id
                        .clone()
                        .unwrap_or_else(|| finding.element.pointer.clone()),
                    "fullyQualifiedName": finding.element.pointer,
                    "kind": "element",
                }],
            }],
            "partialFingerprints": { "policyAnalysisFinding/v1": finding.fingerprint()? },
            "properties": properties,
        });
        if let (true, Some(result)) = (suppressions.available, result.as_object_mut()) {
            let accepted = applied
                .filter(|applied| applied.state == SuppressionState::Suppressed)
                .map(|applied| {
                    json!({
                        "kind": "external",
                        "status": "accepted",
                        "properties": { "suppression_id": applied.suppression_id },
                    })
                });
            result.insert(
                "suppressions".to_owned(),
                Value::Array(accepted.into_iter().collect()),
            );
        }
        results.push(result);
    }
    let mut properties = json!({
        "mode": "structural",
        "request_digest": binding.request_digest,
        "base_etag": binding.base_etag,
        "analyzed_source": binding.source,
        "analyzed_etag": binding.analyzed_etag,
        "resource_snapshot_complete": binding.resource_snapshot.is_complete(),
        "complete": outcome.complete,
        "limitations": limitation_codes(outcome),
        "suppressions": suppressions_json(suppressions),
        "summary": summary(outcome, suppressions),
        "analyzer": analyzer_versions(),
    });
    if let Some(properties) = properties.as_object_mut() {
        if let Some(revision) = binding.security_revision {
            properties.insert("security_revision".to_owned(), json!(revision));
        }
        if let Some(digest) = binding.analyzed_semantic_digest {
            properties.insert("analyzed_semantic_digest".to_owned(), json!(digest));
        }
        if let Some(digest) = binding.resource_snapshot.digest() {
            properties.insert("resource_snapshot_digest".to_owned(), json!(digest));
        }
        if let Some(stored) = binding.stored {
            stored.describe("analyzed_", properties);
        }
    }
    Ok(json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                },
            },
            "automationDetails": { "id": format!("policy-analysis/{}", binding.request_digest) },
            "results": results,
            "properties": properties,
        }],
    }))
}
