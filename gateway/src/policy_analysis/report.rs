//! Stable renderings of an analysis: the authoritative JSON report and SARIF
//! 2.1.0 for code-scanning consumers.
//!
//! Both are derived from the same [`AnalysisOutcome`] and are deterministic:
//! the same policy, resources and analyzer version produce byte-identical
//! output, which is why neither carries a timestamp or a duration. SARIF
//! carries no more than the JSON: codes, pointers, positions, element ids,
//! fingerprints and the bindings, never a path, permission, role or caller.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::{
    AnalysisError, AnalysisOutcome, CandidatePatch, Finding, FindingCode, ProofBasis, Severity,
    ANALYZER_VERSION, MAX_COMPARISONS, MAX_FINDINGS, RESULT_SCHEMA_VERSION,
};
use crate::policy_eval::{
    tools::{TOOL_CONTEXT_VERSION, TOOL_SEMANTICS_VERSION},
    CONTEXT_VERSION, HTTP_SEMANTICS_VERSION,
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
    /// `active`, `edits` or `inline`.
    pub(crate) source: &'static str,
    /// The ETag of the analyzed document, which every position names.
    pub(crate) analyzed_etag: &'a str,
    pub(crate) edit_count: usize,
    pub(crate) mcp_alias_paths: usize,
}

/// Counts only: no finding identity, so the summary is safe to audit.
pub(crate) fn summary(outcome: &AnalysisOutcome) -> Value {
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
    })
}

/// The authoritative JSON report.
pub(crate) fn to_json(
    outcome: &AnalysisOutcome,
    binding: &AnalysisBinding<'_>,
) -> Result<Value, AnalysisError> {
    let findings = outcome
        .findings
        .iter()
        .map(|finding| finding_json(finding, binding.analyzed_etag))
        .collect::<Result<Vec<_>, _>>()?;
    let mut base = json!({ "source": "active", "etag": binding.base_etag });
    if let (Some(revision), Some(base)) = (binding.security_revision, base.as_object_mut()) {
        base.insert("security_revision".to_owned(), json!(revision));
    }
    let mut analyzed = json!({ "source": binding.source, "etag": binding.analyzed_etag });
    if let (true, Some(analyzed)) = (binding.source == "edits", analyzed.as_object_mut()) {
        analyzed.insert("edits".to_owned(), json!(binding.edit_count));
    }
    Ok(json!({
        "schema_version": RESULT_SCHEMA_VERSION,
        "mode": "structural",
        "request_digest": binding.request_digest,
        "analyzer": analyzer_versions(),
        "base": base,
        "analyzed": analyzed,
        "resources": { "mcp_alias_paths": binding.mcp_alias_paths },
        "complete": outcome.complete,
        "limitations": limitation_codes(outcome),
        "budget": {
            "comparisons": outcome.comparisons,
            "max_comparisons": MAX_COMPARISONS,
            "max_findings": MAX_FINDINGS,
        },
        "summary": summary(outcome),
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

fn finding_json(finding: &Finding, analyzed_etag: &str) -> Result<Value, AnalysisError> {
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
pub(crate) fn to_sarif(
    outcome: &AnalysisOutcome,
    binding: &AnalysisBinding<'_>,
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
    for finding in &outcome.findings {
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
        let index = sarif_rule_index(finding.code);
        results.push(json!({
            "ruleId": format!("policy-analysis/{}", finding.code.as_str()),
            "ruleIndex": index,
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
        }));
    }
    let mut properties = json!({
        "mode": "structural",
        "request_digest": binding.request_digest,
        "base_etag": binding.base_etag,
        "analyzed_source": binding.source,
        "analyzed_etag": binding.analyzed_etag,
        "complete": outcome.complete,
        "limitations": limitation_codes(outcome),
        "summary": summary(outcome),
        "analyzer": analyzer_versions(),
    });
    if let (Some(revision), Some(properties)) =
        (binding.security_revision, properties.as_object_mut())
    {
        properties.insert("security_revision".to_owned(), json!(revision));
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
