//! Stable renderings of a run: the authoritative JSON report, SARIF 2.1.0 for
//! code-scanning consumers, and JUnit XML for CI test reporters.
//!
//! All three are derived from the same [`RunReport`] and are deterministic: the
//! same policy and suite produce byte-identical output, which is why no
//! rendering carries a timestamp or a duration. The SARIF and JUnit forms
//! carry no more than the JSON one -- case ids, stable codes, the suite digest
//! and the policy ETag -- and never a fixture value.

use serde::Serialize;
use serde_json::{json, Value};

use super::{
    runner::{CaseResult, CaseStatus, MatchedView, RunOutcome, RunStatus, Summary},
    suite::SUITE_SCHEMA_VERSION,
    NOT_EVALUATED,
};
use crate::policy_eval::{
    tools::{TOOL_CONTEXT_VERSION, TOOL_SEMANTICS_VERSION},
    CONTEXT_VERSION, HTTP_SEMANTICS_VERSION,
};

/// The schema version of the JSON report.
pub(crate) const RESULT_SCHEMA_VERSION: &str = "policy-test-results.v1";
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_NAME: &str = "greengateway-policy-tests";
/// SARIF rules, one per non-passing case outcome, in a fixed order so a
/// result's `ruleIndex` is stable.
const SARIF_RULES: &[(&str, &str)] = &[
    (
        "policy-test/failed",
        "The evaluator decided the case, and at least one stated expectation did not hold.",
    ),
    (
        "policy-test/incomplete",
        "The evaluator could not decide the case; an undecided case never passes.",
    ),
    (
        "policy-test/error",
        "The evaluator refused the case; a refusal never counts as a passing assertion.",
    ),
];

/// Which policy a run judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicySource {
    /// The live policy, as its authority holds it.
    Active,
    /// A candidate submitted with the run. Never persisted or activated.
    InlineCandidate,
}

impl PolicySource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::InlineCandidate => "inline_candidate",
        }
    }
}

/// The identity of the policy a run judged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PolicyBinding {
    pub(crate) source: PolicySource,
    /// The policy ETag: the live one for `active`, and for a candidate the
    /// ETag it would have once written.
    pub(crate) etag: String,
    /// The cluster security revision the active document was read at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) security_revision: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SuiteBinding {
    pub(crate) schema_version: &'static str,
    pub(crate) digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct EvaluatorBinding {
    pub(crate) http_semantics_version: &'static str,
    pub(crate) http_context_version: u16,
    pub(crate) tool_semantics_version: &'static str,
    pub(crate) tool_context_version: u16,
}

impl EvaluatorBinding {
    pub(crate) fn current() -> Self {
        Self {
            http_semantics_version: HTTP_SEMANTICS_VERSION,
            http_context_version: CONTEXT_VERSION,
            tool_semantics_version: TOOL_SEMANTICS_VERSION,
            tool_context_version: TOOL_CONTEXT_VERSION,
        }
    }
}

/// The authoritative result of a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct RunReport {
    pub(crate) schema_version: &'static str,
    pub(crate) status: RunStatus,
    pub(crate) mode: &'static str,
    pub(crate) suite: SuiteBinding,
    pub(crate) policy: PolicyBinding,
    pub(crate) evaluator: EvaluatorBinding,
    pub(crate) gateway_version: &'static str,
    /// The stages no case's verdict covers. A passing run is a statement about
    /// policy decisions only, never that a real request would succeed.
    pub(crate) not_evaluated: &'static [&'static str],
    pub(crate) summary: Summary,
    pub(crate) cases: Vec<CaseResult>,
}

impl RunReport {
    pub(crate) fn new(suite_digest: String, policy: PolicyBinding, outcome: RunOutcome) -> Self {
        Self {
            schema_version: RESULT_SCHEMA_VERSION,
            status: outcome.status(),
            mode: "test",
            suite: SuiteBinding {
                schema_version: SUITE_SCHEMA_VERSION,
                digest: suite_digest,
            },
            policy,
            evaluator: EvaluatorBinding::current(),
            gateway_version: env!("CARGO_PKG_VERSION"),
            not_evaluated: NOT_EVALUATED,
            summary: outcome.summary,
            cases: outcome.cases,
        }
    }
}

/// The JSON report, as a value for the caller to serialize.
pub(crate) fn to_json(report: &RunReport) -> Result<Value, serde_json::Error> {
    serde_json::to_value(report)
}

/// One sentence describing a non-passing case, from stable codes only.
fn case_message(case: &CaseResult) -> String {
    match case.status {
        CaseStatus::Passed => format!("Case {} passed.", case.id),
        CaseStatus::Error => format!(
            "Case {} was refused by the evaluator: {}.",
            case.id,
            case.error.unwrap_or("unknown")
        ),
        CaseStatus::Incomplete => format!(
            "Case {} could not be decided: {}.",
            case.id,
            case.actual
                .as_ref()
                .and_then(|actual| actual.limitation)
                .unwrap_or("incomplete")
        ),
        CaseStatus::Failed => {
            let details = case
                .mismatches
                .iter()
                .map(|field| {
                    format!(
                        "{field} expected {}, got {}",
                        expected_text(case, field),
                        actual_text(case, field)
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            format!("Case {} failed: {details}.", case.id)
        }
    }
}

fn matched_text(matched: &MatchedView) -> String {
    match matched {
        MatchedView::None => "none".to_owned(),
        MatchedView::Rule(id) => format!("rule {id}"),
        MatchedView::Route(index) => format!("route {index}"),
    }
}

fn override_text(selected: Option<usize>) -> String {
    selected.map_or_else(
        || "no override".to_owned(),
        |index| format!("override {index}"),
    )
}

fn expected_text(case: &CaseResult, field: &str) -> String {
    let expected = &case.expected;
    let text = match field {
        "logical" => expected.logical.map(str::to_owned),
        "effect" => expected.effect.map(str::to_owned),
        "reason" => expected.reason.map(str::to_owned),
        "matched" => expected.matched.as_ref().map(matched_text),
        "rate_override" => expected.rate_override.map(override_text),
        _ => None,
    };
    text.unwrap_or_else(|| "-".to_owned())
}

fn actual_text(case: &CaseResult, field: &str) -> String {
    let Some(actual) = case.actual.as_ref() else {
        return "-".to_owned();
    };
    let text = match field {
        "logical" => actual.logical.map(str::to_owned),
        "effect" => actual.effect.map(str::to_owned),
        "reason" => actual.reason.map(str::to_owned),
        "matched" => actual.matched.as_ref().map(matched_text),
        "rate_override" => actual.rate_override.map(override_text),
        _ => None,
    };
    text.unwrap_or_else(|| "-".to_owned())
}

fn sarif_rule_index(status: CaseStatus) -> Option<usize> {
    match status {
        CaseStatus::Passed => None,
        CaseStatus::Failed => Some(0),
        CaseStatus::Incomplete => Some(1),
        CaseStatus::Error => Some(2),
    }
}

/// SARIF 2.1.0: one result per case that did not pass, so an empty result
/// list means every case passed. The run's properties carry the bindings and
/// counts, so a consumer can tell an all-passing run from an empty file.
pub(crate) fn to_sarif(report: &RunReport) -> Value {
    let rules = SARIF_RULES
        .iter()
        .map(|(id, description)| {
            json!({
                "id": id,
                "shortDescription": { "text": description },
                "defaultConfiguration": { "level": "error" },
            })
        })
        .collect::<Vec<_>>();
    let results = report
        .cases
        .iter()
        .filter_map(|case| {
            let index = sarif_rule_index(case.status)?;
            Some(json!({
                "ruleId": SARIF_RULES[index].0,
                "ruleIndex": index,
                "kind": "fail",
                "level": "error",
                "message": { "text": case_message(case) },
                "locations": [{
                    "logicalLocations": [{
                        "name": case.id,
                        "fullyQualifiedName": case.pointer,
                        "kind": "element",
                    }],
                }],
                "partialFingerprints": { "policyTestCase/v1": case.id },
                "properties": {
                    "case_kind": case.kind.as_str(),
                    "status": case.status.as_str(),
                    "mismatches": case.mismatches,
                },
            }))
        })
        .collect::<Vec<_>>();
    let mut properties = json!({
        "status": report.status.as_str(),
        "suite_schema_version": report.suite.schema_version,
        "suite_digest": report.suite.digest,
        "policy_source": report.policy.source.as_str(),
        "policy_etag": report.policy.etag,
        "summary": report.summary,
        "not_evaluated": report.not_evaluated,
    });
    if let (Some(revision), Some(properties)) =
        (report.policy.security_revision, properties.as_object_mut())
    {
        properties.insert("security_revision".to_owned(), json!(revision));
    }
    json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": report.gateway_version,
                    "semanticVersion": report.gateway_version,
                    "rules": rules,
                },
            },
            "automationDetails": { "id": format!("policy-tests/{}", report.suite.digest) },
            "results": results,
            "properties": properties,
        }],
    })
}

/// JUnit XML: one `testcase` per case. A failed or incomplete case is a
/// `failure`, a refused one an `error`; nothing is ever `skipped`, because a
/// case that did not run cannot be reported as one that did.
pub(crate) fn to_junit(report: &RunReport) -> String {
    let summary = report.summary;
    let failures = summary.failed + summary.incomplete;
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<testsuites name=\"{}\" tests=\"{}\" failures=\"{failures}\" errors=\"{}\" skipped=\"0\">\n",
        TOOL_NAME, summary.total, summary.errors
    ));
    xml.push_str(&format!(
        "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{failures}\" errors=\"{}\" skipped=\"0\">\n",
        report.suite.schema_version, summary.total, summary.errors
    ));
    xml.push_str("    <properties>\n");
    let mut properties = vec![
        ("status", report.status.as_str().to_owned()),
        ("suite_digest", report.suite.digest.clone()),
        ("policy_source", report.policy.source.as_str().to_owned()),
        ("policy_etag", report.policy.etag.clone()),
        ("gateway_version", report.gateway_version.to_owned()),
        (
            "http_semantics_version",
            report.evaluator.http_semantics_version.to_owned(),
        ),
        (
            "tool_semantics_version",
            report.evaluator.tool_semantics_version.to_owned(),
        ),
    ];
    if let Some(revision) = report.policy.security_revision {
        properties.push(("security_revision", revision.to_string()));
    }
    for (name, value) in properties {
        xml.push_str(&format!(
            "      <property name=\"{}\" value=\"{}\"/>\n",
            xml_escape(name),
            xml_escape(&value)
        ));
    }
    xml.push_str("    </properties>\n");
    for case in &report.cases {
        let opening = format!(
            "    <testcase classname=\"policy.{}\" name=\"{}\"",
            case.kind.as_str(),
            xml_escape(&case.id)
        );
        match case.status {
            CaseStatus::Passed => {
                xml.push_str(&opening);
                xml.push_str("/>\n");
            }
            CaseStatus::Failed | CaseStatus::Incomplete | CaseStatus::Error => {
                let (element, kind) = match case.status {
                    CaseStatus::Error => ("error", "evaluator_refused"),
                    CaseStatus::Incomplete => ("failure", "incomplete"),
                    _ => ("failure", "expectation_mismatch"),
                };
                xml.push_str(&opening);
                xml.push_str(">\n");
                xml.push_str(&format!(
                    "      <{element} type=\"{kind}\" message=\"{}\"/>\n",
                    xml_escape(&case_message(case))
                ));
                xml.push_str("    </testcase>\n");
            }
        }
    }
    xml.push_str("  </testsuite>\n");
    xml.push_str("</testsuites>\n");
    xml
}

/// Escape text for an XML attribute value. Every character outside the XML
/// 1.0 character range is replaced, so a value can never end the document.
fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' | '\n' | '\r' => {
                escaped.push_str(&format!("&#{};", u32::from(character)));
            }
            character if character < ' ' || character == '\u{FFFE}' || character == '\u{FFFF}' => {
                escaped.push('\u{FFFD}');
            }
            character => escaped.push(character),
        }
    }
    escaped
}
