//! What `ggctl diff` writes for a semantic diff (issue #242, PR 9; ADR-0008,
//! "Plan, risk acknowledgment, and conditional apply").
//!
//! The diff is `gateway_config::semantic_diff`'s, the one the gateway's
//! plans will report, so the CLI cannot approximate it. This module renders
//! it three ways, all value-free because the diff is:
//!
//! - human: one line per change, then the sorted risk codes;
//! - `--format json`: the `diffResult` a `GgctlReport` carries;
//! - `--format sarif`: one SARIF result per risk code of each change, with
//!   the change's field as a logical location, so CI can annotate a review.
//!   A change that carries no risk code is not a finding and is not a result.
//!
//! `--check` exits `4` when anything differs. Comparing needs the bundle
//! reader and the configuration compiler, which move into gateway-config
//! with `ggctl validate` (#242 PR 8); until then no command writes these and
//! they are exercised by their tests.
// `ggctl diff` (#242 PR 8) is the caller; until then only the tests are.
#![cfg_attr(not(test), expect(dead_code))]

use gateway_config::semantic_diff::{Change, Display, SemanticDiff, Severity, Shown};
use serde_json::{json, Value};

use crate::{diagnostic::Exit, sarif};

/// Where every risk code is described.
const RISK_CODES_ANCHOR: &str = "docs/semantic-diff.md#risk-codes";

/// The exit status of a diff that ran: `4` (`drift`) under `--check` when
/// anything differs, otherwise `0`.
pub(crate) fn exit(diff: &SemanticDiff, check: bool) -> Exit {
    if check && !diff.is_empty() {
        Exit::Drift
    } else {
        Exit::Success
    }
}

/// The report's `result`. `None` only when the diff cannot be serialized,
/// which a caller reports as an internal failure rather than a partial
/// result.
pub(crate) fn result(diff: &SemanticDiff) -> Option<Value> {
    serde_json::to_value(diff).ok()
}

/// The human form: one line per change, ordered by section and field, then
/// the risk codes.
pub(crate) fn human(diff: &SemanticDiff) -> String {
    if diff.is_empty() {
        return "no changes\n".to_owned();
    }
    let mut text = String::new();
    for change in diff.changes() {
        let codes: Vec<&str> = change.risks().iter().map(|code| code.as_str()).collect();
        let mut line = format!(
            "{:<6}  {}  {} {}, {}, {}",
            severity_name(change.severity()),
            change.field(),
            change.kind().as_str(),
            value(change),
            change.class().as_str(),
            change.effect().as_str(),
        );
        if !codes.is_empty() {
            line.push_str(&format!("  [{}]", codes.join(", ")));
        }
        text.push_str(line.trim_end());
        text.push('\n');
    }
    let codes: Vec<&str> = diff.risks().into_iter().map(|code| code.as_str()).collect();
    text.push_str(&format!(
        "{} changed, highest risk {}: {}\n",
        diff.changes().len(),
        severity_name(diff.severity()),
        if codes.is_empty() {
            "no risk codes".to_owned()
        } else {
            codes.join(", ")
        }
    ));
    text
}

fn value(change: &Change) -> String {
    let entries = change.entries().map(|entries| {
        format!(
            " ({} added, {} removed, {} changed)",
            entries.added, entries.removed, entries.changed
        )
    });
    match change.display() {
        Display::Shown { before, after } => format!("{} -> {}", shown(before), shown(after)),
        Display::Withheld => format!("(value withheld){}", entries.unwrap_or_default()),
        Display::Reference => format!("(reference changed){}", entries.unwrap_or_default()),
    }
}

fn shown(value: Shown) -> String {
    match value {
        Shown::Flag(flag) => flag.to_string(),
        Shown::Word(word) => word.to_owned(),
        Shown::Count(count) => count.to_string(),
        Shown::Rate(rate) => rate.to_string(),
        Shown::Unbounded => "unbounded".to_owned(),
    }
}

fn severity_name(severity: Option<Severity>) -> &'static str {
    severity.map_or("none", Severity::as_str)
}

/// The SARIF log: one rule per risk code the diff carries, in code order,
/// and one result per risk code of each change.
pub(crate) fn sarif(diff: &SemanticDiff) -> Value {
    let codes: Vec<_> = diff.risks().into_iter().collect();
    let rules: Vec<Value> = codes
        .iter()
        .map(|code| {
            json!({
                "id": code.as_str(),
                "shortDescription": {"text": code.description()},
                "help": {"text": format!("See {RISK_CODES_ANCHOR}")},
                "defaultConfiguration": {"level": level(code.severity())},
            })
        })
        .collect();
    let mut results = Vec::new();
    for change in diff.changes() {
        for code in change.risks() {
            let index = codes
                .iter()
                .position(|listed| listed == code)
                .unwrap_or_default();
            results.push(json!({
                "ruleId": code.as_str(),
                "ruleIndex": index,
                "level": level(code.severity()),
                "message": {
                    "text": format!("{}: {}", change.field(), code.description()),
                },
                "locations": [{
                    "logicalLocations": [{
                        "fullyQualifiedName": change.field(),
                        "kind": "member",
                    }],
                }],
                "properties": {
                    "section": change.section().as_str(),
                    "kind": change.kind().as_str(),
                    "class": change.class().as_str(),
                    "effect": change.effect().as_str(),
                },
            }));
        }
    }
    sarif::envelope(rules, results)
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

#[cfg(test)]
mod tests {
    use gateway_config::semantic_diff::{ChangeClass, Comparison, Field, RiskCode, Rule, Section};
    use serde_json::json;

    use super::{exit, human, result, sarif};
    use crate::diagnostic::Exit;

    static AUTH: Field = Field {
        id: "AUTH_ENABLED",
        section: Section::Authentication,
        class: ChangeClass::Restart,
        risk: RiskCode::AuthDisabled,
        rule: Rule::LooserWhen(false),
    };
    static HOSTS: Field = Field {
        id: "EGRESS_ALLOWED_HOSTS",
        section: Section::Egress,
        class: ChangeClass::Restart,
        risk: RiskCode::EgressBroadened,
        rule: Rule::GrowthIsLooser,
    };
    static KEY: Field = Field {
        id: "TLS_KEY_FILE",
        section: Section::Tls,
        class: ChangeClass::Restart,
        risk: RiskCode::CredentialBindingChanged,
        rule: Rule::AnyChange,
    };
    static BODY: Field = Field {
        id: "MAX_BODY_SIZE",
        section: Section::Limits,
        class: ChangeClass::Restart,
        risk: RiskCode::LimitsLoosened,
        rule: Rule::HigherIsLooser,
    };

    fn weakened() -> gateway_config::semantic_diff::SemanticDiff {
        let mut comparison = Comparison::new();
        comparison.flag(&AUTH, true, false);
        comparison.set(&HOSTS, ["a.test"], ["a.test", "zqcanary.test"]);
        comparison.secret(
            &KEY,
            Some("/run/zqcanary/a.pem"),
            Some("/run/zqcanary/b.pem"),
        );
        comparison.count(&BODY, Some(2), Some(1));
        comparison.finish()
    }

    #[test]
    fn check_exits_drift_only_when_something_differs() {
        let empty = Comparison::new().finish();
        assert_eq!(exit(&empty, true), Exit::Success);
        assert_eq!(exit(&weakened(), false), Exit::Success);
        assert_eq!(exit(&weakened(), true), Exit::Drift);
        assert_eq!(Exit::Drift.code(), 4);
    }

    #[test]
    fn the_human_form_lists_each_change_and_never_a_value() {
        let text = human(&weakened());
        assert_eq!(
            text,
            concat!(
                "high    TLS_KEY_FILE  modified (reference changed), restart, loosened  [risk.credential_binding_changed]\n",
                "high    AUTH_ENABLED  modified true -> false, restart, loosened  [risk.auth_disabled]\n",
                "high    EGRESS_ALLOWED_HOSTS  modified (value withheld) (1 added, 0 removed, 0 changed), restart, loosened  [risk.egress_broadened]\n",
                "none    MAX_BODY_SIZE  modified 2 -> 1, restart, tightened\n",
                "4 changed, highest risk high: risk.auth_disabled, risk.credential_binding_changed, risk.egress_broadened\n",
            )
        );
        assert!(!text.contains("zqcanary"));
        assert_eq!(human(&Comparison::new().finish()), "no changes\n");
    }

    #[test]
    fn the_report_result_is_the_engines_diff() {
        let value = result(&weakened()).expect("serializes");
        assert_eq!(value["changed"], true);
        assert_eq!(value["severity"], "high");
        assert_eq!(value["changes"].as_array().map(Vec::len), Some(4));
        assert!(!value.to_string().contains("zqcanary"));
    }

    #[test]
    fn sarif_has_one_rule_per_code_and_one_result_per_code_of_each_change() {
        let log = sarif(&weakened());
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "ggctl");
        let rules = run["tool"]["driver"]["rules"].as_array().expect("rules");
        let ids: Vec<&str> = rules
            .iter()
            .filter_map(|rule| rule["id"].as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "risk.auth_disabled",
                "risk.credential_binding_changed",
                "risk.egress_broadened"
            ]
        );
        assert_eq!(
            rules[0]["help"]["text"],
            "See docs/semantic-diff.md#risk-codes"
        );
        let results = run["results"].as_array().expect("results");
        assert_eq!(results.len(), 3);
        assert_eq!(
            results[1],
            json!({
                "ruleId": "risk.auth_disabled",
                "ruleIndex": 0,
                "level": "error",
                "message": {"text": "AUTH_ENABLED: authentication is turned off"},
                "locations": [{"logicalLocations": [{"fullyQualifiedName": "AUTH_ENABLED", "kind": "member"}]}],
                "properties": {"section": "authentication", "kind": "modified", "class": "restart", "effect": "loosened"}
            })
        );
        assert!(!log.to_string().contains("zqcanary"));

        let empty = sarif(&Comparison::new().finish());
        assert_eq!(empty["runs"][0]["results"], json!([]));
        assert_eq!(empty["runs"][0]["tool"]["driver"]["rules"], json!([]));
    }
}
