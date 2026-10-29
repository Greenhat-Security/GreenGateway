use gateway_config::semantic_diff::{
    ChangeClass, Comparison, Field, RiskCode, Rule, Section, SemanticDiff,
};
use serde_json::{json, Value};

use super::{exit, human, sarif_log};
use crate::{
    diagnostic::Exit,
    validate::tests::{assert_no_canary, codes, report, run, Fixture, CANARY},
};

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

fn weakened() -> SemanticDiff {
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
fn sarif_has_one_rule_per_code_and_one_result_per_code_of_each_change() {
    let log = sarif_log(&weakened(), &[]);
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

    let empty = sarif_log(&Comparison::new().finish(), &[]);
    assert_eq!(empty["runs"][0]["results"], json!([]));
    assert_eq!(empty["runs"][0]["tool"]["driver"]["rules"], json!([]));
}

fn broadened() -> Fixture {
    Fixture::with(
        "production",
        &format!(
            "{{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\", \"roles\": {{\"{CANARY}\": {{\"permissions\": [\"admin:policy:write\"]}}}}, \"egress\": {{\"hosts\": [\"{CANARY}.example.test\"]}}}}\n"
        ),
    )
}

fn assert_paths_not_echoed(captured: &crate::report::tests::Captured, fixtures: &[&Fixture]) {
    for fixture in fixtures {
        for output in [captured.stdout(), captured.stderr()] {
            assert!(!output.contains(fixture.path()), "{output}");
        }
    }
}

#[test]
fn diff_compares_two_bundles_by_what_they_configure() {
    let base = Fixture::valid();
    let (exit, captured) = run(&["diff", base.path(), "--against", base.path(), "--check"]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(captured.stdout(), "no changes\n");

    let candidate = broadened();
    let (exit, captured) = run(&[
        "diff",
        candidate.path(),
        "--against",
        base.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["command"], "diff");
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(
        found["result"]["diff"]["riskCodes"],
        json!(["risk.egress_broadened", "risk.policy_broadened"])
    );
    assert_eq!(found["result"]["diff"]["severity"], "high");
    assert_eq!(codes(&found), ["validate.production_validators_not_run"]);
    assert_no_canary(&captured);
    assert_paths_not_echoed(&captured, &[&base, &candidate]);

    // The reverse is a tightening: the same fields, no risk.
    let (_, captured) = run(&[
        "diff",
        base.path(),
        "--against",
        candidate.path(),
        "--format",
        "json",
    ]);
    let reverse = report(&captured);
    assert_eq!(reverse["result"]["diff"]["riskCodes"], json!([]));
    assert_eq!(reverse["result"]["diff"]["changed"], true);
}

#[test]
fn check_exits_4_on_any_difference_and_sarif_carries_the_risk_codes() {
    let base = Fixture::valid();
    let candidate = broadened();
    let (exit, captured) = run(&[
        "diff",
        candidate.path(),
        "--against",
        base.path(),
        "--check",
    ]);
    assert_eq!(exit, Exit::Drift);
    assert!(captured.stdout().contains("[risk.egress_broadened]"));
    assert!(captured.stderr().contains("diff.drift_found"));
    assert_no_canary(&captured);

    let (exit, captured) = run(&[
        "diff",
        candidate.path(),
        "--against",
        base.path(),
        "--check",
        "--format",
        "sarif",
    ]);
    assert_eq!(exit, Exit::Drift);
    assert!(captured.stderr().is_empty());
    let log: Value = serde_json::from_str(captured.stdout()).expect("one SARIF log");
    let rule_ids: Vec<&str> = log["runs"][0]["results"]
        .as_array()
        .expect("results")
        .iter()
        .filter_map(|result| result["ruleId"].as_str())
        .collect();
    assert_eq!(
        rule_ids,
        [
            "validate.production_validators_not_run",
            "diff.drift_found",
            "risk.egress_broadened",
            "risk.policy_broadened",
        ]
    );
    let rules = log["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules");
    for result in log["runs"][0]["results"].as_array().expect("results") {
        let index = result["ruleIndex"].as_u64().expect("an index") as usize;
        assert_eq!(rules[index]["id"], result["ruleId"]);
    }
    assert_no_canary(&captured);
    assert_paths_not_echoed(&captured, &[&base, &candidate]);
}

#[test]
fn an_invalid_bundle_is_not_compared() {
    let base = Fixture::valid();
    let allow = Fixture::with(
        "production",
        &format!(
            "{{\"schema_version\": \"0.1.0\", \"id\": \"{CANARY}\", \"default_action\": \"allow\"}}\n"
        ),
    );
    let (exit, captured) = run(&[
        "diff",
        allow.path(),
        "--against",
        base.path(),
        "--check",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], false);
    assert!(found["result"].get("diff").is_none());
    assert_eq!(codes(&found)[0], "profile.policy_default_allow");
    assert_no_canary(&captured);

    // --against is required.
    let (exit, _) = run(&["diff", base.path()]);
    assert_eq!(exit, Exit::Usage);
}
