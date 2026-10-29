use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{
    report::{self, PolicyBinding, PolicySource, RunReport},
    run_against_policy,
    runner::{CaseStatus, RunStatus, Summary},
    suite::{parse_suite, Diagnostics, MAX_CASES, SUITE_SCHEMA_VERSION},
    RunError,
};
use crate::{policy_eval::PolicyAuthority, rbac::Policy};

/// Values a case supplies that no rendering may repeat. Each is unusual
/// enough that finding it in output can only mean it leaked from a fixture.
const SUBJECT_CANARY: &str = "subject-canary-7f3a";
const HOST_CANARY: &str = "tenant-canary.example.test";
const PATH_CANARY: &str = "/orders/path-canary-91c2";

fn policy() -> Policy {
    Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "reader": { "permissions": ["orders:read"] },
            "auditor": { "permissions": ["audit:read"] }
        },
        "rules": [
            { "id": "deny-internal", "methods": ["*"], "path": "/internal/**", "action": "deny" },
            { "id": "public-health", "methods": ["GET"], "path": "/health", "action": "allow" },
            { "id": "shadow-reports", "methods": ["GET"], "path": "/reports/**", "action": "shadow" },
            {
                "id": "deny-export-for-auditors",
                "tool_name": "reports.export",
                "principal": { "roles": ["auditor"] },
                "action": "deny"
            },
            { "methods": ["POST"], "path": "/render/blocked", "action": "deny" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" },
            {
                "methods": ["GET"],
                "hosts": [HOST_CANARY],
                "path_prefix": "/tenant",
                "permission": "orders:read"
            }
        ],
        "tools": {
            "reports.export": { "allowed_roles": ["reader", "auditor"] },
            "disabled.tool": { "enabled": false }
        },
        "rate_limits": [
            {
                "principal": { "roles": ["reader"] },
                "methods": ["GET"],
                "path": "/orders/**",
                "requests_per_second": 5,
                "burst": 10
            }
        ]
    }))
    .expect("the test policy is valid")
}

fn reader() -> Value {
    json!({
        "subject": SUBJECT_CANARY,
        "issuer": "https://idp.example.test/",
        "roles": ["reader"],
        "auth_method": "bearer_token"
    })
}

fn auditor() -> Value {
    json!({
        "subject": "auditor-1",
        "roles": ["auditor"],
        "auth_method": "session_cookie"
    })
}

fn suite(cases: Vec<Value>) -> Value {
    json!({ "schema_version": SUITE_SCHEMA_VERSION, "cases": cases })
}

/// One case of every kind and most outcomes, all expected to pass.
fn passing_cases() -> Vec<Value> {
    vec![
        json!({
            "id": "health-is-public",
            "kind": "http",
            "request": { "method": "GET", "path": "/health" },
            "principal": "anonymous",
            "expect": { "logical": "allow", "effect": "allow", "reason": "matched_rule", "matched": { "rule": "public-health" } }
        }),
        json!({
            "id": "reader-reads-orders",
            "description": "the orders route grants orders:read",
            "kind": "http",
            "request": { "method": "GET", "path": PATH_CANARY },
            "principal": reader(),
            "expect": { "logical": "allow", "reason": "matched_rule", "matched": { "route": 0 } }
        }),
        json!({
            "id": "anonymous-orders-denied",
            "kind": "http",
            "request": { "method": "GET", "path": "/orders/1" },
            "principal": "anonymous",
            "expect": { "logical": "deny", "effect": "block", "reason": "missing_principal", "matched": { "route": 0 } }
        }),
        json!({
            "id": "internal-denied-even-for-readers",
            "kind": "http",
            "request": { "method": "GET", "path": "/internal/metrics" },
            "principal": reader(),
            "expect": { "logical": "deny", "effect": "block", "matched": { "rule": "deny-internal" } }
        }),
        json!({
            "id": "reports-are-shadowed",
            "kind": "http",
            "request": { "method": "GET", "path": "/reports/q3" },
            "principal": reader(),
            "expect": { "logical": "deny", "effect": "observe", "matched": { "rule": "shadow-reports" } }
        }),
        json!({
            "id": "unmatched-falls-to-default",
            "kind": "http",
            "request": { "method": "DELETE", "path": "/elsewhere" },
            "principal": reader(),
            "expect": { "logical": "deny", "reason": "default_deny", "matched": "none" }
        }),
        json!({
            "id": "host-bound-route",
            "kind": "http",
            "request": {
                "method": "GET",
                "path": "/tenant/a",
                "host": HOST_CANARY,
                "target": {
                    "kind": "proxy_dispatch",
                    "upstream_origin": "https://tenant.internal.example.test:443/",
                    "route_id": "tenant",
                    "route_host": HOST_CANARY,
                    "route_path_prefix": "/tenant"
                }
            },
            "principal": reader(),
            "expect": { "logical": "allow", "matched": { "route": 1 } }
        }),
        json!({
            "id": "host-bound-upstream-without-route",
            "kind": "http",
            "request": {
                "method": "GET",
                "path": "/health",
                "host": "other.example.test",
                "target": {
                    "kind": "proxy_dispatch",
                    "upstream_origin": "pool:other",
                    "route_id": "other",
                    "route_host": "other.example.test"
                }
            },
            "principal": "anonymous",
            "expect": { "logical": "deny", "effect": "block", "reason": "host_policy_required" }
        }),
        json!({
            "id": "mcp-alias-takes-the-restrictive-identity",
            "kind": "http",
            "request": {
                "method": "GET",
                "path": "/health",
                "target": { "kind": "mcp_alias", "canonical_path": "/internal/mcp" }
            },
            "principal": "anonymous",
            "expect": { "logical": "deny", "matched": { "rule": "deny-internal" } }
        }),
        json!({
            "id": "reader-invokes-export",
            "kind": "tool",
            "tool": { "name": "reports.export" },
            "principal": reader(),
            "expect": { "logical": "allow", "reason": "allowed", "matched": "none" }
        }),
        json!({
            "id": "auditor-export-denied-by-rule",
            "kind": "tool",
            "tool": { "name": "reports.export", "operation": "invocation" },
            "principal": auditor(),
            "expect": { "logical": "deny", "reason": "matched_rule", "matched": { "rule": "deny-export-for-auditors" } }
        }),
        json!({
            "id": "unknown-tool",
            "kind": "tool",
            "tool": { "name": "no.such.tool" },
            "principal": reader(),
            "expect": { "logical": "deny", "reason": "unknown_tool" }
        }),
        json!({
            "id": "disabled-tool-hidden",
            "kind": "tool",
            "tool": { "name": "disabled.tool", "operation": "visibility" },
            "principal": reader(),
            "expect": { "logical": "deny", "reason": "policy_disabled" }
        }),
        json!({
            "id": "auditor-ineligible-by-rule",
            "kind": "tool",
            "tool": { "name": "reports.export", "operation": "eligibility" },
            "principal": auditor(),
            "expect": { "logical": "deny", "reason": "policy_denied" }
        }),
        json!({
            "id": "rendered-request-blocked",
            "kind": "tool_http",
            "tool": { "name": "reports.export" },
            "request": { "method": "POST", "path": "/render/blocked" },
            "principal": reader(),
            "expect": { "logical": "deny", "matched": { "rule": "4" } }
        }),
        json!({
            "id": "rendered-escaped-path-has-no-rule",
            "kind": "tool_http",
            "tool": { "name": "reports.export" },
            "request": { "method": "POST", "path": "/render/a%20b" },
            "principal": reader(),
            "expect": { "logical": "allow", "reason": "no_http_rule" }
        }),
        json!({
            "id": "reader-rate-override",
            "kind": "rate",
            "request": { "method": "GET", "path": "/orders/1" },
            "principal": reader(),
            "expect": { "rate_override": 0 }
        }),
        json!({
            "id": "anonymous-never-reaches-an-override",
            "kind": "rate",
            "request": { "method": "GET", "path": "/orders/1" },
            "principal": "anonymous",
            "expect": { "rate_override": null }
        }),
    ]
}

fn binding() -> PolicyBinding {
    PolicyBinding {
        source: PolicySource::Active,
        etag: "\"sha256:test\"".to_owned(),
        security_revision: None,
    }
}

/// A deadline no test run comes near: these tests are about verdicts, and
/// `a_run_past_its_deadline_returns_nothing` about the bound.
fn far_deadline() -> Instant {
    Instant::now() + Duration::from_secs(600)
}

fn run(document: &Value) -> RunReport {
    let suite = parse_suite(document).expect("the suite is valid");
    let digest = suite.digest.clone();
    let outcome = run_against_policy(
        policy(),
        PolicyAuthority::Standalone,
        &suite,
        far_deadline(),
    )
    .expect("policy compiles and the run finishes");
    RunReport::new(digest, binding(), outcome)
}

fn refused(document: &Value) -> Diagnostics {
    parse_suite(document).expect_err("the suite is refused")
}

fn codes(diagnostics: &Diagnostics) -> Vec<(&'static str, String)> {
    diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code, diagnostic.pointer.clone()))
        .collect()
}

#[test]
fn every_case_kind_decides_through_the_evaluator_and_passes() {
    let report = run(&suite(passing_cases()));
    let failures: Vec<_> = report
        .cases
        .iter()
        .filter(|case| case.status != CaseStatus::Passed)
        .map(|case| {
            (
                case.id.clone(),
                case.status,
                case.mismatches.clone(),
                case.actual.clone(),
            )
        })
        .collect();
    assert!(failures.is_empty(), "unexpected outcomes: {failures:?}");
    assert_eq!(report.status, RunStatus::Passed);
    assert_eq!(
        report.summary,
        Summary {
            total: passing_cases().len(),
            passed: passing_cases().len(),
            failed: 0,
            incomplete: 0,
            errors: 0,
        }
    );
}

#[test]
fn a_wrong_expectation_fails_and_names_every_mismatch_in_order() {
    let report = run(&suite(vec![json!({
        "id": "wrong",
        "kind": "http",
        "request": { "method": "GET", "path": "/internal/x" },
        "principal": "anonymous",
        "expect": {
            "logical": "allow",
            "effect": "allow",
            "reason": "default_allow",
            "matched": { "rule": "public-health" }
        }
    })]));
    let case = &report.cases[0];
    assert_eq!(case.status, CaseStatus::Failed);
    assert_eq!(case.mismatches, ["logical", "effect", "reason", "matched"]);
    assert_eq!(report.status, RunStatus::Failed);
    let actual = case
        .actual
        .as_ref()
        .expect("a decided case reports its answer");
    assert_eq!(actual.logical, Some("deny"));
    assert_eq!(actual.effect, Some("block"));
}

#[test]
fn an_expectation_on_one_field_ignores_the_others() {
    let report = run(&suite(vec![json!({
        "id": "logical-only",
        "kind": "http",
        "request": { "method": "GET", "path": "/reports/x" },
        "principal": "anonymous",
        "expect": { "logical": "deny" }
    })]));
    assert_eq!(report.cases[0].status, CaseStatus::Passed);
}

#[test]
fn a_wrong_rate_override_fails() {
    let report = run(&suite(vec![json!({
        "id": "rate",
        "kind": "rate",
        "request": { "method": "POST", "path": "/orders/1" },
        "principal": reader(),
        "expect": { "rate_override": 0 }
    })]));
    assert_eq!(report.cases[0].status, CaseStatus::Failed);
    assert_eq!(report.cases[0].mismatches, ["rate_override"]);
}

#[test]
fn run_status_is_the_worst_outcome_and_never_passes_an_empty_run() {
    let summary = |passed, failed, incomplete, errors| Summary {
        total: passed + failed + incomplete + errors,
        passed,
        failed,
        incomplete,
        errors,
    };
    assert_eq!(summary(3, 0, 0, 0).status(), RunStatus::Passed);
    assert_eq!(summary(2, 1, 0, 0).status(), RunStatus::Failed);
    assert_eq!(summary(1, 1, 1, 0).status(), RunStatus::Incomplete);
    assert_eq!(summary(1, 1, 1, 1).status(), RunStatus::Error);
    assert_eq!(summary(0, 0, 0, 0).status(), RunStatus::Failed);
}

/// A run is a cooperative bound on CPU time, like a simulation: past its
/// deadline it decides no further case and returns no partial report, which
/// could read as a smaller suite that passed.
#[test]
fn a_run_past_its_deadline_returns_nothing() {
    let suite = parse_suite(&suite(passing_cases())).expect("the suite is valid");
    let past = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap_or_else(Instant::now);
    assert!(matches!(
        run_against_policy(policy(), PolicyAuthority::Standalone, &suite, past),
        Err(RunError::DeadlineExceeded)
    ));
    // The same suite inside its deadline decides every case.
    let outcome = run_against_policy(
        policy(),
        PolicyAuthority::Standalone,
        &suite,
        far_deadline(),
    )
    .expect("the run finishes");
    assert_eq!(outcome.summary.total, passing_cases().len());
}

#[test]
fn the_digest_is_the_jcs_digest_of_the_document_and_ignores_member_order() {
    let first = parse_suite(&suite(passing_cases())).expect("valid");
    let reordered: Value = serde_json::from_str(
        r#"{"cases":[{"principal":"anonymous","expect":{"effect":"allow","logical":"allow"},"request":{"path":"/health","method":"GET"},"kind":"http","id":"a"}],"schema_version":"policy-tests.v1"}"#,
    )
    .expect("json");
    let canonical = suite(vec![json!({
        "id": "a",
        "kind": "http",
        "request": { "method": "GET", "path": "/health" },
        "principal": "anonymous",
        "expect": { "logical": "allow", "effect": "allow" }
    })]);
    let reordered = parse_suite(&reordered).expect("valid");
    let canonical = parse_suite(&canonical).expect("valid");
    assert_eq!(reordered.digest, canonical.digest);
    assert_ne!(first.digest, canonical.digest);
    assert!(first.digest.starts_with("sha256:"));
    assert_eq!(first.digest.len(), "sha256:".len() + 64);
}

#[test]
fn schema_dispatch_is_exact() {
    for version in [
        json!("policy-tests.v2"),
        json!("policy-tests.v1.0"),
        json!("Policy-Tests.v1"),
        json!(1),
    ] {
        let mut document = suite(passing_cases());
        document["schema_version"] = version;
        let diagnostics = refused(&document);
        assert_eq!(
            codes(&diagnostics),
            [("unsupported_schema_version", "/schema_version".to_owned())]
        );
    }
    let mut document = suite(passing_cases());
    document
        .as_object_mut()
        .expect("object")
        .remove("schema_version");
    assert!(codes(&refused(&document)).contains(&("missing_field", "/schema_version".to_owned())));
}

#[test]
fn an_empty_or_oversized_suite_is_refused() {
    assert_eq!(
        codes(&refused(&suite(Vec::new()))),
        [("empty_suite", "/cases".to_owned())]
    );
    let case = passing_cases().remove(0);
    let many = (0..=MAX_CASES)
        .map(|index| {
            let mut case = case.clone();
            case["id"] = json!(format!("case-{index}"));
            case
        })
        .collect();
    assert_eq!(
        codes(&refused(&suite(many))),
        [("too_many_cases", "/cases".to_owned())]
    );
}

#[test]
fn case_ids_are_unique_and_restricted() {
    let mut cases = passing_cases();
    cases[1]["id"] = cases[0]["id"].clone();
    assert_eq!(
        codes(&refused(&suite(cases))),
        [("duplicate_case_id", "/cases/1/id".to_owned())]
    );
    for id in ["", "-leading", "has space", "quote\"", "<xml>"] {
        let mut cases = passing_cases();
        cases[0]["id"] = json!(id);
        let diagnostics = refused(&suite(cases));
        assert_eq!(diagnostics.diagnostics.len(), 1, "{id}");
        assert_eq!(diagnostics.diagnostics[0].pointer, "/cases/0/id");
    }
}

#[test]
fn credentials_have_no_field_and_naming_one_is_refused_without_echoing_it() {
    const CANARY: &str = "credential-value-canary-c0ffee";
    let mut cases = passing_cases();
    cases[1]["principal"]["token"] = json!(CANARY);
    cases[2]["Authorization"] = json!(CANARY);
    cases[3]["request"]["headers"] = json!({ "cookie": CANARY });
    cases[4]["request"]["query"] = json!(CANARY);
    let diagnostics = refused(&suite(cases));
    assert_eq!(
        codes(&diagnostics),
        [
            ("forbidden_field", "/cases/1/principal/token".to_owned()),
            ("forbidden_field", "/cases/2/Authorization".to_owned()),
            ("forbidden_field", "/cases/3/request/headers".to_owned()),
            ("unknown_field", "/cases/4/request/query".to_owned()),
        ]
    );
    let rendered = serde_json::to_string(&diagnostics).expect("diagnostics serialize");
    assert!(!rendered.contains(CANARY));
}

#[test]
fn invalid_inputs_are_refused_with_pointers_and_never_echoed() {
    const CANARY: &str = "value-canary-5a5a";
    let mut cases = passing_cases();
    cases[0]["request"]["path"] = json!(format!("/health?{CANARY}"));
    cases[1]["request"]["method"] = json!(format!("GET {CANARY}"));
    cases[2]["request"]["host"] = json!(format!("{CANARY}.example.test:8443"));
    cases[3]["principal"]["auth_method"] = json!(CANARY);
    cases[4]["expect"]["logical"] = json!("indeterminate");
    cases[5]["expect"]["reason"] = json!(CANARY);
    cases[6]["request"]["target"]["upstream_origin"] =
        json!(format!("https://user:{CANARY}@upstream.example.test"));
    cases[7]["request"]["target"]["kind"] = json!(CANARY);
    cases[8]["request"]["target"]["canonical_path"] = json!("relative/path");
    cases[9]["tool"]["operation"] = json!(CANARY);
    cases[10]["expect"]["matched"] = json!({ "route": 0 });
    cases[16]["expect"]["rate_override"] = json!(-1);
    cases[17]["kind"] = json!(CANARY);
    let diagnostics = refused(&suite(cases));
    assert_eq!(
        codes(&diagnostics),
        [
            ("invalid_path", "/cases/0/request/path".to_owned()),
            ("invalid_method", "/cases/1/request/method".to_owned()),
            ("invalid_host", "/cases/2/request/host".to_owned()),
            ("invalid_value", "/cases/3/principal/auth_method".to_owned()),
            ("invalid_value", "/cases/4/expect/logical".to_owned()),
            ("invalid_value", "/cases/5/expect/reason".to_owned()),
            (
                "invalid_origin",
                "/cases/6/request/target/upstream_origin".to_owned()
            ),
            ("invalid_value", "/cases/7/request/target/kind".to_owned()),
            (
                "invalid_path",
                "/cases/8/request/target/canonical_path".to_owned()
            ),
            ("invalid_value", "/cases/9/tool/operation".to_owned()),
            ("invalid_value", "/cases/10/expect/matched".to_owned()),
            ("invalid_value", "/cases/16/expect/rate_override".to_owned()),
            ("invalid_value", "/cases/17/kind".to_owned()),
        ]
    );
    let rendered = serde_json::to_string(&diagnostics).expect("diagnostics serialize");
    assert!(!rendered.contains(CANARY));
}

#[test]
fn eligibility_requires_an_authenticated_principal() {
    let mut cases = passing_cases();
    cases[13]["principal"] = json!("anonymous");
    assert_eq!(
        codes(&refused(&suite(cases))),
        [("inconsistent_case", "/cases/13/principal".to_owned())]
    );
}

#[test]
fn a_principal_outside_the_authenticated_shape_is_refused() {
    let mut cases = passing_cases();
    cases[1]["principal"]["roles"] = json!((0..257)
        .map(|index| format!("role-{index}"))
        .collect::<Vec<_>>());
    cases[3]["principal"]["subject"] = json!("x".repeat(4097));
    let diagnostics = refused(&suite(cases));
    assert_eq!(
        codes(&diagnostics),
        [
            ("invalid_principal", "/cases/1/principal".to_owned()),
            ("invalid_principal", "/cases/3/principal".to_owned()),
        ]
    );
}

#[test]
fn diagnostics_are_bounded() {
    let cases = (0..200)
        .map(|index| json!({ "id": format!("c{index}"), "kind": "nope" }))
        .collect();
    let diagnostics = refused(&suite(cases));
    assert_eq!(diagnostics.diagnostics.len(), super::suite::MAX_DIAGNOSTICS);
    assert!(diagnostics.truncated);
}

#[test]
fn reports_are_deterministic_and_carry_no_fixture_values() {
    let document = suite(passing_cases());
    let first = run(&document);
    let second = run(&document);
    let json_first = serde_json::to_vec(&report::to_json(&first).expect("json")).expect("bytes");
    let json_second = serde_json::to_vec(&report::to_json(&second).expect("json")).expect("bytes");
    assert_eq!(json_first, json_second);
    let sarif = serde_json::to_string(&report::to_sarif(&first)).expect("sarif");
    let junit = report::to_junit(&first);
    assert_eq!(junit, report::to_junit(&second));
    let json_text = String::from_utf8(json_first).expect("utf-8");
    for rendering in [&json_text, &sarif, &junit] {
        for canary in [SUBJECT_CANARY, HOST_CANARY, PATH_CANARY, "idp.example.test"] {
            assert!(
                !rendering.contains(canary),
                "a rendering repeats the fixture value {canary}"
            );
        }
    }
}

#[test]
fn the_json_report_binds_suite_policy_and_evaluator() {
    let report = run(&suite(passing_cases()));
    let value = report::to_json(&report).expect("json");
    assert_eq!(value["schema_version"], json!("policy-test-results.v1"));
    assert_eq!(value["status"], json!("passed"));
    assert_eq!(value["mode"], json!("test"));
    assert_eq!(
        value["suite"]["schema_version"],
        json!(SUITE_SCHEMA_VERSION)
    );
    assert_eq!(value["suite"]["digest"], json!(report.suite.digest));
    assert_eq!(value["policy"]["source"], json!("active"));
    assert_eq!(value["policy"]["etag"], json!("\"sha256:test\""));
    assert!(value["policy"].get("security_revision").is_none());
    assert_eq!(
        value["evaluator"]["http_semantics_version"],
        json!(crate::policy_eval::HTTP_SEMANTICS_VERSION)
    );
    assert!(value["not_evaluated"]
        .as_array()
        .expect("list")
        .contains(&json!("authentication")));
    let health = &value["cases"][0];
    assert_eq!(health["id"], json!("health-is-public"));
    assert_eq!(health["pointer"], json!("/cases/0"));
    assert_eq!(health["kind"], json!("http"));
    assert_eq!(
        health["actual"]["matched"],
        json!({ "rule": "public-health" })
    );
    assert_eq!(health["actual"]["complete"], json!(true));
    let rate = value["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == json!("anonymous-never-reaches-an-override"))
        .expect("rate case");
    assert_eq!(rate["expected"]["rate_override"], Value::Null);
    assert_eq!(rate["actual"]["rate_override"], Value::Null);
}

#[test]
fn sarif_reports_only_cases_that_did_not_pass() {
    let mut cases = passing_cases();
    cases[0]["expect"]["logical"] = json!("deny");
    let report = run(&suite(cases));
    let sarif = report::to_sarif(&report);
    assert_eq!(sarif["version"], json!("2.1.0"));
    let run = &sarif["runs"][0];
    assert_eq!(
        run["tool"]["driver"]["name"],
        json!("greengateway-policy-tests")
    );
    let results = run["results"].as_array().expect("results");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ruleId"], json!("policy-test/failed"));
    assert_eq!(results[0]["ruleIndex"], json!(0));
    assert_eq!(
        run["tool"]["driver"]["rules"][0]["id"],
        json!("policy-test/failed")
    );
    assert_eq!(
        results[0]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
        json!("/cases/0")
    );
    assert_eq!(
        results[0]["message"]["text"],
        json!("Case health-is-public failed: logical expected deny, got allow.")
    );
    assert_eq!(run["properties"]["status"], json!("failed"));
    assert_eq!(run["properties"]["summary"]["failed"], json!(1));
    let passing = report::to_sarif(&run_passing());
    assert_eq!(passing["runs"][0]["results"], json!([]));
    assert_eq!(passing["runs"][0]["properties"]["status"], json!("passed"));
}

fn run_passing() -> RunReport {
    run(&suite(passing_cases()))
}

#[test]
fn junit_counts_failures_and_escapes_attributes() {
    let mut cases = passing_cases();
    cases[0]["expect"]["logical"] = json!("deny");
    let mut report = run(&suite(cases));
    report.policy.etag = "\"<&'>\"".to_owned();
    let xml = report::to_junit(&report);
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"));
    let total = passing_cases().len();
    assert!(xml.contains(&format!(
        "<testsuites name=\"greengateway-policy-tests\" tests=\"{total}\" failures=\"1\" errors=\"0\" skipped=\"0\">"
    )));
    assert!(
        xml.contains("<property name=\"policy_etag\" value=\"&quot;&lt;&amp;&apos;&gt;&quot;\"/>")
    );
    assert!(xml.contains("<testcase classname=\"policy.http\" name=\"health-is-public\">"));
    assert!(xml.contains(
        "<failure type=\"expectation_mismatch\" message=\"Case health-is-public failed: logical expected deny, got allow.\"/>"
    ));
    assert!(xml.contains("<testcase classname=\"policy.rate\" name=\"reader-rate-override\"/>"));
    assert_eq!(xml.matches("<testcase ").count(), total);
}

fn suite_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/policy-tests.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// The published schema and the parser agree on the documents both can
/// judge: everything the parser accepts in these tests, the schema accepts,
/// and the refusals JSON Schema can express are refused by both.
#[test]
fn the_published_schema_agrees_with_the_parser() {
    let schema = suite_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let accepted = suite(passing_cases());
    assert!(parse_suite(&accepted).is_ok());
    if let Err(error) = validator.validate(&accepted) {
        panic!("the schema refuses a suite the parser accepts: {error}");
    }
    let mut refusals = Vec::new();
    let mut document = suite(passing_cases());
    document["schema_version"] = json!("policy-tests.v2");
    refusals.push(document);
    refusals.push(suite(Vec::new()));
    for (index, member, value) in [(1, "token", json!("x")), (0, "unexpected", json!(true))] {
        let mut cases = passing_cases();
        cases[index][member] = value;
        refusals.push(suite(cases));
    }
    let mut cases = passing_cases();
    cases[4]["expect"]["logical"] = json!("indeterminate");
    refusals.push(suite(cases));
    let mut cases = passing_cases();
    cases[10]["expect"]["matched"] = json!({ "route": 0 });
    refusals.push(suite(cases));
    let mut cases = passing_cases();
    cases[0]["id"] = json!("-leading");
    refusals.push(suite(cases));
    let mut cases = passing_cases();
    cases[16]["expect"] = json!({});
    refusals.push(suite(cases));
    for document in refusals {
        assert!(parse_suite(&document).is_err(), "parser: {document}");
        assert!(!validator.is_valid(&document), "schema: {document}");
    }
}

/// Every reason code the schema lists is one the parser accepts for that
/// lane, and every decisive code the evaluator reports is listed.
#[test]
fn the_published_schema_lists_exactly_the_reason_codes_the_parser_accepts() {
    use crate::policy_eval::{tools::ToolReason, Reason};
    let schema = suite_schema();
    let listed = |definition: &str| -> Vec<String> {
        schema["$defs"][definition]["properties"]["reason"]["enum"]
            .as_array()
            .expect("a reason enum")
            .iter()
            .map(|code| code.as_str().expect("a code").to_owned())
            .collect()
    };
    let http = listed("http_expect");
    let decisive_http = [
        Reason::MatchedRule,
        Reason::MissingPermission,
        Reason::MissingPrincipal,
        Reason::DefaultAllow,
        Reason::DefaultDeny,
        Reason::HostPolicyRequired,
    ];
    assert_eq!(http.len(), decisive_http.len());
    for reason in decisive_http {
        assert!(http.contains(&reason.as_str().to_owned()));
        assert_eq!(
            super::suite::parse_http_reason(reason.as_str()),
            Some(reason)
        );
    }
    assert!(super::suite::parse_http_reason(Reason::Incomplete.as_str()).is_none());
    let tool = listed("tool_expect");
    let decisive_tool = [
        ToolReason::UnknownTool,
        ToolReason::Disabled,
        ToolReason::RoleNotAllowed,
        ToolReason::MatchedRule,
        ToolReason::Allowed,
        ToolReason::NotInPolicy,
        ToolReason::PolicyDisabled,
        ToolReason::PrincipalNotEligible,
        ToolReason::PolicyDenied,
        ToolReason::Eligible,
        ToolReason::NoHttpRule,
    ];
    assert_eq!(tool.len(), decisive_tool.len());
    for reason in decisive_tool {
        assert!(tool.contains(&reason.as_str().to_owned()));
        assert_eq!(
            super::suite::parse_tool_reason(reason.as_str()),
            Some(reason)
        );
    }
    assert!(super::suite::parse_tool_reason(ToolReason::Incomplete.as_str()).is_none());
}

/// The runner and the live tool adapters ask the same evaluator the same
/// questions, so over a matrix of tools, principals and rendered requests
/// they must agree: a visibility case is allowed exactly when the live
/// listing shows the tool, and a rendered request is decided by exactly the
/// rule the live executor would report.
#[test]
fn tool_cases_agree_with_the_live_tool_adapters() {
    use crate::{
        audit::{sink::tests::CaptureSink, AuditLog, AuditSink},
        auth::{AuthMethod, Principal},
        middleware::rbac::RbacState,
    };
    use std::sync::Arc;

    let policy = policy();
    let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
    let live = RbacState::new(policy.clone(), vec![], false, audit);
    let principals: Vec<(Value, Option<Principal>)> = vec![
        (json!("anonymous"), None),
        (
            reader(),
            Some(Principal {
                user_id: SUBJECT_CANARY.to_owned(),
                issuer: Some("https://idp.example.test".to_owned()),
                email: None,
                org_id: None,
                roles: vec!["reader".to_owned()],
                session_id: String::new(),
                auth_method: AuthMethod::Bearer,
            }),
        ),
        (
            auditor(),
            Some(Principal {
                user_id: "auditor-1".to_owned(),
                issuer: None,
                email: None,
                org_id: None,
                roles: vec!["auditor".to_owned()],
                session_id: String::new(),
                auth_method: AuthMethod::Cookie,
            }),
        ),
    ];
    let tools = ["reports.export", "disabled.tool", "no.such.tool"];
    let rendered = [
        ("POST", "/render/blocked"),
        ("GET", "/render/blocked"),
        ("DELETE", "/internal/x"),
        ("GET", "/health"),
        ("PUT", "/render/a%2Fb"),
    ];
    let mut cases = Vec::new();
    let mut expected = Vec::new();
    for (principal_index, (principal, live_principal)) in principals.iter().enumerate() {
        for tool in tools {
            cases.push(json!({
                "id": format!("visible-{principal_index}-{tool}"),
                "kind": "tool",
                "tool": { "name": tool, "operation": "visibility" },
                "principal": principal,
                "expect": { "logical": "allow" }
            }));
            expected.push(Ok(live.tool_visible(tool, live_principal.as_ref())));
        }
        for (method, path) in rendered {
            cases.push(json!({
                "id": format!("rendered-{principal_index}-{method}-{}", cases.len()),
                "kind": "tool_http",
                "tool": { "name": "reports.export" },
                "request": { "method": method, "path": path },
                "principal": principal,
                "expect": { "logical": "allow" }
            }));
            expected.push(Err(live
                .evaluate_tool_http_rule("reports.export", method, path, live_principal.as_ref())
                .expect("the live adapter decides every rendered request here")));
        }
    }
    let report = run(&suite(cases));
    for (case, expected) in report.cases.iter().zip(expected) {
        let actual = case.actual.as_ref().expect("every case is decided");
        match expected {
            Ok(visible) => assert_eq!(actual.effect == Some("allow"), visible, "{}", case.id),
            Err(None) => {
                assert_eq!(actual.reason, Some("no_http_rule"), "{}", case.id);
                assert_eq!(actual.logical, Some("allow"), "{}", case.id);
            }
            Err(Some(decision)) => {
                assert_eq!(
                    actual.matched,
                    Some(super::runner::MatchedView::Rule(
                        decision.matched_rule_id.clone()
                    )),
                    "{}",
                    case.id
                );
                let effect = match decision.action {
                    crate::rbac::RuleAction::Allow => "allow",
                    crate::rbac::RuleAction::Deny => "block",
                    crate::rbac::RuleAction::Shadow => "observe",
                };
                assert_eq!(actual.effect, Some(effect), "{}", case.id);
            }
        }
    }
}
