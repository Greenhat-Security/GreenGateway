//! The simulation request, edits, projections and runner, without the admin
//! API. The endpoint, its authorization and its side-effect freedom are
//! covered in `admin_policy_simulations_tests`.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{
    edits::{apply_edits, parse_edits},
    request::{parse_request, CandidateSource, SimulationRequest, MAX_SIMULATION_CASES},
    run::{compile_pairs, simulate, SimulationError, SimulationOutcome, MAX_TRACE_STAGES},
    Projection, TraceLevel, SIMULATION_SCHEMA_VERSION,
};
use crate::{
    policy_eval::PolicyAuthority,
    policy_testing::suite::Diagnostics,
    rbac::{EnforcementMode, Policy, RuleAction},
};

/// Fixture values a result must never repeat.
const SUBJECT_CANARY: &str = "simulated-subject-canary-7e1";
const PATH_CANARY: &str = "path-canary-0b5";

fn base_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": { "reader": { "permissions": ["orders:read"] } },
        "rules": [
            { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" },
            { "id": "watched", "methods": ["GET"], "path": "/orders/watched", "action": "shadow" },
            { "id": "search-tool", "tool_name": "search", "action": "allow" }
        ],
        "routes": [
            { "path_prefix": "/orders", "permission": "orders:read" },
            { "path_prefix": "/reports", "permission": "reports:read", "enforcement_mode": "shadow" }
        ],
        "rate_limits": [
            { "path": "/orders/**", "requests_per_second": 2.5, "burst": 5 }
        ],
        "tools": {
            "search": { "enabled": true }
        }
    })
}

fn base() -> Policy {
    Policy::validate_json_value(base_document()).expect("base policy validates")
}

fn reader() -> Value {
    json!({ "subject": SUBJECT_CANARY, "roles": ["reader"], "auth_method": "bearer_token" })
}

fn cases() -> Value {
    json!([
        {
            "id": "public-page",
            "kind": "http",
            "request": { "method": "GET", "path": format!("/public/{PATH_CANARY}") },
            "principal": "anonymous"
        },
        {
            "id": "watched-order",
            "kind": "http",
            "request": { "method": "GET", "path": "/orders/watched" },
            "principal": reader()
        },
        {
            "id": "order-read",
            "kind": "http",
            "request": { "method": "GET", "path": "/orders/7" },
            "principal": reader()
        },
        {
            "id": "report-read",
            "kind": "http",
            "request": { "method": "GET", "path": "/reports/1" },
            "principal": reader()
        },
        {
            "id": "unrouted",
            "kind": "http",
            "request": { "method": "GET", "path": "/elsewhere" },
            "principal": "anonymous"
        },
        {
            "id": "search-tool",
            "kind": "tool",
            "tool": { "name": "search" },
            "principal": reader()
        },
        {
            "id": "order-rate",
            "kind": "rate",
            "request": { "method": "GET", "path": "/orders/7" },
            "principal": reader()
        }
    ])
}

fn document(candidate: Value, trace: &str, projections: Value) -> Value {
    json!({
        "schema_version": SIMULATION_SCHEMA_VERSION,
        "base_etag": "\"sha256:base\"",
        "candidate": candidate,
        "trace": trace,
        "projections": projections,
        "cases": cases()
    })
}

fn parse(document: &Value) -> Result<SimulationRequest, Diagnostics> {
    let bytes = serde_json::to_vec(document).expect("document serializes");
    parse_request(&bytes, document)
}

fn codes(diagnostics: &Diagnostics) -> Vec<(&'static str, String)> {
    diagnostics
        .diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code, diagnostic.pointer.clone()))
        .collect()
}

fn refused(document: &Value) -> Diagnostics {
    match parse(document) {
        Ok(_) => panic!("the request should be refused"),
        Err(diagnostics) => diagnostics,
    }
}

/// The candidate a request describes, as the endpoint builds it.
fn candidate_of(request: &SimulationRequest, base: &Policy) -> Option<Policy> {
    match &request.candidate {
        CandidateSource::Active => None,
        CandidateSource::Inline(document) => {
            Some(Policy::validate_json_value(document.clone()).expect("candidate validates"))
        }
        CandidateSource::Edits(edits) => {
            let document = apply_edits(
                &serde_json::to_value(base).expect("base serializes"),
                edits,
                "/candidate/edits",
            )
            .unwrap_or_else(|diagnostics| panic!("edits apply: {:?}", codes(&diagnostics)));
            Some(Policy::validate_json_value(document).expect("candidate validates"))
        }
    }
}

fn run(document: &Value) -> SimulationOutcome {
    let request = parse(document).unwrap_or_else(|diagnostics| {
        panic!("request parses: {:?}", codes(&diagnostics));
    });
    let base = base();
    let candidate = candidate_of(&request, &base);
    let pairs = compile_pairs(
        &base,
        PolicyAuthority::Standalone,
        candidate.as_ref(),
        &request.projections,
    )
    .expect("policies compile");
    simulate(
        &pairs,
        &request.cases,
        request.trace,
        Instant::now() + Duration::from_secs(30),
    )
    .expect("simulation completes")
}

fn case<'a>(outcome: &'a SimulationOutcome, id: &str) -> &'a Value {
    outcome
        .cases
        .iter()
        .find(|case| case["id"] == json!(id))
        .unwrap_or_else(|| panic!("case {id} is reported"))
}

fn result<'a>(case: &'a Value, projection: &str) -> &'a Value {
    case["results"]
        .as_array()
        .and_then(|results| {
            results
                .iter()
                .find(|result| result["projection"] == json!(projection))
        })
        .unwrap_or_else(|| panic!("projection {projection} is reported"))
}

#[test]
fn a_minimal_request_defaults_to_a_terminal_as_authored_simulation() {
    let request = parse(&json!({
        "schema_version": SIMULATION_SCHEMA_VERSION,
        "base_etag": "\"sha256:base\"",
        "candidate": { "source": "active" },
        "cases": cases()
    }))
    .expect("request parses");
    assert_eq!(request.trace, TraceLevel::Terminal);
    assert_eq!(request.projections, vec![Projection::AsAuthored]);
    assert!(matches!(request.candidate, CandidateSource::Active));
    assert_eq!(request.cases.len(), 7);
    assert!(request.digest.starts_with("sha256:"));
}

#[test]
fn schema_dispatch_is_exact_and_unknown_or_credential_members_are_refused() {
    for version in [
        json!("policy-simulation.v2"),
        json!("Policy-Simulation.v1"),
        json!(1),
    ] {
        let mut request = document(
            json!({ "source": "active" }),
            "terminal",
            json!(["as_authored"]),
        );
        request["schema_version"] = version;
        assert_eq!(
            codes(&refused(&request)),
            [("unsupported_schema_version", "/schema_version".to_owned())]
        );
    }
    const CANARY: &str = "credential-canary-41";
    let mut request = document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored"]),
    );
    request["token"] = json!(CANARY);
    request["callback_url"] = json!(CANARY);
    request["candidate"]["policy"] = json!({});
    let diagnostics = refused(&request);
    assert_eq!(
        codes(&diagnostics),
        [
            ("unknown_field", "/callback_url".to_owned()),
            ("forbidden_field", "/token".to_owned()),
            ("unknown_field", "/candidate/policy".to_owned()),
        ]
    );
    assert!(!serde_json::to_string(&diagnostics)
        .expect("diagnostics serialize")
        .contains(CANARY));
}

#[test]
fn every_request_member_is_bounded_and_typed() {
    let mut request = document(json!({ "source": "draft" }), "verbose", json!([]));
    request.as_object_mut().expect("object").remove("base_etag");
    assert_eq!(
        codes(&refused(&request)),
        [
            ("missing_field", "/base_etag".to_owned()),
            ("invalid_value", "/candidate/source".to_owned()),
            ("invalid_value", "/trace".to_owned()),
            ("invalid_value", "/projections".to_owned()),
        ]
    );
    let request = document(
        json!({ "source": "inline", "policy": "not a policy" }),
        "full",
        json!(["as_authored", "as_authored"]),
    );
    assert_eq!(
        codes(&refused(&request)),
        [
            ("invalid_type", "/candidate/policy".to_owned()),
            ("duplicate_projection", "/projections/1".to_owned()),
        ]
    );
    let mut request = document(
        json!({ "source": "active" }),
        "full",
        json!(["as_authored"]),
    );
    request["base_etag"] = json!("x".repeat(257));
    assert_eq!(
        codes(&refused(&request)),
        [("too_long", "/base_etag".to_owned())]
    );
}

#[test]
fn cases_are_test_cases_without_an_expectation() {
    let mut request = document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored"]),
    );
    request["cases"][0]["expect"] = json!({ "logical": "allow" });
    request["cases"][1]["request"]["path"] = json!("relative/path");
    request["cases"][2]["principal"]["cookie"] = json!("session=1");
    assert_eq!(
        codes(&refused(&request)),
        [
            ("unknown_field", "/cases/0/expect".to_owned()),
            ("invalid_path", "/cases/1/request/path".to_owned()),
            ("forbidden_field", "/cases/2/principal/cookie".to_owned()),
        ]
    );
    let mut request = document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored"]),
    );
    request["cases"] = json!([]);
    assert_eq!(
        codes(&refused(&request)),
        [("empty_simulation", "/cases".to_owned())]
    );
    let case = cases()[0].clone();
    request["cases"] = Value::Array(
        (0..=MAX_SIMULATION_CASES)
            .map(|index| {
                let mut case = case.clone();
                case["id"] = json!(format!("case-{index}"));
                case
            })
            .collect(),
    );
    assert_eq!(
        codes(&refused(&request)),
        [("too_many_cases", "/cases".to_owned())]
    );
}

#[test]
fn the_request_digest_binds_the_exact_bytes() {
    let request = document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored"]),
    );
    let compact = serde_json::to_vec(&request).expect("serializes");
    let pretty = serde_json::to_vec_pretty(&request).expect("serializes");
    let first = parse_request(&compact, &request).expect("parses").digest;
    assert_eq!(
        first,
        parse_request(&compact, &request).expect("parses").digest
    );
    assert_ne!(
        first,
        parse_request(&pretty, &request).expect("parses").digest
    );
}

fn edits(value: Value) -> Result<Value, Vec<(&'static str, String)>> {
    let mut diagnostics = Diagnostics::new();
    let parsed = parse_edits(Some(&value), "/candidate/edits", &mut diagnostics);
    if !diagnostics.is_empty() {
        return Err(codes(&diagnostics));
    }
    apply_edits(&base_document(), &parsed, "/candidate/edits")
        .map_err(|diagnostics| codes(&diagnostics))
}

fn rule_ids(document: &Value) -> Vec<String> {
    document["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .map(|rule| rule["id"].as_str().unwrap_or("").to_owned())
        .collect()
}

#[test]
fn edits_land_exactly_where_they_say_in_order() {
    let rule = |id: &str| json!({ "id": id, "path": "/x", "action": "deny" });
    let edited = edits(json!([
        { "op": "insert", "section": "rules", "position": 0, "value": rule("first") },
        { "op": "insert", "section": "rules", "position": 4, "value": rule("appended") },
        { "op": "move", "section": "rules", "from": 2, "to": 0, "expect_id": "watched" },
        { "op": "replace", "section": "rules", "position": 3, "expect_id": "search-tool", "value": rule("replaced") },
        { "op": "delete", "section": "rules", "position": 2, "expect_id": "public" },
        { "op": "delete", "section": "routes", "position": 1 },
        { "op": "set", "field": "enforcement_mode", "value": "shadow" }
    ]))
    .expect("edits apply");
    assert_eq!(
        rule_ids(&edited),
        ["watched", "first", "replaced", "appended"]
    );
    assert_eq!(edited["routes"].as_array().map(Vec::len), Some(1));
    assert_eq!(edited["enforcement_mode"], json!("shadow"));
    Policy::validate_json_value(edited).expect("the edited candidate validates");
}

#[test]
fn an_edit_that_cannot_apply_refuses_the_candidate_with_its_pointer() {
    let rule = json!({ "id": "new", "path": "/x", "action": "deny" });
    assert_eq!(
        edits(json!([{ "op": "insert", "section": "rules", "position": 4, "value": rule }])),
        Err(vec![(
            "position_out_of_range",
            "/candidate/edits/0/position".to_owned()
        )])
    );
    assert_eq!(
        edits(json!([
            { "op": "delete", "section": "rules", "position": 0 },
            { "op": "delete", "section": "rules", "position": 0, "expect_id": "public" }
        ])),
        Err(vec![(
            "edit_target_mismatch",
            "/candidate/edits/1/expect_id".to_owned()
        )])
    );
    assert_eq!(
        edits(json!([{ "op": "move", "section": "routes", "from": 0, "to": 2 }])),
        Err(vec![(
            "position_out_of_range",
            "/candidate/edits/0/to".to_owned()
        )])
    );
    // A section the base omits is an empty one, so only position 0 exists.
    let mut document = base_document();
    document
        .as_object_mut()
        .expect("object")
        .remove("rate_limits");
    let override_rule = json!({ "requests_per_second": 1, "burst": 1 });
    let mut diagnostics = Diagnostics::new();
    let parsed = parse_edits(
        Some(
            &json!([{ "op": "insert", "section": "rate_limits", "position": 0, "value": override_rule }]),
        ),
        "/candidate/edits",
        &mut diagnostics,
    );
    let edited = apply_edits(&document, &parsed, "/candidate/edits").expect("insert applies");
    assert_eq!(edited["rate_limits"].as_array().map(Vec::len), Some(1));
}

/// A policy v1 base: every rule, route and rate override carries an id.
fn v1_base_document() -> Value {
    json!({
        "schema_version": "1.0.0",
        "id": "simulation-v1",
        "default_action": "deny",
        "roles": { "reader": { "permissions": ["orders:read"] } },
        "rules": [
            { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" }
        ],
        "routes": [
            { "id": "orders-route", "path_prefix": "/orders", "permission": "orders:read" },
            { "id": "reports-route", "path_prefix": "/reports", "permission": "reports:read" }
        ],
        "rate_limits": [
            { "id": "orders-rate", "path": "/orders/**", "requests_per_second": 2.5, "burst": 5 }
        ]
    })
}

fn v1_base() -> Policy {
    Policy::validate_json_value(v1_base_document()).expect("v1 base policy validates")
}

fn edits_over(base: &Policy, value: Value) -> Result<Value, Vec<(&'static str, String)>> {
    let mut diagnostics = Diagnostics::new();
    let parsed = parse_edits(Some(&value), "/candidate/edits", &mut diagnostics);
    if !diagnostics.is_empty() {
        return Err(codes(&diagnostics));
    }
    apply_edits(
        &serde_json::to_value(base).expect("base serializes"),
        &parsed,
        "/candidate/edits",
    )
    .map_err(|diagnostics| codes(&diagnostics))
}

#[test]
fn a_v1_route_or_rate_override_is_named_by_its_id() {
    let base = v1_base();
    let edited = edits_over(
        &base,
        json!([
            { "op": "move", "section": "routes", "from": 1, "to": 0, "expect_id": "reports-route" },
            { "op": "delete", "section": "rate_limits", "position": 0, "expect_id": "orders-rate" },
            {
                "op": "replace", "section": "routes", "position": 1, "expect_id": "orders-route",
                "value": { "id": "orders-route", "path_prefix": "/orders", "permission": "orders:write" }
            }
        ]),
    )
    .expect("edits apply");
    // The gateway's own serialization of a v1 policy, edited, is a v1
    // document again: nothing about the round trip loses an id or a member.
    let candidate = Policy::validate_json_value(edited).expect("the edited v1 candidate validates");
    assert_eq!(
        candidate
            .routes
            .iter()
            .map(|route| route.id.as_deref())
            .collect::<Vec<_>>(),
        [Some("reports-route"), Some("orders-route")]
    );
    assert_eq!(candidate.routes[1].permission, "orders:write");
    assert!(candidate.rate_limits.is_empty());

    assert_eq!(
        edits_over(
            &base,
            json!([{ "op": "delete", "section": "routes", "position": 0, "expect_id": "reports-route" }])
        ),
        Err(vec![(
            "edit_target_mismatch",
            "/candidate/edits/0/expect_id".to_owned()
        )])
    );
    // A v1 element inserted without an id is the validator's refusal, not a
    // silently anonymous route.
    let inserted = edits_over(
        &base,
        json!([{
            "op": "insert", "section": "routes", "position": 0,
            "value": { "path_prefix": "/admin", "permission": "admin:read" }
        }]),
    )
    .expect("the insert applies");
    assert!(Policy::validate_json_value(inserted).is_err());
    // A 0.x route has no id, so naming one can only mismatch.
    assert_eq!(
        edits(
            json!([{ "op": "delete", "section": "routes", "position": 0, "expect_id": "orders" }])
        ),
        Err(vec![(
            "edit_target_mismatch",
            "/candidate/edits/0/expect_id".to_owned()
        )])
    );
}

#[test]
fn a_v1_result_names_the_route_and_rate_override_by_id() {
    let base = v1_base();
    let mut request = document(
        json!({ "source": "active" }),
        "matched",
        json!(["as_authored"]),
    );
    request["cases"] = json!([
        {
            "id": "order-read",
            "kind": "http",
            "request": { "method": "GET", "path": "/orders/7" },
            "principal": reader()
        },
        {
            "id": "order-rate",
            "kind": "rate",
            "request": { "method": "GET", "path": "/orders/7" },
            "principal": reader()
        }
    ]);
    let request = parse(&request).expect("request parses");
    let pairs = compile_pairs(
        &base,
        PolicyAuthority::Standalone,
        None,
        &request.projections,
    )
    .expect("compiles");
    let outcome = simulate(
        &pairs,
        &request.cases,
        request.trace,
        Instant::now() + Duration::from_secs(30),
    )
    .expect("simulation completes");
    assert_eq!(
        result(case(&outcome, "order-read"), "as_authored")["candidate"]["matched"],
        json!({
            "kind": "route",
            "position": 0,
            "id": "orders-route",
            "permission": "orders:read",
            "permission_granted": true
        })
    );
    assert_eq!(
        result(case(&outcome, "order-rate"), "as_authored")["candidate"]["rate_override"],
        json!({ "position": 0, "id": "orders-rate", "requests_per_second": 2.5, "burst": 5 })
    );
}

#[test]
fn edits_are_parsed_strictly() {
    assert_eq!(
        edits(json!([])),
        Err(vec![("empty_edits", "/candidate/edits".to_owned())])
    );
    assert_eq!(
        edits(json!([
            { "op": "append", "section": "rules", "value": {} },
            { "op": "insert", "section": "rules", "value": {} },
            { "op": "replace", "section": "routes", "position": 0, "expect_id": "", "value": {} },
            { "op": "insert", "section": "rules", "position": 0, "value": "rule" },
            { "op": "set", "field": "roles", "value": "allow" },
            { "op": "set", "field": "default_action", "value": "maybe" },
            { "op": "delete", "section": "egress", "position": 0 },
            { "op": "delete", "section": "rules", "position": -1, "expect_id": "public" },
            { "op": "insert", "section": "rules", "position": 0, "expect_id": "x", "value": {} }
        ])),
        Err(vec![
            ("invalid_value", "/candidate/edits/0/op".to_owned()),
            ("missing_field", "/candidate/edits/1/position".to_owned()),
            ("invalid_value", "/candidate/edits/2/expect_id".to_owned()),
            ("invalid_type", "/candidate/edits/3/value".to_owned()),
            ("invalid_value", "/candidate/edits/4/field".to_owned()),
            ("invalid_value", "/candidate/edits/5/value".to_owned()),
            ("invalid_value", "/candidate/edits/6/section".to_owned()),
            ("invalid_value", "/candidate/edits/7/position".to_owned()),
            ("unknown_field", "/candidate/edits/8/expect_id".to_owned()),
        ])
    );
}

#[test]
fn enforce_all_shadow_makes_every_shadow_enforcing_and_nothing_else() {
    let mut document = base_document();
    document["enforcement_mode"] = json!("shadow");
    let policy = Policy::validate_json_value(document).expect("validates");
    let projected = Projection::EnforceAllShadow.apply(&policy);
    assert_eq!(projected.enforcement_mode, EnforcementMode::Enforce);
    assert_eq!(projected.rules[1].action, RuleAction::Deny);
    assert_eq!(projected.rules[0].action, RuleAction::Allow);
    // A route keeps its own override, now enforcing; one without stays without.
    assert_eq!(projected.routes[0].enforcement_mode, None);
    assert_eq!(
        projected.routes[1].enforcement_mode,
        Some(EnforcementMode::Enforce)
    );
    let mut restored = projected.clone();
    restored.enforcement_mode = policy.enforcement_mode;
    restored.rules[1].action = RuleAction::Shadow;
    restored.routes[1].enforcement_mode = Some(EnforcementMode::Shadow);
    assert_eq!(restored, policy, "nothing but shadow changed");
    assert_eq!(Projection::AsAuthored.apply(&policy), policy);
}

#[test]
fn a_shadowed_deny_is_never_reported_as_an_allow_and_the_projection_enforces_it() {
    let outcome = run(&document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored", "enforce_all_shadow"]),
    ));
    let watched = case(&outcome, "watched-order");
    let authored = &result(watched, "as_authored")["candidate"];
    assert_eq!(authored["logical"], json!("deny"));
    assert_eq!(authored["enforcement"], json!("shadowed"));
    assert_eq!(authored["effective_action"], json!("would_forward"));
    let enforced = &result(watched, "enforce_all_shadow")["candidate"];
    assert_eq!(enforced["logical"], json!("deny"));
    assert_eq!(enforced["enforcement"], json!("enforced"));
    assert_eq!(enforced["effective_action"], json!("would_block"));
    assert_eq!(watched["projection_changed"], json!(true));

    // A per-route shadow override is projected as enforced too.
    let report = case(&outcome, "report-read");
    assert_eq!(
        result(report, "as_authored")["candidate"]["enforcement"],
        json!("shadowed")
    );
    assert_eq!(
        result(report, "enforce_all_shadow")["candidate"]["effective_action"],
        json!("would_block")
    );
    // An allow is untouched by the projection.
    let public = case(&outcome, "public-page");
    assert_eq!(public["projection_changed"], json!(false));
    assert_eq!(
        result(public, "enforce_all_shadow")["candidate"]["effective_action"],
        json!("would_forward")
    );
    // The active source is its own base, so nothing is compared with one.
    assert!(result(public, "as_authored").get("base").is_none());
    assert_eq!(outcome.summary["projection_changed"], json!(2));
    assert_eq!(
        outcome.summary["projections"]["as_authored"]["shadowed"],
        json!(2)
    );
}

#[test]
fn a_candidate_is_compared_with_its_base_by_outcome() {
    let outcome = run(&document(
        json!({ "source": "edits", "edits": [
            {
                "op": "insert", "section": "rules", "position": 0,
                "value": { "id": "lockdown", "methods": ["GET"], "path": "/orders/**", "action": "deny" }
            }
        ] }),
        "matched",
        json!(["as_authored"]),
    ));
    let order = result(case(&outcome, "order-read"), "as_authored");
    assert_eq!(order["changed"], json!(true));
    assert_eq!(order["base"]["effective_action"], json!("would_forward"));
    assert_eq!(
        order["base"]["matched"],
        json!({ "kind": "route", "position": 0, "permission": "orders:read", "permission_granted": true })
    );
    assert_eq!(order["candidate"]["effective_action"], json!("would_block"));
    assert_eq!(
        order["candidate"]["matched"],
        json!({ "kind": "rule", "position": 0, "id": "lockdown", "action": "deny" })
    );
    // The inserted rule shifted every position, and an unchanged outcome is
    // still unchanged.
    let public = result(case(&outcome, "public-page"), "as_authored");
    assert_eq!(public["changed"], json!(false));
    assert_eq!(public["base"]["matched"]["position"], json!(0));
    assert_eq!(public["candidate"]["matched"]["position"], json!(1));
    assert_eq!(
        outcome.summary["projections"]["as_authored"]["changed_from_base"],
        json!(2)
    );
}

#[test]
fn each_trace_level_explains_as_much_as_it_names() {
    let terminal = run(&document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored"]),
    ));
    let order = &result(case(&terminal, "order-read"), "as_authored")["candidate"];
    assert_eq!(
        *order,
        json!({
            "lane": "http",
            "logical": "allow",
            "enforcement": "not_applicable",
            "effective_action": "would_forward",
            "reason": "matched_rule",
            "complete": true
        })
    );

    let matched = run(&document(
        json!({ "source": "active" }),
        "matched",
        json!(["as_authored"]),
    ));
    let watched = &result(case(&matched, "watched-order"), "as_authored")["candidate"];
    assert_eq!(
        watched["matched"],
        json!({ "kind": "rule", "position": 1, "id": "watched", "action": "shadow" })
    );
    assert_eq!(watched["observation"], Value::Null);
    assert!(watched.get("stages").is_none());
    let unrouted = &result(case(&matched, "unrouted"), "as_authored")["candidate"];
    assert_eq!(unrouted["matched"], Value::Null);
    assert_eq!(unrouted["reason"], json!("default_deny"));

    let full = run(&document(
        json!({ "source": "active" }),
        "full",
        json!(["as_authored"]),
    ));
    let order = &result(case(&full, "order-read"), "as_authored")["candidate"];
    assert_eq!(
        order["stages"],
        json!([
            { "stage": "facts", "status": "matched" },
            { "stage": "request_host", "status": "matched", "host": "absent" },
            { "stage": "direct_rules", "status": "no_match" },
            { "stage": "upstream_host_binding", "status": "not_applicable" },
            {
                "stage": "routes",
                "status": "matched",
                "element": { "kind": "route", "position": 0, "permission": "orders:read" },
                "permission": "granted",
                "enforcement_mode": "enforce",
                "mode_inherited": true
            },
            { "stage": "default", "status": "skipped" }
        ])
    );
    let unrouted = &result(case(&full, "unrouted"), "as_authored")["candidate"];
    assert_eq!(
        unrouted["stages"][5],
        json!({ "stage": "default", "status": "matched", "default_action": "deny", "enforcement_mode": "enforce" })
    );
    assert!(!full.stages_truncated);
}

#[test]
fn tool_and_rate_cases_answer_from_their_own_lanes() {
    let outcome = run(&document(
        json!({ "source": "active" }),
        "matched",
        json!(["as_authored"]),
    ));
    let tool = &result(case(&outcome, "search-tool"), "as_authored")["candidate"];
    assert_eq!(tool["lane"], json!("tool"));
    assert_eq!(tool["operation"], json!("invocation"));
    assert_eq!(tool["logical"], json!("allow"));
    assert_eq!(
        tool["matched"],
        json!({ "kind": "rule", "position": 2, "id": "search-tool", "action": "allow" })
    );
    let rate = &result(case(&outcome, "order-rate"), "as_authored")["candidate"];
    assert_eq!(
        *rate,
        json!({
            "lane": "rate_selection",
            "selected": "override",
            "complete": true,
            "rate_override": { "position": 0, "requests_per_second": 2.5, "burst": 5 }
        })
    );
    assert_eq!(
        outcome.summary["projections"]["as_authored"]["rate_override"],
        json!(1)
    );
}

#[test]
fn results_never_repeat_a_fixture_value() {
    let outcome = run(&document(
        json!({ "source": "active" }),
        "full",
        json!(["as_authored", "enforce_all_shadow"]),
    ));
    let rendered = serde_json::to_string(&outcome.cases).expect("cases serialize")
        + &serde_json::to_string(&outcome.summary).expect("summary serializes");
    for absent in [
        SUBJECT_CANARY,
        PATH_CANARY,
        "/orders/7",
        "reader",
        "bearer_token",
    ] {
        assert!(!rendered.contains(absent), "a result repeats {absent}");
    }
}

#[test]
fn the_stage_budget_is_explicit_when_it_runs_out() {
    let mut request = document(
        json!({ "source": "edits", "edits": [{ "op": "set", "field": "default_action", "value": "allow" }] }),
        "full",
        json!(["as_authored", "enforce_all_shadow"]),
    );
    let case = cases()[2].clone();
    request["cases"] = Value::Array(
        (0..MAX_SIMULATION_CASES)
            .map(|index| {
                let mut case = case.clone();
                case["id"] = json!(format!("case-{index}"));
                case
            })
            .collect(),
    );
    let outcome = run(&request);
    assert!(outcome.stages_truncated);
    let returned: usize = outcome
        .cases
        .iter()
        .flat_map(|case| case["results"].as_array().cloned().unwrap_or_default())
        .flat_map(|result| [result["candidate"].clone(), result["base"].clone()])
        .filter_map(|view| view["stages"].as_array().map(Vec::len))
        .sum();
    assert!(returned <= MAX_TRACE_STAGES);
    let last = &outcome.cases[MAX_SIMULATION_CASES - 1]["results"][0]["candidate"];
    assert_eq!(last["stages_truncated"], json!(true));
    assert!(last.get("stages").is_none());
    // The decision is still reported in full; only the steps are omitted.
    assert_eq!(last["effective_action"], json!("would_forward"));
}

/// The run itself -- compiling the base and a candidate and deciding every
/// case under both projections at the full trace level -- records no metric.
/// The endpoint's side-effect test cannot see this part, because the endpoint
/// runs it on a blocking thread, outside the recorder that test installs.
#[test]
fn the_run_records_no_metric() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let outcome = ::metrics::with_local_recorder(&recorder, || {
        run(&document(
            json!({ "source": "edits", "edits": [
                { "op": "set", "field": "default_action", "value": "allow" }
            ] }),
            "full",
            json!(["as_authored", "enforce_all_shadow"]),
        ))
    });
    assert_eq!(outcome.cases.len(), 7);
    let rendered = handle.render();
    assert!(
        rendered
            .lines()
            .all(|line| line.trim().is_empty() || line.starts_with('#')),
        "a simulation run recorded a metric: {rendered}"
    );
}

#[test]
fn a_simulation_past_its_deadline_returns_nothing() {
    let request = parse(&document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored"]),
    ))
    .expect("parses");
    let pairs = compile_pairs(
        &base(),
        PolicyAuthority::Standalone,
        None,
        &request.projections,
    )
    .expect("compiles");
    let past = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap_or_else(Instant::now);
    assert!(matches!(
        simulate(&pairs, &request.cases, request.trace, past),
        Err(SimulationError::DeadlineExceeded)
    ));
}

#[test]
fn an_authored_string_longer_than_the_echo_bound_is_reported_by_position() {
    let long_id = "r".repeat(129);
    let outcome = run(&document(
        json!({ "source": "edits", "edits": [{
            "op": "replace", "section": "rules", "position": 0, "expect_id": "public",
            "value": { "id": long_id, "methods": ["GET"], "path": "/public/**", "action": "allow" }
        }] }),
        "matched",
        json!(["as_authored"]),
    ));
    let public = result(case(&outcome, "public-page"), "as_authored");
    assert_eq!(
        public["candidate"]["matched"],
        json!({ "kind": "rule", "position": 0, "action": "allow", "id_omitted": true })
    );
    assert!(!serde_json::to_string(&outcome.cases)
        .expect("serializes")
        .contains(&long_id));
}

fn request_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/policy-simulation.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// The published schema and the parser agree on the requests both can judge:
/// every request the parser accepts here, the schema accepts, and the
/// refusals JSON Schema can express are refused by both.
#[test]
fn the_published_schema_agrees_with_the_parser() {
    let schema = request_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let every_edit = json!({ "source": "edits", "edits": [
        { "op": "insert", "section": "rules", "position": 0, "value": { "id": "n", "path": "/n", "action": "deny" } },
        { "op": "replace", "section": "rules", "position": 1, "expect_id": "public", "value": { "id": "p", "path": "/p", "action": "allow" } },
        { "op": "move", "section": "routes", "from": 1, "to": 0 },
        { "op": "delete", "section": "rate_limits", "position": 0 },
        { "op": "set", "field": "default_action", "value": "allow" },
        { "op": "set", "field": "enforcement_mode", "value": "shadow" }
    ] });
    let mut accepted = vec![
        document(
            json!({ "source": "active" }),
            "terminal",
            json!(["as_authored"]),
        ),
        document(
            every_edit.clone(),
            "full",
            json!(["enforce_all_shadow", "as_authored"]),
        ),
        document(
            json!({ "source": "inline", "policy": base_document() }),
            "matched",
            json!(["as_authored"]),
        ),
    ];
    let mut minimal = document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored"]),
    );
    let object = minimal.as_object_mut().expect("object");
    object.remove("trace");
    object.remove("projections");
    object.insert("description".to_owned(), json!("simulated"));
    accepted.push(minimal);
    for request in &accepted {
        assert!(parse(request).is_ok(), "parser: {request}");
        if let Err(error) = validator.validate(request) {
            panic!("the schema refuses a request the parser accepts: {error}");
        }
    }

    let active = || {
        document(
            json!({ "source": "active" }),
            "terminal",
            json!(["as_authored"]),
        )
    };
    let mut refusals = Vec::new();
    let mut request = active();
    request["schema_version"] = json!("policy-simulation.v2");
    refusals.push(request);
    let mut request = active();
    request.as_object_mut().expect("object").remove("base_etag");
    refusals.push(request);
    let mut request = active();
    request["token"] = json!("x");
    refusals.push(request);
    let mut request = active();
    request["cases"][0]["expect"] = json!({ "logical": "allow" });
    refusals.push(request);
    let mut request = active();
    request["cases"] = json!([]);
    refusals.push(request);
    refusals.push(document(
        json!({ "source": "active" }),
        "terminal",
        json!(["as_authored", "as_authored"]),
    ));
    refusals.push(document(
        json!({ "source": "active" }),
        "verbose",
        json!(["as_authored"]),
    ));
    refusals.push(document(
        json!({ "source": "draft" }),
        "terminal",
        json!(["as_authored"]),
    ));
    refusals.push(document(
        json!({ "source": "edits", "edits": [] }),
        "terminal",
        json!(["as_authored"]),
    ));
    for edit in [
        json!({ "op": "append", "section": "rules", "value": {} }),
        json!({ "op": "insert", "section": "rules", "value": {} }),
        json!({ "op": "insert", "section": "rules", "position": 0, "expect_id": "x", "value": {} }),
        json!({ "op": "delete", "section": "egress", "position": 0 }),
        json!({ "op": "set", "field": "default_action", "value": "shadow" }),
        json!({ "op": "move", "section": "rules", "from": -1, "to": 0 }),
    ] {
        refusals.push(document(
            json!({ "source": "edits", "edits": [edit] }),
            "terminal",
            json!(["as_authored"]),
        ));
    }
    for request in refusals {
        assert!(parse(&request).is_err(), "parser: {request}");
        assert!(!validator.is_valid(&request), "schema: {request}");
    }
}
