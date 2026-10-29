use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{json, Value};

use super::*;
use crate::auth::{AuthMethod, Principal};

const ISSUER: &str = "https://idp.example.test";

fn compiled(condition: Value) -> CompiledCondition {
    let condition: Condition = serde_json::from_value(condition).expect("condition fixture");
    CompiledCondition::new(&condition)
}

fn principal(issuer: Option<&str>) -> Principal {
    Principal {
        user_id: "alice".to_owned(),
        issuer: issuer.map(str::to_owned),
        email: None,
        org_id: None,
        roles: vec!["reader".to_owned()],
        session_id: String::new(),
        auth_method: AuthMethod::Bearer,
    }
}

fn facts() -> PolicyFacts {
    PolicyFacts {
        organization: Fact::Captured(Some("acme".to_owned())),
        source_ip: Fact::Captured(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        headers: Fact::Captured(vec![
            ("X-Environment".to_owned(), "staging".to_owned()),
            ("x-environment".to_owned(), "prod".to_owned()),
        ]),
        query: Fact::Captured(vec![
            ("mode".to_owned(), "read".to_owned()),
            ("mode".to_owned(), "write".to_owned()),
            ("flag".to_owned(), String::new()),
        ]),
        tool_arguments: Fact::Captured(json!({
            "region": "eu",
            "count": 3,
            "dry_run": true,
            "nested": { "a/b": { "~c": "deep" } },
            "list": ["eu"]
        })),
        now: Fact::Captured(1_767_225_600), // 2026-01-01T00:00:00Z
    }
}

fn validate(condition: Value, target: ConditionTarget) -> Result<(), PolicyIssue> {
    let condition: Condition = serde_json::from_value(condition).expect("condition fixture");
    validate_condition(
        &condition,
        target,
        "/rules/0/conditions",
        "rules[0].conditions",
    )
}

fn refusal(condition: Value, target: ConditionTarget) -> (&'static str, String) {
    let issue = validate(condition, target).expect_err("the condition should be refused");
    (issue.code.as_str(), issue.pointer)
}

#[test]
fn each_leaf_answers_from_its_own_captured_fact() {
    let alice = principal(Some(ISSUER));
    let facts = facts();
    for (condition, expected) in [
        (
            json!({ "organization": { "issuer": ISSUER, "in": ["acme"] } }),
            Truth::True,
        ),
        (
            json!({ "organization": { "issuer": ISSUER, "in": ["other"] } }),
            Truth::False,
        ),
        (
            json!({ "source_network": { "cidrs": ["10.0.0.0/8"] } }),
            Truth::True,
        ),
        (
            json!({ "source_network": { "cidrs": ["192.168.0.0/16", "fd00::/8"] } }),
            Truth::False,
        ),
        (
            json!({ "header": { "name": "x-environment", "in": ["prod"] } }),
            Truth::True,
        ),
        (
            json!({ "header": { "name": "x-environment", "in": ["Prod"] } }),
            Truth::False,
        ),
        (
            json!({ "header": { "name": "x-absent", "in": ["prod"] } }),
            Truth::False,
        ),
        (
            json!({ "query": { "name": "mode", "in": ["write"] } }),
            Truth::True,
        ),
        (
            json!({ "query": { "name": "Mode", "in": ["write"] } }),
            Truth::False,
        ),
        (
            json!({ "query": { "name": "flag", "in": [""] } }),
            Truth::True,
        ),
        (
            json!({ "tool_argument": { "pointer": "/region", "in": ["eu", "us"] } }),
            Truth::True,
        ),
        (
            json!({ "tool_argument": { "pointer": "/count", "in": [3.0] } }),
            Truth::True,
        ),
        (
            json!({ "tool_argument": { "pointer": "/dry_run", "in": [true] } }),
            Truth::True,
        ),
        (
            json!({ "tool_argument": { "pointer": "/nested/a~1b/~0c", "in": ["deep"] } }),
            Truth::True,
        ),
        // A list or object is never equal to a scalar, and a missing member
        // is not there.
        (
            json!({ "tool_argument": { "pointer": "/list", "in": ["eu"] } }),
            Truth::False,
        ),
        (
            json!({ "tool_argument": { "pointer": "/missing", "in": ["eu"] } }),
            Truth::False,
        ),
        (
            json!({ "tool_argument": { "pointer": "/count", "in": ["3"] } }),
            Truth::False,
        ),
        (
            json!({ "time_window": { "from": "2026-01-01T00:00:00Z" } }),
            Truth::True,
        ),
        (
            json!({ "time_window": { "until": "2026-01-01T00:00:00Z" } }),
            Truth::False,
        ),
        (
            json!({ "time_window": { "from": "2025-12-31T23:59:59Z", "until": "2026-01-01T00:00:01Z" } }),
            Truth::True,
        ),
    ] {
        assert_eq!(
            compiled(condition.clone()).evaluate(Some(&alice), &facts),
            expected,
            "{condition}"
        );
    }
}

#[test]
fn every_leaf_is_unknown_when_its_fact_was_not_captured() {
    let alice = principal(Some(ISSUER));
    for condition in [
        json!({ "organization": { "issuer": ISSUER, "in": ["acme"] } }),
        json!({ "source_network": { "cidrs": ["10.0.0.0/8"] } }),
        json!({ "header": { "name": "x-environment", "in": ["prod"] } }),
        json!({ "query": { "name": "mode", "in": ["read"] } }),
        json!({ "tool_argument": { "pointer": "/region", "in": ["eu"] } }),
        json!({ "time_window": { "from": "2026-01-01T00:00:00Z" } }),
    ] {
        assert_eq!(
            compiled(condition.clone()).evaluate(Some(&alice), &UNCAPTURED_FACTS),
            Truth::Unknown,
            "{condition}"
        );
        // Unknown is not a match, and negating it does not make it one.
        assert_eq!(
            compiled(json!({ "not": condition.clone() })).evaluate(Some(&alice), &UNCAPTURED_FACTS),
            Truth::Unknown,
            "{condition}"
        );
    }
}

#[test]
fn an_organization_is_bound_to_the_issuer_that_verified_it() {
    let condition = compiled(json!({ "organization": { "issuer": ISSUER, "in": ["acme"] } }));
    let facts = facts();
    // The same organization name from another issuer, from a principal with
    // no issuer (a service token), or for an anonymous caller is a different
    // organization -- and the answer is certain, not unknown, because the
    // issuer is always known.
    for principal in [
        Some(principal(Some("https://other.example.test"))),
        Some(principal(None)),
        None,
    ] {
        assert_eq!(condition.evaluate(principal.as_ref(), &facts), Truth::False);
        assert_eq!(
            condition.evaluate(principal.as_ref(), &UNCAPTURED_FACTS),
            Truth::False
        );
    }
    // A principal with no verified organization is not in any.
    let mut none = facts.clone();
    none.organization = Fact::Captured(None);
    assert_eq!(
        condition.evaluate(Some(&principal(Some(ISSUER))), &none),
        Truth::False
    );
    // The authored issuer is canonicalized as every policy issuer is.
    let mut authored: Condition = serde_json::from_value(
        json!({ "organization": { "issuer": " https://idp.example.test/ ", "in": ["acme"] } }),
    )
    .expect("fixture");
    canonicalize_condition_issuers(&mut authored);
    assert_eq!(
        CompiledCondition::new(&authored).evaluate(Some(&principal(Some(ISSUER))), &facts),
        Truth::True
    );
}

#[test]
fn source_network_reads_only_the_canonical_client_address() {
    let condition = compiled(json!({ "source_network": { "cidrs": ["203.0.113.0/24"] } }));
    let mut spoofed = facts();
    // A forwarding header claiming an allowed address changes nothing: the
    // leaf reads the address the gateway derived, never a header.
    spoofed.headers = Fact::Captured(vec![
        ("x-forwarded-for".to_owned(), "203.0.113.7".to_owned()),
        ("forwarded".to_owned(), "for=203.0.113.7".to_owned()),
    ]);
    spoofed.source_ip = Fact::Captured(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
    assert_eq!(condition.evaluate(None, &spoofed), Truth::False);
    // An IPv4-mapped IPv6 address is the IPv4 address it maps.
    spoofed.source_ip = Fact::Captured(IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped()));
    assert_eq!(condition.evaluate(None, &spoofed), Truth::True);
    spoofed.source_ip = Fact::Captured(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(condition.evaluate(None, &spoofed), Truth::False);
}

#[test]
fn combinators_follow_kleene_logic() {
    let alice = principal(Some(ISSUER));
    let yes = json!({ "query": { "name": "mode", "in": ["read"] } });
    let no = json!({ "query": { "name": "mode", "in": ["delete"] } });
    let unknown = json!({ "time_window": { "from": "2026-01-01T00:00:00Z" } });
    let mut facts = facts();
    facts.now = Fact::Uncaptured;
    let truth = |condition: Value| compiled(condition).evaluate(Some(&alice), &facts);
    assert_eq!(
        truth(json!({ "all": [yes.clone(), yes.clone()] })),
        Truth::True
    );
    assert_eq!(
        truth(json!({ "all": [yes.clone(), no.clone()] })),
        Truth::False
    );
    assert_eq!(
        truth(json!({ "all": [unknown.clone(), no.clone()] })),
        Truth::False
    );
    assert_eq!(
        truth(json!({ "all": [no.clone(), unknown.clone()] })),
        Truth::False
    );
    assert_eq!(
        truth(json!({ "all": [yes.clone(), unknown.clone()] })),
        Truth::Unknown
    );
    assert_eq!(
        truth(json!({ "any": [no.clone(), no.clone()] })),
        Truth::False
    );
    assert_eq!(
        truth(json!({ "any": [unknown.clone(), yes.clone()] })),
        Truth::True
    );
    assert_eq!(
        truth(json!({ "any": [yes.clone(), unknown.clone()] })),
        Truth::True
    );
    assert_eq!(
        truth(json!({ "any": [no.clone(), unknown.clone()] })),
        Truth::Unknown
    );
    assert_eq!(truth(json!({ "not": yes.clone() })), Truth::False);
    assert_eq!(truth(json!({ "not": no.clone() })), Truth::True);
    assert_eq!(truth(json!({ "not": unknown })), Truth::Unknown);
    assert_eq!(truth(json!({ "not": { "not": yes } })), Truth::True);
}

#[test]
fn a_leaf_that_does_not_compile_is_never_answered() {
    // Validation refuses every one of these; a policy assembled in memory
    // around validation still never matches or misses on them.
    for condition in [
        Condition::SourceNetwork(SourceNetworkCondition {
            cidrs: vec!["not a network".to_owned()],
        }),
        Condition::Organization(OrganizationCondition {
            issuer: " ".to_owned(),
            values: vec!["acme".to_owned()],
        }),
        Condition::TimeWindow(TimeWindowCondition {
            from: Some("yesterday".to_owned()),
            until: None,
        }),
        Condition::TimeWindow(TimeWindowCondition {
            from: None,
            until: None,
        }),
    ] {
        let compiled = CompiledCondition::new(&condition);
        assert_eq!(
            compiled.evaluate(Some(&principal(Some(ISSUER))), &facts()),
            Truth::Unknown,
            "{condition:?}"
        );
    }
}

#[test]
fn a_time_window_includes_from_and_excludes_until_in_utc() {
    let window = compiled(json!({
        "time_window": { "from": "2026-03-29T01:00:00Z", "until": "2026-03-29T02:00:00Z" }
    }));
    let at = |instant: &str| {
        let mut facts = UNCAPTURED_FACTS.clone();
        facts.now = Fact::Captured(parse_utc_instant(instant).expect("instant"));
        window.evaluate(None, &facts)
    };
    assert_eq!(at("2026-03-29T00:59:59Z"), Truth::False);
    assert_eq!(at("2026-03-29T01:00:00Z"), Truth::True);
    assert_eq!(at("2026-03-29T01:59:59Z"), Truth::True);
    assert_eq!(at("2026-03-29T02:00:00Z"), Truth::False);
    // One spelling per instant: no offset, no fraction, no lowercase.
    for spelling in [
        "2026-03-29T01:00:00+00:00",
        "2026-03-29T01:00:00.000Z",
        "2026-03-29t01:00:00z",
        "2026-03-29 01:00:00Z",
        "2026-02-30T01:00:00Z",
        "",
    ] {
        assert_eq!(parse_utc_instant(spelling), None, "{spelling:?}");
    }
    assert_eq!(parse_utc_instant("1970-01-01T00:00:00Z"), Some(0));
}

#[test]
fn validation_refuses_headers_that_carry_credentials_identity_or_routing() {
    for name in [
        "authorization",
        "proxy-authorization",
        "cookie",
        "host",
        "connection",
        "transfer-encoding",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-original-url",
        "x-api-key",
        "x-auth-request-user",
        "x-csrf-token",
        "x-user",
        "x-remote-user",
        "x-email",
        "x-real-ip",
        "x-client-cert",
        "x-org-id",
        "x-tenant",
        "x-session",
        "x-amz-security-token",
    ] {
        assert_eq!(
            refusal(
                json!({ "header": { "name": name, "in": ["v"] } }),
                ConditionTarget::HttpPath
            ),
            (
                "condition_name_forbidden",
                "/rules/0/conditions/header/name".to_owned()
            ),
            "{name}"
        );
    }
    for name in ["x-environment", "accept-language", "x-request-priority"] {
        assert!(
            validate(
                json!({ "header": { "name": name, "in": ["v"] } }),
                ConditionTarget::HttpPath
            )
            .is_ok(),
            "{name}"
        );
    }
    // A name with uppercase letters has a lowercase spelling, which is the
    // one a policy uses.
    assert_eq!(
        refusal(
            json!({ "header": { "name": "X-Environment", "in": ["v"] } }),
            ConditionTarget::HttpPath
        ),
        (
            "condition_value_invalid",
            "/rules/0/conditions/header/name".to_owned()
        )
    );
}

#[test]
fn validation_refuses_query_parameters_that_carry_credentials() {
    for name in [
        "access_token",
        "api_key",
        "code",
        "STATE",
        "sig",
        "X-Amz-Signature",
        "password",
        "session_id",
    ] {
        assert_eq!(
            refusal(
                json!({ "query": { "name": name, "in": ["v"] } }),
                ConditionTarget::HttpPath
            )
            .0,
            "condition_name_forbidden",
            "{name}"
        );
    }
    assert!(validate(
        json!({ "query": { "name": "mode", "in": ["read", ""] } }),
        ConditionTarget::HttpPath
    )
    .is_ok());
}

#[test]
fn validation_keeps_each_leaf_where_its_fact_exists() {
    for (condition, target, pointer) in [
        (
            json!({ "header": { "name": "x-environment", "in": ["prod"] } }),
            ConditionTarget::ToolName,
            "/rules/0/conditions/header",
        ),
        (
            json!({ "query": { "name": "mode", "in": ["read"] } }),
            ConditionTarget::ToolName,
            "/rules/0/conditions/query",
        ),
        (
            json!({ "any": [{ "tool_argument": { "pointer": "/region", "in": ["eu"] } }] }),
            ConditionTarget::HttpPath,
            "/rules/0/conditions/any/0/tool_argument",
        ),
    ] {
        assert_eq!(
            refusal(condition, target),
            ("condition_not_applicable", pointer.to_owned())
        );
    }
    for (condition, target) in [
        (
            json!({ "organization": { "issuer": ISSUER, "in": ["acme"] } }),
            ConditionTarget::ToolName,
        ),
        (
            json!({ "source_network": { "cidrs": ["10.0.0.0/8"] } }),
            ConditionTarget::ToolName,
        ),
        (
            json!({ "time_window": { "until": "2027-01-01T00:00:00Z" } }),
            ConditionTarget::HttpPath,
        ),
        (
            json!({ "tool_argument": { "pointer": "/region", "in": ["eu", 1, false] } }),
            ConditionTarget::ToolName,
        ),
    ] {
        assert!(validate(condition.clone(), target).is_ok(), "{condition}");
    }
}

#[test]
fn validation_bounds_and_locates_every_leaf_value() {
    let long = "a".repeat(MAX_CONDITION_VALUE_BYTES + 1);
    let many: Vec<String> = (0..=MAX_CONDITION_VALUES).map(|n| n.to_string()).collect();
    for (condition, target, expected) in [
        (
            json!({ "all": [] }),
            ConditionTarget::HttpPath,
            ("condition_value_invalid", "/rules/0/conditions/all"),
        ),
        (
            json!({ "organization": { "issuer": " ", "in": ["acme"] } }),
            ConditionTarget::HttpPath,
            ("issuer_empty", "/rules/0/conditions/organization/issuer"),
        ),
        (
            json!({ "organization": { "issuer": ISSUER, "in": [] } }),
            ConditionTarget::HttpPath,
            (
                "condition_value_invalid",
                "/rules/0/conditions/organization/in",
            ),
        ),
        (
            json!({ "organization": { "issuer": ISSUER, "in": [""] } }),
            ConditionTarget::HttpPath,
            (
                "condition_value_invalid",
                "/rules/0/conditions/organization/in/0",
            ),
        ),
        (
            json!({ "organization": { "issuer": ISSUER, "in": many } }),
            ConditionTarget::HttpPath,
            (
                "condition_value_invalid",
                "/rules/0/conditions/organization/in",
            ),
        ),
        (
            json!({ "source_network": { "cidrs": ["10.0.0.0/8", "10.0.0.1/8"] } }),
            ConditionTarget::HttpPath,
            (
                "condition_cidr_invalid",
                "/rules/0/conditions/source_network/cidrs/1",
            ),
        ),
        (
            json!({ "source_network": { "cidrs": ["10.0.0.0"] } }),
            ConditionTarget::HttpPath,
            (
                "condition_cidr_invalid",
                "/rules/0/conditions/source_network/cidrs/0",
            ),
        ),
        (
            json!({ "header": { "name": "x-environment", "in": [" prod"] } }),
            ConditionTarget::HttpPath,
            ("condition_value_invalid", "/rules/0/conditions/header/in/0"),
        ),
        (
            json!({ "header": { "name": "x-environment", "in": [long] } }),
            ConditionTarget::HttpPath,
            ("condition_value_invalid", "/rules/0/conditions/header/in/0"),
        ),
        (
            json!({ "query": { "name": "mo\u{7}de", "in": ["read"] } }),
            ConditionTarget::HttpPath,
            ("condition_value_invalid", "/rules/0/conditions/query/name"),
        ),
        (
            json!({ "tool_argument": { "pointer": "region", "in": ["eu"] } }),
            ConditionTarget::ToolName,
            (
                "condition_pointer_invalid",
                "/rules/0/conditions/tool_argument/pointer",
            ),
        ),
        (
            json!({ "tool_argument": { "pointer": "/a~2", "in": ["eu"] } }),
            ConditionTarget::ToolName,
            (
                "condition_pointer_invalid",
                "/rules/0/conditions/tool_argument/pointer",
            ),
        ),
        (
            json!({ "tool_argument": { "pointer": "/1/2/3/4/5/6/7/8/9", "in": ["eu"] } }),
            ConditionTarget::ToolName,
            (
                "condition_pointer_invalid",
                "/rules/0/conditions/tool_argument/pointer",
            ),
        ),
        (
            json!({ "tool_argument": { "pointer": "/region", "in": [["eu"]] } }),
            ConditionTarget::ToolName,
            (
                "condition_value_invalid",
                "/rules/0/conditions/tool_argument/in/0",
            ),
        ),
        (
            json!({ "time_window": {} }),
            ConditionTarget::HttpPath,
            ("condition_time_invalid", "/rules/0/conditions/time_window"),
        ),
        (
            json!({ "time_window": { "from": "2026-01-01T00:00:00+01:00" } }),
            ConditionTarget::HttpPath,
            (
                "condition_time_invalid",
                "/rules/0/conditions/time_window/from",
            ),
        ),
        (
            json!({ "time_window": { "until": "tomorrow" } }),
            ConditionTarget::HttpPath,
            (
                "condition_time_invalid",
                "/rules/0/conditions/time_window/until",
            ),
        ),
        (
            json!({ "time_window": { "from": "2026-01-01T00:00:00Z", "until": "2026-01-01T00:00:00Z" } }),
            ConditionTarget::HttpPath,
            (
                "condition_time_invalid",
                "/rules/0/conditions/time_window/until",
            ),
        ),
    ] {
        assert_eq!(
            refusal(condition.clone(), target),
            (expected.0, expected.1.to_owned()),
            "{condition}"
        );
    }
}

#[test]
fn validation_bounds_the_shape_of_a_tree_built_in_memory() {
    let leaf = || {
        Condition::Query(QueryCondition {
            name: "mode".to_owned(),
            values: vec!["read".to_owned()],
        })
    };
    let mut deep = leaf();
    for _ in 0..MAX_CONDITION_DEPTH {
        deep = Condition::Not(Box::new(deep));
    }
    let wide = Condition::Any(vec![leaf(); MAX_CONDITION_BRANCHES + 1]);
    let crowded = Condition::All(vec![
        Condition::Any(vec![leaf(); MAX_CONDITION_BRANCHES]),
        Condition::Any(vec![leaf(); MAX_CONDITION_BRANCHES]),
    ]);
    for condition in [deep, wide, crowded] {
        let issue = validate_condition(
            &condition,
            ConditionTarget::HttpPath,
            "/rules/0/conditions",
            "rules[0].conditions",
        )
        .expect_err("the tree is past a bound");
        assert_eq!(issue.code, IssueCode::ConditionTooComplex, "{condition:?}");
    }
}

#[test]
fn a_condition_round_trips_through_its_one_serialization() {
    let document = json!({
        "all": [
            { "organization": { "issuer": ISSUER, "in": ["acme"] } },
            { "any": [
                { "source_network": { "cidrs": ["10.0.0.0/8"] } },
                { "not": { "header": { "name": "x-environment", "in": ["prod"] } } }
            ] },
            { "query": { "name": "mode", "in": ["read"] } },
            { "time_window": { "until": "2027-01-01T00:00:00Z" } }
        ]
    });
    let condition: Condition = serde_json::from_value(document.clone()).expect("parse");
    assert_eq!(
        serde_json::to_value(&condition).expect("serialize"),
        document
    );
    // A node with two operators, or an unknown one, has no typed reading.
    for malformed in [
        json!({ "all": [], "any": [] }),
        json!({ "regex": { "pattern": ".*" } }),
        json!({ "header": { "name": "x-environment", "in": ["prod"], "case": "any" } }),
    ] {
        assert!(
            serde_json::from_value::<Condition>(malformed.clone()).is_err(),
            "{malformed}"
        );
    }
}
