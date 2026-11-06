//! The decision facts the HTTP stage and the tool lane attach to a verdict
//! (issue #243): what `policy-decision.v1` names, that it names the snapshot
//! that decided, that a request the stage refused to answer has none, and
//! that a verdict adds only a shared reference and a fixed-size value to the
//! request path.

use std::mem::size_of;

use super::*;
use crate::{
    middleware::decision::{
        facts_available, EvaluationFacts, PolicyDecisionFacts, MAX_DECISION_ELEMENT_ID_BYTES,
        POLICY_DECISION_FACTS_VERSION,
    },
    policy_eval::{tools::TOOL_SEMANTICS_VERSION, CONTEXT_VERSION, HTTP_SEMANTICS_VERSION},
    rbac::policy_document::accepted_policy_semantic_digest,
};

const ISSUER: &str = "https://idp.example.test";

/// A v1 policy whose roles come from an identity mapping, so the
/// organization is one of the facts every lane captures.
fn mapped_policy() -> Policy {
    Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "id": "decision-facts",
        "default_action": "deny",
        "roles": { "reader": { "permissions": ["data:read"] } },
        "identity_mappings": [
            { "id": "acme-readers", "issuer": ISSUER, "organizations": ["acme"], "grant_roles": ["reader"] }
        ],
        "routes": [
            { "id": "data", "path_prefix": "/data", "permission": "data:read" }
        ],
        "rules": [
            { "id": "deny-secret", "path": "/data/secret/**", "action": "deny" },
            { "id": "deny-ruled", "tool_name": "ruled", "action": "deny" }
        ],
        "tools": {
            "open": {},
            "off": { "enabled": false },
            "ruled": {}
        }
    }))
    .expect("the fixture validates")
}

fn acme_reader() -> Principal {
    Principal {
        user_id: "synthetic-subject".to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: None,
        org_id: Some("acme".to_owned()),
        roles: Vec::new(),
        session_id: "synthetic-session".to_owned(),
        auth_method: AuthMethod::Bearer,
        scopes: None,
        verified_claims: Vec::new(),
    }
}

async fn decision_for(router: &Router, uri: &str) -> PolicyDecision {
    router
        .clone()
        .oneshot(request(Method::GET, uri))
        .await
        .expect("the request completes")
        .extensions()
        .get::<PolicyDecision>()
        .cloned()
        .expect("the stage records its decision")
}

fn facts_json(decision: &PolicyDecision) -> Value {
    decision
        .facts
        .as_ref()
        .expect("a verdict carries its facts")
        .to_json()
}

/// What every HTTP verdict of [`mapped_policy`] states for a classified,
/// contextless request: everything but the reason and the element.
fn http_facts(policy: &Policy, reason: &str, element: Value) -> Value {
    json!({
        "schema_version": POLICY_DECISION_FACTS_VERSION,
        "lane": "http",
        "policy_etag": crate::policy_etag(policy).expect("the policy has an ETag"),
        "policy_semantic_digest": accepted_policy_semantic_digest(policy)
            .expect("a v1 policy has a canonical form")
            .expect("a v1 policy has a semantic digest"),
        "semantics_version": HTTP_SEMANTICS_VERSION,
        "context_version": CONTEXT_VERSION,
        "facts_available": facts_available::METHOD
            | facts_available::PATH
            | facts_available::PRINCIPAL
            | facts_available::ROUTING
            | facts_available::REQUEST_HOST
            | facts_available::ORGANIZATION,
        "routing": "contextless",
        "reason": reason,
        "element": element,
    })
}

#[tokio::test]
async fn every_http_verdict_names_the_policy_evaluator_inputs_and_element_that_decided() {
    let policy = mapped_policy();
    let (state, _capture) = test_state(policy.clone(), &[]);
    let installed = state.current_policy();
    let router = test_router(state, Some(acme_reader()));

    let denied = decision_for(&router, "/data/secret/x").await;
    assert_eq!(denied.outcome, PolicyDecisionOutcome::Denied);
    assert_eq!(
        facts_json(&denied),
        http_facts(
            &installed,
            "matched_rule",
            json!({ "kind": "rule", "position": 0, "id": "deny-secret" })
        )
    );
    let allowed = decision_for(&router, "/data/items").await;
    assert_eq!(allowed.outcome, PolicyDecisionOutcome::Allowed);
    assert_eq!(
        facts_json(&allowed),
        http_facts(
            &installed,
            allowed.reason,
            json!({ "kind": "route", "position": 0, "id": "data" })
        )
    );
    let defaulted = decision_for(&router, "/elsewhere").await;
    assert_eq!(defaulted.reason, "default_deny");
    assert_eq!(
        facts_json(&defaulted),
        http_facts(&installed, "default_deny", json!({ "kind": "default" }))
    );
}

#[tokio::test]
async fn a_0x_policy_has_no_semantic_digest_and_an_id_less_rule_is_named_by_position() {
    let policy = Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "default_action": "allow",
        "rules": [
            { "id": "first", "methods": ["POST"], "path": "/items/**", "action": "deny" },
            { "methods": ["GET"], "path": "/items/**", "action": "shadow" },
            { "id": "x".repeat(MAX_DECISION_ELEMENT_ID_BYTES + 1), "methods": ["DELETE"], "path": "/items/**", "action": "deny" }
        ]
    }))
    .expect("the fixture validates");
    let (state, _capture) = test_state(policy, &[]);
    let router = test_router(state, None);

    let shadowed = facts_json(&decision_for(&router, "/items/1").await);
    assert!(
        shadowed.get("policy_semantic_digest").is_none(),
        "{shadowed}"
    );
    assert_eq!(
        shadowed["element"],
        json!({ "kind": "rule", "position": 1 })
    );
    // Anonymous is a principal the evaluator had; no organization was
    // captured, because the policy maps no identity.
    assert_eq!(
        shadowed["facts_available"],
        json!(
            facts_available::METHOD
                | facts_available::PATH
                | facts_available::PRINCIPAL
                | facts_available::ROUTING
                | facts_available::REQUEST_HOST
        )
    );
    let overlong = facts_json(
        &router
            .clone()
            .oneshot(request(Method::DELETE, "/items/1"))
            .await
            .expect("the request completes")
            .extensions()
            .get::<PolicyDecision>()
            .cloned()
            .expect("the stage records its decision"),
    );
    // An id past the bound is flagged, never cut.
    assert_eq!(
        overlong["element"],
        json!({ "kind": "rule", "position": 2, "id_omitted": true })
    );
}

#[tokio::test]
async fn a_request_the_stage_refuses_to_answer_carries_no_decision_facts() {
    let policy = Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "default_action": "allow",
        "rules": [
            { "id": "payments", "methods": ["POST"], "path": "/api/**",
              "dispatch": { "kind": "route", "route_id": "payments" }, "action": "deny" }
        ]
    }))
    .expect("the fixture validates");
    let (state, _capture) = test_state(policy, &[]);
    // Classified requests are answered; an unsafe path is refused first.
    let classified = test_router(state.clone(), None);
    let unsafe_path = decision_for(&classified, "/api/%2e%2e/x").await;
    assert_eq!(unsafe_path.reason, "unsafe_path");
    assert!(unsafe_path.facts.is_none());
    // Unclassified routing leaves a dispatch-scoped rule unanswerable.
    let unclassified = Router::new()
        .fallback(any(|| async { "ok" }))
        .layer(from_fn_with_state(state, rbac_middleware));
    let response = unclassified
        .oneshot(request(Method::POST, "/api/items"))
        .await
        .expect("the request completes");
    let refused = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("the stage records its refusal");
    assert_eq!(refused.reason, "policy_evaluation_incomplete");
    assert!(refused.facts.is_none());
}

/// The data-plane budget for the facts: building them allocates nothing. A
/// verdict copies a fixed-size value of codes, versions and positions and
/// takes one reference to the identity computed when its snapshot was
/// installed; the ETag, digest and ids are never recomputed or copied per
/// request. The kernel call the `http_policy` and `tool_policy` microbench
/// targets measure is unchanged.
#[tokio::test]
async fn a_verdict_shares_its_snapshot_identity_and_copies_only_a_fixed_size_value() {
    fn copy_only<T: Copy>() {}
    copy_only::<EvaluationFacts>();
    assert!(
        size_of::<EvaluationFacts>() <= 64,
        "{}",
        size_of::<EvaluationFacts>()
    );
    assert!(size_of::<Option<PolicyDecisionFacts>>() <= 80);

    let (state, _capture) = test_state(mapped_policy(), &[]);
    let installed = state.installed_compiled_policy();
    let identity = installed
        .decision_identity
        .as_ref()
        .expect("an installed snapshot has an identity");
    let router = test_router(state.clone(), Some(acme_reader()));
    let first = decision_for(&router, "/data/items").await;
    let second = decision_for(&router, "/data/secret/x").await;
    for decision in [&first, &second] {
        let facts = decision
            .facts
            .as_ref()
            .expect("a verdict carries its facts");
        assert!(Arc::ptr_eq(facts.identity(), identity));
    }

    // A new install is a new identity, naming the new policy.
    let mut replaced = mapped_policy();
    replaced.default_action = DefaultAction::Allow;
    state.replace_policy(replaced.clone());
    let after = decision_for(&router, "/elsewhere").await;
    let facts = after.facts.as_ref().expect("a verdict carries its facts");
    assert!(!Arc::ptr_eq(facts.identity(), identity));
    assert_eq!(
        facts.identity().etag(),
        crate::policy_etag(&state.current_policy()).expect("the policy has an ETag")
    );
    assert_ne!(facts.identity().etag(), identity.etag());
}

#[test]
fn tool_invocation_verdicts_carry_facts_and_a_refusal_carries_none() {
    let policy = mapped_policy();
    let (state, _capture) = test_state(policy.clone(), &[]);
    let installed = state.current_policy();
    let principal = acme_reader();
    let facts = |tool_name: &str| {
        state.evaluate_tool_authorization_without_arguments(
            tool_name,
            Some(&principal),
            None,
            |authorization| authorization.decision_facts.map(|facts| facts.to_json()),
        )
    };
    let expected = |reason: &str, element: Value| {
        json!({
            "schema_version": POLICY_DECISION_FACTS_VERSION,
            "lane": "tool",
            "policy_etag": crate::policy_etag(&installed).expect("the policy has an ETag"),
            "policy_semantic_digest": accepted_policy_semantic_digest(&installed)
                .expect("a v1 policy has a canonical form")
                .expect("a v1 policy has a semantic digest"),
            "semantics_version": TOOL_SEMANTICS_VERSION,
            "context_version": crate::policy_eval::tools::TOOL_CONTEXT_VERSION,
            "facts_available": facts_available::TOOL_NAME
                | facts_available::PRINCIPAL
                | facts_available::ORGANIZATION,
            "reason": reason,
            "element": element,
        })
    };
    assert_eq!(
        facts("open"),
        Some(expected("allowed", json!({ "kind": "tool_entry" })))
    );
    assert_eq!(
        facts("off"),
        Some(expected("disabled", json!({ "kind": "tool_entry" })))
    );
    assert_eq!(
        facts("missing"),
        Some(expected("unknown_tool", json!({ "kind": "no_tool_entry" })))
    );
    assert_eq!(
        facts("ruled"),
        Some(expected(
            "matched_rule",
            json!({ "kind": "rule", "position": 1, "id": "deny-ruled" })
        ))
    );
    // A name no policy can carry is refused before evaluation: no verdict.
    assert_eq!(facts(&"t".repeat(MAX_TOOL_NAME_BYTES + 1)), None);
}

/// A tool call's arguments are marked available once a `tool_argument`
/// condition asked for them and they were captured, whether the rule then
/// matched or not, and the facts never carry them; a call whose rules read
/// no argument never has them asked for, and its bit stays clear.
#[test]
fn tool_argument_facts_are_marked_available_without_their_values() {
    const REGION: &str = "facts-region-canary-91e3";
    let policy = Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "id": "argument-facts",
        "default_action": "allow",
        "rules": [{
            "id": "deny-exports",
            "tool_name": "export",
            "action": "deny",
            "conditions": { "tool_argument": { "pointer": "/region", "in": [REGION] } }
        }],
        "tools": { "export": {}, "open": {} }
    }))
    .expect("the fixture validates");
    let (state, _capture) = test_state(policy, &[]);
    let principal = acme_reader();
    let schema = json!({
        "type": "object",
        "properties": { "region": { "type": "string" } }
    });
    let asked = std::cell::Cell::new(0_u32);
    let facts = |tool_name: &str, arguments: Value| {
        state
            .evaluate_tool_authorization(
                tool_name,
                Some(&principal),
                None,
                |pointers| {
                    asked.set(asked.get() + 1);
                    Ok::<_, std::convert::Infallible>(
                        crate::middleware::policy_facts::tool_argument_facts(
                            &schema, &arguments, pointers,
                        ),
                    )
                },
                |authorization| authorization.decision_facts.map(|facts| facts.to_json()),
            )
            .unwrap_or_else(|never| match never {})
            .expect("a verdict carries its facts")
    };
    let with_arguments =
        facts_available::TOOL_NAME | facts_available::PRINCIPAL | facts_available::TOOL_ARGUMENTS;

    let denied = facts("export", json!({ "region": REGION }));
    assert_eq!(asked.get(), 1);
    assert_eq!(denied["reason"], "matched_rule");
    assert_eq!(denied["facts_available"], json!(with_arguments));
    assert_eq!(
        denied["element"],
        json!({ "kind": "rule", "position": 0, "id": "deny-exports" })
    );

    let admitted = facts("export", json!({ "region": "elsewhere" }));
    assert_eq!(asked.get(), 2);
    assert_eq!(admitted["reason"], "allowed");
    assert_eq!(admitted["facts_available"], json!(with_arguments));

    let unread = facts("open", json!({ "region": REGION }));
    assert_eq!(asked.get(), 2, "no rule for the tool reads an argument");
    assert_eq!(
        unread["facts_available"],
        json!(facts_available::TOOL_NAME | facts_available::PRINCIPAL)
    );

    for rendered in [denied, admitted, unread].map(|facts| facts.to_string()) {
        for value in [REGION, "elsewhere", "/region"] {
            assert!(!rendered.contains(value), "the facts repeat {value}");
        }
    }
}

/// A fact a rule condition reads is marked available once the lane captured
/// it, and the facts never carry the value it had.
#[tokio::test]
async fn the_facts_a_rule_condition_reads_are_marked_available_without_their_values() {
    const ADDRESS: &str = "10.42.7.9";
    const HEADER_VALUE: &str = "facts-header-canary-7d2a";
    const QUERY_VALUE: &str = "facts-query-canary-4c81";
    let policy = Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "id": "conditioned-facts",
        "default_action": "allow",
        "rules": [{
            "id": "office-exports",
            "path": "/exports/**",
            "action": "deny",
            "conditions": { "all": [
                { "source_network": { "cidrs": ["10.0.0.0/8"] } },
                { "query": { "name": "format", "in": [QUERY_VALUE] } },
                { "header": { "name": "x-environment", "in": [HEADER_VALUE] } },
                { "time_window": {
                    "from": "2026-06-01T00:00:00Z",
                    "until": "2026-06-01T02:00:00Z"
                } }
            ] }
        }]
    }))
    .expect("the fixture validates");
    let (state, _capture) = test_state(policy, &[]);
    // 2026-06-01T01:00:00Z, inside the window.
    let state = state.with_policy_clock(crate::middleware::policy_facts::PolicyClock::fixed(
        1_780_275_600,
    ));
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(format!("/exports/a?format={QUERY_VALUE}"))
        .header("x-environment", HEADER_VALUE)
        .body(Body::empty())
        .expect("request should build");
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(
            ADDRESS.parse().expect("an address"),
            443,
        )));
    let decision = test_router(state, None)
        .oneshot(request)
        .await
        .expect("the request completes")
        .extensions()
        .get::<PolicyDecision>()
        .cloned()
        .expect("the stage records its decision");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Denied);
    let facts = facts_json(&decision);
    assert_eq!(
        facts["facts_available"],
        json!(
            facts_available::METHOD
                | facts_available::PATH
                | facts_available::PRINCIPAL
                | facts_available::ROUTING
                | facts_available::REQUEST_HOST
                | facts_available::CLIENT_ADDRESS
                | facts_available::HEADERS
                | facts_available::QUERY
                | facts_available::CLOCK
        )
    );
    assert_eq!(
        facts["element"],
        json!({ "kind": "rule", "position": 0, "id": "office-exports" })
    );
    let rendered = facts.to_string();
    for value in [
        ADDRESS,
        HEADER_VALUE,
        QUERY_VALUE,
        "x-environment",
        "format",
        "1780275600",
    ] {
        assert!(!rendered.contains(value), "the facts repeat {value}");
    }
}

/// The verified scopes and allowlisted claims a `scope` or `claim` condition
/// reads are marked available once the lane captured them, on the HTTP and
/// tool lanes alike, and the facts never carry a scope or claim value.
#[tokio::test]
async fn the_scopes_and_claims_a_condition_reads_are_marked_available_without_their_values() {
    const SCOPE: &str = "facts-scope-canary-5e19";
    const CLAIM_VALUE: &str = "facts-claim-canary-9b62";
    let policy = Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "id": "scoped-facts",
        "default_action": "allow",
        "rules": [
            {
                "id": "scoped-orders",
                "path": "/orders/**",
                "action": "deny",
                "conditions": { "all": [
                    { "scope": { "issuer": ISSUER, "in": [SCOPE] } },
                    { "claim": { "issuer": ISSUER, "name": "department", "in": [CLAIM_VALUE] } }
                ] }
            },
            {
                "id": "scoped-reports",
                "path": "/reports/**",
                "action": "deny",
                "conditions": { "scope": { "issuer": ISSUER, "in": [SCOPE] } }
            },
            {
                "id": "scoped-tool",
                "tool_name": "ruled",
                "action": "deny",
                "conditions": { "scope": { "issuer": ISSUER, "in": [SCOPE] } }
            }
        ],
        "tools": { "ruled": {} }
    }))
    .expect("the fixture validates");
    let (state, _capture) = test_state(policy, &[]);
    let principal = Principal {
        scopes: Some(vec![SCOPE.to_owned()]),
        verified_claims: vec![crate::auth::VerifiedClaim {
            name: "department".to_owned(),
            values: vec![json!(CLAIM_VALUE)],
        }],
        ..acme_reader()
    };
    let http = facts_available::METHOD
        | facts_available::PATH
        | facts_available::PRINCIPAL
        | facts_available::ROUTING
        | facts_available::REQUEST_HOST;

    let decision = decision_for(
        &test_router(state.clone(), Some(principal.clone())),
        "/orders/1",
    )
    .await;
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Denied);
    let facts = facts_json(&decision);
    assert_eq!(
        facts["facts_available"],
        json!(http | facts_available::SCOPES | facts_available::CLAIMS)
    );
    assert_eq!(
        facts["element"],
        json!({ "kind": "rule", "position": 0, "id": "scoped-orders" })
    );

    // An anonymous caller is verified to hold no scope and no claim: both
    // facts were captured, and neither matches.
    let anonymous = decision_for(&test_router(state.clone(), None), "/reports/1").await;
    assert_eq!(anonymous.outcome, PolicyDecisionOutcome::Allowed);
    assert_eq!(
        facts_json(&anonymous)["facts_available"],
        json!(http | facts_available::SCOPES | facts_available::CLAIMS)
    );

    let tool = state
        .evaluate_tool_authorization_without_arguments(
            "ruled",
            Some(&principal),
            None,
            |authorization| authorization.decision_facts.map(|facts| facts.to_json()),
        )
        .expect("a tool verdict carries its facts");
    assert_eq!(
        tool["facts_available"],
        json!(
            facts_available::TOOL_NAME
                | facts_available::PRINCIPAL
                | facts_available::SCOPES
                | facts_available::CLAIMS
        )
    );
    assert_eq!(
        tool["element"],
        json!({ "kind": "rule", "position": 2, "id": "scoped-tool" })
    );

    for rendered in [facts.to_string(), tool.to_string()] {
        for value in [SCOPE, CLAIM_VALUE, "department"] {
            assert!(!rendered.contains(value), "the facts repeat {value}");
        }
    }
}
