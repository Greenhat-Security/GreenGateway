//! Scope and claim matchers on the live lanes (issue #243).
//!
//! The HTTP stage, the tool lanes and the management lane answer exactly
//! what the shared evaluator answers when it is handed the scopes and
//! allowlisted claims the principal's own issuer verified, built here by
//! hand. Nothing else a request carries -- a header named like a scope or a
//! claim, another issuer's scopes, a service token's scopes -- satisfies a
//! scope or claim condition, and a scope or claim authentication did not
//! capture is refused as incomplete rather than read as absent, under `not`
//! too. No scope or claim value reaches an audit record, a decision or a
//! response.

use super::*;
use crate::{
    auth::VerifiedClaim,
    policy_eval::{
        stages::NoStages,
        tools::{ToolEvaluationContext, TOOL_CONTEXT_VERSION},
        Evaluation, Fact, HostFact, HttpTarget, LogicalDecision, PolicyEvaluationContext,
        PolicyFacts, PrincipalFact, PrincipalIdentity, CONTEXT_VERSION,
    },
};

const ISSUER: &str = "https://idp.example.test";
const OTHER_ISSUER: &str = "https://other.example.test";
/// A claim value no condition lists, that must never leave the request.
const CLAIM_CANARY: &str = "claim-canary-31d7";

fn document() -> Value {
    json!({
        "schema_version": "1.0.0",
        "id": "scoped-lanes",
        "default_action": "allow",
        "rules": [
            {
                "id": "writers-write",
                "methods": ["PUT"],
                "path": "/orders/**",
                "action": "allow",
                "conditions": { "scope": { "issuer": ISSUER, "in": ["orders.write"] } }
            },
            { "id": "orders-read-only", "methods": ["PUT"], "path": "/orders/**", "action": "deny" },
            {
                "id": "engineering-only",
                "path": "/eng/**",
                "action": "deny",
                "conditions": { "not": { "claim": {
                    "issuer": ISSUER,
                    "name": "department",
                    "in": ["engineering"]
                } } }
            },
            {
                "id": "mfa-reports",
                "path": "/reports/**",
                "action": "allow",
                "conditions": { "all": [
                    { "claim": { "issuer": ISSUER, "name": "amr", "in": ["mfa"] } },
                    { "claim": { "issuer": ISSUER, "name": "email_verified", "in": [true] } }
                ] }
            },
            { "id": "reports-closed", "path": "/reports/**", "action": "deny" },
            {
                "id": "level-two-shadowed",
                "path": "/levels/**",
                "action": "shadow",
                "conditions": { "claim": { "issuer": ISSUER, "name": "level", "in": [2] } }
            },
            {
                "id": "exports-need-a-scope",
                "tool_name": "reports.export",
                "action": "deny",
                "conditions": { "not": { "scope": { "issuer": ISSUER, "in": ["reports.export"] } } }
            }
        ],
        "tools": { "reports.export": { "allowed_roles": [] } }
    })
}

fn state() -> (RbacState, CaptureSink) {
    test_state(
        Policy::validate_json_value(document()).expect("the fixture validates"),
        &[],
    )
}

fn claim(name: &str, values: &[Value]) -> VerifiedClaim {
    VerifiedClaim {
        name: name.to_owned(),
        values: values.to_vec(),
    }
}

fn person(
    issuer: Option<&str>,
    scopes: Option<&[&str]>,
    claims: Vec<VerifiedClaim>,
    auth_method: AuthMethod,
) -> Principal {
    Principal {
        user_id: "synthetic-subject".to_owned(),
        issuer: issuer.map(str::to_owned),
        email: None,
        org_id: None,
        roles: vec!["orders.write".to_owned()],
        session_id: "synthetic-session".to_owned(),
        auth_method,
        scopes: scopes.map(|scopes| scopes.iter().map(|scope| (*scope).to_owned()).collect()),
        verified_claims: claims,
    }
}

/// Every principal shape the matchers must tell apart.
fn principals() -> Vec<(&'static str, Option<Principal>)> {
    let engineer_claims = || {
        vec![
            claim("amr", &[json!("pwd"), json!("mfa")]),
            claim("department", &[json!("engineering")]),
            claim("email_verified", &[json!(true)]),
            claim("level", &[json!(2.0)]),
        ]
    };
    vec![
        ("anonymous", None),
        (
            "an engineer",
            Some(person(
                Some(ISSUER),
                Some(&["orders.write", "reports.export"]),
                engineer_claims(),
                AuthMethod::Bearer,
            )),
        ),
        (
            "a seller",
            Some(person(
                Some(ISSUER),
                Some(&["orders.read"]),
                vec![
                    claim("amr", &[json!("pwd")]),
                    claim("department", &[json!("sales"), json!(CLAIM_CANARY)]),
                    claim("email_verified", &[json!(false)]),
                    claim("level", &[json!(1)]),
                ],
                AuthMethod::Bearer,
            )),
        ),
        (
            "a token whose claims the token did not carry",
            Some(person(
                Some(ISSUER),
                Some(&[]),
                vec![
                    claim("amr", &[]),
                    claim("department", &[]),
                    claim("email_verified", &[]),
                    claim("level", &[]),
                ],
                AuthMethod::Bearer,
            )),
        ),
        (
            "another issuer's engineer",
            Some(person(
                Some(OTHER_ISSUER),
                Some(&["orders.write", "reports.export"]),
                engineer_claims(),
                AuthMethod::Bearer,
            )),
        ),
        (
            "a session without scope or claim facts",
            Some(person(Some(ISSUER), None, Vec::new(), AuthMethod::Cookie)),
        ),
        (
            "a service token whose scopes are its roles",
            Some(person(None, None, Vec::new(), AuthMethod::ServiceToken)),
        ),
    ]
}

/// The facts a lane captures for `principal` under the fixture, built by
/// hand: its scope fact as authentication captured it, and its verified
/// claims of the names the conditions read.
fn hand_built_facts(principal: Option<&Principal>) -> PolicyFacts {
    let mut facts = PolicyFacts::uncaptured();
    facts.scopes = match principal {
        None => Fact::Captured(Vec::new()),
        Some(principal) => principal
            .scopes
            .clone()
            .map_or(Fact::Uncaptured, Fact::Captured),
    };
    facts.claims = Fact::Captured(
        principal
            .map(|principal| {
                principal
                    .verified_claims
                    .iter()
                    .filter(|claim| {
                        ["amr", "department", "email_verified", "level"]
                            .contains(&claim.name.as_str())
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default(),
    );
    facts
}

fn kernel_http(
    state: &RbacState,
    method: Method,
    path: &str,
    principal: Option<&Principal>,
    facts: &PolicyFacts,
) -> Evaluation {
    let snapshot = state.installed_compiled_policy();
    let compiled = snapshot.compiled();
    let context = PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(method),
        path: Some(path.to_owned()),
        principal: principal.map_or(PrincipalFact::Anonymous, |principal| {
            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
        }),
        target: HttpTarget::Contextless,
        request_host: HostFact::Absent,
        dispatch: None,
    };
    compiled
        .evaluate_with_facts(&context, facts)
        .expect("the kernel answers")
}

async fn decide(
    state: &RbacState,
    principal: Option<&Principal>,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, PolicyDecision) {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = test_router(state.clone(), principal.cloned())
        .oneshot(request.body(Body::empty()).expect("request should build"))
        .await
        .expect("the request completes");
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .cloned()
        .expect("a decision is attached");
    (response.status(), decision)
}

fn requests() -> Vec<(Method, &'static str)> {
    vec![
        (Method::PUT, "/orders/1"),
        (Method::GET, "/orders/1"),
        (Method::GET, "/eng/roadmap"),
        (Method::GET, "/reports/q3"),
        (Method::GET, "/levels/2"),
    ]
}

/// Every scope and claim condition decides on the live HTTP stage exactly as
/// the kernel decides it with the facts built by hand, for every principal
/// shape; an undetermined answer is refused as incomplete.
#[tokio::test]
async fn the_http_stage_decides_scope_and_claim_conditions_exactly_as_the_kernel() {
    let (state, capture) = state();
    for (name, principal) in principals() {
        let facts = hand_built_facts(principal.as_ref());
        for (method, path) in requests() {
            let expected = kernel_http(&state, method.clone(), path, principal.as_ref(), &facts);
            let (status, decision) =
                decide(&state, principal.as_ref(), method.clone(), path, &[]).await;
            let case = format!("{name}: {method} {path}: {expected:?}");
            if expected.logical() == LogicalDecision::Indeterminate {
                assert_eq!(status, StatusCode::FORBIDDEN, "{case}");
                assert_eq!(decision.reason, "policy_evaluation_incomplete", "{case}");
                continue;
            }
            assert_eq!(
                status == StatusCode::FORBIDDEN,
                expected.effect() == PolicyEffect::Block,
                "{case}"
            );
            assert_eq!(decision.reason, expected.reason().as_str(), "{case}");
            let expected_rule = match expected.matched() {
                Some(RuleReference::Direct(index)) => {
                    Some(state.installed_compiled_policy().rule_ids()[index].clone())
                }
                _ => None,
            };
            assert_eq!(decision.matched_rule_id, expected_rule, "{case}");
            if expected.effect() == PolicyEffect::Observe {
                captured_event(&capture, AUTHZ_WOULD_DENY).await;
            }
        }
    }
}

/// The matrix above, stated as outcomes: who may write, read the
/// engineering pages and the reports, and who is refused as incomplete.
#[tokio::test]
async fn scope_and_claim_conditions_admit_exactly_the_verified_principals() {
    let (state, _capture) = state();
    let principals = principals();
    let by_name = |wanted: &str| {
        principals
            .iter()
            .find(|(name, _)| *name == wanted)
            .and_then(|(_, principal)| principal.clone())
    };
    let engineer = by_name("an engineer");
    let seller = by_name("a seller");
    let absent = by_name("a token whose claims the token did not carry");
    let elsewhere = by_name("another issuer's engineer");
    let session = by_name("a session without scope or claim facts");
    let service = by_name("a service token whose scopes are its roles");
    for (principal, method, path, status, rule) in [
        (
            &engineer,
            Method::PUT,
            "/orders/1",
            StatusCode::OK,
            Some("writers-write"),
        ),
        (
            &seller,
            Method::PUT,
            "/orders/1",
            StatusCode::FORBIDDEN,
            Some("orders-read-only"),
        ),
        // Another issuer's scope, and a service token's scopes, which are its
        // roles, never satisfy a scope condition bound to this issuer.
        (
            &elsewhere,
            Method::PUT,
            "/orders/1",
            StatusCode::FORBIDDEN,
            Some("orders-read-only"),
        ),
        (
            &service,
            Method::PUT,
            "/orders/1",
            StatusCode::FORBIDDEN,
            Some("orders-read-only"),
        ),
        (&engineer, Method::GET, "/eng/roadmap", StatusCode::OK, None),
        (
            &seller,
            Method::GET,
            "/eng/roadmap",
            StatusCode::FORBIDDEN,
            Some("engineering-only"),
        ),
        (
            &absent,
            Method::GET,
            "/eng/roadmap",
            StatusCode::FORBIDDEN,
            Some("engineering-only"),
        ),
        (
            &elsewhere,
            Method::GET,
            "/eng/roadmap",
            StatusCode::FORBIDDEN,
            Some("engineering-only"),
        ),
        (
            &engineer,
            Method::GET,
            "/reports/q3",
            StatusCode::OK,
            Some("mfa-reports"),
        ),
        (
            &seller,
            Method::GET,
            "/reports/q3",
            StatusCode::FORBIDDEN,
            Some("reports-closed"),
        ),
        (
            &elsewhere,
            Method::GET,
            "/reports/q3",
            StatusCode::FORBIDDEN,
            Some("reports-closed"),
        ),
    ] {
        let (actual, decision) =
            decide(&state, principal.as_ref(), method.clone(), path, &[]).await;
        assert_eq!(actual, status, "{method} {path} {principal:?}");
        assert_eq!(
            decision.matched_rule_id.as_deref(),
            rule,
            "{method} {path} {principal:?}"
        );
    }
    // A session carries no scope or claim fact, so neither the allow nor the
    // `not` over one is decided for it, and both are refused as incomplete.
    for (method, path) in [(Method::PUT, "/orders/1"), (Method::GET, "/eng/roadmap")] {
        let (status, decision) = decide(&state, session.as_ref(), method.clone(), path, &[]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(
            decision.reason, "policy_evaluation_incomplete",
            "{method} {path}"
        );
    }
}

/// Headers named like scopes, claims or tokens are never read as identity:
/// a principal that lacks a scope or claim gains nothing by sending one,
/// and an anonymous caller gains nothing either.
#[tokio::test]
async fn scope_and_claim_headers_are_ignored() {
    let (state, _capture) = state();
    let principals = principals();
    let seller = principals
        .iter()
        .find(|(name, _)| *name == "a seller")
        .and_then(|(_, principal)| principal.clone());
    let spoofing = [
        ("scope", "orders.write"),
        ("x-scope", "orders.write"),
        ("x-oauth-scopes", "orders.write"),
        ("department", "engineering"),
        ("x-claim-department", "engineering"),
        ("x-forwarded-user", "engineer"),
        ("x-auth-request-groups", "engineering"),
    ];
    for principal in [seller.as_ref(), None] {
        let (status, decision) =
            decide(&state, principal, Method::PUT, "/orders/1", &spoofing).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            decision.matched_rule_id.as_deref(),
            Some("orders-read-only")
        );
    }
    let (status, decision) = decide(
        &state,
        seller.as_ref(),
        Method::GET,
        "/eng/roadmap",
        &spoofing,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("engineering-only")
    );
}

/// The tool lanes read the scopes and claims the invoking principal carries,
/// exactly as the kernel does with them built by hand.
#[test]
fn the_tool_lanes_decide_scope_conditions_as_the_kernel() {
    let (state, _capture) = state();
    let snapshot = state.installed_compiled_policy();
    let compiled = snapshot.compiled();
    for (name, principal) in principals() {
        let Some(principal) = principal else { continue };
        let facts = hand_built_facts(Some(&principal));
        for operation in [ToolOperation::Invocation, ToolOperation::Visibility] {
            let context = ToolEvaluationContext {
                version: TOOL_CONTEXT_VERSION,
                snapshot: compiled.snapshot(),
                operation,
                tool_name: Some("reports.export".to_owned()),
                principal: PrincipalFact::Authenticated(PrincipalIdentity::from_principal(
                    &principal,
                )),
                method: None,
                path: None,
            };
            let expected = compiled
                .evaluate_tool_with_facts(&context, &facts, &mut NoStages)
                .expect("the kernel answers");
            let live = match operation {
                ToolOperation::Visibility => {
                    state.tool_visible("reports.export", Some(&principal), None)
                }
                _ => state.evaluate_tool_authorization_without_arguments(
                    "reports.export",
                    Some(&principal),
                    None,
                    |authorization| match authorization.verdict {
                        ToolInvocationVerdict::Entry { rule_decision, .. } => {
                            rule_decision.is_none_or(|decision| decision.action != RuleAction::Deny)
                        }
                        _ => false,
                    },
                ),
            };
            assert_eq!(
                live,
                expected.effect() == PolicyEffect::Allow,
                "{name} {operation:?}: {expected:?}"
            );
            assert_eq!(live, name == "an engineer", "{name} {operation:?}");
        }
    }
}

/// In mapped-role mode a mapping's `scopes` decide internal roles on every
/// lane, the management lane included; a principal with no scope fact holds
/// no role there, and a scope never becomes a role of its own name.
#[tokio::test]
async fn a_scope_mapping_grants_roles_on_every_lane() {
    let policy = Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "roles": {
            "writer": { "permissions": ["orders:write", "admin:tokens:write"] },
            "orders.write": { "permissions": ["orders:everything"] }
        },
        "identity_mappings": [
            { "id": "writers", "issuer": ISSUER, "scopes": ["orders.write"], "grant_roles": ["writer"] }
        ],
        "routes": [
            { "id": "orders", "path_prefix": "/orders", "permission": "orders:write" }
        ]
    }))
    .expect("the mapped fixture validates");
    let (state, _capture) = test_state(policy, &[]);
    let writer = person(
        Some(ISSUER),
        Some(&["orders.write"]),
        Vec::new(),
        AuthMethod::Bearer,
    );
    let reader = person(
        Some(ISSUER),
        Some(&["orders.read"]),
        Vec::new(),
        AuthMethod::Bearer,
    );
    let session = person(Some(ISSUER), None, Vec::new(), AuthMethod::Cookie);

    let (status, _) = decide(&state, Some(&writer), Method::GET, "/orders/1", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let (status, decision) = decide(&state, Some(&reader), Method::GET, "/orders/1", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(decision.reason, "missing_permission");
    let (status, decision) = decide(&state, Some(&session), Method::GET, "/orders/1", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(decision.reason, "policy_evaluation_incomplete");

    assert!(state.principal_has_permission(&writer, "admin:tokens:write"));
    // A role named like the scope is not granted by holding the scope.
    assert!(!state.principal_has_permission(&writer, "orders:everything"));
    assert!(!state.principal_has_permission(&reader, "admin:tokens:write"));
    assert!(!state.principal_has_permission(&session, "admin:tokens:write"));
}

/// No claim or scope value a condition reads, matched or not, reaches an
/// audit record, the policy decision the response carries, or the response.
#[tokio::test]
async fn no_scope_or_claim_value_reaches_audit_the_decision_or_the_response() {
    let (state, capture) = state();
    let principals = principals();
    let seller = principals
        .iter()
        .find(|(name, _)| *name == "a seller")
        .and_then(|(_, principal)| principal.clone());
    let mut sent = 0;
    for (method, path) in requests() {
        let mut request = Request::builder().method(method).uri(path);
        request = request.header("x-environment", "prod");
        let response = test_router(state.clone(), seller.clone())
            .oneshot(request.body(Body::empty()).expect("request should build"))
            .await
            .expect("the request completes");
        sent += 1;
        let decision = format!("{:?}", response.extensions().get::<PolicyDecision>());
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("the body reads");
        for rendered in [decision, String::from_utf8_lossy(&body).into_owned()] {
            assert!(!rendered.contains(CLAIM_CANARY), "{rendered}");
            assert!(!rendered.contains("orders.read"), "{rendered}");
        }
    }
    assert_eventually(Duration::from_secs(1), || capture.events().len() >= sent);
    let audited = serde_json::to_string(&capture.events()).expect("events serialize");
    assert!(!audited.contains(CLAIM_CANARY));
    assert!(!audited.contains("orders.read"));
    assert!(!audited.contains("sales"));
}
