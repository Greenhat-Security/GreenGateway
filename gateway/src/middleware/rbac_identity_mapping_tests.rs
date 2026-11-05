//! Identity mappings on the live lanes (issue #243).
//!
//! Every serving lane of [`RbacState`] -- the HTTP stage, tool admission,
//! visibility, inventory eligibility, the rendered-HTTP rule and the
//! management lane -- answers exactly what the shared evaluator answers when
//! it is handed the organization the principal's own issuer verified. The
//! expectation is computed here, from the kernel, with that fact built by
//! hand rather than through the adapters' own `serving_facts`, so a lane that
//! dropped the fact, read it from somewhere else, or judged by claimed roles
//! would disagree. Nothing else a request carries -- an organization-like
//! header, a claimed role named like an internal one, another issuer's
//! organization, a service token's scopes -- changes a role.

use super::*;
use crate::policy_eval::{
    stages::NoStages,
    tools::{ToolEvaluation, ToolEvaluationContext, ToolReason, TOOL_CONTEXT_VERSION},
    DispatchFacts, Evaluation, Fact, HostFact, HttpTarget, PolicyEvaluationContext, PolicyFacts,
    PrincipalFact, PrincipalIdentity, RuleReference, CONTEXT_VERSION,
};

const ISSUER: &str = "https://idp.example.test";
const TENANT_HOST: &str = "tenant.example.test";

fn mapped_document() -> Value {
    json!({
        "schema_version": "1.0.0",
        "id": "mapped-lanes",
        "default_action": "deny",
        "roles": {
            "admin": { "permissions": ["admin:policy:write", "admin:tokens:write", "data:read"] },
            "reader": { "permissions": ["data:read"] },
            "auditor": { "permissions": ["audit:read"], "auth_methods": ["session_cookie"] }
        },
        "identity_mappings": [
            {
                "id": "acme-admins",
                "issuer": ISSUER,
                "organizations": ["acme"],
                "claimed_roles": ["Platform-Admins"],
                "grant_roles": ["admin"]
            },
            { "id": "acme-readers", "issuer": ISSUER, "organizations": ["acme"], "grant_roles": ["reader"] },
            { "id": "auditors", "issuer": ISSUER, "claimed_roles": ["Auditors"], "grant_roles": ["auditor"] }
        ],
        "routes": [
            { "id": "tenant-data", "path_prefix": "/data", "hosts": [TENANT_HOST], "permission": "data:read" },
            { "id": "data", "path_prefix": "/data", "permission": "data:read" },
            { "id": "audit", "path_prefix": "/audit", "permission": "audit:read" }
        ],
        "rules": [
            {
                "id": "watch-admin-exports",
                "path": "/data/exports/**",
                "principal": { "roles": ["admin"] },
                "action": "shadow"
            },
            { "id": "admins-only", "path": "/admin/**", "principal": { "roles": ["admin"] }, "action": "allow" },
            { "id": "deny-admin", "path": "/admin/**", "action": "deny" },
            {
                "id": "readers-export",
                "tool_name": "reports.export",
                "principal": { "roles": ["reader"] },
                "action": "shadow"
            },
            {
                "id": "readers-never-delete",
                "methods": ["DELETE"],
                "path": "/upstream/**",
                "principal": { "roles": ["reader"] },
                "action": "deny"
            }
        ],
        "tools": {
            "reports.export": { "allowed_roles": ["admin", "reader"] },
            "lookup": { "allowed_roles": ["admin"] }
        }
    })
}

fn policy_from(document: Value) -> Policy {
    Policy::validate_json_value(document).expect("the fixture validates")
}

fn identity(
    issuer: Option<&str>,
    organization: Option<&str>,
    roles: &[&str],
    auth_method: AuthMethod,
) -> Principal {
    Principal {
        user_id: "synthetic-subject".to_owned(),
        issuer: issuer.map(str::to_owned),
        email: None,
        org_id: organization.map(str::to_owned),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: "synthetic-session".to_owned(),
        auth_method,
    }
}

/// Every principal shape the mappings must tell apart, with the internal
/// roles the fixture's mappings grant each.
fn principals() -> Vec<(&'static str, Principal, &'static [&'static str])> {
    vec![
        (
            "an acme platform admin",
            identity(
                Some(ISSUER),
                Some("acme"),
                &["Platform-Admins"],
                AuthMethod::Bearer,
            ),
            &["admin", "reader"],
        ),
        (
            "an acme member",
            identity(Some(ISSUER), Some("acme"), &[], AuthMethod::Bearer),
            &["reader"],
        ),
        (
            "a platform admin of another organization",
            identity(
                Some(ISSUER),
                Some("globex"),
                &["Platform-Admins"],
                AuthMethod::Bearer,
            ),
            &[],
        ),
        (
            "a platform admin whose provider verified no organization",
            identity(Some(ISSUER), None, &["Platform-Admins"], AuthMethod::Bearer),
            &[],
        ),
        (
            "acme claimed under another issuer",
            identity(
                Some("https://other.example.test"),
                Some("acme"),
                &["Platform-Admins", "admin"],
                AuthMethod::Bearer,
            ),
            &[],
        ),
        (
            "acme claimed under a lookalike issuer",
            identity(
                Some("https://idp.example.test.attacker.example"),
                Some("acme"),
                &["Platform-Admins"],
                AuthMethod::Bearer,
            ),
            &[],
        ),
        (
            "a service token whose scopes name internal roles",
            identity(
                None,
                Some("acme"),
                &["admin", "reader", "Platform-Admins"],
                AuthMethod::ServiceToken,
            ),
            &[],
        ),
        (
            "an acme member claiming the internal admin role by name",
            identity(Some(ISSUER), Some("acme"), &["admin"], AuthMethod::Bearer),
            &["reader"],
        ),
        (
            "a cookie auditor",
            identity(Some(ISSUER), None, &["Auditors"], AuthMethod::Cookie),
            &["auditor"],
        ),
        (
            "a bearer auditor, whose role admits cookies only",
            identity(Some(ISSUER), None, &["Auditors"], AuthMethod::Bearer),
            &["auditor"],
        ),
    ]
}

/// The organization fact exactly as the principal's issuer verified it.
fn verified_organization(principal: &Principal) -> PolicyFacts {
    let mut facts = PolicyFacts::uncaptured();
    facts.organization = Fact::Captured(principal.org_id.clone());
    facts
}

fn authenticated(principal: &Principal) -> PrincipalFact {
    PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
}

/// The kernel's answer for the request the HTTP stage judges: a classified
/// contextless request without a `Host`, or a proxy dispatch to the tenant
/// host, built exactly as [`proxy_request`] marks one.
fn kernel_http(state: &RbacState, path: &str, principal: &Principal, proxied: bool) -> Evaluation {
    let snapshot = state.installed_compiled_policy();
    let compiled = snapshot.compiled();
    let (target, request_host, dispatch) = if proxied {
        (
            HttpTarget::ProxyDispatch,
            HostFact::Present(TENANT_HOST.to_owned()),
            Some(DispatchFacts {
                route_id: None,
                route_host: Some(TENANT_HOST.to_owned()),
                route_path_prefix: Some("/data".to_owned()),
                upstream_origin: "https://upstream.example.test".to_owned(),
            }),
        )
    } else {
        (HttpTarget::Contextless, HostFact::Absent, None)
    };
    let context = PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(Method::GET),
        path: Some(path.to_owned()),
        principal: authenticated(principal),
        target,
        request_host,
        dispatch,
    };
    compiled
        .evaluate_with_facts(&context, &verified_organization(principal))
        .expect("the kernel answers")
}

fn kernel_tool(
    state: &RbacState,
    operation: ToolOperation,
    tool_name: &str,
    principal: &Principal,
    rendered: Option<(Method, &str)>,
) -> ToolEvaluation {
    let snapshot = state.installed_compiled_policy();
    let compiled = snapshot.compiled();
    let (method, path) = rendered
        .map(|(method, path)| (method, path.to_owned()))
        .unzip();
    let context = ToolEvaluationContext {
        version: TOOL_CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        operation,
        tool_name: Some(tool_name.to_owned()),
        principal: authenticated(principal),
        method,
        path,
    };
    compiled
        .evaluate_tool_with_facts(&context, &verified_organization(principal), &mut NoStages)
        .expect("the kernel answers")
}

fn rule_id(state: &RbacState, reference: Option<RuleReference>) -> Option<String> {
    match reference {
        Some(RuleReference::Direct(index)) => {
            Some(state.installed_compiled_policy().rule_ids()[index].clone())
        }
        _ => None,
    }
}

fn outcome_of(effect: PolicyEffect) -> PolicyDecisionOutcome {
    match effect {
        PolicyEffect::Allow => PolicyDecisionOutcome::Allowed,
        PolicyEffect::Block => PolicyDecisionOutcome::Denied,
        PolicyEffect::Observe => PolicyDecisionOutcome::WouldDeny,
    }
}

async fn would_deny_rule_ids(capture: &CaptureSink) -> Vec<String> {
    // The verdict is the last record written; once it is there, so is any
    // observation queued before it.
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            matches!(
                event.event_type.as_str(),
                AUTHZ_ALLOWED | AUTHZ_DENIED | AUTHZ_WOULD_DENY
            )
        })
    });
    capture
        .events()
        .iter()
        .filter(|event| event.event_type == AUTHZ_WOULD_DENY)
        .filter_map(|event| event.payload["matched_rule_id"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn the_http_stage_decides_and_observes_exactly_as_the_kernel_with_the_verified_organization()
{
    let requests = [
        ("/data/1", false),
        ("/data/exports/latest", false),
        ("/admin/settings", false),
        ("/audit/log", false),
        ("/elsewhere", false),
        ("/data/exports/latest", true),
        ("/data/2", true),
    ];
    for (label, principal, _) in principals() {
        for (path, proxied) in requests {
            let (state, capture) = test_state(policy_from(mapped_document()), &[]);
            let expected = kernel_http(&state, path, &principal, proxied);
            let request = if proxied {
                proxy_request(Method::GET, path, TENANT_HOST)
            } else {
                request(Method::GET, path)
            };
            let response = test_router(state.clone(), Some(principal.clone()))
                .oneshot(request)
                .await
                .expect("the request completes");
            let case = format!("{label}, GET {path}, proxied {proxied}");
            assert_eq!(
                response.status() == StatusCode::FORBIDDEN,
                expected.effect() == PolicyEffect::Block,
                "{case}: {expected:?}"
            );
            let decision = response
                .extensions()
                .get::<PolicyDecision>()
                .expect("a decision is attached");
            assert_eq!(decision.outcome, outcome_of(expected.effect()), "{case}");
            assert_eq!(decision.reason, expected.reason().as_str(), "{case}");
            let mut observed: Vec<String> = rule_id(&state, expected.observation())
                .into_iter()
                .collect();
            if expected.effect() == PolicyEffect::Observe {
                observed.extend(rule_id(&state, expected.matched()));
            }
            assert_eq!(would_deny_rule_ids(&capture).await, observed, "{case}");
        }
    }
}

/// The shadow rule that watches admin exports is judged by the internal
/// roles, on the request that also records it beside a host-bound verdict.
#[tokio::test]
async fn a_direct_shadow_observation_is_judged_by_the_mapped_roles() {
    let admin = identity(
        Some(ISSUER),
        Some("acme"),
        &["Platform-Admins"],
        AuthMethod::Bearer,
    );
    let claimed_admin = identity(Some(ISSUER), Some("acme"), &["admin"], AuthMethod::Bearer);
    for (principal, watched) in [(admin, true), (claimed_admin, false)] {
        let (state, capture) = test_state(policy_from(mapped_document()), &[]);
        let response = test_router(state, Some(principal))
            .oneshot(proxy_request(
                Method::GET,
                "/data/exports/latest",
                TENANT_HOST,
            ))
            .await
            .expect("the request completes");
        assert_eq!(response.status(), StatusCode::OK);
        let expected: Vec<String> = if watched {
            vec!["watch-admin-exports".to_owned()]
        } else {
            Vec::new()
        };
        assert_eq!(would_deny_rule_ids(&capture).await, expected);
    }
}

#[test]
fn every_tool_lane_answers_exactly_as_the_kernel_with_the_verified_organization() {
    let (state, _capture) = test_state(policy_from(mapped_document()), &[]);
    for (label, principal, _) in principals() {
        // Inventory eligibility, which a shadow rule leaves eligible.
        let expected = kernel_tool(
            &state,
            ToolOperation::PolicyEligibility,
            "reports.export",
            &principal,
            None,
        );
        let eligibility = state.tool_policy_eligibility("reports.export", &principal);
        assert_eq!(
            (eligibility.eligible, eligibility.reason),
            (
                expected.effect() == PolicyEffect::Allow,
                expected.reason().as_str()
            ),
            "{label}: eligibility"
        );

        // Visibility of a tool only the admin role may use.
        let expected = kernel_tool(
            &state,
            ToolOperation::Visibility,
            "lookup",
            &principal,
            None,
        );
        assert_eq!(
            state.tool_visible("lookup", Some(&principal), None),
            expected.effect() == PolicyEffect::Allow,
            "{label}: visibility"
        );

        // The rendered request's direct rules, which deny readers a DELETE.
        let expected = kernel_tool(
            &state,
            ToolOperation::RenderedHttp,
            "reports.export",
            &principal,
            Some((Method::DELETE, "/upstream/items/1")),
        );
        let rendered = state
            .evaluate_tool_http_rule(
                "reports.export",
                "DELETE",
                "/upstream/items/1",
                Some(&principal),
                None,
            )
            .expect("the rendered rule is answered");
        assert_eq!(
            rendered.map(|decision| (decision.action, decision.matched_rule_id)),
            (expected.reason() == ToolReason::MatchedRule).then(|| {
                (
                    RuleAction::Deny,
                    rule_id(&state, expected.matched()).expect("a direct rule"),
                )
            }),
            "{label}: rendered HTTP rule"
        );

        // Admission, where a reader's shadow rule is an observation.
        let expected = kernel_tool(
            &state,
            ToolOperation::Invocation,
            "reports.export",
            &principal,
            None,
        );
        let admitted = state.evaluate_tool_authorization(
            "reports.export",
            Some(&principal),
            None,
            |authorization| match authorization.verdict {
                ToolInvocationVerdict::Entry { rule_decision, .. } => {
                    Some(rule_decision.map(|decision| (decision.action, decision.matched_rule_id)))
                }
                ToolInvocationVerdict::RoleNotAllowed { .. } => None,
                _ => panic!("{label}: an answer the fixture cannot produce"),
            },
        );
        let expected_admission = match expected.reason() {
            ToolReason::RoleNotAllowed => None,
            ToolReason::Allowed => Some(None),
            ToolReason::MatchedRule => Some(Some((
                RuleAction::Shadow,
                rule_id(&state, expected.matched()).expect("a direct rule"),
            ))),
            other => panic!("{label}: unexpected kernel reason {other:?}"),
        };
        assert_eq!(admitted, expected_admission, "{label}: admission");
    }
}

#[test]
fn the_management_lane_grants_exactly_the_mapped_roles_permissions() {
    let (state, _capture) = test_state(policy_from(mapped_document()), &[]);
    let snapshot = state.installed_compiled_policy();
    let compiled = snapshot.compiled();
    let requested: Vec<String> = ["admin", "reader", "auditor"]
        .iter()
        .map(|role| (*role).to_owned())
        .collect();
    for (label, principal, granted) in principals() {
        let effective = compiled
            .effective_principal(&principal, &verified_organization(&principal))
            .expect("every organization is captured");
        assert_eq!(effective.roles, granted, "{label}: internal roles");
        for permission in [
            "admin:policy:write",
            "admin:tokens:write",
            "data:read",
            "audit:read",
        ] {
            assert_eq!(
                state.principal_has_permission(&principal, permission),
                compiled
                    .engine()
                    .principal_has_permission(&effective, permission),
                "{label}: {permission}"
            );
            assert_eq!(
                state.request_snapshot_grants_permission(&principal, permission),
                state.principal_has_permission(&principal, permission),
                "{label}: {permission} through the request snapshot"
            );
        }
        let expected: Vec<String> = requested
            .iter()
            .filter(|role| {
                !compiled
                    .engine()
                    .principal_has_active_role(&effective, role)
            })
            .cloned()
            .collect();
        assert_eq!(
            state.disallowed_delegated_roles(&principal, &requested),
            expected,
            "{label}: delegation"
        );
    }
}

/// No request header names an organization: a member whose provider
/// verified none gains nothing from one, and a verified member loses
/// nothing to one.
#[tokio::test]
async fn an_organization_like_header_changes_no_role() {
    const HEADERS: &[(&str, &str)] = &[
        ("x-org-id", "acme"),
        ("x-organization", "acme"),
        ("x-organization-id", "acme"),
        ("x-tenant", "acme"),
        ("x-tenant-id", "acme"),
        ("x-greengateway-organization", "acme"),
        ("org", "acme"),
        ("forwarded", "for=192.0.2.1;org=acme"),
    ];
    let unverified = identity(Some(ISSUER), None, &[], AuthMethod::Bearer);
    let verified = identity(Some(ISSUER), Some("acme"), &[], AuthMethod::Bearer);
    for (principal, expected) in [
        (unverified, StatusCode::FORBIDDEN),
        (verified, StatusCode::OK),
    ] {
        for (name, value) in HEADERS {
            let (state, _capture) = test_state(policy_from(mapped_document()), &[]);
            let mut request = request(Method::GET, "/data/1");
            let spoof = if principal.org_id.is_some() {
                "globex"
            } else {
                value
            };
            request.headers_mut().insert(
                *name,
                http::HeaderValue::from_str(spoof).expect("header value"),
            );
            let response = test_router(state, Some(principal.clone()))
                .oneshot(request)
                .await
                .expect("the request completes");
            assert_eq!(response.status(), expected, "{name}");
        }
    }
}

/// An organization past the kernel's bound is refused, never compared, on
/// every lane of a mapped-role policy -- and not read at all by a policy
/// without mappings, which serves it exactly as before.
#[tokio::test]
async fn an_oversized_organization_is_refused_in_mapped_role_mode_only() {
    let oversized = "o".repeat(crate::policy_eval::MAX_FACT_VALUE_BYTES + 1);
    let principal = identity(
        Some(ISSUER),
        Some(&oversized),
        &["Platform-Admins"],
        AuthMethod::Bearer,
    );

    let (state, capture) = test_state(policy_from(mapped_document()), &[]);
    let response = test_router(state.clone(), Some(principal.clone()))
        .oneshot(request(Method::GET, "/data/1"))
        .await
        .expect("the request completes");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["reason"], json!("policy_evaluation_error"));
    assert!(!state.principal_has_permission(&principal, "data:read"));
    assert!(!state.tool_visible("lookup", Some(&principal), None));
    assert_eq!(
        state
            .tool_policy_eligibility("reports.export", &principal)
            .reason,
        "policy_evaluation_error"
    );

    // The same principal under the claimed-role policy, whose claimed role
    // grants the route: the organization is never captured, so never refused.
    let mut claimed = mapped_document();
    claimed
        .as_object_mut()
        .expect("object")
        .remove("identity_mappings");
    claimed["roles"]["Platform-Admins"] = json!({ "permissions": ["data:read"] });
    let (state, _capture) = test_state(policy_from(claimed), &[]);
    let response = test_router(state.clone(), Some(principal.clone()))
        .oneshot(request(Method::GET, "/data/1"))
        .await
        .expect("the request completes");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.principal_has_permission(&principal, "data:read"));
}

/// A policy without mappings captures no fact on any lane, so its answers,
/// bindings included, are the uncaptured ones it always gave.
#[test]
fn claimed_role_mode_captures_no_fact() {
    let mut claimed = mapped_document();
    claimed
        .as_object_mut()
        .expect("object")
        .remove("identity_mappings");
    let claimed = policy_from(claimed);
    let compiled = crate::policy_eval::CompiledPolicy::from_validated_policy(
        claimed,
        crate::policy_eval::PolicyAuthority::Standalone,
    )
    .expect("compiles");
    for (label, principal, _) in principals() {
        assert_eq!(
            compiled.serving_facts(Some(&principal)),
            PolicyFacts::uncaptured(),
            "{label}"
        );
    }
    assert_eq!(compiled.serving_facts(None), PolicyFacts::uncaptured());

    let mapped = crate::policy_eval::CompiledPolicy::from_validated_policy(
        policy_from(mapped_document()),
        crate::policy_eval::PolicyAuthority::Standalone,
    )
    .expect("compiles");
    for (label, principal, _) in principals() {
        assert_eq!(
            mapped.serving_facts(Some(&principal)),
            verified_organization(&principal),
            "{label}"
        );
    }
    // An anonymous caller has no organization, which is a fact, not an
    // unknown.
    let mut anonymous = PolicyFacts::uncaptured();
    anonymous.organization = Fact::Captured(None);
    assert_eq!(mapped.serving_facts(None), anonymous);
}
