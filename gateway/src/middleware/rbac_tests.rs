use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{body::Body, middleware::from_fn_with_state, routing::any, Router};
use http::Request;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::*;
use crate::{
    audit::{sink::tests::CaptureSink, AuditSink},
    auth::{AuthMethod, Principal},
    rbac::{
        policy::{EgressPolicy, PolicyError, RoleEntry, ToolPolicyEntry},
        PrincipalMatcher, Rule, RuleAction,
    },
};

#[test]
fn tool_policy_eligibility_returns_bounded_safe_reasons_without_auditing() {
    let principal = test_principal(&["operator"]);

    let (missing_state, missing_capture) =
        test_state(test_policy(DefaultAction::Deny, &[], &[]), &[]);
    assert_eq!(
        missing_state.tool_policy_eligibility("reports.export", &principal),
        ToolPolicyEligibility {
            eligible: false,
            reason: "not_in_policy",
        }
    );
    assert!(missing_capture.events().is_empty());

    let (disabled_state, disabled_capture) =
        tool_eligibility_state(tool_policy_entry(false, &["operator"], &[], &[]), None);
    assert_eq!(
        disabled_state.tool_policy_eligibility("reports.export", &principal),
        ToolPolicyEligibility {
            eligible: false,
            reason: "policy_disabled",
        }
    );
    assert!(disabled_capture.events().is_empty());

    let (role_state, role_capture) =
        tool_eligibility_state(tool_policy_entry(true, &["admin"], &[], &[]), None);
    assert_eq!(
        role_state.tool_policy_eligibility("reports.export", &principal),
        ToolPolicyEligibility {
            eligible: false,
            reason: "principal_not_eligible",
        }
    );
    assert!(role_capture.events().is_empty());

    let (issuer_state, issuer_capture) = tool_eligibility_state(
        tool_policy_entry(true, &[], &["https://idp.example/"], &[]),
        None,
    );
    assert_eq!(
        issuer_state.tool_policy_eligibility("reports.export", &principal),
        ToolPolicyEligibility {
            eligible: false,
            reason: "principal_not_eligible",
        }
    );
    assert!(issuer_capture.events().is_empty());

    let (auth_method_state, auth_method_capture) =
        tool_eligibility_state(tool_policy_entry(true, &[], &[], &["service_token"]), None);
    assert_eq!(
        auth_method_state.tool_policy_eligibility("reports.export", &principal),
        ToolPolicyEligibility {
            eligible: false,
            reason: "principal_not_eligible",
        }
    );
    assert!(auth_method_capture.events().is_empty());

    let (deny_state, deny_capture) = tool_eligibility_state(
        tool_policy_entry(true, &["operator"], &[], &["bearer_token"]),
        Some(RuleAction::Deny),
    );
    let denied = deny_state.tool_policy_eligibility("reports.export", &principal);
    assert_eq!(
        denied,
        ToolPolicyEligibility {
            eligible: false,
            reason: "policy_denied",
        }
    );
    assert_eq!(
        serde_json::to_value(denied).expect("eligibility should serialize"),
        json!({
            "eligible": false,
            "reason": "policy_denied"
        })
    );
    assert!(deny_capture.events().is_empty());
}

#[test]
fn tool_policy_eligibility_treats_allow_and_shadow_rules_as_eligible() {
    let principal = test_principal(&["operator"]);

    for action in [None, Some(RuleAction::Allow), Some(RuleAction::Shadow)] {
        let (state, capture) = tool_eligibility_state(
            tool_policy_entry(true, &["operator"], &[], &["bearer_token"]),
            action,
        );

        assert_eq!(
            state.tool_policy_eligibility("reports.export", &principal),
            ToolPolicyEligibility {
                eligible: true,
                reason: "eligible",
            }
        );
        assert!(capture.events().is_empty());
    }
}

#[tokio::test]
async fn exempt_path_returns_ok_without_authz_event() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
        ),
        &["/health"],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::GET, "/health"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(capture.events().is_empty());
}

#[tokio::test]
async fn default_probe_exempt_paths_return_ok_without_authz_event() {
    let (state, capture) = test_state(
        test_policy(DefaultAction::Deny, &[], &[]),
        &["/health", "/version", "/metrics"],
    );
    let router = test_router(state, None);

    for path in ["/health", "/version", "/metrics"] {
        let response = router
            .clone()
            .oneshot(request(Method::GET, path))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    assert!(capture.events().is_empty());
}

#[tokio::test]
async fn admin_exempt_path_matches_subpaths_but_not_lookalikes() {
    let (state, capture) = test_state(test_policy(DefaultAction::Deny, &[], &[]), &["/admin"]);
    let router = test_router(state, None);

    let response = router
        .clone()
        .oneshot(request(Method::GET, "/admin/assets/app.js"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(capture.events().is_empty());

    for path in ["/administrator", "/admin-panel"] {
        let response = router
            .clone()
            .oneshot(request(Method::GET, path))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn mcp_alias_under_exempt_prefix_is_not_exempt_from_rbac() {
    let (state, capture) = test_state_with_mcp_route_paths(
        test_policy(
            DefaultAction::Deny,
            &[("mcp-user", &["admin:mcp:use"])],
            &[route(&["POST"], "/mcp", "admin:mcp:use")],
        ),
        &["/admin"],
        &["/mcp", "/admin/mcp"],
    );

    let denied_response = test_router(state.clone(), None)
        .oneshot(request(Method::POST, "/admin/mcp"))
        .await
        .expect("unauthenticated MCP alias request should complete");

    assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);
    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["reason"], json!("missing_principal"));
    assert_eq!(denied.payload["path"], json!("/admin/mcp"));
    assert_eq!(denied.payload["path_prefix"], json!("/mcp"));
    assert_eq!(denied.payload["permission"], json!("admin:mcp:use"));

    let allowed_response = test_router(state, Some(test_principal(&["mcp-user"])))
        .oneshot(request(Method::POST, "/admin/mcp"))
        .await
        .expect("authorized MCP alias request should complete");

    assert_eq!(allowed_response.status(), StatusCode::OK);
    let allowed = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(allowed.payload["path"], json!("/admin/mcp"));
    assert_eq!(allowed.payload["path_prefix"], json!("/mcp"));
    assert_eq!(allowed.payload["permission"], json!("admin:mcp:use"));
}

#[tokio::test]
async fn mcp_alias_subpath_under_exempt_prefix_remains_exempt() {
    let (state, capture) = test_state_with_mcp_route_paths(
        test_policy(DefaultAction::Deny, &[], &[]),
        &["/admin"],
        &["/mcp", "/admin/mcp"],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::GET, "/admin/mcp/assets"))
        .await
        .expect("non-MCP subpath request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(capture.events().is_empty());
}

#[tokio::test]
async fn principal_with_required_permission_is_allowed_and_audited() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(event.payload["path_prefix"], json!("/data"));
    assert_eq!(event.payload["permission"], json!("data:read"));
    assert!(event.actor.is_some());
}

#[tokio::test]
async fn prefixed_mcp_route_does_not_use_broad_public_prefix_permission() {
    let (state, capture) = test_state_with_mcp_route_paths(
        test_policy(
            DefaultAction::Deny,
            &[
                ("base-reader", &["base:read"]),
                ("mcp-user", &["admin:mcp:use"]),
            ],
            &[
                route(&["POST"], "/base", "base:read"),
                route(&["POST"], "/mcp", "admin:mcp:use"),
            ],
        ),
        &[],
        &["/mcp", "/base/mcp"],
    );
    let router = test_router(state.clone(), Some(test_principal(&["base-reader"])));

    let response = router
        .clone()
        .oneshot(request(Method::POST, "/base/mcp"))
        .await
        .expect("prefixed MCP request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["path"], json!("/base/mcp"));
    assert_eq!(denied.payload["path_prefix"], json!("/mcp"));
    assert_eq!(denied.payload["permission"], json!("admin:mcp:use"));

    let allowed_response = test_router(state, Some(test_principal(&["mcp-user"])))
        .oneshot(request(Method::POST, "/base/mcp"))
        .await
        .expect("prefixed MCP request with MCP permission should complete");

    assert_eq!(allowed_response.status(), StatusCode::OK);
    let allowed = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(allowed.payload["path"], json!("/base/mcp"));
    assert_eq!(allowed.payload["path_prefix"], json!("/mcp"));
    assert_eq!(allowed.payload["permission"], json!("admin:mcp:use"));
}

#[tokio::test]
async fn prefixed_mcp_route_canonical_direct_deny_precedes_raw_prefix_allow() {
    let (state, capture) = test_state_with_mcp_route_paths(
        test_policy_with_rules(
            DefaultAction::Allow,
            &[],
            &[],
            &[
                direct_rule(
                    Some("allow-public-prefix"),
                    &["POST"],
                    "/base/**",
                    RuleAction::Allow,
                ),
                direct_rule(
                    Some("deny-canonical-mcp"),
                    &["POST"],
                    "/mcp",
                    RuleAction::Deny,
                ),
            ],
        ),
        &[],
        &["/mcp", "/base/mcp"],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::POST, "/base/mcp"))
        .await
        .expect("prefixed MCP request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Denied);
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("deny-canonical-mcp")
    );

    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["path"], json!("/base/mcp"));
    assert_eq!(
        denied.payload["matched_rule_id"],
        json!("deny-canonical-mcp")
    );
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.payload["matched_rule_id"] == json!("allow-public-prefix")));
}

#[tokio::test]
async fn prefixed_mcp_route_canonical_shadow_precedes_raw_prefix_allow() {
    let (state, capture) = test_state_with_mcp_route_paths(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[],
            &[],
            &[
                direct_rule(
                    Some("allow-public-prefix"),
                    &["POST"],
                    "/base/**",
                    RuleAction::Allow,
                ),
                direct_rule(
                    Some("shadow-canonical-mcp"),
                    &["POST"],
                    "/mcp",
                    RuleAction::Shadow,
                ),
            ],
        ),
        &[],
        &["/mcp", "/base/mcp"],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::POST, "/base/mcp"))
        .await
        .expect("prefixed MCP request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::WouldDeny);
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("shadow-canonical-mcp")
    );

    let shadow = captured_event(&capture, AUTHZ_WOULD_DENY).await;
    assert_eq!(shadow.payload["path"], json!("/base/mcp"));
    assert_eq!(
        shadow.payload["matched_rule_id"],
        json!("shadow-canonical-mcp")
    );
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.payload["matched_rule_id"] == json!("allow-public-prefix")));
}

#[tokio::test]
async fn prefixed_mcp_route_raw_direct_deny_precedes_canonical_allow() {
    let (state, capture) = test_state_with_mcp_route_paths(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[],
            &[],
            &[
                direct_rule(
                    Some("allow-canonical-mcp"),
                    &["POST"],
                    "/mcp",
                    RuleAction::Allow,
                ),
                direct_rule(
                    Some("deny-public-alias"),
                    &["POST"],
                    "/base/**",
                    RuleAction::Deny,
                ),
            ],
        ),
        &[],
        &["/mcp", "/base/mcp"],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::POST, "/base/mcp"))
        .await
        .expect("prefixed MCP request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Denied);
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("deny-public-alias")
    );

    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["path"], json!("/base/mcp"));
    assert_eq!(
        denied.payload["matched_rule_id"],
        json!("deny-public-alias")
    );
}

#[tokio::test]
async fn prefixed_mcp_route_raw_direct_deny_precedes_canonical_shadow() {
    let (state, capture) = test_state_with_mcp_route_paths(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[],
            &[],
            &[
                direct_rule(
                    Some("shadow-canonical-mcp"),
                    &["POST"],
                    "/mcp",
                    RuleAction::Shadow,
                ),
                direct_rule(
                    Some("deny-exact-alias"),
                    &["POST"],
                    "/base/mcp",
                    RuleAction::Deny,
                ),
            ],
        ),
        &[],
        &["/mcp", "/base/mcp"],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::POST, "/base/mcp"))
        .await
        .expect("prefixed MCP request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Denied);
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("deny-exact-alias")
    );

    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["path"], json!("/base/mcp"));
    assert_eq!(denied.payload["matched_rule_id"], json!("deny-exact-alias"));
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.payload["matched_rule_id"] == json!("shadow-canonical-mcp")));
}

#[tokio::test]
async fn prefixed_mcp_route_uses_raw_direct_rule_when_canonical_has_no_match() {
    let (state, capture) = test_state_with_mcp_route_paths(
        test_policy_with_rules(
            DefaultAction::Allow,
            &[],
            &[],
            &[direct_rule(
                Some("deny-exact-alias"),
                &["POST"],
                "/base/mcp",
                RuleAction::Deny,
            )],
        ),
        &[],
        &["/mcp", "/base/mcp"],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::POST, "/base/mcp"))
        .await
        .expect("prefixed MCP request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Denied);
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("deny-exact-alias")
    );

    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["path"], json!("/base/mcp"));
    assert_eq!(denied.payload["matched_rule_id"], json!("deny-exact-alias"));
}

#[tokio::test]
async fn principal_without_required_permission_is_denied_without_leaking_permission() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/admin", "admin:read")],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/admin/settings"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = body_string(response).await;
    assert_eq!(body, r#"{"error":"forbidden"}"#);
    assert!(!body.contains("admin:read"));

    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["reason"], json!("missing_permission"));
    assert_eq!(event.payload["permission"], json!("admin:read"));
    assert_eq!(event.payload["path"], json!("/admin/settings"));
    assert!(event.actor.is_some());
}

#[tokio::test]
async fn admin_wildcard_role_is_allowed_on_any_matched_route() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("admin", &["*"])],
            &[route(&[], "/admin", "admin:write")],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["admin"])))
        .oneshot(request(Method::DELETE, "/admin/settings"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(event.payload["permission"], json!("admin:write"));
}

#[tokio::test]
async fn missing_principal_on_matching_route_fails_closed() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
        ),
        &[],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["reason"], json!("missing_principal"));
    assert!(event.actor.is_none());
}

#[tokio::test]
async fn global_shadow_mode_forwards_matched_rule_denial_and_emits_would_deny() {
    let (state, capture) = test_state(
        test_policy_with_enforcement(
            DefaultAction::Deny,
            EnforcementMode::Shadow,
            &[("reader", &["data:read"])],
            &[route(&[], "/admin", "admin:read")],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/admin/settings"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::WouldDeny);
    assert_eq!(decision.reason, "missing_permission");
    assert_eq!(decision.path_prefix.as_deref(), Some("/admin"));
    assert_eq!(decision.permission.as_deref(), Some("admin:read"));

    let event = captured_event(&capture, AUTHZ_WOULD_DENY).await;
    assert_eq!(event.payload["reason"], json!("missing_permission"));
    assert_eq!(event.payload["path_prefix"], json!("/admin"));
    assert_eq!(event.payload["permission"], json!("admin:read"));
    assert_eq!(event.payload["path"], json!("/admin/settings"));
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == AUTHZ_DENIED));
}

#[tokio::test]
async fn global_shadow_mode_forwards_default_deny_and_emits_would_deny() {
    let (state, capture) = test_state(
        test_policy_with_enforcement(
            DefaultAction::Deny,
            EnforcementMode::Shadow,
            &[("reader", &["data:read"])],
            &[],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::WouldDeny);
    assert_eq!(decision.reason, "default_deny");
    assert!(decision.path_prefix.is_none());
    assert!(decision.permission.is_none());

    let event = captured_event(&capture, AUTHZ_WOULD_DENY).await;
    assert_eq!(event.payload["reason"], json!("default_deny"));
    assert_eq!(event.payload["path"], json!("/unmatched"));
    assert!(event.payload.get("path_prefix").is_none());
    assert!(event.payload.get("permission").is_none());
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == AUTHZ_DENIED));
}

#[tokio::test]
async fn rule_shadow_override_forwards_only_that_rule_when_global_mode_enforces() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[
                route_with_enforcement(
                    &[],
                    "/shadow",
                    "shadow:read",
                    Some(EnforcementMode::Shadow),
                ),
                route(&[], "/strict", "strict:read"),
            ],
        ),
        &[],
    );
    let router = test_router(state, Some(test_principal(&["reader"])));

    let shadow_response = router
        .clone()
        .oneshot(request(Method::GET, "/shadow/item"))
        .await
        .expect("request should complete");
    assert_eq!(shadow_response.status(), StatusCode::OK);
    assert_eq!(
        shadow_response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .outcome,
        PolicyDecisionOutcome::WouldDeny
    );

    let strict_response = router
        .oneshot(request(Method::GET, "/strict/item"))
        .await
        .expect("request should complete");
    assert_eq!(strict_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        strict_response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .outcome,
        PolicyDecisionOutcome::Denied
    );

    let would_deny = captured_event(&capture, AUTHZ_WOULD_DENY).await;
    assert_eq!(would_deny.payload["path_prefix"], json!("/shadow"));
    assert_eq!(would_deny.payload["permission"], json!("shadow:read"));
    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["path_prefix"], json!("/strict"));
    assert_eq!(denied.payload["permission"], json!("strict:read"));
}

#[tokio::test]
async fn rule_enforce_override_blocks_when_global_mode_is_shadow() {
    let (state, capture) = test_state(
        test_policy_with_enforcement(
            DefaultAction::Deny,
            EnforcementMode::Shadow,
            &[("reader", &["data:read"])],
            &[route_with_enforcement(
                &[],
                "/strict",
                "strict:read",
                Some(EnforcementMode::Enforce),
            )],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/strict/item"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .outcome,
        PolicyDecisionOutcome::Denied
    );

    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["path_prefix"], json!("/strict"));
    assert_eq!(event.payload["permission"], json!("strict:read"));
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == AUTHZ_WOULD_DENY));
}

#[tokio::test]
async fn shadow_mode_does_not_change_allowed_matched_rule_path() {
    let (state, capture) = test_state(
        test_policy_with_enforcement(
            DefaultAction::Deny,
            EnforcementMode::Shadow,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .outcome,
        PolicyDecisionOutcome::Allowed
    );
    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(event.payload["path_prefix"], json!("/data"));
    assert_eq!(event.payload["permission"], json!("data:read"));
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == AUTHZ_WOULD_DENY));
}

#[tokio::test]
async fn direct_allow_rule_takes_precedence_over_route_and_default_deny() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/direct", "admin:read")],
            &[direct_rule(
                Some("allow-public-direct"),
                &["GET"],
                "/direct/**",
                RuleAction::Allow,
            )],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/direct/report"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Allowed);
    assert_eq!(decision.reason, "matched_rule");
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("allow-public-direct")
    );
    assert!(decision.permission.is_none());
    assert!(decision.path_prefix.is_none());

    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(
        event.payload["matched_rule_id"],
        json!("allow-public-direct")
    );
    assert_eq!(event.payload["reason"], json!("matched_rule"));
    assert!(event.payload.get("permission").is_none());
    assert!(event.payload.get("path_prefix").is_none());
}

#[tokio::test]
async fn direct_deny_rule_takes_precedence_over_route_allow() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
            &[direct_rule(
                Some("deny-data-direct"),
                &["GET"],
                "/data/**",
                RuleAction::Deny,
            )],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/report"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Denied);
    assert_eq!(decision.reason, "matched_rule");
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("deny-data-direct")
    );
    assert!(decision.permission.is_none());
    assert!(decision.path_prefix.is_none());

    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["matched_rule_id"], json!("deny-data-direct"));
    assert_eq!(event.payload["reason"], json!("matched_rule"));
    assert!(event.payload.get("permission").is_none());
    assert!(event.payload.get("path_prefix").is_none());
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == AUTHZ_ALLOWED));
}

#[tokio::test]
async fn direct_shadow_rule_emits_would_deny_and_forwards() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[],
            &[],
            &[direct_rule(
                Some("shadow-admin-direct"),
                &["GET"],
                "/admin/**",
                RuleAction::Shadow,
            )],
        ),
        &[],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::GET, "/admin/report"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::WouldDeny);
    assert_eq!(decision.reason, "matched_rule");
    assert_eq!(
        decision.matched_rule_id.as_deref(),
        Some("shadow-admin-direct")
    );

    let event = captured_event(&capture, AUTHZ_WOULD_DENY).await;
    assert_eq!(
        event.payload["matched_rule_id"],
        json!("shadow-admin-direct")
    );
    assert_eq!(event.payload["reason"], json!("matched_rule"));
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == AUTHZ_DENIED));
}

#[tokio::test]
async fn first_matching_direct_rule_wins_and_records_only_first_id() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[],
            &[],
            &[
                direct_rule(
                    Some("first-shadow"),
                    &["GET"],
                    "/admin/**",
                    RuleAction::Shadow,
                ),
                direct_rule(Some("second-deny"), &["GET"], "/admin/**", RuleAction::Deny),
            ],
        ),
        &[],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::GET, "/admin/settings"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::WouldDeny);
    assert_eq!(decision.matched_rule_id.as_deref(), Some("first-shadow"));

    let event = captured_event(&capture, AUTHZ_WOULD_DENY).await;
    assert_eq!(event.payload["matched_rule_id"], json!("first-shadow"));
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.payload["matched_rule_id"] == json!("second-deny")));
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == AUTHZ_DENIED));
}

#[tokio::test]
async fn direct_rule_without_id_records_index_fallback() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[],
            &[],
            &[direct_rule(None, &["GET"], "/public/**", RuleAction::Allow)],
        ),
        &[],
    );

    let response = test_router(state, None)
        .oneshot(request(Method::GET, "/public/status"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.matched_rule_id.as_deref(), Some("0"));

    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(event.payload["matched_rule_id"], json!("0"));
}

#[tokio::test]
async fn unmatched_direct_rules_fall_through_to_routes_and_default_action() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
            &[direct_rule(
                Some("admin-only-direct"),
                &["GET"],
                "/admin/**",
                RuleAction::Deny,
            )],
        ),
        &[],
    );
    let router = test_router(state, Some(test_principal(&["reader"])));

    let route_response = router
        .clone()
        .oneshot(request(Method::GET, "/data/report"))
        .await
        .expect("route request should complete");
    assert_eq!(route_response.status(), StatusCode::OK);
    let route_decision = route_response
        .extensions()
        .get::<PolicyDecision>()
        .expect("route policy decision should be attached");
    assert_eq!(route_decision.outcome, PolicyDecisionOutcome::Allowed);
    assert_eq!(route_decision.permission.as_deref(), Some("data:read"));
    assert_eq!(route_decision.path_prefix.as_deref(), Some("/data"));
    assert!(route_decision.matched_rule_id.is_none());

    let default_response = router
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("default request should complete");
    assert_eq!(default_response.status(), StatusCode::FORBIDDEN);
    let default_decision = default_response
        .extensions()
        .get::<PolicyDecision>()
        .expect("default policy decision should be attached");
    assert_eq!(default_decision.reason, "default_deny");
    assert!(default_decision.permission.is_none());
    assert!(default_decision.path_prefix.is_none());
    assert!(default_decision.matched_rule_id.is_none());

    let allowed = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(allowed.payload["permission"], json!("data:read"));
    assert!(allowed.payload.get("matched_rule_id").is_none());
    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["reason"], json!("default_deny"));
    assert!(denied.payload.get("matched_rule_id").is_none());
}

#[tokio::test]
async fn same_path_on_different_upstream_hosts_uses_host_bound_permissions() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"]), ("admin", &["admin:read"])],
            &[
                host_route(&["GET"], &["admin.example.test"], "/data", "admin:read"),
                route(&["GET"], "/data", "data:read"),
            ],
        ),
        &[],
    );
    let denied = test_router(state.clone(), Some(test_principal(&["reader"])))
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "admin.example.test:443",
        ))
        .await
        .expect("host-qualified request should complete");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied_decision = denied
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(denied_decision.reason, "missing_permission");
    assert_eq!(denied_decision.permission.as_deref(), Some("admin:read"));

    let host_allowed = test_router(state.clone(), Some(test_principal(&["admin"])))
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "ADMIN.EXAMPLE.TEST",
        ))
        .await
        .expect("authorized host-qualified request should complete");
    assert_eq!(host_allowed.status(), StatusCode::OK);
    assert_eq!(
        host_allowed
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .permission
            .as_deref(),
        Some("admin:read")
    );

    let allowed = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request_with_host(
            Method::GET,
            "/data/report",
            "public.example.test",
        ))
        .await
        .expect("path-only upstream request should complete");
    assert_eq!(allowed.status(), StatusCode::OK);
    let allowed_decision = allowed
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(allowed_decision.permission.as_deref(), Some("data:read"));

    assert_eq!(
        captured_event(&capture, AUTHZ_DENIED).await.payload["permission"],
        json!("admin:read")
    );
    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        ["admin:read", "data:read"].iter().all(|permission| {
            events.iter().any(|event| {
                event.event_type == AUTHZ_ALLOWED
                    && event.payload["permission"] == json!(permission)
            })
        })
    });
    let events = capture.events();
    assert!(events.iter().any(|event| {
        event.event_type == AUTHZ_ALLOWED && event.payload["permission"] == json!("admin:read")
    }));
    assert!(events.iter().any(|event| {
        event.event_type == AUTHZ_ALLOWED && event.payload["permission"] == json!("data:read")
    }));
}

#[tokio::test]
async fn host_qualified_proxy_binding_applies_on_rbac_exempt_path() {
    let (state, capture) = test_state(test_policy(DefaultAction::Allow, &[], &[]), &["/data"]);

    let response = test_router(state, None)
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "admin.example.test",
        ))
        .await
        .expect("host-qualified exempt request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.reason, "host_policy_required");
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["reason"], json!("host_policy_required"));
    assert_eq!(event.payload["upstream_host"], json!("admin.example.test"));
    assert_eq!(
        event.payload["upstream_origin"],
        json!("https://upstream.example.test")
    );
}

#[tokio::test]
async fn direct_shadow_keeps_telemetry_before_host_bound_route_allows() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[("admin", &["admin:read"])],
            &[host_route(
                &["GET"],
                &["admin.example.test"],
                "/data",
                "admin:read",
            )],
            &[direct_rule(
                Some("shadow-data"),
                &["GET"],
                "/data/**",
                RuleAction::Shadow,
            )],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["admin"])))
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "admin.example.test",
        ))
        .await
        .expect("host-qualified shadow request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Allowed);
    assert_eq!(decision.permission.as_deref(), Some("admin:read"));
    let shadow = captured_event(&capture, AUTHZ_WOULD_DENY).await;
    assert_eq!(shadow.payload["matched_rule_id"], json!("shadow-data"));
    let allowed = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(allowed.payload["permission"], json!("admin:read"));
}

#[tokio::test]
async fn direct_shadow_keeps_telemetry_when_later_deny_blocks_host_route() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Deny,
            &[("admin", &["admin:read"])],
            &[host_route(
                &["GET"],
                &["admin.example.test"],
                "/data",
                "admin:read",
            )],
            &[
                direct_rule(
                    Some("shadow-data"),
                    &["GET"],
                    "/data/**",
                    RuleAction::Shadow,
                ),
                direct_rule(Some("deny-data"), &["GET"], "/data/**", RuleAction::Deny),
            ],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["admin"])))
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "admin.example.test",
        ))
        .await
        .expect("host-qualified shadow request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.outcome, PolicyDecisionOutcome::Denied);
    assert_eq!(decision.matched_rule_id.as_deref(), Some("deny-data"));
    let shadow = captured_event(&capture, AUTHZ_WOULD_DENY).await;
    assert_eq!(shadow.payload["matched_rule_id"], json!("shadow-data"));
    let denied = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(denied.payload["matched_rule_id"], json!("deny-data"));
}

#[tokio::test]
async fn policy_reload_adds_and_removes_live_host_bindings() {
    let host_policy = test_policy(
        DefaultAction::Deny,
        &[("admin", &["admin:read"])],
        &[host_route(
            &["GET"],
            &["admin.example.test"],
            "/data",
            "admin:read",
        )],
    );
    let policy_file = TempPolicyFile::new(
        &serde_json::to_string(&host_policy).expect("host policy should serialize"),
    );
    let (state, _capture) = test_state(host_policy.clone(), &[]);
    let router = test_router(state.clone(), Some(test_principal(&["admin"])));

    let allowed = router
        .clone()
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "admin.example.test",
        ))
        .await
        .expect("initial host-bound request should complete");
    assert_eq!(allowed.status(), StatusCode::OK);

    let unbound_policy = test_policy(
        DefaultAction::Allow,
        &[("admin", &["admin:read"])],
        &[route(&["GET"], "/data", "admin:read")],
    );
    policy_file
        .write(&serde_json::to_string(&unbound_policy).expect("unbound policy should serialize"));
    reload_policy_from_file(&state, policy_file.path())
        .await
        .expect("removing the host binding should reload");
    let denied = router
        .clone()
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "admin.example.test",
        ))
        .await
        .expect("request after removing host binding should complete");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        denied
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .reason,
        "host_policy_required"
    );

    policy_file.write(&serde_json::to_string(&host_policy).expect("host policy should serialize"));
    reload_policy_from_file(&state, policy_file.path())
        .await
        .expect("restoring the host binding should reload");
    let restored = router
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "admin.example.test",
        ))
        .await
        .expect("request after restoring host binding should complete");
    assert_eq!(restored.status(), StatusCode::OK);
}

#[tokio::test]
async fn broad_allow_and_default_allow_cannot_authorize_host_qualified_upstream() {
    for action in [RuleAction::Allow, RuleAction::Shadow] {
        let (state, capture) = test_state(
            test_policy_with_rules(
                DefaultAction::Allow,
                &[],
                &[],
                &[direct_rule(Some("broad-rule"), &["GET"], "/**", action)],
            ),
            &[],
        );
        let response = test_router(state, None)
            .oneshot(proxy_request(
                Method::GET,
                "/data/report",
                "admin.example.test",
            ))
            .await
            .expect("host-qualified request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let decision = response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached");
        assert_eq!(decision.reason, "host_policy_required");
        assert!(decision.matched_rule_id.is_none());
        let event = captured_event(&capture, AUTHZ_DENIED).await;
        assert_eq!(event.payload["reason"], json!("host_policy_required"));
    }
}

#[tokio::test]
async fn direct_deny_still_applies_to_host_qualified_upstream() {
    let (state, capture) = test_state(
        test_policy_with_rules(
            DefaultAction::Allow,
            &[],
            &[],
            &[
                direct_rule(Some("broad-allow"), &["GET"], "/**", RuleAction::Allow),
                direct_rule(
                    Some("deny-admin-host"),
                    &["GET"],
                    "/data/**",
                    RuleAction::Deny,
                ),
            ],
        ),
        &[],
    );
    let response = test_router(state, None)
        .oneshot(proxy_request(
            Method::GET,
            "/data/report",
            "admin.example.test",
        ))
        .await
        .expect("host-qualified request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("policy decision should be attached");
    assert_eq!(decision.reason, "matched_rule");
    assert_eq!(decision.matched_rule_id.as_deref(), Some("deny-admin-host"));
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["matched_rule_id"], json!("deny-admin-host"));
}

#[tokio::test]
async fn absent_and_empty_rules_lists_have_identical_route_behavior() {
    let absent_file = TempPolicyFile::new(&route_policy_document_without_rules());
    let empty_file = TempPolicyFile::new(&route_policy_document_with_empty_rules());
    let absent_policy =
        Policy::from_file(absent_file.path()).expect("absent-rules policy should parse");
    let empty_policy =
        Policy::from_file(empty_file.path()).expect("empty-rules policy should parse");

    let absent_route = behavior_snapshot(absent_policy.clone(), "/data/report").await;
    let empty_route = behavior_snapshot(empty_policy.clone(), "/data/report").await;
    let absent_default = behavior_snapshot(absent_policy, "/unmatched").await;
    let empty_default = behavior_snapshot(empty_policy, "/unmatched").await;

    assert_eq!(empty_route, absent_route);
    assert_eq!(empty_default, absent_default);
    assert!(absent_route.decision.matched_rule_id.is_none());
    assert!(absent_route.event_payload.get("matched_rule_id").is_none());
    assert!(absent_default.decision.matched_rule_id.is_none());
    assert!(absent_default
        .event_payload
        .get("matched_rule_id")
        .is_none());
}

#[test]
fn route_prefix_matches_only_at_segment_boundary() {
    let routes = vec![
        route(&[], "/data", "data:read"),
        route(&[], "/database", "database:read"),
        route(&[], "/data-export", "data:export"),
    ];

    let rule = matching_route(&routes, &Method::GET, "/data").expect("rule should match");
    assert_eq!(rule.path_prefix, "/data");

    let rule = matching_route(&routes, &Method::GET, "/data/report").expect("rule should match");
    assert_eq!(rule.path_prefix, "/data");

    let rule = matching_route(&routes, &Method::GET, "/database").expect("rule should match");
    assert_eq!(rule.path_prefix, "/database");

    let rule = matching_route(&routes, &Method::GET, "/data-export").expect("rule should match");
    assert_eq!(rule.path_prefix, "/data-export");
}

#[tokio::test]
async fn unsafe_paths_fail_closed_with_unsafe_path_reason() {
    for path in ["/data/../admin", "/data/..\\admin", "/%61dmin", "/a/./b"] {
        let (state, capture) = test_state(
            test_policy(
                DefaultAction::Allow,
                &[("reader", &["data:read"])],
                &[route(&[], "/data", "data:read")],
            ),
            &[],
        );

        let response = test_router(state, Some(test_principal(&["reader"])))
            .oneshot(request(Method::GET, path))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let event = captured_event(&capture, AUTHZ_DENIED).await;
        assert_eq!(event.payload["reason"], json!("unsafe_path"));
        assert_eq!(event.payload["path"], json!(path));
    }
}

#[tokio::test]
async fn safe_paths_continue_to_normal_rule_evaluation() {
    let (state, capture) = test_state(test_policy(DefaultAction::Deny, &[], &[]), &[]);

    let response = test_router(state, None)
        .oneshot(request(Method::GET, "/file.json"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["reason"], json!("default_deny"));
    assert_eq!(event.payload["path"], json!("/file.json"));

    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/report"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(event.payload["path_prefix"], json!("/data"));
    assert_eq!(event.payload["path"], json!("/data/report"));
}

#[tokio::test]
async fn unmatched_route_with_default_deny_is_denied_and_audited() {
    let (state, capture) = test_state(
        test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["reason"], json!("default_deny"));
    assert_eq!(event.payload["path"], json!("/unmatched"));
}

#[tokio::test]
async fn unmatched_route_with_default_allow_is_allowed_and_audited() {
    let (state, capture) = test_state(test_policy(DefaultAction::Allow, &[], &[]), &[]);

    let response = test_router(state, None)
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(event.payload["reason"], json!("default_allow"));
    assert_eq!(event.payload["default_allow"], json!(true));
    assert_eq!(event.payload["path"], json!("/unmatched"));
    assert!(event.actor.is_none());
}

#[tokio::test]
async fn invalid_policy_reload_is_rejected_and_old_policy_still_serves() {
    let file = TempPolicyFile::new(&default_policy_document("allow"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);
    let router = test_router(state.clone(), None);

    let response = router
        .clone()
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete before reload");
    assert_eq!(response.status(), StatusCode::OK);

    file.write(r#"{ "schema_version": "#);
    let error = reload_policy_from_file(&state, file.path())
        .await
        .expect_err("invalid policy reload should be rejected");

    assert!(
        error.to_string().contains("failed to parse policy file"),
        "unexpected reload error: {error}"
    );

    let response = router
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete after rejected reload");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .reason,
        "default_allow"
    );
}

#[tokio::test]
async fn policy_reload_waits_for_the_policy_write_guard() {
    let file = TempPolicyFile::new(&default_policy_document("deny"));
    let initial = Policy::from_file(file.path()).expect("initial policy should parse");
    let (state, _capture) = test_state(initial, &[]);
    file.write(&default_policy_document("allow"));

    let guard = state.policy_write_guard().await;
    let reload_state = state.clone();
    let reload_path = file.path().to_owned();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let reload = tokio::spawn(async move {
        let _ = started_tx.send(());
        reload_policy_from_file(&reload_state, reload_path).await
    });

    started_rx.await.expect("reload task should start");
    tokio::task::yield_now().await;
    assert!(
        !reload.is_finished(),
        "reload must wait while another policy writer owns the lane"
    );
    assert_eq!(state.current_policy().default_action, DefaultAction::Deny);

    drop(guard);
    tokio::time::timeout(Duration::from_secs(1), reload)
        .await
        .expect("reload should finish after the guard is released")
        .expect("reload task should join")
        .expect("valid policy reload should succeed");
    assert_eq!(state.current_policy().default_action, DefaultAction::Allow);
}

#[test]
fn current_egress_policy_reflects_live_policy() {
    let file = TempPolicyFile::new(&egress_policy_document("deny", "initial.example.test"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);

    assert_eq!(
        state.current_egress_policy(),
        EgressPolicy {
            hosts: vec!["initial.example.test".to_owned()],
            ..EgressPolicy::default()
        }
    );
}

#[tokio::test]
async fn reload_rejected_when_egress_section_changes() {
    let file = TempPolicyFile::new(&egress_policy_document("deny", "initial.example.test"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);

    file.write(&egress_policy_document("allow", "replacement.example.test"));
    let error = reload_policy_from_file(&state, file.path())
        .await
        .expect_err("egress-changing reload should be rejected");

    assert!(matches!(error, PolicyError::EgressReloadRejected));
    assert!(error.to_string().contains("restart"));
    assert_eq!(state.current_policy().default_action, DefaultAction::Deny);
    assert_eq!(
        state.current_egress_policy().hosts,
        vec!["initial.example.test".to_owned()]
    );
}

#[tokio::test]
async fn reload_accepted_when_egress_section_is_unchanged() {
    let file = TempPolicyFile::new(&egress_policy_document("deny", "unchanged.example.test"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);

    file.write(&egress_policy_document("allow", "unchanged.example.test"));
    reload_policy_from_file(&state, file.path())
        .await
        .expect("RBAC-only reload should be accepted when egress is unchanged");

    assert_eq!(state.current_policy().default_action, DefaultAction::Allow);
    assert_eq!(
        state.current_egress_policy().hosts,
        vec!["unchanged.example.test".to_owned()]
    );
}

#[tokio::test]
async fn reload_accepted_when_both_policies_have_empty_egress() {
    let file = TempPolicyFile::new(&default_policy_document("deny"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);

    file.write(&default_policy_document("allow"));
    reload_policy_from_file(&state, file.path())
        .await
        .expect("RBAC-only reload should be accepted for empty egress policies");

    assert_eq!(state.current_policy().default_action, DefaultAction::Allow);
    assert_eq!(state.current_egress_policy(), EgressPolicy::default());
}

#[tokio::test]
async fn valid_policy_reload_updates_default_action() {
    let file = TempPolicyFile::new(&default_policy_document("deny"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);
    let router = test_router(state.clone(), None);

    let response = router
        .clone()
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete before reload");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    file.write(&default_policy_document("allow"));
    reload_policy_from_file(&state, file.path())
        .await
        .expect("valid policy reload should succeed");

    let response = router
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete after reload");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .reason,
        "default_allow"
    );
}

#[tokio::test]
async fn valid_policy_reload_swaps_routes_and_engine_together() {
    let file = TempPolicyFile::new(&swap_policy_document("old:read"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);
    let router = test_router(state.clone(), Some(test_principal(&["user"])));

    let response = router
        .clone()
        .oneshot(request(Method::GET, "/swap/item"))
        .await
        .expect("request should complete before reload");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .permission
            .as_deref(),
        Some("old:read")
    );

    file.write(&swap_policy_document("new:read"));
    reload_policy_from_file(&state, file.path())
        .await
        .expect("valid policy reload should succeed");

    let response = router
        .oneshot(request(Method::GET, "/swap/item"))
        .await
        .expect("request should complete after reload");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .permission
            .as_deref(),
        Some("new:read")
    );
}

#[tokio::test]
async fn valid_policy_reload_swaps_direct_rule_matcher_together() {
    let file = TempPolicyFile::new(&direct_rule_policy_document("old-deny", "deny"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);
    let router = test_router(state.clone(), None);

    let response = router
        .clone()
        .oneshot(request(Method::GET, "/swap/item"))
        .await
        .expect("request should complete before reload");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .matched_rule_id
            .as_deref(),
        Some("old-deny")
    );

    file.write(&direct_rule_policy_document("new-allow", "allow"));
    reload_policy_from_file(&state, file.path())
        .await
        .expect("valid policy reload should succeed");

    let response = router
        .oneshot(request(Method::GET, "/swap/item"))
        .await
        .expect("request should complete after reload");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .matched_rule_id
            .as_deref(),
        Some("new-allow")
    );
}

#[tokio::test]
async fn file_watch_reload_applies_valid_policy_update() {
    let file = TempPolicyFile::new(&default_policy_document("deny"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);
    spawn_policy_reload_tasks(file.path().to_owned(), state.clone())
        .expect("policy file watcher should start");
    let router = test_router(state, None);

    let response = router
        .clone()
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete before reload");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    file.write(&default_policy_document("allow"));
    wait_for_status(router, "/unmatched", StatusCode::OK).await;
}

#[tokio::test]
async fn file_watch_reload_applies_policy_persisted_atomically() {
    let file = TempPolicyFile::new(&default_policy_document("deny"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);
    spawn_policy_reload_tasks(file.path().to_owned(), state.clone())
        .expect("policy file watcher should start");
    let router = test_router(state, None);

    let response = router
        .clone()
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete before persisted reload");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let persisted_policy = test_policy(DefaultAction::Allow, &[], &[]);
    persisted_policy
        .persist_to_file(file.path())
        .expect("policy should persist atomically");

    wait_for_status(router, "/unmatched", StatusCode::OK).await;
}

#[tokio::test]
async fn file_watch_invalid_update_keeps_old_policy_and_accepts_later_valid_update() {
    let file = TempPolicyFile::new(&default_policy_document("allow"));
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);
    spawn_policy_reload_tasks(file.path().to_owned(), state.clone())
        .expect("policy file watcher should start");
    let router = test_router(state, None);

    file.write(r#"{ "schema_version": "#);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let response = router
        .clone()
        .oneshot(request(Method::GET, "/unmatched"))
        .await
        .expect("request should complete after rejected watched reload");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<PolicyDecision>()
            .expect("policy decision should be attached")
            .reason,
        "default_allow"
    );

    file.write(&default_policy_document("deny"));
    wait_for_status(router, "/unmatched", StatusCode::FORBIDDEN).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_complete_during_policy_swaps() {
    let old_policy = swap_policy_document("old:read");
    let new_policy = swap_policy_document("new:read");
    let file = TempPolicyFile::new(&old_policy);
    let initial_policy =
        Policy::from_file(file.path()).expect("initial policy should parse before test");
    let (state, _capture) = test_state(initial_policy, &[]);
    let router = test_router(state.clone(), Some(test_principal(&["user"])));

    let reload_state = state.clone();
    let reload_path = file.path().to_owned();
    let reload_task = tokio::spawn(async move {
        for iteration in 0..100 {
            let policy = if iteration % 2 == 0 {
                &new_policy
            } else {
                &old_policy
            };
            fs::write(&reload_path, policy)
                .unwrap_or_else(|err| panic!("failed to write reload policy: {err}"));
            reload_policy_from_file(&reload_state, &reload_path)
                .await
                .expect("valid reload policy should be accepted");
            tokio::task::yield_now().await;
        }
    });

    let mut request_tasks = Vec::new();
    for _ in 0..500 {
        let router = router.clone();
        request_tasks.push(tokio::spawn(async move {
            let response = tokio::time::timeout(
                Duration::from_secs(5),
                router.oneshot(request(Method::GET, "/swap/item")),
            )
            .await
            .expect("request should not hang")
            .expect("request should complete");
            let status = response.status();
            let decision = response
                .extensions()
                .get::<PolicyDecision>()
                .cloned()
                .expect("policy decision should be attached");
            (status, decision)
        }));
    }

    let mut old_decisions = 0;
    let mut new_decisions = 0;
    for task in request_tasks {
        let (status, decision) = task.await.expect("request task should join");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(decision.outcome, PolicyDecisionOutcome::Allowed);
        assert_eq!(decision.reason, "matched_rule");
        assert_eq!(decision.path_prefix.as_deref(), Some("/swap"));
        match decision.permission.as_deref() {
            Some("old:read") => old_decisions += 1,
            Some("new:read") => new_decisions += 1,
            other => panic!("unexpected permission decision: {other:?}"),
        }
    }

    reload_task.await.expect("reload task should join");
    assert_eq!(old_decisions + new_decisions, 500);
}

#[tokio::test]
async fn first_matching_route_rule_wins() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[
                route(&[], "/admin", "admin:read"),
                route(&[], "/admin/reports", "data:read"),
            ],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/admin/reports"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["path_prefix"], json!("/admin"));
    assert_eq!(event.payload["permission"], json!("admin:read"));
}

#[tokio::test]
async fn method_specific_rule_does_not_match_other_methods() {
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("writer", &["data:write"])],
            &[route(&["POST"], "/data", "data:write")],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["writer"])))
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["reason"], json!("default_deny"));
    assert!(event.payload.get("permission").is_none());
}

fn test_router(state: RbacState, principal: Option<Principal>) -> Router {
    async fn ok() -> &'static str {
        "ok"
    }

    Router::new()
        .fallback(any(ok))
        .layer(from_fn_with_state(state, rbac_middleware))
        .layer(from_fn_with_state(principal, inject_principal))
}

/// A deterministic revision gate for the middleware's cluster-mode
/// behavior tests: no database, just the outcome under test.
#[cfg(feature = "postgres")]
struct MockRevisionGate(Result<i64, SecurityRevisionCheckError>);

#[cfg(feature = "postgres")]
#[async_trait]
impl SecurityRevisionGate for MockRevisionGate {
    async fn ensure_current_revision(&self) -> Result<i64, SecurityRevisionCheckError> {
        self.0
    }
}

#[cfg(feature = "postgres")]
async fn gated_state(
    policy: Policy,
    revision: i64,
    gate: Result<i64, SecurityRevisionCheckError>,
) -> (RbacState, Arc<crate::audit::sink::tests::CaptureSink>) {
    let (state, capture) = test_state(policy.clone(), &[]);
    state.install_revision_snapshot(policy, revision).await;
    (
        state.with_revision_gate(Arc::new(MockRevisionGate(gate))),
        Arc::new(capture),
    )
}

/// A gate that publishes bundles: admits at the bundle's revision and
/// hands the bundle out, exactly as the cluster runtime does.
#[cfg(feature = "postgres")]
struct BundleGate(Arc<crate::security_cluster::SecurityBundle>);

#[cfg(feature = "postgres")]
#[async_trait]
impl SecurityRevisionGate for BundleGate {
    async fn ensure_current_revision(&self) -> Result<i64, SecurityRevisionCheckError> {
        Ok(self.0.revision)
    }

    async fn admit(&self) -> Result<Admission, SecurityRevisionCheckError> {
        Ok(Admission {
            revision: self.0.revision,
            bundle: Some(Arc::clone(&self.0)),
        })
    }
}

#[cfg(feature = "postgres")]
fn bundle_with_policy(
    policy: Policy,
    revision: i64,
) -> Arc<crate::security_cluster::SecurityBundle> {
    let registry = crate::tools::definitions::ToolRegistry::from_config(
        &crate::config::Config::test_defaults(),
    )
    .expect("an empty registry");
    Arc::new(crate::security_cluster::SecurityBundle {
        revision,
        policy: Arc::new(RbacPolicyState::from_policy(policy)),
        tools: registry.state_handle().load_full(),
        connections: Arc::new(
            crate::connections::control_plane::ConnectionRuntimeSnapshot::empty_for_test(),
        ),
    })
}

/// An admitted request is judged by the policy in the bundle the gate
/// published at its watermark, never by the live lane -- which a
/// concurrent reconcile may have swapped since admission.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn an_admitted_request_is_judged_by_the_bundles_policy_not_the_live_lane() {
    let allowing = test_policy(
        DefaultAction::Deny,
        &[("reader", &["data:read"])],
        &[route(&[], "/data", "data:read")],
    );
    let denying = test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]);

    // The live lane denies (swapped after admission); the bundle allows.
    let (state, _capture) = test_state(denying.clone(), &[]);
    state.install_revision_snapshot(denying.clone(), 7).await;
    let state = state.with_revision_gate(Arc::new(BundleGate(bundle_with_policy(
        allowing.clone(),
        7,
    ))));
    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the bundle's policy authorizes the admitted request"
    );

    // The inverse: the live lane allows, the bundle denies.
    let (state, _capture) = test_state(allowing.clone(), &[]);
    state.install_revision_snapshot(allowing, 7).await;
    let state = state.with_revision_gate(Arc::new(BundleGate(bundle_with_policy(denying, 7))));
    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the bundle's policy denies even though the live lane would allow"
    );
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn revision_gate_failure_returns_503_with_zero_upstream_and_a_distinct_audit_event() {
    // The gate failing is a dependency state, not a policy decision:
    // the response is 503 (never 401/403), the upstream handler is
    // never reached, and the audit trail records a dedicated
    // revision-check event rather than laundering the failure into an
    // authz denial.
    let (state, capture) = gated_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
        ),
        4,
        Err(SecurityRevisionCheckError::Unavailable),
    )
    .await;

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("body should read");
    assert_ne!(
        body.as_ref(),
        b"ok",
        "a request the gate refused must never reach the upstream handler"
    );
    let event = captured_event(&capture, AUTHZ_REVISION_CHECK_FAILED).await;
    assert_eq!(
        event.payload["reason"],
        json!("security_revision_unavailable")
    );
    assert_eq!(event.payload["outcome"], json!("service_unavailable"));
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn revision_gate_success_allows_the_request_and_records_the_served_revision() {
    let policy = test_policy(
        DefaultAction::Deny,
        &[("reader", &["data:read"])],
        &[route(&[], "/data", "data:read")],
    );
    let (state, capture) = gated_state(policy, 6, Ok(6)).await;

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert_eq!(
        event.payload["security_revision"],
        json!(6),
        "the audit event must record the revision the request served under"
    );
}

#[tokio::test]
async fn audit_payloads_omit_the_revision_in_standalone_mode() {
    // No gate, no revision: the standalone audit shape is unchanged.
    let (state, capture) = test_state(
        test_policy(
            DefaultAction::Deny,
            &[("reader", &["data:read"])],
            &[route(&[], "/data", "data:read")],
        ),
        &[],
    );

    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, "/data/items"))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let event = captured_event(&capture, AUTHZ_ALLOWED).await;
    assert!(event.payload.get("security_revision").is_none());
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn install_revision_snapshot_never_regresses_the_compiled_state() {
    let (state, _capture) = test_state(
        test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
        &[],
    );
    state
        .install_revision_snapshot(
            test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
            5,
        )
        .await;
    assert_eq!(state.snapshot_security_revision(), 5);
    // A stale reconciler delivering an older revision must not
    // overwrite a newer compiled snapshot.
    state
        .install_revision_snapshot(
            test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
            3,
        )
        .await;
    assert_eq!(state.snapshot_security_revision(), 5);
    state
        .install_revision_snapshot(
            test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
            9,
        )
        .await;
    assert_eq!(state.snapshot_security_revision(), 9);
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn revision_snapshot_install_waits_for_the_policy_write_guard() {
    let (state, _capture) = test_state(
        test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
        &[],
    );
    let guard = state.policy_write_guard().await;
    let install_state = state.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let install = tokio::spawn(async move {
        let _ = started_tx.send(());
        install_state
            .install_revision_snapshot(
                test_policy(DefaultAction::Allow, &[("reader", &["data:read"])], &[]),
                7,
            )
            .await;
    });

    started_rx.await.expect("install task should start");
    tokio::task::yield_now().await;
    assert!(
        !install.is_finished(),
        "cluster install must wait while another policy writer owns the lane"
    );
    assert_eq!(state.snapshot_security_revision(), 0);
    assert_eq!(state.current_policy().default_action, DefaultAction::Deny);

    drop(guard);
    tokio::time::timeout(Duration::from_secs(1), install)
        .await
        .expect("install should finish after the guard is released")
        .expect("install task should join");
    assert_eq!(state.snapshot_security_revision(), 7);
    assert_eq!(state.current_policy().default_action, DefaultAction::Allow);
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn concurrent_snapshot_installs_converge_on_the_higher_revision() {
    let (state, _capture) = test_state(
        test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
        &[],
    );
    let low = state.clone();
    let high = state.clone();
    let (low, high) = tokio::join!(
        tokio::spawn(async move {
            low.install_revision_snapshot(
                test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
                7,
            )
            .await;
        }),
        tokio::spawn(async move {
            high.install_revision_snapshot(
                test_policy(DefaultAction::Deny, &[("reader", &["data:read"])], &[]),
                8,
            )
            .await;
        })
    );
    low.expect("low install should join");
    high.expect("high install should join");
    assert_eq!(state.snapshot_security_revision(), 8);
}

async fn inject_principal(
    State(principal): State<Option<Principal>>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if let Some(principal) = principal {
        req.extensions_mut().insert(principal);
    }

    next.run(req).await
}

#[derive(Debug, PartialEq, Eq)]
struct BehaviorSnapshot {
    status: StatusCode,
    body: String,
    decision: PolicyDecision,
    event_type: String,
    event_payload: Value,
}

async fn behavior_snapshot(policy: Policy, path: &str) -> BehaviorSnapshot {
    let (state, capture) = test_state(policy, &[]);
    let response = test_router(state, Some(test_principal(&["reader"])))
        .oneshot(request(Method::GET, path))
        .await
        .expect("request should complete");
    let status = response.status();
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .cloned()
        .expect("policy decision should be attached");
    let body = body_string(response).await;
    let event_type = if status == StatusCode::OK {
        AUTHZ_ALLOWED
    } else {
        AUTHZ_DENIED
    };
    let event = captured_event(&capture, event_type).await;

    BehaviorSnapshot {
        status,
        body,
        decision,
        event_type: event.event_type,
        event_payload: event.payload,
    }
}

fn test_state(policy: Policy, exempt_paths: &[&str]) -> (RbacState, CaptureSink) {
    test_state_with_mcp_route_paths(
        policy,
        exempt_paths,
        &[protected_resource::MCP_RESOURCE_PATH],
    )
}

fn test_state_with_mcp_route_paths(
    policy: Policy,
    exempt_paths: &[&str],
    mcp_route_paths: &[&str],
) -> (RbacState, CaptureSink) {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);

    (
        RbacState::new_with_mcp_route_paths(
            policy,
            exempt_paths.iter().map(|path| (*path).to_owned()).collect(),
            ClientIpPolicy::default(),
            audit,
            mcp_route_paths
                .iter()
                .map(|path| (*path).to_owned())
                .collect(),
        ),
        capture,
    )
}

async fn wait_for_status(router: Router, path: &str, expected: StatusCode) {
    let started = Instant::now();

    loop {
        let response = router
            .clone()
            .oneshot(request(Method::GET, path))
            .await
            .expect("request should complete while waiting for status");
        if response.status() == expected {
            return;
        }

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "status {expected} did not become active within the reload window"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn test_policy(
    default_action: DefaultAction,
    roles: &[(&str, &[&str])],
    routes: &[RouteRule],
) -> Policy {
    test_policy_with_enforcement(default_action, EnforcementMode::Enforce, roles, routes)
}

fn test_policy_with_rules(
    default_action: DefaultAction,
    roles: &[(&str, &[&str])],
    routes: &[RouteRule],
    rules: &[Rule],
) -> Policy {
    let mut policy = test_policy(default_action, roles, routes);
    policy.rules = rules.to_vec();
    policy
}

fn test_policy_with_enforcement(
    default_action: DefaultAction,
    enforcement_mode: EnforcementMode,
    roles: &[(&str, &[&str])],
    routes: &[RouteRule],
) -> Policy {
    Policy {
        schema_version: "0.1.0".to_owned(),
        id: Some("test-policy".to_owned()),
        default_action,
        enforcement_mode,
        roles: roles
            .iter()
            .map(|(role, permissions)| {
                (
                    (*role).to_owned(),
                    RoleEntry {
                        permissions: permissions
                            .iter()
                            .map(|permission| (*permission).to_owned())
                            .collect(),
                        issuers: Vec::new(),
                        auth_methods: Vec::new(),
                    },
                )
            })
            .collect::<HashMap<_, _>>(),
        routes: routes.to_vec(),
        rules: Vec::new(),
        egress: EgressPolicy::default(),
        rate_limits: Vec::new(),
        tools: HashMap::new(),
    }
}

fn route(methods: &[&str], path_prefix: &str, permission: &str) -> RouteRule {
    route_with_enforcement(methods, path_prefix, permission, None)
}

fn host_route(methods: &[&str], hosts: &[&str], path_prefix: &str, permission: &str) -> RouteRule {
    let mut rule = route(methods, path_prefix, permission);
    rule.hosts = hosts.iter().map(|host| (*host).to_owned()).collect();
    rule
}

fn direct_rule(id: Option<&str>, methods: &[&str], path: &str, action: RuleAction) -> Rule {
    Rule {
        id: id.map(str::to_owned),
        enabled: true,
        methods: methods.iter().map(|method| (*method).to_owned()).collect(),
        path: path.to_owned(),
        tool_name: None,
        dispatch: None,
        principal: PrincipalMatcher::default(),
        action,
    }
}

fn route_with_enforcement(
    methods: &[&str],
    path_prefix: &str,
    permission: &str,
    enforcement_mode: Option<EnforcementMode>,
) -> RouteRule {
    RouteRule {
        methods: methods.iter().map(|method| (*method).to_owned()).collect(),
        hosts: Vec::new(),
        path_prefix: path_prefix.to_owned(),
        permission: permission.to_owned(),
        enforcement_mode,
    }
}

fn test_principal(roles: &[&str]) -> Principal {
    Principal {
        user_id: "user-123".to_owned(),
        issuer: None,
        email: Some("user@example.test".to_owned()),
        org_id: None,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: "session-123".to_owned(),
        auth_method: AuthMethod::Bearer,
    }
}

fn tool_eligibility_state(
    tool: ToolPolicyEntry,
    rule_action: Option<RuleAction>,
) -> (RbacState, CaptureSink) {
    let mut policy = test_policy(DefaultAction::Deny, &[], &[]);
    policy.tools.insert("reports.export".to_owned(), tool);
    if let Some(action) = rule_action {
        policy.rules.push(Rule {
            id: Some("reports-export-rule".to_owned()),
            enabled: true,
            methods: Vec::new(),
            path: String::new(),
            tool_name: Some("reports.export".to_owned()),
            dispatch: None,
            principal: PrincipalMatcher::default(),
            action,
        });
    }
    test_state(policy, &[])
}

fn tool_policy_entry(
    enabled: bool,
    allowed_roles: &[&str],
    issuers: &[&str],
    auth_methods: &[&str],
) -> ToolPolicyEntry {
    ToolPolicyEntry {
        enabled,
        allowed_roles: allowed_roles
            .iter()
            .map(|role| (*role).to_owned())
            .collect(),
        issuers: issuers.iter().map(|issuer| (*issuer).to_owned()).collect(),
        auth_methods: auth_methods
            .iter()
            .map(|auth_method| (*auth_method).to_owned())
            .collect(),
        timeout_ms: 1_000,
        max_concurrent: 1,
    }
}

fn request(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("request should build")
}

fn request_with_host(method: Method, uri: &str, host: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host)
        .body(Body::empty())
        .expect("request should build")
}

fn proxy_request(method: Method, uri: &str, host: &str) -> Request<Body> {
    let normalized_host = host
        .split_once(':')
        .map_or(host, |(hostname, _)| hostname)
        .to_ascii_lowercase();
    let mut request = request_with_host(method, uri, host);
    request
        .extensions_mut()
        .insert(ProxyRouteAuthorizationContext::new(
            normalized_host,
            Some("/data".to_owned()),
            "https://upstream.example.test".to_owned(),
        ));
    request
}

fn default_policy_document(default_action: &str) -> String {
    format!(
        r#"{{
                "schema_version": "0.1.0",
                "default_action": "{default_action}",
                "roles": {{}}
            }}"#
    )
}

fn egress_policy_document(default_action: &str, host: &str) -> String {
    format!(
        r#"{{
                "schema_version": "0.1.0",
                "default_action": "{default_action}",
                "roles": {{}},
                "egress": {{
                    "hosts": ["{host}"]
                }}
            }}"#
    )
}

fn swap_policy_document(permission: &str) -> String {
    format!(
        r#"{{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "roles": {{
                    "user": {{ "permissions": ["{permission}"] }}
                }},
                "routes": [
                    {{
                        "path_prefix": "/swap",
                        "permission": "{permission}"
                    }}
                ]
            }}"#
    )
}

fn direct_rule_policy_document(rule_id: &str, action: &str) -> String {
    format!(
        r#"{{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "rules": [
                    {{
                        "id": "{rule_id}",
                        "path": "/swap/**",
                        "action": "{action}"
                    }}
                ]
            }}"#
    )
}

fn route_policy_document_without_rules() -> String {
    r#"{
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": {
                "reader": { "permissions": ["data:read"] }
            },
            "routes": [
                {
                    "path_prefix": "/data",
                    "permission": "data:read"
                }
            ]
        }"#
    .to_owned()
}

fn route_policy_document_with_empty_rules() -> String {
    r#"{
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": {
                "reader": { "permissions": ["data:read"] }
            },
            "routes": [
                {
                    "path_prefix": "/data",
                    "permission": "data:read"
                }
            ],
            "rules": []
        }"#
    .to_owned()
}

async fn captured_event(capture: &CaptureSink, event_type: &str) -> AuditEvent {
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == event_type)
    });

    capture
        .events()
        .into_iter()
        .find(|event| event.event_type == event_type)
        .expect("event should be captured")
}

fn assert_eventually(timeout: Duration, condition: impl Fn() -> bool) {
    let started = Instant::now();

    while started.elapsed() < timeout {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(
        condition(),
        "condition did not become true within {timeout:?}"
    );
}

async fn body_string(response: Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read")
            .to_vec(),
    )
    .expect("body should be UTF-8")
}

struct TempPolicyFile {
    path: PathBuf,
}

impl TempPolicyFile {
    fn new(contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-rbac-reload-test-{}.json",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write(&self, contents: &str) {
        fs::write(&self.path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", self.path.display()));
    }
}

impl Drop for TempPolicyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
