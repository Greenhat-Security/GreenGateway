//! Route-level RBAC authorization middleware.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{Method, StatusCode};
use serde::Serialize;
use serde_json::json;

use crate::{
    audit::{AuditEvent, AuditLog},
    auth::{self, actor_from_principal},
    client_ip::{canonical_client_ip, request_id},
    config::Config,
    rbac::{DefaultAction, Policy, PolicyEngine, RouteRule},
};

use super::decision::PolicyDecision;

const AUTHZ_ALLOWED: &str = "authz.allowed";
const AUTHZ_DENIED: &str = "authz.denied";

#[derive(Clone)]
pub struct RbacState {
    pub engine: Arc<PolicyEngine>,
    pub default_action: DefaultAction,
    pub routes: Arc<Vec<RouteRule>>,
    pub exempt_paths: Vec<String>,
    pub trust_proxy_headers: bool,
    pub audit: AuditLog,
}

#[derive(Serialize)]
struct ForbiddenBody {
    error: &'static str,
}

struct AuditContext {
    request_id: String,
    source_ip: String,
    path: String,
    method: String,
}

impl RbacState {
    pub fn from_policy(policy: Policy, config: &Config, audit: AuditLog) -> Self {
        Self {
            default_action: policy.default_action.clone(),
            routes: Arc::new(policy.routes.clone()),
            engine: Arc::new(PolicyEngine::new(policy)),
            exempt_paths: config.rbac_exempt_paths.clone(),
            trust_proxy_headers: config.trust_proxy_headers,
            audit,
        }
    }
}

pub async fn rbac_middleware(State(state): State<RbacState>, req: Request, next: Next) -> Response {
    let path = req.uri().path();

    // Conservative fail-closed guard for the current local-handler stage. When
    // the Phase 3 reverse proxy lands, upgrade this to proper path
    // normalization (percent-decode plus dot-segment resolution) before route
    // matching so legitimate percent-encoded upstream paths can be supported.
    // Until then, rejecting unsafe raw paths is the safe default.
    if is_unsafe_request_path(path) {
        let context = audit_context(&req, state.trust_proxy_headers);
        let principal = req.extensions().get::<auth::Principal>().cloned();
        emit_denied(&state, &context, principal.as_ref(), "unsafe_path", None);
        return with_policy_decision(
            forbidden(),
            PolicyDecision {
                allowed: false,
                reason: "unsafe_path",
                permission: None,
                path_prefix: None,
            },
        );
    }

    if state
        .exempt_paths
        .iter()
        .any(|exempt_path| exempt_path == path)
    {
        return next.run(req).await;
    }

    let context = audit_context(&req, state.trust_proxy_headers);
    let principal = req.extensions().get::<auth::Principal>().cloned();

    if let Some(rule) = matching_route(&state.routes, req.method(), path) {
        if principal.as_ref().is_some_and(|principal| {
            state
                .engine
                .principal_has_permission(principal, &rule.permission)
        }) {
            emit_allowed(&state, &context, principal.as_ref(), Some(rule), None);
            let decision = decision_for_rule(true, "matched_rule", rule);
            let response = next.run(req).await;
            return with_policy_decision(response, decision);
        }

        let reason = if principal.is_some() {
            "missing_permission"
        } else {
            "missing_principal"
        };
        emit_denied(&state, &context, principal.as_ref(), reason, Some(rule));
        return with_policy_decision(forbidden(), decision_for_rule(false, reason, rule));
    }

    match state.default_action {
        DefaultAction::Allow => {
            let decision = PolicyDecision {
                allowed: true,
                reason: "default_allow",
                permission: None,
                path_prefix: None,
            };
            emit_allowed(
                &state,
                &context,
                principal.as_ref(),
                None,
                Some("default_allow"),
            );
            let response = next.run(req).await;
            with_policy_decision(response, decision)
        }
        DefaultAction::Deny => {
            emit_denied(&state, &context, principal.as_ref(), "default_deny", None);
            with_policy_decision(
                forbidden(),
                PolicyDecision {
                    allowed: false,
                    reason: "default_deny",
                    permission: None,
                    path_prefix: None,
                },
            )
        }
    }
}

fn matching_route<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
) -> Option<&'a RouteRule> {
    routes.iter().find(|rule| {
        path_prefix_matches(path, &rule.path_prefix) && method_matches(&rule.methods, method)
    })
}

fn path_prefix_matches(path: &str, path_prefix: &str) -> bool {
    if !path_prefix.starts_with('/') {
        return false;
    }

    if path == path_prefix {
        return true;
    }

    if path_prefix.ends_with('/') {
        return path.starts_with(path_prefix);
    }

    path.strip_prefix(path_prefix)
        .is_some_and(|remaining| remaining.starts_with('/'))
}

fn is_unsafe_request_path(path: &str) -> bool {
    path.contains('%')
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

fn method_matches(methods: &[String], method: &Method) -> bool {
    methods.is_empty()
        || methods.iter().any(|configured| {
            let configured = configured.trim();
            configured == "*" || configured.eq_ignore_ascii_case(method.as_str())
        })
}

fn audit_context(req: &Request, trust_proxy_headers: bool) -> AuditContext {
    AuditContext {
        request_id: request_id(req.headers(), req.extensions()),
        source_ip: canonical_client_ip(req.headers(), req.extensions(), trust_proxy_headers),
        path: req.uri().path().to_owned(),
        method: req.method().as_str().to_owned(),
    }
}

fn emit_allowed(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    rule: Option<&RouteRule>,
    reason: Option<&'static str>,
) {
    let actor = principal.map(actor_from_principal);
    let payload = match rule {
        Some(rule) => json!({
            "path": &context.path,
            "method": &context.method,
            "path_prefix": &rule.path_prefix,
            "permission": &rule.permission,
        }),
        None => json!({
            "path": &context.path,
            "method": &context.method,
            "reason": reason.unwrap_or("default_allow"),
            "default_allow": true,
        }),
    };

    state.audit.emit(AuditEvent::new(
        AUTHZ_ALLOWED,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ));
}

fn emit_denied(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    rule: Option<&RouteRule>,
) {
    let actor = principal.map(actor_from_principal);
    let payload = match rule {
        Some(rule) => json!({
            "path": &context.path,
            "method": &context.method,
            "reason": reason,
            "path_prefix": &rule.path_prefix,
            "permission": &rule.permission,
        }),
        None => json!({
            "path": &context.path,
            "method": &context.method,
            "reason": reason,
        }),
    };

    state.audit.emit(AuditEvent::new(
        AUTHZ_DENIED,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ));
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ForbiddenBody { error: "forbidden" }),
    )
        .into_response()
}

fn decision_for_rule(allowed: bool, reason: &'static str, rule: &RouteRule) -> PolicyDecision {
    PolicyDecision {
        allowed,
        reason,
        permission: Some(rule.permission.clone()),
        path_prefix: Some(rule.path_prefix.clone()),
    }
}

fn with_policy_decision(mut response: Response, decision: PolicyDecision) -> Response {
    response.extensions_mut().insert(decision);
    response
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, Instant},
    };

    use axum::{body::Body, middleware::from_fn_with_state, routing::any, Router};
    use http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        audit::{sink::tests::CaptureSink, AuditSink},
        auth::{AuthMethod, Principal},
        rbac::policy::RoleEntry,
    };

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

    #[test]
    fn route_prefix_matches_only_at_segment_boundary() {
        let routes = vec![
            route(&[], "/data", "data:read"),
            route(&[], "/database", "database:read"),
            route(&[], "/data-export", "data:export"),
        ];

        let rule = matching_route(&routes, &Method::GET, "/data").expect("rule should match");
        assert_eq!(rule.path_prefix, "/data");

        let rule =
            matching_route(&routes, &Method::GET, "/data/report").expect("rule should match");
        assert_eq!(rule.path_prefix, "/data");

        let rule = matching_route(&routes, &Method::GET, "/database").expect("rule should match");
        assert_eq!(rule.path_prefix, "/database");

        let rule =
            matching_route(&routes, &Method::GET, "/data-export").expect("rule should match");
        assert_eq!(rule.path_prefix, "/data-export");
    }

    #[tokio::test]
    async fn unsafe_paths_fail_closed_with_unsafe_path_reason() {
        for path in ["/data/../admin", "/%61dmin", "/a/./b"] {
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

    fn test_state(policy: Policy, exempt_paths: &[&str]) -> (RbacState, CaptureSink) {
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let default_action = policy.default_action.clone();
        let routes = Arc::new(policy.routes.clone());

        (
            RbacState {
                engine: Arc::new(PolicyEngine::new(policy)),
                default_action,
                routes,
                exempt_paths: exempt_paths.iter().map(|path| (*path).to_owned()).collect(),
                trust_proxy_headers: false,
                audit,
            },
            capture,
        )
    }

    fn test_policy(
        default_action: DefaultAction,
        roles: &[(&str, &[&str])],
        routes: &[RouteRule],
    ) -> Policy {
        Policy {
            schema_version: "0.1.0".to_owned(),
            id: Some("test-policy".to_owned()),
            default_action,
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
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
            routes: routes.to_vec(),
        }
    }

    fn route(methods: &[&str], path_prefix: &str, permission: &str) -> RouteRule {
        RouteRule {
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            path_prefix: path_prefix.to_owned(),
            permission: permission.to_owned(),
        }
    }

    fn test_principal(roles: &[&str]) -> Principal {
        Principal {
            user_id: "user-123".to_owned(),
            email: Some("user@example.test".to_owned()),
            org_id: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: "session-123".to_owned(),
            auth_method: AuthMethod::Bearer,
        }
    }

    fn request(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .expect("request should build")
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
}
