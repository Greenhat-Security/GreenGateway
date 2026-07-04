//! Route-level RBAC authorization middleware.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{Method, StatusCode};
use notify::{RecursiveMode, Watcher};
use serde::Serialize;
use serde_json::json;
use tokio::sync::mpsc;

use crate::{
    audit::{AuditEvent, AuditLog},
    auth::{self, actor_from_principal},
    client_ip::{canonical_client_ip, request_id},
    config::Config,
    path_match::path_prefix_matches,
    rbac::{DefaultAction, EnforcementMode, Policy, PolicyEngine, RouteRule},
};

use super::decision::{PolicyDecision, PolicyDecisionOutcome};

const AUTHZ_ALLOWED: &str = "authz.allowed";
const AUTHZ_DENIED: &str = "authz.denied";
const AUTHZ_WOULD_DENY: &str = "authz.would_deny";
const POLICY_RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub struct RbacState {
    policy: Arc<ArcSwap<RbacPolicyState>>,
    pub exempt_paths: Vec<String>,
    pub trust_proxy_headers: bool,
    pub audit: AuditLog,
}

struct RbacPolicyState {
    engine: PolicyEngine,
    default_action: DefaultAction,
    enforcement_mode: EnforcementMode,
    routes: Vec<RouteRule>,
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
        Self::new(
            policy,
            config.rbac_exempt_paths.clone(),
            config.trust_proxy_headers,
            audit,
        )
    }

    pub fn new(
        policy: Policy,
        exempt_paths: Vec<String>,
        trust_proxy_headers: bool,
        audit: AuditLog,
    ) -> Self {
        Self {
            policy: Arc::new(ArcSwap::from_pointee(RbacPolicyState::from_policy(policy))),
            exempt_paths,
            trust_proxy_headers,
            audit,
        }
    }

    fn replace_policy(&self, policy: Policy) {
        self.policy
            .store(Arc::new(RbacPolicyState::from_policy(policy)));
    }
}

impl RbacPolicyState {
    fn from_policy(policy: Policy) -> Self {
        let default_action = policy.default_action.clone();
        let enforcement_mode = policy.enforcement_mode;
        let routes = policy.routes.clone();

        Self {
            engine: PolicyEngine::new(policy),
            default_action,
            enforcement_mode,
            routes,
        }
    }
}

pub fn reload_policy_from_file(
    state: &RbacState,
    path: impl AsRef<Path>,
) -> Result<(), crate::rbac::policy::PolicyError> {
    let path = path.as_ref();

    match Policy::from_file(path) {
        Ok(policy) => {
            let policy_id = policy.id.clone();
            let route_rules = policy.routes.len();
            state.replace_policy(policy);
            tracing::info!(
                policy_file = %path.display(),
                policy_id = policy_id.as_deref().unwrap_or("unnamed"),
                route_rules,
                "RBAC policy reload accepted"
            );
            Ok(())
        }
        Err(err) => {
            tracing::error!(
                policy_file = %path.display(),
                error = %err,
                "RBAC policy reload rejected; existing policy remains active"
            );
            Err(err)
        }
    }
}

pub fn spawn_policy_reload_tasks(
    policy_file: impl Into<PathBuf>,
    state: RbacState,
) -> notify::Result<()> {
    let policy_file = policy_file.into();
    spawn_policy_file_watcher(policy_file.clone(), state.clone())?;
    spawn_sighup_reload_task(policy_file, state);
    Ok(())
}

fn spawn_policy_file_watcher(policy_file: PathBuf, state: RbacState) -> notify::Result<()> {
    let (sender, receiver) = mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = sender.send(event);
    })?;
    watcher.watch(&watch_directory(&policy_file), RecursiveMode::NonRecursive)?;

    tokio::spawn(policy_file_watch_loop(
        policy_file,
        state,
        receiver,
        watcher,
    ));

    Ok(())
}

async fn policy_file_watch_loop(
    policy_file: PathBuf,
    state: RbacState,
    mut events: mpsc::UnboundedReceiver<notify::Result<notify::Event>>,
    _watcher: notify::RecommendedWatcher,
) {
    while let Some(event) = events.recv().await {
        if !handle_policy_watch_event(&policy_file, event) {
            continue;
        }

        tokio::time::sleep(POLICY_RELOAD_DEBOUNCE).await;
        while let Ok(event) = events.try_recv() {
            let _ = handle_policy_watch_event(&policy_file, event);
        }

        let _ = reload_policy_from_file(&state, &policy_file);
    }
}

fn handle_policy_watch_event(policy_file: &Path, event: notify::Result<notify::Event>) -> bool {
    match event {
        Ok(event) => policy_reload_event(&event, policy_file),
        Err(err) => {
            tracing::error!(error = %err, "policy file watch error");
            false
        }
    }
}

fn policy_reload_event(event: &notify::Event, policy_file: &Path) -> bool {
    !matches!(event.kind, notify::EventKind::Access(_))
        && event
            .paths
            .iter()
            .any(|path| path_matches_policy_file(path, policy_file))
}

fn path_matches_policy_file(path: &Path, policy_file: &Path) -> bool {
    path == policy_file
        || path
            .file_name()
            .is_some_and(|file_name| Some(file_name) == policy_file.file_name())
}

fn watch_directory(policy_file: &Path) -> PathBuf {
    policy_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_owned()
}

#[cfg(unix)]
fn spawn_sighup_reload_task(policy_file: PathBuf, state: RbacState) {
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(err) => {
                tracing::error!(error = %err, "failed to register SIGHUP policy reload handler");
                return;
            }
        };

        while sighup.recv().await.is_some() {
            let _ = reload_policy_from_file(&state, &policy_file);
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(_policy_file: PathBuf, _state: RbacState) {}

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
                outcome: PolicyDecisionOutcome::Denied,
                reason: "unsafe_path",
                permission: None,
                path_prefix: None,
            },
        );
    }

    if state
        .exempt_paths
        .iter()
        .any(|exempt_path| path_prefix_matches(path, exempt_path))
    {
        return next.run(req).await;
    }

    let context = audit_context(&req, state.trust_proxy_headers);
    let principal = req.extensions().get::<auth::Principal>().cloned();

    let policy = state.policy.load();
    if let Some(rule) = matching_route(&policy.routes, req.method(), path) {
        if principal.as_ref().is_some_and(|principal| {
            policy
                .engine
                .principal_has_permission(principal, &rule.permission)
        }) {
            emit_allowed(&state, &context, principal.as_ref(), Some(rule), None);
            let decision = decision_for_rule(PolicyDecisionOutcome::Allowed, "matched_rule", rule);
            drop(policy);
            let response = next.run(req).await;
            return with_policy_decision(response, decision);
        }

        let reason = if principal.is_some() {
            "missing_permission"
        } else {
            "missing_principal"
        };
        return match effective_enforcement_mode(&policy, rule) {
            EnforcementMode::Enforce => {
                emit_denied(&state, &context, principal.as_ref(), reason, Some(rule));
                with_policy_decision(
                    forbidden(),
                    decision_for_rule(PolicyDecisionOutcome::Denied, reason, rule),
                )
            }
            EnforcementMode::Shadow => {
                emit_would_deny(&state, &context, principal.as_ref(), reason, Some(rule));
                let decision = decision_for_rule(PolicyDecisionOutcome::WouldDeny, reason, rule);
                drop(policy);
                let response = next.run(req).await;
                with_policy_decision(response, decision)
            }
        };
    }

    let default_action = policy.default_action.clone();
    let enforcement_mode = policy.enforcement_mode;
    drop(policy);

    match default_action {
        DefaultAction::Allow => {
            let decision = PolicyDecision {
                outcome: PolicyDecisionOutcome::Allowed,
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
        DefaultAction::Deny => match enforcement_mode {
            EnforcementMode::Enforce => {
                emit_denied(&state, &context, principal.as_ref(), "default_deny", None);
                with_policy_decision(
                    forbidden(),
                    PolicyDecision {
                        outcome: PolicyDecisionOutcome::Denied,
                        reason: "default_deny",
                        permission: None,
                        path_prefix: None,
                    },
                )
            }
            EnforcementMode::Shadow => {
                emit_would_deny(&state, &context, principal.as_ref(), "default_deny", None);
                let response = next.run(req).await;
                with_policy_decision(
                    response,
                    PolicyDecision {
                        outcome: PolicyDecisionOutcome::WouldDeny,
                        reason: "default_deny",
                        permission: None,
                        path_prefix: None,
                    },
                )
            }
        },
    }
}

fn effective_enforcement_mode(policy: &RbacPolicyState, rule: &RouteRule) -> EnforcementMode {
    rule.enforcement_mode.unwrap_or(policy.enforcement_mode)
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
    emit_denial_event(state, context, principal, reason, rule, AUTHZ_DENIED);
}

fn emit_would_deny(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    rule: Option<&RouteRule>,
) {
    emit_denial_event(state, context, principal, reason, rule, AUTHZ_WOULD_DENY);
}

fn emit_denial_event(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    rule: Option<&RouteRule>,
    event_type: &'static str,
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
        event_type,
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

fn decision_for_rule(
    outcome: PolicyDecisionOutcome,
    reason: &'static str,
    rule: &RouteRule,
) -> PolicyDecision {
    PolicyDecision {
        outcome,
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
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, Instant},
    };

    use axum::{body::Body, middleware::from_fn_with_state, routing::any, Router};
    use http::Request;
    use serde_json::json;
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
        reload_policy_from_file(&state, file.path()).expect("valid policy reload should succeed");

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
        reload_policy_from_file(&state, file.path()).expect("valid policy reload should succeed");

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

        (
            RbacState::new(
                policy,
                exempt_paths.iter().map(|path| (*path).to_owned()).collect(),
                false,
                audit,
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
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
            routes: routes.to_vec(),
        }
    }

    fn route(methods: &[&str], path_prefix: &str, permission: &str) -> RouteRule {
        route_with_enforcement(methods, path_prefix, permission, None)
    }

    fn route_with_enforcement(
        methods: &[&str],
        path_prefix: &str,
        permission: &str,
        enforcement_mode: Option<EnforcementMode>,
    ) -> RouteRule {
        RouteRule {
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            path_prefix: path_prefix.to_owned(),
            permission: permission.to_owned(),
            enforcement_mode,
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

    fn default_policy_document(default_action: &str) -> String {
        format!(
            r#"{{
                "schema_version": "0.1.0",
                "default_action": "{default_action}",
                "roles": {{}}
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
}
