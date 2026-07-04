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
    rbac::{
        DefaultAction, EnforcementMode, Policy, PolicyEngine, RouteRule, RuleAction, RuleMatcher,
    },
};

use super::{
    decision::{PolicyDecision, PolicyDecisionOutcome},
    rate_limit::RateLimitState,
};

const AUTHZ_ALLOWED: &str = "authz.allowed";
const AUTHZ_DENIED: &str = "authz.denied";
const AUTHZ_WOULD_DENY: &str = "authz.would_deny";
const POLICY_RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub struct RbacState {
    policy: Arc<ArcSwap<RbacPolicyState>>,
    rate_limit: Option<RateLimitState>,
    pub exempt_paths: Vec<String>,
    pub trust_proxy_headers: bool,
    pub audit: AuditLog,
}

struct RbacPolicyState {
    engine: PolicyEngine,
    rule_matcher: RuleMatcher,
    rule_ids: Vec<String>,
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
            rate_limit: None,
            exempt_paths,
            trust_proxy_headers,
            audit,
        }
    }

    pub(crate) fn with_rate_limit_state(mut self, rate_limit: RateLimitState) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    fn replace_policy(&self, policy: Policy) {
        if let Some(rate_limit) = &self.rate_limit {
            rate_limit.replace_policy(&policy);
        }

        self.policy
            .store(Arc::new(RbacPolicyState::from_policy(policy)));
    }

    pub fn current_policy(&self) -> Policy {
        self.policy.load().engine.policy().clone()
    }

    pub fn principal_has_permission(&self, principal: &auth::Principal, permission: &str) -> bool {
        self.policy
            .load()
            .engine
            .principal_has_permission(principal, permission)
    }
}

impl RbacPolicyState {
    fn from_policy(policy: Policy) -> Self {
        let default_action = policy.default_action.clone();
        let enforcement_mode = policy.enforcement_mode;
        let routes = policy.routes.clone();
        let rule_ids = policy
            .rules
            .iter()
            .enumerate()
            .map(|(rule_index, rule)| rule.id.clone().unwrap_or_else(|| rule_index.to_string()))
            .collect();
        let rule_matcher = RuleMatcher::new(&policy.rules);

        Self {
            engine: PolicyEngine::new(policy),
            rule_matcher,
            rule_ids,
            default_action,
            enforcement_mode,
            routes,
        }
    }

    fn rule_id(&self, rule_index: usize) -> String {
        self.rule_ids
            .get(rule_index)
            .cloned()
            .unwrap_or_else(|| rule_index.to_string())
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
            let direct_rules = policy.rules.len();
            let rate_limit_rules = policy.rate_limits.len();
            state.replace_policy(policy);
            tracing::info!(
                policy_file = %path.display(),
                policy_id = policy_id.as_deref().unwrap_or("unnamed"),
                route_rules,
                direct_rules,
                rate_limit_rules,
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
                matched_rule_id: None,
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
    // Direct firewall rules are additive alongside route-to-permission rules
    // and run first because they make an explicit allow/deny/shadow decision
    // for the full request tuple. If no direct rule matches, route and
    // default-action behavior continues exactly as it did before rules were
    // integrated.
    if let Some(rule_decision) =
        policy
            .rule_matcher
            .evaluate(req.method().as_str(), path, principal.as_ref())
    {
        let matched_rule_id = policy.rule_id(rule_decision.rule_index);
        return match rule_decision.action {
            RuleAction::Allow => {
                emit_rule_allowed(&state, &context, principal.as_ref(), &matched_rule_id);
                let decision = decision_for_direct_rule(
                    PolicyDecisionOutcome::Allowed,
                    "matched_rule",
                    matched_rule_id,
                );
                drop(policy);
                let response = next.run(req).await;
                with_policy_decision(response, decision)
            }
            RuleAction::Deny => {
                emit_rule_denied(&state, &context, principal.as_ref(), &matched_rule_id);
                with_policy_decision(
                    forbidden(),
                    decision_for_direct_rule(
                        PolicyDecisionOutcome::Denied,
                        "matched_rule",
                        matched_rule_id,
                    ),
                )
            }
            RuleAction::Shadow => {
                emit_rule_would_deny(&state, &context, principal.as_ref(), &matched_rule_id);
                let decision = decision_for_direct_rule(
                    PolicyDecisionOutcome::WouldDeny,
                    "matched_rule",
                    matched_rule_id,
                );
                drop(policy);
                let response = next.run(req).await;
                with_policy_decision(response, decision)
            }
        };
    }

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
                matched_rule_id: None,
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
                        matched_rule_id: None,
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
                        matched_rule_id: None,
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

fn emit_rule_allowed(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    matched_rule_id: &str,
) {
    emit_direct_rule_event(
        state,
        context,
        principal,
        "matched_rule",
        matched_rule_id,
        AUTHZ_ALLOWED,
    );
}

fn emit_rule_denied(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    matched_rule_id: &str,
) {
    emit_direct_rule_event(
        state,
        context,
        principal,
        "matched_rule",
        matched_rule_id,
        AUTHZ_DENIED,
    );
}

fn emit_rule_would_deny(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    matched_rule_id: &str,
) {
    emit_direct_rule_event(
        state,
        context,
        principal,
        "matched_rule",
        matched_rule_id,
        AUTHZ_WOULD_DENY,
    );
}

fn emit_direct_rule_event(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    matched_rule_id: &str,
    event_type: &'static str,
) {
    let actor = principal.map(actor_from_principal);
    let payload = json!({
        "path": &context.path,
        "method": &context.method,
        "reason": reason,
        "matched_rule_id": matched_rule_id,
    });

    state.audit.emit(AuditEvent::new(
        event_type,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ));
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
        matched_rule_id: None,
    }
}

fn decision_for_direct_rule(
    outcome: PolicyDecisionOutcome,
    reason: &'static str,
    matched_rule_id: String,
) -> PolicyDecision {
    PolicyDecision {
        outcome,
        reason,
        permission: None,
        path_prefix: None,
        matched_rule_id: Some(matched_rule_id),
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
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        audit::{sink::tests::CaptureSink, AuditSink},
        auth::{AuthMethod, Principal},
        rbac::{
            policy::{EgressPolicy, RoleEntry},
            PrincipalMatcher, Rule, RuleAction,
        },
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
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
            routes: routes.to_vec(),
            rules: Vec::new(),
            egress: EgressPolicy::default(),
            rate_limits: Vec::new(),
        }
    }

    fn route(methods: &[&str], path_prefix: &str, permission: &str) -> RouteRule {
        route_with_enforcement(methods, path_prefix, permission, None)
    }

    fn direct_rule(id: Option<&str>, methods: &[&str], path: &str, action: RuleAction) -> Rule {
        Rule {
            id: id.map(str::to_owned),
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            path: path.to_owned(),
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
}
