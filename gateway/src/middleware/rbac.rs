//! Route-level RBAC authorization middleware.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LockResult, Mutex, MutexGuard},
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
    auth::{self, actor_from_principal, protected_resource},
    client_ip::{canonical_client_ip, request_id, ClientIpPolicy},
    config::Config,
    path_match::{is_unsafe_request_path, path_prefix_matches},
    rbac::{
        policy::ToolPolicyEntry, DefaultAction, EgressPolicy, EnforcementMode, Policy,
        PolicyEngine, RouteRule, RuleAction, RuleDecision, RuleDispatchContext, RuleMatcher,
    },
    upstream_route::{
        self, ProxyRouteAuthorizationContext, ProxyRouteClassificationCompleted,
        ProxyRouteObservationContext,
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
    policy_write_lock: Arc<Mutex<()>>,
    rate_limit: Option<RateLimitState>,
    pub exempt_paths: Vec<String>,
    pub client_ip_policy: ClientIpPolicy,
    pub audit: AuditLog,
    mcp_route_paths: Vec<String>,
}

struct RbacPolicyState {
    engine: PolicyEngine,
    rule_matcher: RuleMatcher,
    rule_ids: Vec<String>,
    default_action: DefaultAction,
    enforcement_mode: EnforcementMode,
    routes: Vec<RouteRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatchedRuleDecision {
    pub action: RuleAction,
    pub matched_rule_id: String,
}

pub(crate) struct ToolAuthorizationSnapshot<'a> {
    pub tool: Option<ToolPolicySnapshot<'a>>,
    pub rule_decision: Option<MatchedRuleDecision>,
    pub tools: &'a HashMap<String, ToolPolicyEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ToolPolicySnapshot<'a> {
    pub enabled: bool,
    pub allowed_roles: &'a [String],
    pub issuers: &'a [String],
    pub auth_methods: &'a [String],
    pub timeout_ms: u64,
    pub max_concurrent: u32,
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
        Self::new_with_mcp_route_paths(
            policy,
            config.rbac_exempt_paths.clone(),
            ClientIpPolicy::from_config(config),
            audit,
            protected_resource::mcp_route_paths(config),
        )
    }

    #[cfg(test)]
    pub fn new(
        policy: Policy,
        exempt_paths: Vec<String>,
        trust_proxy_headers: bool,
        audit: AuditLog,
    ) -> Self {
        Self::new_with_mcp_route_paths(
            policy,
            exempt_paths,
            {
                assert!(
                    !trust_proxy_headers,
                    "tests that trust proxies must provide an explicit ClientIpPolicy"
                );
                ClientIpPolicy::default()
            },
            audit,
            vec![protected_resource::MCP_RESOURCE_PATH.to_owned()],
        )
    }

    fn new_with_mcp_route_paths(
        policy: Policy,
        exempt_paths: Vec<String>,
        client_ip_policy: ClientIpPolicy,
        audit: AuditLog,
        mcp_route_paths: Vec<String>,
    ) -> Self {
        Self {
            policy: Arc::new(ArcSwap::from_pointee(RbacPolicyState::from_policy(policy))),
            policy_write_lock: Arc::new(Mutex::new(())),
            rate_limit: None,
            exempt_paths,
            client_ip_policy,
            audit,
            mcp_route_paths,
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

    pub fn current_egress_policy(&self) -> EgressPolicy {
        self.policy.load().engine.policy().egress.clone()
    }

    pub(crate) fn policy_write_guard(&self) -> LockResult<MutexGuard<'_, ()>> {
        self.policy_write_lock.lock()
    }

    pub fn principal_has_permission(&self, principal: &auth::Principal, permission: &str) -> bool {
        self.policy
            .load()
            .engine
            .principal_has_permission(principal, permission)
    }

    /// Returns requested delegated roles that the principal cannot activate.
    /// Wildcard principals may delegate any role. The policy is read once so
    /// the wildcard and per-role decisions use the same live snapshot.
    pub fn disallowed_delegated_roles(
        &self,
        principal: &auth::Principal,
        requested_roles: &[String],
    ) -> Vec<String> {
        let policy = self.policy.load();
        if policy.engine.principal_has_wildcard(principal) {
            return Vec::new();
        }

        requested_roles
            .iter()
            .filter(|role| !policy.engine.principal_has_active_role(principal, role))
            .cloned()
            .collect()
    }

    fn is_mcp_route_path(&self, path: &str) -> bool {
        self.mcp_route_paths
            .iter()
            .any(|route_path| path == route_path)
    }

    fn policy_path_for_request<'a>(&'a self, path: &'a str) -> &'a str {
        if path != protected_resource::MCP_RESOURCE_PATH && self.is_mcp_route_path(path) {
            protected_resource::MCP_RESOURCE_PATH
        } else {
            path
        }
    }

    pub(crate) fn evaluate_tool_authorization<R>(
        &self,
        tool_name: &str,
        principal: Option<&auth::Principal>,
        evaluate: impl FnOnce(ToolAuthorizationSnapshot<'_>) -> R,
    ) -> R {
        let policy = self.policy.load();
        let tool = policy.tool_policy(tool_name);
        let rule_decision = policy.evaluate_tool_rule(tool_name, principal);

        evaluate(ToolAuthorizationSnapshot {
            tool,
            rule_decision,
            tools: &policy.engine.policy().tools,
        })
    }

    pub(crate) fn evaluate_tool_http_rule(
        &self,
        method: &str,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> Option<MatchedRuleDecision> {
        self.policy
            .load()
            .evaluate_tool_http_rule(method, path, principal)
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

    fn tool_policy(&self, tool_name: &str) -> Option<ToolPolicySnapshot<'_>> {
        self.engine
            .policy()
            .tools
            .get(tool_name)
            .map(|entry| ToolPolicySnapshot {
                enabled: entry.enabled,
                allowed_roles: entry.allowed_roles.as_slice(),
                issuers: entry.issuers.as_slice(),
                auth_methods: entry.auth_methods.as_slice(),
                timeout_ms: entry.timeout_ms,
                max_concurrent: entry.max_concurrent,
            })
    }

    fn evaluate_tool_rule(
        &self,
        tool_name: &str,
        principal: Option<&auth::Principal>,
    ) -> Option<MatchedRuleDecision> {
        self.rule_matcher
            .evaluate_tool(tool_name, principal)
            .map(|decision| MatchedRuleDecision {
                action: decision.action,
                matched_rule_id: self.rule_id(decision.rule_index),
            })
    }

    fn evaluate_tool_http_rule(
        &self,
        method: &str,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> Option<MatchedRuleDecision> {
        self.rule_matcher
            .evaluate_with_dispatch(method, path, principal, RuleDispatchContext::unknown())
            .map(|decision| MatchedRuleDecision {
                action: decision.action,
                matched_rule_id: self.rule_id(decision.rule_index),
            })
    }
}

pub fn reload_policy_from_file(
    state: &RbacState,
    path: impl AsRef<Path>,
) -> Result<(), crate::rbac::policy::PolicyError> {
    let path = path.as_ref();

    match Policy::from_file(path) {
        Ok(policy) => {
            if policy.egress != state.current_egress_policy() {
                tracing::error!(
                    policy_file = %path.display(),
                    "RBAC policy reload rejected: egress section changed; egress changes require a gateway restart. Existing policy (including egress allowlist) remains active."
                );
                return Err(crate::rbac::policy::PolicyError::EgressReloadRejected);
            }

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
    let proxy_context = req
        .extensions()
        .get::<ProxyRouteAuthorizationContext>()
        .cloned();

    // Conservative fail-closed guard for the current local-handler stage. When
    // the Phase 3 reverse proxy lands, upgrade this to proper path
    // normalization (percent-decode plus dot-segment resolution) before route
    // matching so legitimate percent-encoded upstream paths can be supported.
    // Until then, rejecting unsafe raw paths is the safe default.
    if is_unsafe_request_path(path) {
        let context = audit_context(&req, &state.client_ip_policy);
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

    if proxy_context.is_none() && auth::protected_resource::is_well_known_path(path) {
        return next.run(req).await;
    }

    if proxy_context.is_none()
        && !state.is_mcp_route_path(path)
        && state
            .exempt_paths
            .iter()
            .any(|exempt_path| path_prefix_matches(path, exempt_path))
    {
        return next.run(req).await;
    }

    let context = audit_context(&req, &state.client_ip_policy);
    let principal = req.extensions().get::<auth::Principal>().cloned();
    let policy_path = state.policy_path_for_request(path);
    let request_host = upstream_route::request_host_without_port(req.headers());
    let required_upstream_host = proxy_context.as_ref().map(|context| context.host.as_str());
    let dispatch_context = if req
        .extensions()
        .get::<ProxyRouteClassificationCompleted>()
        .is_none()
    {
        RuleDispatchContext::unknown()
    } else if let Some(context) = req.extensions().get::<ProxyRouteObservationContext>() {
        RuleDispatchContext::classified(
            context.route_host.as_deref(),
            context.route_path_prefix.as_deref(),
            Some(context.upstream_origin.as_str()),
        )
    } else {
        RuleDispatchContext::contextless()
    };

    let policy = state.policy.load();
    // Direct firewall rules run before route-to-permission rules. A direct deny
    // remains global, but host-qualified upstreams require an explicit host-bound
    // route permission. Direct allow cannot authorize them, while first-match
    // shadow telemetry is retained before route evaluation. MCP aliases evaluate
    // their raw and canonical policy identities together so a deny or shadow on
    // either identity cannot be suppressed by an allow on the other.
    let first_direct_rule = matching_direct_rule(
        &policy.rule_matcher,
        req.method().as_str(),
        path,
        policy_path,
        principal.as_ref(),
        dispatch_context,
        false,
    );
    let direct_rule_decision = if required_upstream_host.is_some() {
        matching_direct_rule(
            &policy.rule_matcher,
            req.method().as_str(),
            path,
            policy_path,
            principal.as_ref(),
            dispatch_context,
            true,
        )
    } else {
        first_direct_rule.clone()
    };
    if required_upstream_host.is_some() {
        if let Some(rule_decision) = first_direct_rule.as_ref() {
            if rule_decision.action == RuleAction::Shadow {
                let matched_rule_id = policy.rule_id(rule_decision.rule_index);
                emit_rule_would_deny(&state, &context, principal.as_ref(), &matched_rule_id);
            }
        }
    }
    if let Some(rule_decision) = direct_rule_decision {
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

    let matching_policy_route = matching_route_for_request(
        &policy.routes,
        req.method(),
        path,
        policy_path,
        required_upstream_host.or(request_host.as_deref()),
        required_upstream_host.is_some(),
    );

    if let Some(rule) = matching_policy_route {
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

    if required_upstream_host.is_some() {
        emit_host_policy_required(
            &state,
            &context,
            principal.as_ref(),
            proxy_context
                .as_ref()
                .expect("host binding requires proxy dispatch context"),
        );
        return with_policy_decision(
            forbidden(),
            PolicyDecision {
                outcome: PolicyDecisionOutcome::Denied,
                reason: "host_policy_required",
                permission: None,
                path_prefix: None,
                matched_rule_id: None,
            },
        );
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

fn matching_direct_rule(
    matcher: &RuleMatcher,
    method: &str,
    path: &str,
    policy_path: &str,
    principal: Option<&auth::Principal>,
    dispatch_context: RuleDispatchContext<'_>,
    denies_only: bool,
) -> Option<RuleDecision> {
    if policy_path != path {
        return matcher.evaluate_equivalent_paths_with_dispatch(
            method,
            &[policy_path, path],
            principal,
            dispatch_context,
            denies_only,
        );
    }

    if denies_only {
        matcher.evaluate_denies_with_dispatch(method, path, principal, dispatch_context)
    } else {
        matcher.evaluate_with_dispatch(method, path, principal, dispatch_context)
    }
}

#[cfg(test)]
fn matching_route<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
) -> Option<&'a RouteRule> {
    matching_route_with_host(routes, method, path, None, false)
}

fn matching_route_with_host<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
    request_host: Option<&str>,
    host_binding_required: bool,
) -> Option<&'a RouteRule> {
    routes.iter().find(|rule| {
        path_prefix_matches(path, &rule.path_prefix)
            && method_matches(&rule.methods, method)
            && route_host_matches(rule, request_host, host_binding_required)
    })
}

fn matching_route_for_request<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
    policy_path: &str,
    request_host: Option<&str>,
    host_binding_required: bool,
) -> Option<&'a RouteRule> {
    if policy_path != path {
        matching_exact_route(routes, method, path, request_host, host_binding_required).or_else(
            || {
                matching_route_with_host(
                    routes,
                    method,
                    policy_path,
                    request_host,
                    host_binding_required,
                )
            },
        )
    } else {
        matching_route_with_host(routes, method, path, request_host, host_binding_required)
    }
}

fn matching_exact_route<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
    request_host: Option<&str>,
    host_binding_required: bool,
) -> Option<&'a RouteRule> {
    routes.iter().find(|rule| {
        rule.path_prefix == path
            && method_matches(&rule.methods, method)
            && route_host_matches(rule, request_host, host_binding_required)
    })
}

fn route_host_matches(
    rule: &RouteRule,
    request_host: Option<&str>,
    host_binding_required: bool,
) -> bool {
    if rule.hosts.is_empty() {
        return !host_binding_required;
    }

    request_host.is_some_and(|request_host| {
        rule.hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(request_host))
    })
}

fn method_matches(methods: &[String], method: &Method) -> bool {
    methods.is_empty()
        || methods.iter().any(|configured| {
            let configured = configured.trim();
            configured == "*" || configured.eq_ignore_ascii_case(method.as_str())
        })
}

fn audit_context(req: &Request, client_ip_policy: &ClientIpPolicy) -> AuditContext {
    AuditContext {
        request_id: request_id(req.headers(), req.extensions()),
        source_ip: canonical_client_ip(req.headers(), req.extensions(), client_ip_policy),
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

fn emit_host_policy_required(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    proxy_context: &ProxyRouteAuthorizationContext,
) {
    let actor = principal.map(actor_from_principal);
    let payload = json!({
        "path": &context.path,
        "method": &context.method,
        "reason": "host_policy_required",
        "upstream_host": &proxy_context.host,
        "upstream_path_prefix": &proxy_context.path_prefix,
        "upstream_origin": &proxy_context.upstream_origin,
    });

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
            policy::{EgressPolicy, PolicyError, RoleEntry},
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
        policy_file.write(
            &serde_json::to_string(&unbound_policy).expect("unbound policy should serialize"),
        );
        reload_policy_from_file(&state, policy_file.path())
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

        policy_file
            .write(&serde_json::to_string(&host_policy).expect("host policy should serialize"));
        reload_policy_from_file(&state, policy_file.path())
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

    #[test]
    fn reload_rejected_when_egress_section_changes() {
        let file = TempPolicyFile::new(&egress_policy_document("deny", "initial.example.test"));
        let initial_policy =
            Policy::from_file(file.path()).expect("initial policy should parse before test");
        let (state, _capture) = test_state(initial_policy, &[]);

        file.write(&egress_policy_document("allow", "replacement.example.test"));
        let error = reload_policy_from_file(&state, file.path())
            .expect_err("egress-changing reload should be rejected");

        assert!(matches!(error, PolicyError::EgressReloadRejected));
        assert!(error.to_string().contains("restart"));
        assert_eq!(state.current_policy().default_action, DefaultAction::Deny);
        assert_eq!(
            state.current_egress_policy().hosts,
            vec!["initial.example.test".to_owned()]
        );
    }

    #[test]
    fn reload_accepted_when_egress_section_is_unchanged() {
        let file = TempPolicyFile::new(&egress_policy_document("deny", "unchanged.example.test"));
        let initial_policy =
            Policy::from_file(file.path()).expect("initial policy should parse before test");
        let (state, _capture) = test_state(initial_policy, &[]);

        file.write(&egress_policy_document("allow", "unchanged.example.test"));
        reload_policy_from_file(&state, file.path())
            .expect("RBAC-only reload should be accepted when egress is unchanged");

        assert_eq!(state.current_policy().default_action, DefaultAction::Allow);
        assert_eq!(
            state.current_egress_policy().hosts,
            vec!["unchanged.example.test".to_owned()]
        );
    }

    #[test]
    fn reload_accepted_when_both_policies_have_empty_egress() {
        let file = TempPolicyFile::new(&default_policy_document("deny"));
        let initial_policy =
            Policy::from_file(file.path()).expect("initial policy should parse before test");
        let (state, _capture) = test_state(initial_policy, &[]);

        file.write(&default_policy_document("allow"));
        reload_policy_from_file(&state, file.path())
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

    fn host_route(
        methods: &[&str],
        hosts: &[&str],
        path_prefix: &str,
        permission: &str,
    ) -> RouteRule {
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
}
