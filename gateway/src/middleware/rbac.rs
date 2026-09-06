//! Route-level RBAC authorization middleware.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
#[cfg(feature = "postgres")]
use async_trait::async_trait;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{Method, StatusCode};
use notify::{RecursiveMode, Watcher};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;

use crate::{
    audit::{AuditEvent, AuditLog},
    auth::{self, actor_from_principal, protected_resource},
    client_ip::{canonical_client_ip, request_id, ClientIpPolicy},
    config::Config,
    path_match::{exempt_path_matches, is_unsafe_request_path, path_prefix_matches},
    rbac::{
        policy::ToolPolicyEntry, rule::principal_identity_matches, DefaultAction, EgressPolicy,
        EnforcementMode, Policy, PolicyEngine, RouteRule, RuleAction, RuleDecision,
        RuleDispatchContext, RuleDispatchKind, RuleMatcher,
    },
    upstream_route::{
        self, ProxyRouteAuthorizationContext, ProxyRouteClassificationCompleted,
        ProxyRouteObservationContext,
    },
};
use url::Url;

use super::{
    decision::{PolicyDecision, PolicyDecisionOutcome},
    rate_limit::RateLimitState,
};

const AUTHZ_ALLOWED: &str = "authz.allowed";
const AUTHZ_DENIED: &str = "authz.denied";
const AUTHZ_WOULD_DENY: &str = "authz.would_deny";
const POLICY_RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);

/// Why a strict security-revision check refused to let a request proceed.
/// Every variant maps to `503` with zero upstream attempts; the reason is
/// a stable audit string, never the underlying error.
#[cfg(feature = "postgres")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityRevisionCheckError {
    /// The authority could not be read (pool, connection, timeout).
    Unavailable,
    /// The local snapshot was still behind the authority when the bounded
    /// reconcile deadline passed.
    ReconcileDeadlineExceeded,
    /// The authoritative document could not be validated by this binary;
    /// a replica that cannot compile the current revision never serves it.
    InvalidDocument,
}

/// Cluster mode's strict revision check failing is neither an allow nor a
/// deny: the authority could not be consulted (or the new document could
/// not be compiled in time), so the request never reached a policy
/// decision. A distinct event type keeps that fact visible instead of
/// laundering a dependency failure into `authz.denied`.
#[cfg(feature = "postgres")]
const AUTHZ_REVISION_CHECK_FAILED: &str = "authz.revision_check_failed";

#[cfg(feature = "postgres")]
impl SecurityRevisionCheckError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "security_revision_unavailable",
            Self::ReconcileDeadlineExceeded => "security_revision_reconcile_deadline",
            Self::InvalidDocument => "security_revision_document_invalid",
        }
    }
}

/// Cluster mode's per-request security-revision gate (issue #241, PR 7).
///
/// The HA state model's strict rule: every protected request reads the
/// current security revision from the PostgreSQL primary after the request
/// starts, and the local compiled policy snapshot is usable only when it is
/// keyed by that exact revision. The implementation behind this trait
/// performs that read and, when the replica is behind, reconciles within a
/// bounded deadline (the state model's 250 ms budget) before giving up.
///
/// Absent in standalone mode: no gate, no database on the request path.
#[cfg(feature = "postgres")]
#[async_trait]
pub trait SecurityRevisionGate: Send + Sync {
    /// Prove the local compiled snapshot is current, returning the
    /// revision it is keyed by. The snapshot in `RbacState` is only valid
    /// for serving once this has returned `Ok` for the request at hand.
    async fn ensure_current_revision(&self) -> Result<i64, SecurityRevisionCheckError>;

    /// Prove the replica current and hand out the bundle of lanes
    /// published at the admitted watermark. The default (gates that do
    /// not publish bundles) admits on the revision alone, and the request
    /// then reads the live lanes.
    async fn admit(&self) -> Result<Admission, SecurityRevisionCheckError> {
        Ok(Admission {
            revision: self.ensure_current_revision().await?,
            bundle: None,
        })
    }
}

/// What the gate admitted a request under: the revision, and the
/// consistent bundle of lanes published at it (None when the gate has no
/// bundle sources, as in tests).
#[cfg(feature = "postgres")]
pub struct Admission {
    pub revision: i64,
    pub bundle: Option<Arc<crate::security_cluster::SecurityBundle>>,
}

#[cfg(feature = "postgres")]
tokio::task_local! {
    /// The policy snapshot pinned for the request being served, set when
    /// the gate admits it. Every policy read inside the request -- the
    /// middleware's own, and the tool runtime's authorization -- goes
    /// through it, so one admitted request is judged by one policy.
    static PINNED_POLICY: Arc<RbacPolicyState>;
}

/// Run `future` with `policy` pinned as the request's policy snapshot.
#[cfg(feature = "postgres")]
pub(crate) async fn with_pinned_policy<F: std::future::Future>(
    policy: Arc<RbacPolicyState>,
    future: F,
) -> F::Output {
    PINNED_POLICY.scope(policy, future).await
}

#[derive(Clone)]
pub struct RbacState {
    policy: Arc<ArcSwap<RbacPolicyState>>,
    /// Serialize policy mutations across async boundaries. The guard may be
    /// held across `.await` points (the history-append repository call), so
    /// the lock is Tokio's: its guard is `Send` and waiting does not block
    /// an executor thread. Only policy mutation/install paths contend;
    /// request-time policy reads remain lock-free.
    ///
    /// Swapping from `std::sync::Mutex` deliberately drops lock-poisoning
    /// semantics, and that is an improvement rather than a loss here. The
    /// `std` lock poisoned when a panic unwound through a policy write, and
    /// the pre-#340 acquisition sites answered poisoning with a 500 — but a
    /// poisoned lock said nothing about the store or the shared state, only
    /// that some *earlier* write panicked, and the write path's mutations are
    /// applied through swap-on-success `ArcSwap`: a panicked write leaves the
    /// last fully validated policy active, so blocking all future writes
    /// added an availability cost without a safety gain. Tokio's lock simply
    /// hands the next writer the mutex; that writer re-reads current state
    /// (`current_policy()`) under the lock rather than trusting anything the
    /// panicked writer left behind.
    policy_write_lock: Arc<Mutex<()>>,
    /// Cluster mode's strict per-request revision check. `None` in
    /// standalone mode, where the local policy file is the authority and
    /// no gate may put a database on the request path.
    #[cfg(feature = "postgres")]
    revision_gate: Option<Arc<dyn SecurityRevisionGate>>,
    /// Cluster mode's Connection control plane, so an admitted request
    /// pins the Connection snapshot it will dispatch under alongside the
    /// policy snapshot it was authorized under.
    #[cfg(feature = "postgres")]
    connections: Option<crate::connections::control_plane::ConnectionControlPlane>,
    rate_limit: Option<RateLimitState>,
    pub exempt_paths: Vec<String>,
    pub client_ip_policy: ClientIpPolicy,
    pub audit: AuditLog,
    mcp_route_paths: Vec<String>,
    proxy_dispatch_inventory: Arc<ProxyDispatchInventory>,
}

/// Proof that a caller owns this [`RbacState`]'s policy-write lane.
///
/// Mutation helpers that end in `_locked` accept this guard so admin paths
/// that already serialize prepare/commit/install can reuse the same critical
/// section without trying to acquire Tokio's non-reentrant mutex twice.
pub(crate) type PolicyWriteGuard<'a> = MutexGuard<'a, ()>;

#[derive(Default)]
struct ProxyDispatchInventory {
    enforce: bool,
    route_ids: HashSet<String>,
    migrated_catch_all_origins: HashMap<String, String>,
}

impl ProxyDispatchInventory {
    fn from_config(config: &Config) -> Self {
        let mut inventory = Self {
            enforce: true,
            ..Self::default()
        };
        if config.upstream_url.is_some() {
            inventory.route_ids.insert("legacy".to_owned());
        }
        for route in &config.upstream_routes {
            // A route without an explicit `id` still has an effective route ID:
            // the proxy derives one and publishes it as `upstream_route_id` on
            // every observation event, and the dispatch matcher compares
            // against it at runtime. Deriving it the same way here keeps
            // validation and runtime agreed on route identity, so an operator
            // can bind a rule to the ID the gateway itself reported.
            inventory.route_ids.insert(
                route
                    .id
                    .clone()
                    .unwrap_or_else(|| crate::proxy::legacy_route_id(route)),
            );
            if route.upstreams.is_empty() || route.host.is_some() || route.path_prefix.is_some() {
                continue;
            }
            let Some(route_id) = route.id.as_ref() else {
                continue;
            };
            for endpoint in &route.upstreams {
                if let Ok(url) = Url::parse(&endpoint.url) {
                    inventory
                        .migrated_catch_all_origins
                        .insert(url.origin().ascii_serialization(), route_id.clone());
                }
            }
        }
        inventory
    }

    fn validate(&self, policy: &Policy) -> Result<(), crate::rbac::policy::PolicyError> {
        if !self.enforce {
            return Ok(());
        }
        for (rule_index, rule) in policy.rules.iter().enumerate() {
            let Some(dispatch) = rule.dispatch.as_ref() else {
                continue;
            };
            match dispatch.kind {
                RuleDispatchKind::Route => {
                    let route_id = dispatch
                        .route_id
                        .as_deref()
                        .expect("validated route dispatch must have route_id");
                    if !self.route_ids.contains(route_id) {
                        return Err(crate::rbac::policy::PolicyError::Invalid(format!(
                            "rules[{rule_index}].dispatch.route_id '{route_id}' does not match a configured proxy route"
                        )));
                    }
                }
                RuleDispatchKind::Legacy => {
                    let origin = dispatch
                        .upstream_origin
                        .as_deref()
                        .and_then(|origin| Url::parse(origin).ok())
                        .map(|origin| origin.origin().ascii_serialization());
                    if let Some((origin, route_id)) = origin.as_ref().and_then(|origin| {
                        self.migrated_catch_all_origins
                            .get(origin)
                            .map(|route_id| (origin, route_id))
                    }) {
                        return Err(crate::rbac::policy::PolicyError::Invalid(format!(
                            "rules[{rule_index}].dispatch legacy origin '{origin}' is now part of catch-all pool '{route_id}'; replace it with {{\"kind\":\"route\",\"route_id\":\"{route_id}\"}} before startup or reload"
                        )));
                    }
                }
                RuleDispatchKind::Contextless => {}
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_policy_proxy_dispatch_config(
    policy: &Policy,
    config: &Config,
) -> Result<(), crate::rbac::policy::PolicyError> {
    ProxyDispatchInventory::from_config(config).validate(policy)
}

pub(crate) struct RbacPolicyState {
    engine: PolicyEngine,
    rule_matcher: RuleMatcher,
    rule_ids: Vec<String>,
    default_action: DefaultAction,
    enforcement_mode: EnforcementMode,
    routes: Vec<RouteRule>,
    /// The security revision this compiled snapshot is keyed by. `0` for
    /// file-served snapshots (standalone mode has no revisions); a cluster
    /// snapshot is only installable at the revision of the authority that
    /// produced it, and [`RbacState::install_revision_snapshot`] refuses to
    /// regress it.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    security_revision: i64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ToolPolicyEligibility {
    pub eligible: bool,
    pub reason: &'static str,
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
    /// The security revision this request's authorization decisions were
    /// served under (cluster mode only; `None` in standalone). Set once,
    /// from the snapshot the middleware actually consulted, so the audit
    /// records the revision that was in force rather than whatever is
    /// current at emit time.
    security_revision: Option<i64>,
}

impl RbacState {
    pub fn from_policy(policy: Policy, config: &Config, audit: AuditLog) -> Self {
        let mut state = Self::new_with_mcp_route_paths(
            policy,
            config.rbac_exempt_paths.clone(),
            ClientIpPolicy::from_config(config),
            audit,
            protected_resource::mcp_route_paths(config),
        );
        state.proxy_dispatch_inventory = Arc::new(ProxyDispatchInventory::from_config(config));
        state
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
            #[cfg(feature = "postgres")]
            revision_gate: None,
            #[cfg(feature = "postgres")]
            connections: None,
            rate_limit: None,
            exempt_paths,
            client_ip_policy,
            audit,
            mcp_route_paths,
            proxy_dispatch_inventory: Arc::new(ProxyDispatchInventory::default()),
        }
    }

    pub(crate) fn with_rate_limit_state(mut self, rate_limit: RateLimitState) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    /// Attach cluster mode's strict revision gate. The snapshot installed
    /// at construction is keyed by revision 0 and therefore not servable
    /// until the gate has reconciled it; production wiring calls
    /// [`RbacState::install_revision_snapshot`] with the authority's
    /// current revision before the listener serves, and the gate keeps it
    /// current afterwards.
    /// Cluster mode: the control plane whose snapshot an admitted request
    /// pins for its dispatch.
    #[cfg(feature = "postgres")]
    pub(crate) fn with_connection_control_plane(
        mut self,
        connections: crate::connections::control_plane::ConnectionControlPlane,
    ) -> Self {
        self.connections = Some(connections);
        self
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn with_revision_gate(mut self, gate: Arc<dyn SecurityRevisionGate>) -> Self {
        self.revision_gate = Some(gate);
        self
    }

    /// The policy snapshot this request is judged by: the one the gate
    /// pinned at admission (cluster mode), else the live lane.
    fn effective_policy(&self) -> Arc<RbacPolicyState> {
        #[cfg(feature = "postgres")]
        if let Ok(pinned) = PINNED_POLICY.try_with(Arc::clone) {
            return pinned;
        }
        self.policy.load_full()
    }

    /// The live policy lane, for the security runtime to capture bundles
    /// from.
    #[cfg(feature = "postgres")]
    pub(crate) fn policy_handle(&self) -> Arc<ArcSwap<RbacPolicyState>> {
        Arc::clone(&self.policy)
    }

    fn replace_policy(&self, policy: Policy) {
        if let Some(rate_limit) = &self.rate_limit {
            rate_limit.replace_policy(&policy);
        }

        self.policy
            .store(Arc::new(RbacPolicyState::from_policy(policy)));
    }

    /// Install a snapshot compiled for a specific authoritative security
    /// revision (cluster mode). The swap is monotonic: a snapshot for a
    /// revision the state already holds or has passed is a no-op, so a slow
    /// reconciler can never overwrite a newer snapshot with an older one
    /// and two racing installs converge on the higher revision.
    ///
    /// Ordinary callers acquire the same policy-write lane used by local
    /// admin mutations and overlay compilation. Admin paths that already
    /// hold that lane call [`RbacState::install_revision_snapshot_locked`]
    /// instead, avoiding a recursive lock acquisition.
    #[cfg(feature = "postgres")]
    pub(crate) async fn install_revision_snapshot(&self, policy: Policy, security_revision: i64) {
        let guard = self.policy_write_guard().await;
        self.install_revision_snapshot_locked(policy, security_revision, &guard);
    }

    /// Key the initial cluster snapshot before the state is shared or the
    /// listener starts. The fresh-state invariant makes contention a wiring
    /// bug, while `try_lock` still routes this synchronous bootstrap swap
    /// through the same policy-write lane as every runtime mutation.
    #[cfg(feature = "postgres")]
    pub(crate) fn install_initial_revision_snapshot(&self, policy: Policy, security_revision: i64) {
        let guard = self
            .policy_write_lock
            .try_lock()
            .expect("initial policy snapshot must be installed before the state is shared");
        self.install_revision_snapshot_locked(policy, security_revision, &guard);
    }

    /// Install an authoritative revision while the caller keeps the policy
    /// write lane across a larger prepare/commit/install transaction.
    #[cfg(feature = "postgres")]
    pub(crate) fn install_revision_snapshot_locked(
        &self,
        policy: Policy,
        security_revision: i64,
        _guard: &PolicyWriteGuard<'_>,
    ) {
        // One candidate Arc built up front: `Arc::ptr_eq` against the rcu's
        // result then distinguishes "this call installed the snapshot" from
        // "another install already held this revision", so a duplicate
        // install does not re-run `replace_policy` and gratuitously reset
        // the policy-lane rate-limit buckets.
        let candidate = Arc::new(RbacPolicyState::from_policy_at_revision(
            policy.clone(),
            security_revision,
        ));
        let installed = self.policy.rcu(|current| {
            if security_revision <= current.security_revision {
                // Already at or past this revision (another install won the
                // race, or this is a duplicate): keep what is installed.
                return current.clone();
            }
            candidate.clone()
        });
        if Arc::ptr_eq(&installed, &candidate) {
            if let Some(rate_limit) = &self.rate_limit {
                rate_limit.replace_policy(&policy);
            }
        }
    }

    /// The security revision the currently installed snapshot is keyed by.
    /// `0` in standalone mode, where snapshots are not revisioned.
    #[cfg(feature = "postgres")]
    pub(crate) fn snapshot_security_revision(&self) -> i64 {
        self.effective_policy().security_revision
    }

    pub fn current_policy(&self) -> Policy {
        self.policy.load().engine.policy().clone()
    }

    pub fn current_egress_policy(&self) -> EgressPolicy {
        self.policy.load().engine.policy().egress.clone()
    }

    pub(crate) async fn policy_write_guard(&self) -> PolicyWriteGuard<'_> {
        self.policy_write_lock.lock().await
    }

    pub(crate) fn validate_proxy_dispatch_policy(
        &self,
        policy: &Policy,
    ) -> Result<(), crate::rbac::policy::PolicyError> {
        self.proxy_dispatch_inventory.validate(policy)
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
        let policy = self.effective_policy();
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
        let policy = self.effective_policy();
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

    /// Previews whether the requesting principal may invoke a policy-backed
    /// tool without emitting audit events or beginning tool execution.
    ///
    /// The live policy is loaded exactly once so the tool entry and any direct
    /// tool-name rule are evaluated from the same immutable snapshot.
    pub(crate) fn tool_policy_eligibility(
        &self,
        tool_name: &str,
        principal: &auth::Principal,
    ) -> ToolPolicyEligibility {
        let policy = self.effective_policy();
        let Some(tool) = policy.tool_policy(tool_name) else {
            return ToolPolicyEligibility {
                eligible: false,
                reason: "not_in_policy",
            };
        };

        if !tool.enabled {
            return ToolPolicyEligibility {
                eligible: false,
                reason: "policy_disabled",
            };
        }

        if !tool_policy_principal_matches(tool, principal) {
            return ToolPolicyEligibility {
                eligible: false,
                reason: "principal_not_eligible",
            };
        }

        if policy
            .evaluate_tool_rule(tool_name, Some(principal))
            .is_some_and(|decision| decision.action == RuleAction::Deny)
        {
            return ToolPolicyEligibility {
                eligible: false,
                reason: "policy_denied",
            };
        }

        ToolPolicyEligibility {
            eligible: true,
            reason: "eligible",
        }
    }
}

fn tool_policy_principal_matches(
    tool: ToolPolicySnapshot<'_>,
    principal: &auth::Principal,
) -> bool {
    principal_identity_matches(tool.issuers, tool.auth_methods, principal)
        && (tool.allowed_roles.is_empty()
            || tool
                .allowed_roles
                .iter()
                .any(|allowed_role| principal.roles.iter().any(|role| role == allowed_role)))
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
            security_revision: 0,
        }
    }

    /// The cluster-mode constructor: a compiled snapshot keyed by the
    /// authoritative security revision it was built for.
    #[cfg(feature = "postgres")]
    fn from_policy_at_revision(policy: Policy, security_revision: i64) -> Self {
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
            security_revision,
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

pub async fn reload_policy_from_file(
    state: &RbacState,
    path: impl AsRef<Path>,
) -> Result<(), crate::rbac::policy::PolicyError> {
    let guard = state.policy_write_guard().await;
    reload_policy_from_file_locked(state, path, &guard)
}

/// Reload a file-backed policy while the caller already owns the policy
/// write lane. This is used by the admin persistence path, which holds the
/// lane across its precondition check, durable write, live install, history,
/// and audit publication.
pub(crate) fn reload_policy_from_file_locked(
    state: &RbacState,
    path: impl AsRef<Path>,
    _guard: &PolicyWriteGuard<'_>,
) -> Result<(), crate::rbac::policy::PolicyError> {
    let path = path.as_ref();

    match Policy::from_file(path) {
        Ok(policy) => {
            state.validate_proxy_dispatch_policy(&policy)?;
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

#[cfg(test)]
pub fn spawn_policy_reload_tasks(
    policy_file: impl Into<PathBuf>,
    state: RbacState,
) -> notify::Result<()> {
    let cancellation = CancellationToken::new();
    spawn_policy_reload_tasks_inner(policy_file.into(), state, cancellation, None)
}

pub fn spawn_policy_reload_tasks_with_lifecycle(
    policy_file: impl Into<PathBuf>,
    state: RbacState,
    lifecycle: &crate::lifecycle::GatewayLifecycle,
) -> notify::Result<()> {
    spawn_policy_reload_tasks_inner(
        policy_file.into(),
        state,
        lifecycle.background_cancellation(),
        Some(lifecycle),
    )
}

fn spawn_policy_reload_tasks_inner(
    policy_file: PathBuf,
    state: RbacState,
    cancellation: CancellationToken,
    lifecycle: Option<&crate::lifecycle::GatewayLifecycle>,
) -> notify::Result<()> {
    let watcher =
        spawn_policy_file_watcher(policy_file.clone(), state.clone(), cancellation.clone())?;
    let sighup = spawn_sighup_reload_task(policy_file, state, cancellation);
    if let Some(lifecycle) = lifecycle {
        lifecycle.register_background_task(watcher);
        if let Some(sighup) = sighup {
            lifecycle.register_background_task(sighup);
        }
    }
    Ok(())
}

fn spawn_policy_file_watcher(
    policy_file: PathBuf,
    state: RbacState,
    cancellation: CancellationToken,
) -> notify::Result<tokio::task::JoinHandle<()>> {
    let (sender, receiver) = mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = sender.send(event);
    })?;
    watcher.watch(&watch_directory(&policy_file), RecursiveMode::NonRecursive)?;

    Ok(tokio::spawn(policy_file_watch_loop(
        policy_file,
        state,
        receiver,
        watcher,
        cancellation,
    )))
}

async fn policy_file_watch_loop(
    policy_file: PathBuf,
    state: RbacState,
    mut events: mpsc::UnboundedReceiver<notify::Result<notify::Event>>,
    _watcher: notify::RecommendedWatcher,
    cancellation: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            event = events.recv() => event,
            () = cancellation.cancelled() => return,
        };
        let Some(event) = event else {
            return;
        };
        if !handle_policy_watch_event(&policy_file, event) {
            continue;
        }

        tokio::select! {
            () = tokio::time::sleep(POLICY_RELOAD_DEBOUNCE) => {}
            () = cancellation.cancelled() => return,
        }
        while let Ok(event) = events.try_recv() {
            let _ = handle_policy_watch_event(&policy_file, event);
        }

        let _ = reload_policy_from_file(&state, &policy_file).await;
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
fn spawn_sighup_reload_task(
    policy_file: PathBuf,
    state: RbacState,
    cancellation: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    Some(tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(err) => {
                tracing::error!(error = %err, "failed to register SIGHUP policy reload handler");
                return;
            }
        };

        loop {
            let signal = tokio::select! {
                signal = sighup.recv() => signal,
                () = cancellation.cancelled() => return,
            };
            if signal.is_none() {
                return;
            }
            let _ = reload_policy_from_file(&state, &policy_file).await;
        }
    }))
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(
    _policy_file: PathBuf,
    _state: RbacState,
    _cancellation: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    None
}

/// `next.run(req)` with the request's Connection snapshot pinned (cluster
/// mode) or without one (standalone, or an exempt path that skipped the
/// gate).
#[cfg(feature = "postgres")]
async fn run_pinned(
    pinned: Option<Arc<crate::connections::control_plane::ConnectionRuntimeSnapshot>>,
    bundle: Option<Arc<crate::security_cluster::SecurityBundle>>,
    next: Next,
    req: Request,
) -> Response {
    let run = async move {
        match pinned {
            Some(snapshot) => {
                crate::connections::http::with_pinned_connections(snapshot, next.run(req)).await
            }
            None => next.run(req).await,
        }
    };
    match bundle {
        Some(bundle) => {
            let policy = Arc::clone(&bundle.policy);
            let tools = Arc::clone(&bundle.tools);
            with_pinned_policy(
                policy,
                crate::tools::definitions::with_pinned_tools(tools, run),
            )
            .await
        }
        None => run.await,
    }
}

#[cfg(not(feature = "postgres"))]
async fn run_pinned(
    _pinned: Option<Arc<()>>,
    _bundle: Option<Arc<()>>,
    next: Next,
    req: Request,
) -> Response {
    next.run(req).await
}

pub async fn rbac_middleware(State(state): State<RbacState>, req: Request, next: Next) -> Response {
    // Pinned for the whole request once the gate admits it (cluster mode):
    // the proxy and the tool executor resolve every Connection target from
    // this snapshot, never from one a later reconcile installed mid-flight.
    #[cfg(feature = "postgres")]
    #[cfg(feature = "postgres")]
    let mut admitted_bundle: Option<Arc<crate::security_cluster::SecurityBundle>> = None;
    #[cfg(not(feature = "postgres"))]
    let admitted_bundle: Option<Arc<()>> = None;
    #[cfg(feature = "postgres")]
    let mut pinned_connections: Option<
        Arc<crate::connections::control_plane::ConnectionRuntimeSnapshot>,
    > = None;
    #[cfg(not(feature = "postgres"))]
    let pinned_connections: Option<Arc<()>> = None;
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
            .any(|exempt_path| exempt_path_matches(path, exempt_path))
    {
        return next.run(req).await;
    }

    #[cfg_attr(not(feature = "postgres"), allow(unused_mut))]
    let mut context = audit_context(&req, &state.client_ip_policy);
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
        RuleDispatchContext::classified_with_route_id(
            context.route_id.as_deref(),
            context.route_host.as_deref(),
            context.route_path_prefix.as_deref(),
            Some(context.upstream_origin.as_str()),
        )
    } else {
        RuleDispatchContext::contextless()
    };

    // Cluster mode's strict revision check (issue #241): this request may
    // consult the local compiled snapshot only if it is keyed by the
    // authority's current security revision. A failed check is `503` with
    // zero upstream attempts -- never a `401`/`403` (a dependency failure
    // is not a policy decision), and never a stale allow.
    #[cfg(feature = "postgres")]
    let mut served_security_revision: Option<i64> = None;
    #[cfg(feature = "postgres")]
    if let Some(gate) = state.revision_gate.as_ref() {
        match gate.admit().await {
            Ok(admission) => {
                served_security_revision = Some(admission.revision);
                admitted_bundle = admission.bundle;
            }
            Err(error) => {
                emit_revision_check_failed(&state, &context, principal.as_ref(), error);
                return with_policy_decision(
                    service_unavailable_response(),
                    PolicyDecision {
                        outcome: PolicyDecisionOutcome::Denied,
                        reason: error.as_str(),
                        permission: None,
                        path_prefix: None,
                        matched_rule_id: None,
                    },
                );
            }
        }
    }

    #[cfg(feature = "postgres")]
    if served_security_revision.is_some() {
        // The bundle's Connection snapshot when the gate published one:
        // the same cut the policy below comes from. A gate without
        // bundle sources pins the live snapshot, as before.
        pinned_connections = admitted_bundle
            .as_ref()
            .map(|bundle| Arc::clone(&bundle.connections))
            .or_else(|| {
                state
                    .connections
                    .as_ref()
                    .map(|control_plane| control_plane.runtime_snapshot())
            });
    }
    // The policy this request is judged by: the bundle's, published with
    // the watermark the gate admitted at -- never a lane a concurrent
    // reconcile may have swapped since.
    #[cfg(feature = "postgres")]
    let policy: Arc<RbacPolicyState> = match admitted_bundle.as_ref() {
        Some(bundle) => Arc::clone(&bundle.policy),
        None => state.policy.load_full(),
    };
    #[cfg(not(feature = "postgres"))]
    let policy = state.policy.load();
    // Record the revision this request actually serves under: the compiled
    // watermark the gate proved current for this request, covering every
    // shared-security resource (policy, tools, ...), not just this
    // snapshot's own key.
    #[cfg(feature = "postgres")]
    {
        context.security_revision = served_security_revision;
    }
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
                let response = run_pinned(
                    pinned_connections.clone(),
                    admitted_bundle.clone(),
                    next,
                    req,
                )
                .await;
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
                let response = run_pinned(
                    pinned_connections.clone(),
                    admitted_bundle.clone(),
                    next,
                    req,
                )
                .await;
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
            let response = run_pinned(
                pinned_connections.clone(),
                admitted_bundle.clone(),
                next,
                req,
            )
            .await;
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
                let response = run_pinned(
                    pinned_connections.clone(),
                    admitted_bundle.clone(),
                    next,
                    req,
                )
                .await;
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
            let response = run_pinned(
                pinned_connections.clone(),
                admitted_bundle.clone(),
                next,
                req,
            )
            .await;
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
                let response = run_pinned(
                    pinned_connections.clone(),
                    admitted_bundle.clone(),
                    next,
                    req,
                )
                .await;
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
        security_revision: None,
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
    let mut payload = match rule {
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
    apply_security_revision(&mut payload, context);

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
    let mut payload = json!({
        "path": &context.path,
        "method": &context.method,
        "reason": reason,
        "matched_rule_id": matched_rule_id,
    });
    apply_security_revision(&mut payload, context);

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
    let mut payload = match rule {
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
    apply_security_revision(&mut payload, context);

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
    let mut payload = json!({
        "path": &context.path,
        "method": &context.method,
        "reason": "host_policy_required",
        "upstream_host": &proxy_context.host,
        "upstream_path_prefix": &proxy_context.path_prefix,
        "upstream_origin": &proxy_context.upstream_origin,
    });
    apply_security_revision(&mut payload, context);

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

/// The strict revision check's fail-closed response. Deliberately carries
/// no detail beyond a stable reason: the failure is a dependency state,
/// not a policy decision, and the underlying store error never crosses
/// the response boundary.
#[cfg(feature = "postgres")]
fn service_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ForbiddenBody {
            error: "policy state unavailable",
        }),
    )
        .into_response()
}

/// Append the served revision to an authorization event's payload when one
/// is in force (cluster mode). Keeping it in the payload -- not just the
/// logs -- is what makes "which revision authorized this request" answerable
/// from the durable audit trail alone.
fn apply_security_revision(payload: &mut Value, context: &AuditContext) {
    if let Some(revision) = context.security_revision {
        if let Some(object) = payload.as_object_mut() {
            object.insert("security_revision".to_owned(), Value::from(revision));
        }
    }
}

#[cfg(feature = "postgres")]
fn emit_revision_check_failed(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    error: SecurityRevisionCheckError,
) {
    let actor = principal.map(actor_from_principal);
    let mut payload = json!({
        "path": &context.path,
        "method": &context.method,
        "reason": error.as_str(),
        "outcome": "service_unavailable",
    });
    apply_security_revision(&mut payload, context);

    state.audit.emit(AuditEvent::new(
        AUTHZ_REVISION_CHECK_FAILED,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ));
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
    // An endpoint may apply a narrower permission than the outer route.
    if response.extensions().get::<PolicyDecision>().is_none() {
        response.extensions_mut().insert(decision);
    }
    response
}

#[cfg(test)]
#[path = "rbac_tests.rs"]
mod tests;
