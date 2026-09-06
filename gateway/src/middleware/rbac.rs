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
        policy_file.write(
            &serde_json::to_string(&unbound_policy).expect("unbound policy should serialize"),
        );
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

        policy_file
            .write(&serde_json::to_string(&host_policy).expect("host policy should serialize"));
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
}
