//! Route-level RBAC authorization middleware.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(test)]
use crate::rbac::{DefaultAction, EnforcementMode, PolicyEngine, RuleDispatchContext, RuleMatcher};
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
    audit::{AuditEvent, AuditLog, AuditReceipt, AuditUnavailable},
    auth::{self, actor_from_principal, protected_resource},
    authority_events::required::{AuthorityOperation, BackgroundEvidenceGate},
    client_ip::{canonical_client_ip, request_id, ClientIpPolicy},
    config::Config,
    path_match::{exempt_path_matches, is_unsafe_request_path},
    policy_eval::{
        tools::{
            ToolEvaluation, ToolEvaluationContext, ToolLimitation, ToolOperation, ToolReason,
            TOOL_CONTEXT_VERSION,
        },
        EvaluationError, LogicalDecision, PolicyEffect, PrincipalFact, PrincipalIdentity,
        RuleReference,
    },
    rbac::{
        policy::ToolPolicyEntry, EgressPolicy, Policy, RouteRule, RuleAction, RuleDispatchKind,
    },
    request_bounds::MAX_TOOL_NAME_BYTES,
    upstream_route::{
        self, ProxyRouteAuthorizationContext, ProxyRouteClassificationCompleted,
        ProxyRouteObservationContext,
    },
};
use url::Url;

use super::{
    decision::{
        audit_unavailable_response, PolicyDecision, PolicyDecisionOutcome, AUDIT_UNAVAILABLE_REASON,
    },
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

tokio::task_local! {
    /// The policy snapshot pinned for the request being served. Cluster mode
    /// sets it when the revision gate admits a request with a published
    /// bundle; [`RbacState::with_request_policy_snapshot`] sets it for a check
    /// whose reads must agree with one another in either mode.
    ///
    /// It covers the reads made through [`RbacState::effective_policy`] in the
    /// pinning task: the tool lane (invocation, visibility, inventory
    /// eligibility, composite enablement, the rendered HTTP rule) and delegated
    /// role checks. It does not cover everything. The middleware judges the
    /// request by `bundle.policy` directly, before the pin is installed around
    /// the rest of the request. The management lane
    /// ([`RbacState::principal_has_permission`]) and the admin read-modify-write
    /// baselines ([`RbacState::current_policy`]) read the live lane on purpose.
    /// A task the request spawns does not inherit the pin: work served from
    /// such a task re-enters it with [`with_request_pins`].
    static PINNED_POLICY: Arc<RbacPolicyState>;
}

/// Run `future` with `policy` pinned as the request's policy snapshot.
pub(crate) async fn with_pinned_policy<F: std::future::Future>(
    policy: Arc<RbacPolicyState>,
    future: F,
) -> F::Output {
    PINNED_POLICY.scope(policy, future).await
}

/// The policy snapshot pinned for the running task, if one is.
///
/// [`RbacState::effective_policy`] answers from it before the live lane, and
/// so does the rate stage, which binds its lane selection to it (see
/// `rate_limit::RateLimitPolicyState::select`).
pub(crate) fn pinned_policy_snapshot() -> Option<Arc<RbacPolicyState>> {
    PINNED_POLICY.try_with(Arc::clone).ok()
}

/// The snapshots the revision gate pinned for one admitted request: the
/// Connection snapshot it dispatches under and the bundle of lanes it is
/// judged by. The pins are task-locals, which a spawned task does not
/// inherit, so [`rbac_middleware`] also hands them to the request as an
/// extension for [`with_request_pins`] to re-enter.
#[cfg(feature = "postgres")]
#[derive(Clone)]
pub(crate) struct RequestPins {
    connections: Option<Arc<crate::connections::control_plane::ConnectionRuntimeSnapshot>>,
    bundle: Option<Arc<crate::security_cluster::SecurityBundle>>,
}

#[cfg(feature = "postgres")]
impl RequestPins {
    /// Run `future` with these snapshots pinned.
    async fn scope<F: std::future::Future>(self, future: F) -> F::Output {
        let Self {
            connections,
            bundle,
        } = self;
        let run = async move {
            match connections {
                Some(snapshot) => {
                    crate::connections::http::with_pinned_connections(snapshot, future).await
                }
                None => future.await,
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
}

/// Run `future` under the snapshots pinned for the request these extensions
/// belong to, for work the request's handler serves from a task it did not
/// run in itself.
///
/// rmcp's Streamable HTTP service is such a handler: it serves every `/mcp`
/// JSON-RPC request from a task it spawns. There the pins
/// [`rbac_middleware`] set are gone, every lane read falls back to the live
/// lane, and a reconcile landing between two of one tool call's checks would
/// have them judged by two revisions (#422). Re-entering the pins here puts
/// those reads back on the admitted snapshots. Without pins (standalone mode,
/// an exempt path, no extensions) `future` reads the live lanes, as the
/// request's own task would.
#[cfg(feature = "postgres")]
pub(crate) async fn with_request_pins<F: std::future::Future>(
    extensions: Option<&http::Extensions>,
    future: F,
) -> F::Output {
    match extensions.and_then(|extensions| extensions.get::<RequestPins>()) {
        Some(pins) => pins.clone().scope(future).await,
        None => future.await,
    }
}

#[cfg(not(feature = "postgres"))]
pub(crate) async fn with_request_pins<F: std::future::Future>(
    _extensions: Option<&http::Extensions>,
    future: F,
) -> F::Output {
    future.await
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
    /// The resources a policy is validated against before it is published
    /// (issue #243, slice 8), attached once at startup. A state built without
    /// them validates with every one reported unavailable.
    policy_resources: Option<Arc<crate::rbac::policy_resources::PolicyResourceSources>>,
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
    /// The pre-cutover permission engine, direct-rule matcher, default,
    /// enforcement mode and route vector, kept only for the frozen
    /// differential oracles in `legacy`. They are copies of their own, so a
    /// differential test compares the compiled instance with something other
    /// than itself. Every serving decision, audit attribution and management
    /// permission reads `compiled`.
    #[cfg(test)]
    engine: PolicyEngine,
    #[cfg(test)]
    rule_matcher: RuleMatcher,
    /// Derived from `compiled`'s own direct rules; see [`Self::rule_ids`].
    rule_ids: Vec<String>,
    #[cfg(test)]
    default_action: DefaultAction,
    #[cfg(test)]
    enforcement_mode: EnforcementMode,
    #[cfg(test)]
    routes: Vec<RouteRule>,
    /// The security revision this compiled snapshot is keyed by. `0` for
    /// file-served snapshots (standalone mode has no revisions); a cluster
    /// snapshot is only installable at the revision of the authority that
    /// produced it, and [`RbacState::install_revision_snapshot`] refuses to
    /// regress it.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    security_revision: i64,
    /// The same policy compiled for the pure kernel, built once per install.
    ///
    /// It lives here rather than on [`RbacState`] deliberately. A request is
    /// judged by the snapshot the revision gate admitted -- `bundle.policy`, not
    /// `state.policy` -- so a compiled policy held one level up could be the
    /// wrong one under a concurrent reconcile, which is exactly the
    /// facts-from-two-snapshots mistake #422 forbids. Held here it cannot
    /// disagree with the snapshot it belongs to, and compiling once per install
    /// keeps three parses and a digest off the request path.
    ///
    /// The HTTP and tool-lane adapters use this instance for every decision,
    /// and resolve every rule and route reference it returns against this
    /// same instance. The management lane asks its permission engine.
    compiled: crate::policy_eval::CompiledPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MatchedRuleDecision {
    pub action: RuleAction,
    pub matched_rule_id: String,
}

/// A tool invocation decided by the shared evaluator over one policy snapshot,
/// with the snapshot data the runtime needs to act on it.
pub(crate) struct ToolInvocationAuthorization<'a> {
    /// Every tool entry the snapshot names, so the runtime can prune the
    /// limiters of tools the policy no longer carries.
    pub tools: &'a HashMap<String, ToolPolicyEntry>,
    pub verdict: ToolInvocationVerdict<'a>,
}

/// The evaluator's invocation answer, translated for the runtime. Each variant
/// keeps the runtime's existing error and audit vocabulary.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToolInvocationVerdict<'a> {
    /// The policy entry exists, is enabled and admits the caller's identity,
    /// and `tool` is that entry, read from the instance that judged it. The
    /// outcome is then `rule_decision`: the first matching tool-name rule,
    /// whose action is the evaluator's effect -- allow, deny, or a shadow
    /// observation -- for the runtime to audit and enforce. No rule allows.
    Entry {
        tool: &'a ToolPolicyEntry,
        rule_decision: Option<MatchedRuleDecision>,
    },
    UnknownTool,
    Disabled,
    RoleNotAllowed {
        allowed_roles: &'a [String],
    },
    /// No decision: blocked, whatever the policy's enforcement mode.
    Refused(ToolPolicyRefusal),
}

/// Why the tool lane refused to answer rather than decide.
///
/// Every variant blocks, in shadow mode too, as an incomplete or refused HTTP
/// evaluation does (#422).
///
/// Policy validation refuses a policy tool name over [`MAX_TOOL_NAME_BYTES`],
/// so no policy can name a tool the evaluator cannot be asked about: a longer
/// name could only ever be unknown to the policy, and refusing it blocks it as
/// unknown would. Discovered MCP and OpenAPI tool names are bounded at 128
/// characters, but a `TOOLS_FILE` definition's name is bounded only by that
/// file's size cap, so a call to such a local tool is the one served call that
/// reaches [`ToolPolicyRefusal::NameOutOfBounds`]. The other variants are not
/// reachable from a served call: tool rendering refuses a method or path the
/// evaluator would refuse, and an authenticated principal has passed the same
/// shape check the evaluator applies. The reason is a stable code; diagnostics
/// are bounded enums, never a name, path or identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolPolicyRefusal {
    /// A tool name over [`MAX_TOOL_NAME_BYTES`], refused before evaluation.
    NameOutOfBounds,
    /// The evaluator lacked a fact it needed.
    Incomplete(Option<ToolLimitation>),
    /// The evaluator refused the question, or its answer could not be
    /// attributed to the snapshot it came from.
    Error(EvaluationError),
}

impl ToolPolicyRefusal {
    /// Every refusal's stable reason, for a consumer that sees only the reason
    /// a runtime rejection carries and must still recognize a policy block.
    pub(crate) const REASONS: [&'static str; 3] = [
        "tool_name_out_of_bounds",
        "policy_evaluation_incomplete",
        "policy_evaluation_error",
    ];

    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::NameOutOfBounds => Self::REASONS[0],
            Self::Incomplete(_) => Self::REASONS[1],
            Self::Error(_) => Self::REASONS[2],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct ToolPolicyEligibility {
    pub eligible: bool,
    pub reason: &'static str,
}

/// One policy snapshot's inventory eligibility answers, for a caller that
/// previews many tools and must not straddle a policy install between them.
pub(crate) struct ToolEligibilitySnapshot(Arc<RbacPolicyState>);

impl ToolEligibilitySnapshot {
    /// Whether `principal` may invoke `tool_name` under this snapshot, without
    /// emitting audit events or beginning execution. A shadow rule leaves a tool
    /// eligible; a refusal is ineligible with the refusal's reason.
    pub(crate) fn eligibility(
        &self,
        tool_name: &str,
        principal: &auth::Principal,
    ) -> ToolPolicyEligibility {
        match self.0.evaluate_tool(
            ToolOperation::PolicyEligibility,
            tool_name,
            principal_fact(Some(principal)),
            None,
        ) {
            Ok(evaluation) => ToolPolicyEligibility {
                eligible: evaluation.effect() == PolicyEffect::Allow,
                reason: evaluation.reason().as_str(),
            },
            Err(refusal) => ToolPolicyEligibility {
                eligible: false,
                reason: refusal.reason(),
            },
        }
    }
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

    pub(crate) fn new_with_mcp_route_paths(
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
            policy_resources: None,
        }
    }

    /// Attach the resources a candidate policy is validated against before
    /// publication. Every clone made afterwards shares them.
    pub(crate) fn with_policy_resources(
        mut self,
        sources: crate::rbac::policy_resources::PolicyResourceSources,
    ) -> Self {
        self.policy_resources = Some(Arc::new(sources));
        self
    }

    /// What the policy resources say now, read once, for one validation.
    pub(crate) fn policy_resource_view(&self) -> crate::rbac::policy_resources::PolicyResourceView {
        let security_revision = self.cluster_security_revision();
        match self.policy_resources.as_deref() {
            Some(sources) => sources.read(
                self.rbac_exempts_path(&sources.policy_route),
                security_revision,
            ),
            None => crate::rbac::policy_resources::PolicyResourceView {
                security_revision,
                ..crate::rbac::policy_resources::PolicyResourceView::default()
            },
        }
    }

    /// Whether the RBAC stage lets a gateway-owned request for `path` through
    /// without evaluating policy: the exemption [`rbac_middleware`] applies to
    /// a request that was not classified as a proxy dispatch. An exact MCP
    /// route is never exempt, whatever prefix encloses it.
    pub(crate) fn rbac_exempts_path(&self, path: &str) -> bool {
        !self.is_mcp_route_path(path)
            && self
                .exempt_paths
                .iter()
                .any(|exempt_path| exempt_path_matches(path, exempt_path))
    }

    /// The security revision of the installed snapshot in cluster mode;
    /// standalone snapshots have none.
    fn cluster_security_revision(&self) -> Option<i64> {
        #[cfg(feature = "postgres")]
        if self.revision_gate.is_some() {
            return Some(self.policy.load().security_revision);
        }
        None
    }

    /// Attach the rate stage, which from now on selects policy rate lanes with
    /// the compiled instance of every snapshot this state installs, paired with
    /// token buckets built for that snapshot. The snapshot installed right now
    /// is handed over first, so the stage never selects with a copy.
    pub(crate) fn with_rate_limit_state(mut self, rate_limit: RateLimitState) -> Self {
        rate_limit.install_policy_snapshot(self.policy.load_full(), &self.audit);
        self.rate_limit = Some(rate_limit);
        self
    }

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

    /// Attach cluster mode's strict revision gate. The snapshot installed
    /// at construction is keyed by revision 0 and therefore not servable
    /// until the gate has reconciled it; production wiring calls
    /// [`RbacState::install_revision_snapshot`] with the authority's
    /// current revision before the listener serves, and the gate keeps it
    /// current afterwards.
    #[cfg(feature = "postgres")]
    pub(crate) fn with_revision_gate(mut self, gate: Arc<dyn SecurityRevisionGate>) -> Self {
        self.revision_gate = Some(gate);
        self
    }

    /// The compiled kernel of the snapshot a request would be judged by right
    /// now, for the differential tests.
    ///
    /// They compare the kernel against the live middleware, and this is what
    /// makes the claim about the instance production consults rather than about a
    /// separately compiled copy of the same policy. A copy would agree with the
    /// middleware while the installed one diverged, and the tests would not say
    /// so.
    #[cfg(test)]
    pub(crate) fn installed_compiled_policy(&self) -> Arc<RbacPolicyState> {
        self.effective_policy()
    }

    /// The policy snapshot this request is judged by: the one pinned for it
    /// (by the gate at admission in cluster mode, or by
    /// [`RbacState::with_request_policy_snapshot`]), else the live lane.
    fn effective_policy(&self) -> Arc<RbacPolicyState> {
        pinned_policy_snapshot().unwrap_or_else(|| self.policy.load_full())
    }

    /// Run `future` with the request's policy snapshot pinned, so every
    /// [`RbacState::effective_policy`] read inside it -- the tool lane and
    /// [`RbacState::request_snapshot_grants_permission`] -- answers from one
    /// snapshot. In cluster mode that is the snapshot already pinned at
    /// admission; in standalone mode it is the live lane, read once here. A
    /// check made of several such reads cannot then straddle a policy install
    /// and be answered by two snapshots (#422).
    ///
    /// The tool runtime runs every invocation inside it, from admission through
    /// the queue wait to the rendered request, so one invocation is never judged
    /// by two snapshots in either mode. Every MCP `tools/list` listing runs
    /// inside it too, so no listing is either.
    pub(crate) async fn with_request_policy_snapshot<F: std::future::Future>(
        &self,
        future: F,
    ) -> F::Output {
        with_pinned_policy(self.effective_policy(), future).await
    }

    /// Run `check` against the live policy lane, even inside a pinned scope.
    ///
    /// Only for a final check that can refuse what the pinned snapshot has
    /// already allowed, never for one that grants: the admin playground's last
    /// rendered-HTTP check, made after its execution precondition, so that a
    /// deny published while the precondition ran still stops the call. Every
    /// decision that grants is made from one pinned snapshot first, so pairing
    /// it with a refusal from a newer one cannot allow what neither allows.
    pub(crate) fn with_live_policy<R>(&self, check: impl FnOnce() -> R) -> R {
        PINNED_POLICY.sync_scope(self.policy.load_full(), check)
    }

    /// The live policy lane, for the security runtime to capture bundles
    /// from.
    #[cfg(feature = "postgres")]
    pub(crate) fn policy_handle(&self) -> Arc<ArcSwap<RbacPolicyState>> {
        Arc::clone(&self.policy)
    }

    fn replace_policy(&self, policy: Policy) {
        let snapshot = Arc::new(RbacPolicyState::from_policy(policy));
        if let Some(rate_limit) = &self.rate_limit {
            rate_limit.install_policy_snapshot(Arc::clone(&snapshot), &self.audit);
        }

        self.policy.store(snapshot);
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
    pub(crate) async fn install_revision_snapshot(
        &self,
        policy: Policy,
        security_revision: i64,
    ) -> Result<(), crate::policy_eval::CompileError> {
        let guard = self.policy_write_guard().await;
        self.install_revision_snapshot_locked(policy, security_revision, &guard)
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
        // Refusing to start beats starting into a gate that answers 503 forever
        // with nothing saying why: a corrupt authority row is a wiring failure.
        self.install_revision_snapshot_locked(policy, security_revision, &guard)
            .expect("the authority's initial revision must be installable");
    }

    /// Install an authoritative revision while the caller keeps the policy
    /// write lane across a larger prepare/commit/install transaction.
    #[cfg(feature = "postgres")]
    pub(crate) fn install_revision_snapshot_locked(
        &self,
        policy: Policy,
        security_revision: i64,
        _guard: &PolicyWriteGuard<'_>,
    ) -> Result<(), crate::policy_eval::CompileError> {
        // A candidate that cannot be compiled is refused before the swap, so the
        // installed snapshot keeps serving. The monotonic guard below would have
        // discarded an impossible revision anyway; refusing here is what makes
        // that visible to the caller instead of silent.
        let candidate = Arc::new(RbacPolicyState::from_policy_at_revision(
            policy,
            security_revision,
        )?);
        let replaced = self.policy.rcu(|current| {
            if security_revision <= current.security_revision {
                // Already at or past this revision (another install won the
                // race, or this is a duplicate): keep what is installed.
                return current.clone();
            }
            candidate.clone()
        });
        // `rcu` returns the snapshot its successful round replaced -- the one
        // that round judged, not the one it installed -- so this call installed
        // the candidate exactly when that snapshot was behind it. Only then is
        // the rate stage handed the candidate: a duplicate install must not
        // reset the policy-lane buckets, and a real one must not leave the rate
        // stage selecting with the previous revision.
        if security_revision > replaced.security_revision {
            if let Some(rate_limit) = &self.rate_limit {
                rate_limit.install_policy_snapshot(candidate, &self.audit);
            }
        }
        Ok(())
    }

    /// The security revision the currently installed snapshot is keyed by.
    /// `0` in standalone mode, where snapshots are not revisioned.
    #[cfg(feature = "postgres")]
    pub(crate) fn snapshot_security_revision(&self) -> i64 {
        self.effective_policy().security_revision
    }

    pub fn current_policy(&self) -> Policy {
        self.policy.load().compiled.engine().policy().clone()
    }

    /// The live lane's installed snapshot, which [`RbacState::current_policy`]
    /// copies, for the admin analysis consumers: endpoint coverage asks its
    /// compiled kernel, and rule hit counts key by its rule attribution ids.
    /// The same instance live requests are judged by, not a recompilation of
    /// a copy of it.
    pub(crate) fn live_policy_snapshot(&self) -> Arc<RbacPolicyState> {
        self.policy.load_full()
    }

    pub fn current_egress_policy(&self) -> EgressPolicy {
        self.policy.load().compiled.engine().policy().egress.clone()
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
            .compiled
            .principal_has_permission(principal, permission)
    }

    /// [`RbacState::principal_has_permission`] judged by the request's policy
    /// snapshot rather than the live lane, for a check that must agree with
    /// the tool-lane decisions made beside it. The management lane itself keeps
    /// reading live.
    pub(crate) fn request_snapshot_grants_permission(
        &self,
        principal: &auth::Principal,
        permission: &str,
    ) -> bool {
        self.effective_policy()
            .compiled
            .principal_has_permission(principal, permission)
    }

    /// Returns requested delegated roles that the principal cannot activate.
    /// Wildcard principals may delegate any role. The request's policy
    /// snapshot is read once so the wildcard and per-role decisions use the
    /// same snapshot.
    pub fn disallowed_delegated_roles(
        &self,
        principal: &auth::Principal,
        requested_roles: &[String],
    ) -> Vec<String> {
        let policy = self.effective_policy();
        let engine = policy.compiled.engine();
        let principal = policy.compiled.management_principal(principal);
        if engine.principal_has_wildcard(&principal) {
            return Vec::new();
        }

        requested_roles
            .iter()
            .filter(|role| !engine.principal_has_active_role(&principal, role))
            .cloned()
            .collect()
    }

    fn is_mcp_route_path(&self, path: &str) -> bool {
        self.mcp_route_paths
            .iter()
            .any(|route_path| path == route_path)
    }

    /// The request paths that reach an MCP endpoint by an alias: every MCP
    /// route path but the canonical one, each evaluated as an alias pair. The
    /// policy analyzer reads them, because an alias request selects the route
    /// whose prefix equals its path before any broader route.
    pub(crate) fn mcp_alias_paths(&self) -> Vec<String> {
        self.mcp_route_paths
            .iter()
            .filter(|path| path.as_str() != protected_resource::MCP_RESOURCE_PATH)
            .cloned()
            .collect()
    }

    fn policy_path_for_request<'a>(&'a self, path: &'a str) -> &'a str {
        if path != protected_resource::MCP_RESOURCE_PATH && self.is_mcp_route_path(path) {
            protected_resource::MCP_RESOURCE_PATH
        } else {
            path
        }
    }

    /// Decide one tool invocation with the shared evaluator, over the request's
    /// policy snapshot, and hand the verdict to `evaluate` along with that
    /// snapshot's tool entries.
    ///
    /// `principal` is the identity the caller projects, which for the tool
    /// runtime is its Actor projection, not necessarily the inbound principal.
    pub(crate) fn evaluate_tool_authorization<R>(
        &self,
        tool_name: &str,
        principal: Option<&auth::Principal>,
        evaluate: impl FnOnce(ToolInvocationAuthorization<'_>) -> R,
    ) -> R {
        let policy = self.effective_policy();
        let verdict = policy.tool_invocation_verdict(tool_name, principal);
        evaluate(ToolInvocationAuthorization {
            tools: policy.compiled.tool_entries(),
            verdict,
        })
    }

    /// Whether a tool is listed to `principal`, decided by the shared evaluator.
    /// A shadow rule does not hide a tool. A refusal hides it.
    pub(crate) fn tool_visible(
        &self,
        tool_name: &str,
        principal: Option<&auth::Principal>,
    ) -> bool {
        self.effective_policy()
            .evaluate_tool(
                ToolOperation::Visibility,
                tool_name,
                principal_fact(principal),
                None,
            )
            .is_ok_and(|evaluation| evaluation.effect() == PolicyEffect::Allow)
    }

    /// Whether a leaf run under an already-admitted composite grant is enabled.
    /// Only the policy entry's enable bit decides: the grant has already
    /// answered for identity, tool rules and admission, so no identity is
    /// supplied. A refusal is not enabled.
    pub(crate) fn composite_leaf_enabled(&self, tool_name: &str) -> bool {
        self.effective_policy()
            .evaluate_tool(
                ToolOperation::CompositeLeaf,
                tool_name,
                PrincipalFact::Missing,
                None,
            )
            .is_ok_and(|evaluation| evaluation.effect() == PolicyEffect::Allow)
    }

    /// The rendered-HTTP firewall rule for a tool's upstream request, decided
    /// by the shared evaluator over the same snapshot as
    /// [`RbacState::evaluate_tool_authorization`]. An invocation admitted under
    /// the pinned policy must not have its rendered request judged by a
    /// revision a reconcile installed while it was in flight: that is one
    /// decision built from two snapshots (#422).
    ///
    /// Direct rules only, under unknown dispatch: no route or default applies,
    /// so `Ok(None)` (no rule matched) allows. The tool name binds the
    /// question but does not decide it. `Ok(None)` is returned only for the
    /// evaluator's own no-rule allow; any other unmatched answer is refused,
    /// so a kernel that ever answered differently would fail closed here.
    pub(crate) fn evaluate_tool_http_rule(
        &self,
        tool_name: &str,
        method: &str,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> Result<Option<MatchedRuleDecision>, ToolPolicyRefusal> {
        // Rendering passes an `http::Method`'s own text, so this cannot fail
        // for a served call; an unparsable method is refused, not guessed.
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| refused(ToolOperation::RenderedHttp, inconsistent()))?;
        let policy = self.effective_policy();
        let evaluation = policy.evaluate_tool(
            ToolOperation::RenderedHttp,
            tool_name,
            principal_fact(principal),
            Some((method, path.to_owned())),
        )?;
        policy.rendered_http_rule(&evaluation)
    }

    /// Previews whether the requesting principal may invoke a policy-backed
    /// tool without emitting audit events or beginning tool execution. One
    /// question against a freshly read snapshot; a caller previewing several
    /// tools takes [`RbacState::tool_eligibility_snapshot`] once instead, as
    /// inventory does.
    #[cfg(test)]
    pub(crate) fn tool_policy_eligibility(
        &self,
        tool_name: &str,
        principal: &auth::Principal,
    ) -> ToolPolicyEligibility {
        self.tool_eligibility_snapshot()
            .eligibility(tool_name, principal)
    }

    /// The request's policy snapshot, read once, for previewing the
    /// eligibility of many tools from the same snapshot.
    pub(crate) fn tool_eligibility_snapshot(&self) -> ToolEligibilitySnapshot {
        ToolEligibilitySnapshot(self.effective_policy())
    }
}

/// The policy fact for an identity a tool-lane consumer projects. No identity
/// is an anonymous caller, never a missing fact: every tool-lane consumer
/// knows whether it has one.
fn principal_fact(principal: Option<&auth::Principal>) -> PrincipalFact {
    principal.map_or(PrincipalFact::Anonymous, |principal| {
        PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
    })
}

/// Whether a tool answer is the evaluator's own allow with no rule behind it,
/// the only unmatched answer a tool-lane adapter admits on.
fn is_unmatched_allow(evaluation: &ToolEvaluation, reason: ToolReason) -> bool {
    evaluation.reason() == reason
        && evaluation.logical() == LogicalDecision::Allow
        && evaluation.effect() == PolicyEffect::Allow
        && evaluation.matched().is_none()
}

fn inconsistent() -> ToolPolicyRefusal {
    ToolPolicyRefusal::Error(EvaluationError::InconsistentContext)
}

fn internal_invariant() -> ToolPolicyRefusal {
    ToolPolicyRefusal::Error(EvaluationError::InternalInvariant)
}

/// Record a tool-lane refusal with bounded diagnostics, and hand it back.
fn refused(operation: ToolOperation, refusal: ToolPolicyRefusal) -> ToolPolicyRefusal {
    tracing::warn!(
        ?operation,
        reason = refusal.reason(),
        ?refusal,
        "tool policy evaluation refused"
    );
    refusal
}

impl RbacPolicyState {
    fn from_policy(policy: Policy) -> Self {
        // Infallible here: the only rejection `from_validated_policy` makes
        // is of an impossible watermark, and a standalone snapshot has none.
        Self::build(policy, crate::policy_eval::PolicyAuthority::Standalone, 0)
            .expect("a standalone authority is always valid")
    }

    /// The cluster-mode constructor: a compiled snapshot keyed by the
    /// authoritative security revision it was built for.
    ///
    /// Fallible, unlike the standalone one, because the revision is the caller's
    /// and `policy_active.security_revision` carries no database CHECK: a corrupt
    /// or out-of-band-edited row arrives here as a watermark that cannot exist.
    /// Such a candidate was already discarded by the monotonic install guard, so
    /// refusing to build it changes which snapshots install not at all -- it turns
    /// a silently dropped candidate into a refusal the caller can report.
    #[cfg(feature = "postgres")]
    fn from_policy_at_revision(
        policy: Policy,
        security_revision: i64,
    ) -> Result<Self, crate::policy_eval::CompileError> {
        Self::build(
            policy,
            crate::policy_eval::PolicyAuthority::PostgreSql { security_revision },
            security_revision,
        )
    }

    /// Compile one snapshot and derive everything a serving path reads from
    /// the compiled instance: its decisions, the rule ids and routes audit
    /// attribution resolves the evaluator's references against, and the
    /// permission engine the management lane asks. None of them can then
    /// describe another policy than the one that decided. The oracle copies
    /// are built only into tests.
    fn build(
        policy: Policy,
        authority: crate::policy_eval::PolicyAuthority,
        security_revision: i64,
    ) -> Result<Self, crate::policy_eval::CompileError> {
        #[cfg(test)]
        let default_action = policy.default_action.clone();
        #[cfg(test)]
        let enforcement_mode = policy.enforcement_mode;
        #[cfg(test)]
        let routes = policy.routes.clone();
        #[cfg(test)]
        let rule_matcher = RuleMatcher::new(&policy.rules);
        #[cfg(test)]
        let engine = PolicyEngine::new(policy.clone());
        let compiled =
            crate::policy_eval::CompiledPolicy::from_validated_policy(policy, authority)?;
        let rule_ids = compiled
            .direct_rules()
            .iter()
            .enumerate()
            .map(|(rule_index, rule)| rule.id.clone().unwrap_or_else(|| rule_index.to_string()))
            .collect();

        Ok(Self {
            #[cfg(test)]
            engine,
            #[cfg(test)]
            rule_matcher,
            rule_ids,
            #[cfg(test)]
            default_action,
            #[cfg(test)]
            enforcement_mode,
            #[cfg(test)]
            routes,
            security_revision,
            compiled,
        })
    }

    /// The pure kernel's view of this snapshot: the same policy, compiled once at
    /// install, pinned to the revision this snapshot serves under.
    pub(crate) fn compiled(&self) -> &crate::policy_eval::CompiledPolicy {
        &self.compiled
    }

    /// The id audit attribution records for each direct rule, in source
    /// order: the rule's `id`, else its zero-based index. These are the ids
    /// `matched_rule_id` carries, so a count keyed by them is a count of what
    /// this snapshot's rules were recorded as. They are derived from the
    /// compiled instance's own direct rules, the vector a
    /// [`RuleReference::Direct`] index it returns names.
    pub(crate) fn rule_ids(&self) -> &[String] {
        &self.rule_ids
    }

    /// Ask the shared evaluator one tool-lane question of this snapshot.
    ///
    /// A tool name longer than any policy may carry is refused before the
    /// evaluator is asked, so its own size refusal is never what decides a
    /// served call. An incomplete answer and an evaluator error are refusals,
    /// never a default; each is logged here, once, with bounded diagnostics.
    fn evaluate_tool(
        &self,
        operation: ToolOperation,
        tool_name: &str,
        principal: PrincipalFact,
        rendered: Option<(Method, String)>,
    ) -> Result<ToolEvaluation, ToolPolicyRefusal> {
        if tool_name.len() > MAX_TOOL_NAME_BYTES {
            return Err(refused(operation, ToolPolicyRefusal::NameOutOfBounds));
        }
        let (method, path) = rendered.unzip();
        let context = ToolEvaluationContext {
            version: TOOL_CONTEXT_VERSION,
            snapshot: self.compiled.snapshot(),
            operation,
            tool_name: Some(tool_name.to_owned()),
            principal,
            method,
            path,
        };
        match self.compiled.evaluate_tool(&context) {
            Ok(evaluation)
                if evaluation.is_complete()
                    && evaluation.logical() != LogicalDecision::Indeterminate =>
            {
                Ok(evaluation)
            }
            Ok(evaluation) => Err(refused(
                operation,
                ToolPolicyRefusal::Incomplete(evaluation.limitation()),
            )),
            Err(error) => Err(refused(operation, ToolPolicyRefusal::Error(error))),
        }
    }

    /// The rule a tool invocation or rendered request matched, attributed by
    /// this snapshot's rule ids exactly as the HTTP adapter attributes one.
    /// The action follows the effect: allow, deny, or a shadow observation.
    ///
    /// An answer naming no direct rule this snapshot has, or whose effect and
    /// logical decision disagree, is refused: the kernel gives neither, so a
    /// kernel that started to would fail closed here rather than be
    /// attributed or admitted.
    fn matched_tool_rule(
        &self,
        evaluation: &ToolEvaluation,
    ) -> Result<Option<MatchedRuleDecision>, ToolPolicyRefusal> {
        if evaluation.reason() != ToolReason::MatchedRule {
            return Ok(None);
        }
        let matched_rule_id = match evaluation.matched() {
            Some(RuleReference::Direct(index)) => self.rule_ids.get(index).cloned(),
            _ => None,
        }
        .ok_or_else(internal_invariant)?;
        let action = match (evaluation.effect(), evaluation.logical()) {
            (PolicyEffect::Allow, LogicalDecision::Allow) => RuleAction::Allow,
            (PolicyEffect::Block, LogicalDecision::Deny) => RuleAction::Deny,
            (PolicyEffect::Observe, LogicalDecision::Deny) => RuleAction::Shadow,
            _ => return Err(internal_invariant()),
        };
        Ok(Some(MatchedRuleDecision {
            action,
            matched_rule_id,
        }))
    }

    /// Translate one accepted rendered-HTTP answer: `Ok(None)` for the
    /// evaluator's own no-rule allow, the attributed rule for a matched one.
    ///
    /// Any other answer is refused as an internal invariant: a block or an
    /// observation with no rule, a rule reference without `MatchedRule`, or a
    /// reason another operation gives. The kernel gives none of them, so
    /// these guards are reached only by a test that crafts such an answer
    /// (`a_rendered_http_answer_the_kernel_never_gives_is_refused`); they
    /// exist so that a kernel change which started to give one would fail
    /// closed rather than let the rendered request through unattributed.
    fn rendered_http_rule(
        &self,
        evaluation: &ToolEvaluation,
    ) -> Result<Option<MatchedRuleDecision>, ToolPolicyRefusal> {
        if evaluation.reason() != ToolReason::MatchedRule
            && !is_unmatched_allow(evaluation, ToolReason::NoHttpRule)
        {
            return Err(refused(ToolOperation::RenderedHttp, internal_invariant()));
        }
        self.matched_tool_rule(evaluation)
            .map_err(|refusal| refused(ToolOperation::RenderedHttp, refusal))
    }

    fn tool_invocation_verdict(
        &self,
        tool_name: &str,
        principal: Option<&auth::Principal>,
    ) -> ToolInvocationVerdict<'_> {
        match self.evaluate_tool(
            ToolOperation::Invocation,
            tool_name,
            principal_fact(principal),
            None,
        ) {
            Ok(evaluation) => self.invocation_verdict(tool_name, &evaluation),
            Err(refusal) => ToolInvocationVerdict::Refused(refusal),
        }
    }

    /// Translate one accepted invocation answer for the runtime, asking the
    /// evaluator nothing more.
    ///
    /// Only an answer the kernel gives admits: its own unmatched allow for a
    /// tool this snapshot has an entry for, or a matched rule this snapshot
    /// can attribute. Any other answer -- an `Allowed` with another effect, a
    /// rule reference or a disagreeing logical decision, a reason that
    /// contradicts whether the entry exists -- is refused as an internal
    /// invariant. The kernel gives none of them, so these guards are reached
    /// only by a test that crafts such an answer
    /// (`an_invocation_answer_the_kernel_never_gives_is_refused`); they exist
    /// so that a kernel change which started to give one would fail closed.
    fn invocation_verdict(
        &self,
        tool_name: &str,
        evaluation: &ToolEvaluation,
    ) -> ToolInvocationVerdict<'_> {
        let rule_decision = match self.matched_tool_rule(evaluation) {
            Ok(rule_decision) => rule_decision,
            Err(refusal) => {
                return ToolInvocationVerdict::Refused(refused(ToolOperation::Invocation, refusal))
            }
        };
        let entry = self.compiled.tool_entries().get(tool_name);
        match (evaluation.reason(), entry, rule_decision) {
            (ToolReason::UnknownTool, None, None) => ToolInvocationVerdict::UnknownTool,
            (ToolReason::Disabled, Some(_), None) => ToolInvocationVerdict::Disabled,
            (ToolReason::RoleNotAllowed, Some(entry), None) => {
                ToolInvocationVerdict::RoleNotAllowed {
                    allowed_roles: &entry.allowed_roles,
                }
            }
            // No rule decided, so only the evaluator's own allow admits; any
            // other answer here is a kernel the adapter does not understand.
            (ToolReason::Allowed, Some(tool), None)
                if is_unmatched_allow(evaluation, ToolReason::Allowed) =>
            {
                ToolInvocationVerdict::Entry {
                    tool,
                    rule_decision: None,
                }
            }
            (ToolReason::MatchedRule, Some(tool), Some(rule_decision)) => {
                ToolInvocationVerdict::Entry {
                    tool,
                    rule_decision: Some(rule_decision),
                }
            }
            _ => ToolInvocationVerdict::Refused(refused(
                ToolOperation::Invocation,
                internal_invariant(),
            )),
        }
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

/// A watched or signalled reload of `policy_file`, once the
/// authority-evidence gate admits it (issue #425, PR 4). Standalone mode
/// records no evidence of a reload, so `AUTHORITY_EVIDENCE_DURABILITY=required`
/// refuses each one -- the gate audits it -- and the active policy stays
/// until a restart activates the file. Without a gate every reload runs.
async fn reload_policy_file_if_admitted(
    state: &RbacState,
    policy_file: &Path,
    evidence: Option<&BackgroundEvidenceGate>,
    trigger: &'static str,
) -> bool {
    if evidence.is_some_and(|gate| !gate.admits(AuthorityOperation::PolicyFileReload, trigger)) {
        tracing::warn!(
            policy_file = %policy_file.display(),
            trigger,
            "RBAC policy reload refused by AUTHORITY_EVIDENCE_DURABILITY=required; existing policy remains active until a restart activates the file"
        );
        return false;
    }
    reload_policy_from_file(state, policy_file).await.is_ok()
}

#[cfg(test)]
pub fn spawn_policy_reload_tasks(
    policy_file: impl Into<PathBuf>,
    state: RbacState,
) -> notify::Result<()> {
    let cancellation = CancellationToken::new();
    spawn_policy_reload_tasks_inner(policy_file.into(), state, None, cancellation, None)
}

pub fn spawn_policy_reload_tasks_with_lifecycle(
    policy_file: impl Into<PathBuf>,
    state: RbacState,
    evidence: BackgroundEvidenceGate,
    lifecycle: &crate::lifecycle::GatewayLifecycle,
) -> notify::Result<()> {
    spawn_policy_reload_tasks_inner(
        policy_file.into(),
        state,
        Some(evidence),
        lifecycle.background_cancellation(),
        Some(lifecycle),
    )
}

fn spawn_policy_reload_tasks_inner(
    policy_file: PathBuf,
    state: RbacState,
    evidence: Option<BackgroundEvidenceGate>,
    cancellation: CancellationToken,
    lifecycle: Option<&crate::lifecycle::GatewayLifecycle>,
) -> notify::Result<()> {
    let watcher = spawn_policy_file_watcher(
        policy_file.clone(),
        state.clone(),
        evidence.clone(),
        cancellation.clone(),
    )?;
    let sighup = spawn_sighup_reload_task(policy_file, state, evidence, cancellation);
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
    evidence: Option<BackgroundEvidenceGate>,
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
        evidence,
        receiver,
        watcher,
        cancellation,
    )))
}

async fn policy_file_watch_loop(
    policy_file: PathBuf,
    state: RbacState,
    evidence: Option<BackgroundEvidenceGate>,
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

        reload_policy_file_if_admitted(&state, &policy_file, evidence.as_ref(), "file_watch").await;
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
    evidence: Option<BackgroundEvidenceGate>,
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
            reload_policy_file_if_admitted(&state, &policy_file, evidence.as_ref(), "signal").await;
        }
    }))
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(
    _policy_file: PathBuf,
    _state: RbacState,
    _evidence: Option<BackgroundEvidenceGate>,
    _cancellation: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    None
}

/// `next.run(req)` with the request's Connection snapshot and bundle pinned
/// (cluster mode) or without them (standalone, or an exempt path that
/// skipped the gate). The pins also travel with the request as a
/// [`RequestPins`] extension, so a handler that serves it from a task of its
/// own can re-enter them.
#[cfg(feature = "postgres")]
async fn run_pinned(
    pinned: Option<Arc<crate::connections::control_plane::ConnectionRuntimeSnapshot>>,
    bundle: Option<Arc<crate::security_cluster::SecurityBundle>>,
    next: Next,
    mut req: Request,
) -> Response {
    let pins = RequestPins {
        connections: pinned,
        bundle,
    };
    if pins.connections.is_some() || pins.bundle.is_some() {
        req.extensions_mut().insert(pins.clone());
    }
    pins.scope(next.run(req)).await
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
        let receipt = emit_denied(&state, &context, principal.as_ref(), "unsafe_path", None);
        return RecordedRefusal::forbidden(&state.audit, receipt, "unsafe_path")
            .answer()
            .await;
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
    let request_host = upstream_route::request_host_without_port(req.uri(), req.headers());
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
                let receipt =
                    emit_revision_check_failed(&state, &context, principal.as_ref(), error);
                return RecordedRefusal {
                    audit: state.audit.clone(),
                    receipt,
                    response: service_unavailable_response(),
                    decision: denied_decision(error.as_str()),
                }
                .answer()
                .await;
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
    // Normalize only facts already established by admission. In particular, no
    // Host is Absent, not Missing, and all policy references below come from the
    // same snapshot the revision gate pinned for this request.
    let compiled = policy.compiled();
    let observation = req.extensions().get::<ProxyRouteObservationContext>();
    let classified = req
        .extensions()
        .get::<ProxyRouteClassificationCompleted>()
        .is_some();
    let dispatch = observation.map(|facts| crate::policy_eval::DispatchFacts {
        route_id: facts.route_id.clone(),
        route_host: facts.route_host.clone(),
        route_path_prefix: facts.route_path_prefix.clone(),
        upstream_origin: facts.upstream_origin.clone(),
    });
    let target = if !classified {
        crate::policy_eval::HttpTarget::Missing
    } else if policy_path != path {
        crate::policy_eval::HttpTarget::McpAlias {
            canonical_path: policy_path.to_owned(),
        }
    } else if observation.is_some() {
        crate::policy_eval::HttpTarget::ProxyDispatch
    } else {
        crate::policy_eval::HttpTarget::Contextless
    };
    let input = crate::policy_eval::PolicyEvaluationContext {
        version: crate::policy_eval::CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(req.method().clone()),
        path: Some(path.to_owned()),
        principal: principal.as_ref().map_or(
            crate::policy_eval::PrincipalFact::Anonymous,
            |principal| {
                crate::policy_eval::PrincipalFact::Authenticated(
                    crate::policy_eval::PrincipalIdentity::from_principal(principal),
                )
            },
        ),
        target,
        request_host: request_host.map_or(
            crate::policy_eval::HostFact::Absent,
            crate::policy_eval::HostFact::Present,
        ),
        dispatch,
    };
    // The classifier derives these two contexts together. Never accept a
    // missing or different host-binding authority as a contextless allow.
    let evaluation = if observation.and_then(|facts| facts.authorization_context()) != proxy_context
    {
        Err(crate::policy_eval::EvaluationError::InconsistentContext)
    } else {
        compiled.evaluate(&input)
    };
    let evaluation = match evaluation {
        Ok(result)
            if result.is_complete()
                && result.logical() != crate::policy_eval::LogicalDecision::Indeterminate =>
        {
            result
        }
        Ok(result) => {
            let refusal = evaluation_failed(
                &state,
                &context,
                principal.as_ref(),
                "policy_evaluation_incomplete",
                result.limitation(),
                None,
            );
            drop(policy);
            return refusal.answer().await;
        }
        Err(error) => {
            let refusal = evaluation_failed(
                &state,
                &context,
                principal.as_ref(),
                "policy_evaluation_error",
                None,
                Some(error),
            );
            drop(policy);
            return refusal.answer().await;
        }
    };
    let (decision, records) = match apply_http_evaluation(
        &state,
        &policy,
        &context,
        principal.as_ref(),
        proxy_context.as_ref(),
        &evaluation,
    ) {
        Ok(evaluated) => evaluated,
        Err(error) => {
            let refusal = evaluation_failed(
                &state,
                &context,
                principal.as_ref(),
                "policy_evaluation_error",
                None,
                Some(error),
            );
            drop(policy);
            return refusal.answer().await;
        }
    };
    drop(policy);
    // Required audit durability (issue #425): the decision is acted on --
    // forwarded, or answered with its 403 -- only once its records are in
    // the audit store of record. Nothing upstream has been touched yet, so
    // a record that cannot commit refuses the request with no upstream I/O.
    if records.confirm(&state.audit).await.is_err() {
        return audit_unavailable();
    }
    if evaluation.effect() == crate::policy_eval::PolicyEffect::Block {
        return with_policy_decision(forbidden(), decision);
    }
    let response = run_pinned(pinned_connections, admitted_bundle, next, req).await;
    with_policy_decision(response, decision)
}

/// The records one HTTP evaluation wrote: a direct shadow rule's
/// observation, when one matched, then the verdict. Both are confirmed
/// before the stage acts on the verdict; they were queued together, so they
/// share one deadline and, normally, one commit.
struct DecisionRecords {
    observed: Option<AuditReceipt>,
    verdict: AuditReceipt,
}

impl DecisionRecords {
    async fn confirm(self, audit: &AuditLog) -> Result<(), AuditUnavailable> {
        if let Some(observed) = self.observed {
            audit.confirm(observed).await?;
        }
        audit.confirm(self.verdict).await
    }
}

/// A refusal this stage has decided and recorded but not yet answered. It
/// is answered with its own response once its record is durable, and with
/// [`audit_unavailable`] when it is not: a refusal the gateway cannot
/// evidence is reported as the outage it is, not as a policy answer.
///
/// It owns everything it needs, so a caller can let go of the request and
/// the policy snapshot before waiting on the store.
pub(crate) struct RecordedRefusal {
    audit: AuditLog,
    receipt: AuditReceipt,
    response: Response,
    decision: PolicyDecision,
}

impl RecordedRefusal {
    fn forbidden(audit: &AuditLog, receipt: AuditReceipt, reason: &'static str) -> Self {
        Self {
            audit: audit.clone(),
            receipt,
            response: forbidden(),
            decision: denied_decision(reason),
        }
    }

    pub(crate) async fn answer(self) -> Response {
        match self.audit.confirm(self.receipt).await {
            Ok(()) => with_policy_decision(self.response, self.decision),
            Err(_) => audit_unavailable(),
        }
    }
}

fn denied_decision(reason: &'static str) -> PolicyDecision {
    PolicyDecision {
        outcome: PolicyDecisionOutcome::Denied,
        reason,
        permission: None,
        path_prefix: None,
        matched_rule_id: None,
    }
}

/// `503 audit_unavailable`, carrying a denied decision with the same reason
/// so the request's own observation (when it can still be written) says
/// why it was refused.
fn audit_unavailable() -> Response {
    with_policy_decision(
        audit_unavailable_response(),
        denied_decision(AUDIT_UNAVAILABLE_REASON),
    )
}

/// Translate a complete verdict without re-evaluating any policy predicate.
/// Resolve all ordinals before emitting anything, preserving the direct-shadow
/// observation followed by the host-bound route's actual verdict.
fn apply_http_evaluation(
    state: &RbacState,
    policy: &RbacPolicyState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    proxy_context: Option<&ProxyRouteAuthorizationContext>,
    evaluation: &crate::policy_eval::Evaluation,
) -> Result<(PolicyDecision, DecisionRecords), crate::policy_eval::EvaluationError> {
    use crate::policy_eval::{EvaluationError, PolicyEffect, Reason, RuleReference};

    let observed = match evaluation.observation() {
        Some(RuleReference::Direct(index)) => Some(
            policy
                .rule_ids
                .get(index)
                .ok_or(EvaluationError::InternalInvariant)?,
        ),
        Some(RuleReference::Route(_)) => return Err(EvaluationError::InternalInvariant),
        None => None,
    };
    let direct = match evaluation.matched() {
        Some(RuleReference::Direct(index)) => Some(
            policy
                .rule_ids
                .get(index)
                .ok_or(EvaluationError::InternalInvariant)?,
        ),
        _ => None,
    };
    // Resolved against the instance that matched it, so the permission and
    // path prefix recorded are the route's that decided.
    let route = match evaluation.matched() {
        Some(RuleReference::Route(index)) => Some(
            policy
                .compiled
                .routes()
                .get(index)
                .ok_or(EvaluationError::InternalInvariant)?,
        ),
        _ => None,
    };
    let host_denial = if evaluation.reason() == Reason::HostPolicyRequired {
        Some(proxy_context.ok_or(EvaluationError::InternalInvariant)?)
    } else {
        None
    };
    let outcome = match evaluation.effect() {
        PolicyEffect::Allow => PolicyDecisionOutcome::Allowed,
        PolicyEffect::Block => PolicyDecisionOutcome::Denied,
        PolicyEffect::Observe => PolicyDecisionOutcome::WouldDeny,
    };
    let reason = evaluation.reason().as_str();
    let observed = observed.map(|id| emit_rule_would_deny(state, context, principal, id));
    if let Some(id) = direct {
        let verdict = match evaluation.effect() {
            PolicyEffect::Allow => emit_rule_allowed(state, context, principal, id),
            PolicyEffect::Block => emit_rule_denied(state, context, principal, id),
            PolicyEffect::Observe => emit_rule_would_deny(state, context, principal, id),
        };
        return Ok((
            decision_for_direct_rule(outcome, reason, id.clone()),
            DecisionRecords { observed, verdict },
        ));
    }
    let verdict = if let Some(proxy_context) = host_denial {
        emit_host_policy_required(state, context, principal, proxy_context)
    } else {
        match evaluation.effect() {
            PolicyEffect::Allow => emit_allowed(state, context, principal, route, Some(reason)),
            PolicyEffect::Block => emit_denied(state, context, principal, reason, route),
            PolicyEffect::Observe => emit_would_deny(state, context, principal, reason, route),
        }
    };
    let decision = match route {
        Some(route) => decision_for_rule(outcome, reason, route),
        None => PolicyDecision {
            outcome,
            reason,
            permission: None,
            path_prefix: None,
            matched_rule_id: None,
        },
    };
    Ok((decision, DecisionRecords { observed, verdict }))
}

/// Incomplete input and evaluator errors block even in shadow mode. Diagnostics
/// contain bounded enums, never the context, policy, credentials or trace.
fn evaluation_failed(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    limitation: Option<crate::policy_eval::Limitation>,
    error: Option<crate::policy_eval::EvaluationError>,
) -> RecordedRefusal {
    tracing::warn!(
        reason,
        ?limitation,
        ?error,
        "HTTP policy evaluation refused"
    );
    let receipt = emit_denied(state, context, principal, reason, None);
    RecordedRefusal::forbidden(&state.audit, receipt, reason)
}

/// Refuse a request that no policy evaluation answered, the way this stage
/// refuses one before it evaluates: `403 {"error":"forbidden"}`, an
/// `authz.denied` record with `reason` and no rule, and a denied policy
/// decision with the same reason.
///
/// For the rate stage, which runs before this one and selects a policy rate
/// lane with the same evaluator (#422). When it cannot select one it refuses the
/// request rather than let it pass unmetered, and it refuses with this answer,
/// so a request this stage would have refused for the same reason -- an unsafe
/// path, or a path the evaluator does not accept -- is answered and audited
/// exactly as before. No upstream, credential or DNS work has started, and the
/// cluster revision gate has not run, so the record carries no served revision.
///
/// The refusal comes back recorded but unanswered: the caller lets go of the
/// request and answers it with [`RecordedRefusal::answer`], which waits for
/// the record under required audit durability exactly as this stage's own
/// refusals do.
pub(crate) fn refuse_unevaluated(
    audit: &AuditLog,
    client_ip_policy: &ClientIpPolicy,
    req: &Request,
    principal: Option<&auth::Principal>,
    reason: &'static str,
) -> RecordedRefusal {
    let context = audit_context(req, client_ip_policy);
    let receipt = emit_denial_event(audit, &context, principal, reason, None, AUTHZ_DENIED);
    RecordedRefusal::forbidden(audit, receipt, reason)
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
) -> AuditReceipt {
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

    state.audit.record(AuditEvent::new(
        AUTHZ_ALLOWED,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ))
}

fn emit_denied(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    rule: Option<&RouteRule>,
) -> AuditReceipt {
    emit_denial_event(&state.audit, context, principal, reason, rule, AUTHZ_DENIED)
}

fn emit_would_deny(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    rule: Option<&RouteRule>,
) -> AuditReceipt {
    emit_denial_event(
        &state.audit,
        context,
        principal,
        reason,
        rule,
        AUTHZ_WOULD_DENY,
    )
}

fn emit_rule_allowed(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    matched_rule_id: &str,
) -> AuditReceipt {
    emit_direct_rule_event(
        state,
        context,
        principal,
        "matched_rule",
        matched_rule_id,
        AUTHZ_ALLOWED,
    )
}

fn emit_rule_denied(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    matched_rule_id: &str,
) -> AuditReceipt {
    emit_direct_rule_event(
        state,
        context,
        principal,
        "matched_rule",
        matched_rule_id,
        AUTHZ_DENIED,
    )
}

fn emit_rule_would_deny(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    matched_rule_id: &str,
) -> AuditReceipt {
    emit_direct_rule_event(
        state,
        context,
        principal,
        "matched_rule",
        matched_rule_id,
        AUTHZ_WOULD_DENY,
    )
}

fn emit_direct_rule_event(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    matched_rule_id: &str,
    event_type: &'static str,
) -> AuditReceipt {
    let actor = principal.map(actor_from_principal);
    let mut payload = json!({
        "path": &context.path,
        "method": &context.method,
        "reason": reason,
        "matched_rule_id": matched_rule_id,
    });
    apply_security_revision(&mut payload, context);

    state.audit.record(AuditEvent::new(
        event_type,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ))
}

fn emit_denial_event(
    audit: &AuditLog,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    reason: &'static str,
    rule: Option<&RouteRule>,
    event_type: &'static str,
) -> AuditReceipt {
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

    audit.record(AuditEvent::new(
        event_type,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ))
}

fn emit_host_policy_required(
    state: &RbacState,
    context: &AuditContext,
    principal: Option<&auth::Principal>,
    proxy_context: &ProxyRouteAuthorizationContext,
) -> AuditReceipt {
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

    state.audit.record(AuditEvent::new(
        AUTHZ_DENIED,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ))
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
) -> AuditReceipt {
    let actor = principal.map(actor_from_principal);
    let mut payload = json!({
        "path": &context.path,
        "method": &context.method,
        "reason": error.as_str(),
        "outcome": "service_unavailable",
    });
    apply_security_revision(&mut payload, context);

    state.audit.record(AuditEvent::new(
        AUTHZ_REVISION_CHECK_FAILED,
        &context.request_id,
        &context.source_ip,
        actor,
        payload,
    ))
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

#[cfg(test)]
#[path = "rbac_legacy_tests.rs"]
pub(crate) mod legacy;
