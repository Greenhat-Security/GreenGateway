//! Cluster-mode shared-security runtime (issue #241, PRs 7-8).
//!
//! [`ClusterSecurityRuntime`] is the production implementation of the
//! strict security-revision gate the RBAC middleware consults on every
//! protected request in cluster mode, and the owner of the background
//! reconciler that keeps local compiled snapshots warm between requests.
//!
//! The runtime reconciles every authority-backed resource of the security
//! snapshot -- the policy document since PR 7, the tools document since
//! PR 8, and the connection surfaces when their PRs land. One global
//! security revision identifies the exact active combination of shared
//! state; the runtime's `compiled_revision` is the highest revision at
//! which this replica has confirmed *every* resource current. The gate is
//! current iff `compiled_revision >=` the authority's counter; a request
//! serves under `compiled_revision`, and the audit records it.
//!
//! Correctness lives in the durable authority, not here: the gate reads
//! the security revision from the PostgreSQL primary after the request
//! starts, and reconciliation reads each resource's active state
//! (verifying recorded ETags) and installs it only after full validation.
//! A lost notification, a dead poller, or a restarted replica all converge
//! on the same answer the next time the gate runs -- the HA state model's
//! "notifications are hints" rule, with the revision counter as the only
//! source of truth.
//!
//! The reconcile deadline is the state model's section 6 budget (250 ms
//! bounded wait, then `503`); it is a normative budget, not operator
//! configuration, so it is a constant here.

use std::{
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::{
    connections::{
        control_plane::ConnectionControlPlane, mcp::McpConnectionCatalogService,
        openapi::OpenApiConnectionCatalogService, pg_store::PostgresConnectionStore,
    },
    lifecycle::GatewayLifecycle,
    middleware::rbac::{RbacState, SecurityRevisionCheckError, SecurityRevisionGate},
    storage::{
        PolicyControlPlane as _, PostgresPolicyStore, PostgresToolStore, SecurityRevisionSource,
        ToolControlPlane as _,
    },
};

/// The bounded reconcile wait after observing a new revision (HA state
/// model section 6): compile happens off the request path only in the
/// sense that the compiled artifact is cached; a request that arrives
/// before its replica has the current revision waits at most this long and
/// then fails closed with `503`.
pub(crate) const RECONCILE_DEADLINE: Duration = Duration::from_millis(250);

/// How often the background reconciler looks for a new revision. A lost
/// poll costs at most one interval of freshness; the per-request gate is
/// what enforces correctness, so this interval is a latency optimization
/// for the common case, never a correctness parameter.
pub(crate) const RECONCILE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The background reconciler's budget for one pass. Deliberately not the
/// request deadline: a request must fail closed quickly, but the
/// background pass is what actually does the work when a resource is
/// large (the Connections resource re-reads every record and every
/// catalog), and giving it the request's 250 ms would cancel every pass
/// that a bounded-but-big deployment needs longer than that -- restarting
/// from scratch each tick, never advancing `installed_revision`, and
/// leaving protected traffic at `503` forever. Requests that arrive while
/// a background pass holds the reconcile lock wait their own bounded
/// deadline and fail closed; the pass completes and the next request
/// serves.
pub(crate) const RECONCILE_BACKGROUND_DEADLINE: Duration = Duration::from_secs(30);

/// One authority-backed resource of the security snapshot. The runtime
/// owns one adapter per resource; each adapter knows how to read its
/// authority's activation revision and how to install a validated,
/// compiled snapshot of its state.
#[async_trait]
pub(crate) trait ReconciledResource: Send + Sync {
    /// A stable name for diagnostics.
    fn name(&self) -> &'static str;

    /// The security revision at which this resource's authoritative state
    /// last changed. `Err` fails the gate closed (the authority could not
    /// be consulted).
    async fn activation_revision(&self) -> Result<i64, SecurityRevisionCheckError>;

    /// Fetch, validate, and install the authoritative state, which the
    /// gate observed at `observed_activation`. An implementation that has
    /// already installed that activation (or a newer one) returns without
    /// fetching; one behind it fetches the current content. The comparison
    /// is against the activation the gate observed, never against the
    /// replica's old watermark: a commit that lands mid-pass moves the
    /// activation past what a resource installed a moment ago, and the next
    /// pass must reinstall it rather than skip it as "already ahead of the
    /// watermark". Implementations install monotonically (a stale reconcile
    /// must never overwrite a newer install) and fail closed on any document
    /// they cannot enforce.
    async fn reconcile(&self, observed_activation: i64) -> Result<(), SecurityRevisionCheckError>;
}

pub(crate) struct ClusterSecurityRuntime {
    revisions: SecurityRevisionSource,
    /// The reconciled resources. Registered at startup as the builder
    /// creates each store (policy first, then tools, then later PRs'
    /// resources); registration completes before the listener serves, and
    /// the gate reads the current set on every reconcile.
    resources: RwLock<Vec<Arc<dyn ReconciledResource>>>,
    /// The highest security revision at which every registered resource
    /// has been confirmed current on this replica. `0` until the first
    /// gate pass completes.
    compiled_revision: AtomicI64,
    /// Serializes reconciles so a burst of requests behind the revision
    /// frontier produces one fetch-and-compile, not one per waiter.
    reconcile_lock: Mutex<()>,
    /// Test seam: runs once, after a pass reconciled its resources and
    /// before the watermark is published -- where a commit can land after
    /// a resource's activation read but before its content fetch.
    #[cfg(test)]
    before_publish: std::sync::Mutex<Option<BeforePublishHook>>,
}

#[cfg(test)]
type BeforePublishHook =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

impl ClusterSecurityRuntime {
    pub(crate) fn new(revisions: SecurityRevisionSource, policy: Arc<PolicyResource>) -> Arc<Self> {
        Arc::new(Self {
            revisions,
            resources: RwLock::new(vec![policy as Arc<dyn ReconciledResource>]),
            compiled_revision: AtomicI64::new(0),
            reconcile_lock: Mutex::new(()),
            #[cfg(test)]
            before_publish: std::sync::Mutex::new(None),
        })
    }

    #[cfg(test)]
    pub(crate) fn set_before_publish_hook_for_test(&self, hook: BeforePublishHook) {
        *self
            .before_publish
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    /// Register a resource's reconciler. Startup-only in practice: called
    /// by the (synchronous) app builder as each store is constructed,
    /// before serving.
    pub(crate) fn register_resource(&self, resource: Arc<dyn ReconciledResource>) {
        // Lock poisoning here means a reader panicked mid-clone; the set
        // itself is still structurally valid, so recover it.
        match self.resources.write() {
            Ok(mut resources) => resources.push(resource),
            Err(poisoned) => poisoned.into_inner().push(resource),
        }
        // A watermark confirmed before this resource existed says nothing
        // about it: if a pass ran between this resource's boot seed and
        // its registration, the watermark may already sit past a commit
        // the new resource has not installed, and every later gate check
        // would return early on it. Resetting forces the next check to
        // confirm every resource, this one included, before serving.
        self.compiled_revision.store(0, Ordering::Release);
    }

    /// The background reconciler: poll the revision counter and reconcile
    /// when behind. Failures are logged and retried on the next tick; the
    /// gate is what turns a persistent failure into refused requests.
    pub(crate) fn spawn_poller(self: &Arc<Self>, lifecycle: &GatewayLifecycle) {
        let runtime = Arc::clone(self);
        let cancellation = lifecycle.background_cancellation();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(RECONCILE_POLL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    () = cancellation.cancelled() => return,
                }
                if let Err(error) = runtime
                    .ensure_current_revision_within(RECONCILE_BACKGROUND_DEADLINE)
                    .await
                {
                    tracing::warn!(
                        reason = error.as_str(),
                        "background security reconciliation failed; the per-request gate refuses protected traffic while behind"
                    );
                }
            }
        });
        lifecycle.register_background_task(handle);
    }

    /// Read the current security revision from the authority, bounded by
    /// the remaining deadline.
    async fn current_revision(&self, deadline: Instant) -> Result<i64, SecurityRevisionCheckError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(SecurityRevisionCheckError::ReconcileDeadlineExceeded);
        }
        tokio::time::timeout(remaining, self.revisions.current())
            .await
            .map_err(|_| SecurityRevisionCheckError::ReconcileDeadlineExceeded)?
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    "the security revision could not be read from the authority"
                );
                SecurityRevisionCheckError::Unavailable
            })
    }

    /// Reconcile every registered resource against `compiled_revision`.
    /// Returns the highest activation revision observed above
    /// `authority_revision` (a commit landed mid-pass and the caller must
    /// re-read the counter), or `None` when the replica is confirmed
    /// current as of `authority_revision`.
    async fn reconcile_resources(
        &self,
        authority_revision: i64,
        compiled_revision: i64,
        deadline: Instant,
    ) -> Result<Option<i64>, SecurityRevisionCheckError> {
        // Clone the set under the lock and drop the guard before any
        // await: registrations are startup-only, and no reconcile holds a
        // reader while a resource runs.
        let resources = match self.resources.read() {
            Ok(resources) => resources.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let mut moved_past_authority: Option<i64> = None;
        for resource in &resources {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SecurityRevisionCheckError::ReconcileDeadlineExceeded);
            }
            let pass = async {
                let activation = resource.activation_revision().await?;
                if activation > authority_revision {
                    // This resource committed after our counter read: the
                    // pass is stale. Finish scanning (installs below are
                    // still monotonic supersets) but the caller must retry
                    // with a fresh counter read.
                    return Ok(Some(activation));
                }
                if activation > compiled_revision {
                    tracing::debug!(
                        resource = resource.name(),
                        compiled_revision,
                        activation,
                        "reconciling a security resource behind the compiled revision"
                    );
                    resource.reconcile(activation).await?;
                }
                Ok(None)
            };
            match tokio::time::timeout(remaining, pass).await {
                Ok(Ok(moved)) => {
                    moved_past_authority = match (moved_past_authority, moved) {
                        (Some(current), Some(seen)) => Some(current.max(seen)),
                        (None, Some(seen)) => Some(seen),
                        (current, None) => current,
                    };
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(SecurityRevisionCheckError::ReconcileDeadlineExceeded),
            }
        }
        Ok(moved_past_authority)
    }
}

/// The policy document as a reconciled resource: the PR 7 adapter.
pub(crate) struct PolicyResource {
    store: Arc<PostgresPolicyStore>,
    rbac_state: RbacState,
}

impl PolicyResource {
    pub(crate) fn new(store: Arc<PostgresPolicyStore>, rbac_state: RbacState) -> Arc<Self> {
        Arc::new(Self { store, rbac_state })
    }

    /// Fetch the active document from the authority, validate it exactly
    /// the way a file reload would (egress section unchanged, proxy
    /// dispatch routes still configured), and install the compiled
    /// snapshot keyed by the authority's revision. Validation failure is
    /// [`SecurityRevisionCheckError::InvalidDocument`]: a replica that
    /// cannot compile the current revision never serves it.
    async fn reconcile(&self) -> Result<(), SecurityRevisionCheckError> {
        let active = self
            .store
            .active()
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    "policy reconciliation could not read the active document"
                );
                SecurityRevisionCheckError::Unavailable
            })?
            .ok_or_else(|| {
                // Startup refuses to serve an uninitialized deployment, and
                // the active pointer is append-only, so this is unreachable in
                // a healthy process. Fail closed anyway: an authority with no
                // active policy authorizes nothing.
                tracing::error!("policy reconciliation found no active document after startup");
                SecurityRevisionCheckError::InvalidDocument
            })?;

        if active.policy.egress != self.rbac_state.current_egress_policy() {
            tracing::error!(
                "policy reconciliation rejected: the active document's egress \
                 section differs from the running configuration; egress changes \
                 require a gateway restart"
            );
            return Err(SecurityRevisionCheckError::InvalidDocument);
        }
        if let Err(error) = self
            .rbac_state
            .validate_proxy_dispatch_policy(&active.policy)
        {
            tracing::error!(
                error = %error,
                "policy reconciliation rejected: the active document does not \
                 match the configured proxy routes"
            );
            return Err(SecurityRevisionCheckError::InvalidDocument);
        }

        // Installing at the activation revision is a superset of any lower
        // revision the waiter compiled at: revisions are monotonic and the
        // installed snapshot includes every policy change at or below it.
        // The runtime's compiled-revision watermark -- not this per-resource
        // key -- is what the gate compares against the global counter.
        self.rbac_state
            .install_revision_snapshot(active.policy, active.security_revision);
        Ok(())
    }
}

#[async_trait]
impl ReconciledResource for PolicyResource {
    fn name(&self) -> &'static str {
        "policy"
    }

    async fn activation_revision(&self) -> Result<i64, SecurityRevisionCheckError> {
        match self.store.active().await {
            Ok(Some(active)) => Ok(active.security_revision),
            Ok(None) => {
                tracing::error!("the policy authority has no active document");
                Err(SecurityRevisionCheckError::InvalidDocument)
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "the policy activation revision could not be read"
                );
                Err(SecurityRevisionCheckError::Unavailable)
            }
        }
    }

    async fn reconcile(&self, observed_activation: i64) -> Result<(), SecurityRevisionCheckError> {
        // The rbac snapshot already carries the activation the gate
        // observed (or a newer one): per-resource installs are monotonic.
        if self.rbac_state.snapshot_security_revision() >= observed_activation {
            return Ok(());
        }
        self.reconcile().await
    }
}

/// The tools document as a reconciled resource (issue #241, PR 8): the
/// local lane of the tool registry, owned by the versioned tools document
/// in the authority. Managed lanes (per-connection catalogs) are derived
/// from the connection store and publish through their own paths; this
/// resource only reconciles the document-owned lane.
pub(crate) struct ToolsResource {
    store: Arc<PostgresToolStore>,
    registry: crate::tools::definitions::ToolRegistry,
    /// The tools-document revision currently installed in the registry's
    /// local lane. Installs are monotonic: a reconcile for a revision at
    /// or below this is a no-op, so a slow reconcile can never overwrite a
    /// newer lane with an older one.
    installed_revision: AtomicI64,
    /// Serializes the compare-and-install so the comparison and the swap
    /// are one step. Without it a register at revision N could pass the
    /// comparison, lose the CPU, and swap after the reconciler installed
    /// N+1 -- the registry would then serve N while both the authority
    /// and the watermark say N+1, and nothing would ever reconcile it.
    install_lock: Mutex<()>,
}

impl ToolsResource {
    pub(crate) fn new(
        store: Arc<PostgresToolStore>,
        registry: crate::tools::definitions::ToolRegistry,
        boot_revision: i64,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            registry,
            installed_revision: AtomicI64::new(boot_revision),
            install_lock: Mutex::new(()),
        })
    }

    /// Install a local lane that was committed at `security_revision`,
    /// unless a newer lane is already live. Returns whether it installed.
    ///
    /// The register endpoint calls this after its commit instead of
    /// installing unconditionally: a commit that pauses between its
    /// transaction and its install can be overtaken by another replica's
    /// commit that this replica's reconciler already installed, and an
    /// unconditional install would then roll the live lane back to the
    /// older document with no revision left to trigger a repair. A
    /// skipped install is not a failure -- the document is durable at the
    /// authority and the lane already serves something newer.
    pub(crate) async fn install_committed(
        &self,
        definitions: Vec<crate::tools::definitions::ToolDefinition>,
        security_revision: i64,
    ) -> Result<bool, crate::tools::definitions::ToolRegistryError> {
        let _guard = self.install_lock.lock().await;
        if self.installed_revision.load(Ordering::Acquire) >= security_revision {
            return Ok(false);
        }
        // Authoritative content: a name another lane still holds here is
        // provably stale (the authority reserved it for this document), so
        // the install evicts it rather than depending on the order lanes
        // reconcile in.
        self.registry.install_local_definitions_with(
            definitions,
            crate::tools::definitions::LaneConflicts::EvictStale,
        )?;
        self.installed_revision
            .store(security_revision, Ordering::Release);
        Ok(true)
    }
}

#[async_trait]
impl ReconciledResource for ToolsResource {
    fn name(&self) -> &'static str {
        "tools"
    }

    async fn activation_revision(&self) -> Result<i64, SecurityRevisionCheckError> {
        match self.store.active_tools().await {
            Ok(Some(active)) => Ok(active.security_revision),
            Ok(None) => {
                // Startup seeds the empty document, and the pointer is
                // append-only, so this is unreachable in a healthy process.
                // Fail closed anyway: no tools document authorizes nothing
                // local, but an authority that lost its pointer is not one
                // to trust for anything.
                tracing::error!("the tools authority has no active document");
                Err(SecurityRevisionCheckError::InvalidDocument)
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "the tools activation revision could not be read"
                );
                Err(SecurityRevisionCheckError::Unavailable)
            }
        }
    }

    async fn reconcile(&self, observed_activation: i64) -> Result<(), SecurityRevisionCheckError> {
        if self.installed_revision.load(Ordering::Acquire) >= observed_activation {
            return Ok(());
        }
        let active = self
            .store
            .active_tools()
            .await
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    "tools reconciliation could not read the active document"
                );
                SecurityRevisionCheckError::Unavailable
            })?
            .ok_or_else(|| {
                tracing::error!("tools reconciliation found no active document after startup");
                SecurityRevisionCheckError::InvalidDocument
            })?;

        // The document must validate exactly the way a file load would;
        // a document this binary cannot enforce never installs.
        let definitions =
            crate::tools::definitions::definitions_from_json_value(active.document, None).map_err(
                |error| {
                    tracing::error!(
                        error = %error,
                        "tools reconciliation rejected: the active document is invalid"
                    );
                    SecurityRevisionCheckError::InvalidDocument
                },
            )?;
        // Install re-validates against the current managed lanes and
        // swaps atomically; a rejection keeps the existing lane (fail
        // closed) and surfaces as InvalidDocument to the gate. The
        // compare-and-install is the same step the register endpoint
        // uses, so the two cannot interleave.
        match self
            .install_committed(definitions, active.security_revision)
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "tools reconciliation rejected: the active document does not validate \
                     against the current managed lanes"
                );
                Err(SecurityRevisionCheckError::InvalidDocument)
            }
        }
    }
}

/// The Connection control plane as a reconciled resource (issue #241,
/// PR 8): the connection records, and the managed catalogs derived from
/// them.
///
/// Connections are authorization-relevant in three ways, which is why they
/// belong behind the gate rather than in a periodically refreshed cache:
/// a record carries whether the Connection is enabled at all, the egress
/// destination a proxy route or tool is allowed to reach, and the
/// credential binding that request will present. A replica serving a stale
/// record can send a request to an upstream a commit already withdrew.
pub(crate) struct ConnectionsResource {
    store: Arc<PostgresConnectionStore>,
    control_plane: ConnectionControlPlane,
    mcp_catalogs: McpConnectionCatalogService,
    openapi_catalogs: OpenApiConnectionCatalogService,
    /// The connections revision currently published on this replica.
    /// Installs are monotonic: a reconcile for a revision at or below this
    /// is a no-op, so a slow reconcile cannot overwrite a newer snapshot
    /// with an older one.
    installed_revision: AtomicI64,
}

impl ConnectionsResource {
    pub(crate) fn new(
        store: Arc<PostgresConnectionStore>,
        control_plane: ConnectionControlPlane,
        mcp_catalogs: McpConnectionCatalogService,
        openapi_catalogs: OpenApiConnectionCatalogService,
        boot_revision: i64,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            control_plane,
            mcp_catalogs,
            openapi_catalogs,
            installed_revision: AtomicI64::new(boot_revision),
        })
    }

    /// Republish the records, then the catalogs derived from them, then
    /// flush any dependency rows a synchronous caller queued.
    ///
    /// The order matters. The catalog republish filters on "is this
    /// Connection still enabled and still of the right kind", so it has to
    /// see the records the authority just returned -- filtering against the
    /// previous snapshot would keep serving a catalog whose Connection was
    /// disabled on another replica.
    async fn reconcile(&self) -> Result<(), SecurityRevisionCheckError> {
        let revision = self.store.state_revision().await.map_err(|error| {
            tracing::error!(
                error = %error,
                "connection reconciliation could not read the state revision"
            );
            SecurityRevisionCheckError::Unavailable
        })?;
        let records = self.store.list().await.map_err(|error| {
            tracing::error!(
                error = %error,
                "connection reconciliation could not read the authoritative records"
            );
            SecurityRevisionCheckError::Unavailable
        })?;
        // A record whose binding cannot be resolved is not enforceable
        // here. Publishing it would leave this replica dispatching to an
        // upstream it cannot authenticate to; refusing keeps the gate
        // closed until an operator fixes the binding or the authority
        // withdraws the record.
        if let Err(error) = self
            .control_plane
            .publish_authoritative_records(records)
            .await
        {
            tracing::error!(
                error = %error,
                "connection reconciliation rejected: an authoritative record is not enforceable \
                 on this replica"
            );
            return Err(SecurityRevisionCheckError::InvalidDocument);
        }
        if let Err(error) = self.mcp_catalogs.reconcile_from_authority().await {
            tracing::error!(
                error = %error,
                "connection reconciliation could not republish the managed MCP catalogs"
            );
            return Err(SecurityRevisionCheckError::Unavailable);
        }
        if let Err(error) = self.openapi_catalogs.reconcile_from_authority().await {
            tracing::error!(
                error = %error,
                "connection reconciliation could not republish the managed OpenAPI catalogs"
            );
            return Err(SecurityRevisionCheckError::Unavailable);
        }
        // Dependency rows are derived state queued by synchronous callers
        // (the proxy builder and the tool registry's definition validator,
        // neither of which can await). A failure here is logged, not
        // fatal: these rows guard admin deletes, they authorize no request,
        // and the queue retries on the next pass.
        if let Err(error) = self.control_plane.flush_pending_dependencies().await {
            tracing::warn!(
                error = %error,
                "connection dependency rows could not be published; the delete guard is \
                 incomplete until the next reconcile"
            );
        }
        self.installed_revision.store(revision, Ordering::Release);
        Ok(())
    }
}

#[async_trait]
impl ReconciledResource for ConnectionsResource {
    fn name(&self) -> &'static str {
        "connections"
    }

    async fn activation_revision(&self) -> Result<i64, SecurityRevisionCheckError> {
        self.store.state_revision().await.map_err(|error| {
            tracing::error!(
                error = %error,
                "the connections activation revision could not be read"
            );
            SecurityRevisionCheckError::Unavailable
        })
    }

    async fn reconcile(&self, observed_activation: i64) -> Result<(), SecurityRevisionCheckError> {
        if self.installed_revision.load(Ordering::Acquire) >= observed_activation {
            return Ok(());
        }
        self.reconcile().await
    }
}

impl ClusterSecurityRuntime {
    /// The gate's body with an explicit budget. Requests use
    /// [`RECONCILE_DEADLINE`] through the trait; the background poller
    /// uses [`RECONCILE_BACKGROUND_DEADLINE`].
    pub(crate) async fn ensure_current_revision_within(
        &self,
        budget: Duration,
    ) -> Result<i64, SecurityRevisionCheckError> {
        let deadline = Instant::now() + budget;
        loop {
            // The one authoritative read the strict rule requires. A
            // revision is only visible here once its transaction committed.
            let current = self.current_revision(deadline).await?;
            let compiled = self.compiled_revision.load(Ordering::Acquire);
            if compiled >= current {
                return Ok(compiled);
            }

            // Behind: reconcile inside the remaining deadline. The lock
            // wait is part of the budget -- a request queued behind a
            // reconcile in flight either benefits from its result or runs
            // out of budget and fails closed.
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _guard = tokio::time::timeout(remaining, self.reconcile_lock.lock())
                .await
                .map_err(|_| SecurityRevisionCheckError::ReconcileDeadlineExceeded)?;
            // A concurrent holder may have reconciled past `current`
            // already; re-check before fetching.
            let compiled = self.compiled_revision.load(Ordering::Acquire);
            if compiled >= current {
                return Ok(compiled);
            }
            let moved_past = self
                .reconcile_resources(current, compiled, deadline)
                .await?;
            if moved_past.is_some() {
                // A resource committed during the pass; re-read the counter
                // and confirm against the new frontier.
                continue;
            }
            #[cfg(test)]
            {
                let hook = self
                    .before_publish
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
                if let Some(hook) = hook {
                    hook().await;
                }
            }
            // A commit that landed after a resource's activation read but
            // before its content fetch installed content newer than
            // `current`; publishing `current` would then admit requests
            // under a watermark older than what they are served with -- a
            // combination the authority never held. Re-read the counter
            // and go again if it moved: the next pass installs whatever the
            // commit touched, and the watermark published is the counter
            // that every installed lane is at or below.
            let settled = self.current_revision(deadline).await?;
            if settled != current {
                continue;
            }
            // Confirmed: every registered resource's authoritative state at
            // or below `current` is compiled locally. Publish the watermark
            // and serve this request under it.
            self.compiled_revision.store(current, Ordering::Release);
            return Ok(current);
        }
    }
}

#[async_trait]
impl SecurityRevisionGate for ClusterSecurityRuntime {
    async fn ensure_current_revision(&self) -> Result<i64, SecurityRevisionCheckError> {
        self.ensure_current_revision_within(RECONCILE_DEADLINE)
            .await
    }
}
