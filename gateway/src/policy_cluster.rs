//! Cluster-mode policy control-plane glue (issue #241, PR 7).
//!
//! [`ClusterPolicyRuntime`] is the production implementation of the strict
//! security-revision gate the RBAC middleware consults on every protected
//! request in cluster mode, and the owner of the background reconciler that
//! keeps the local compiled snapshot warm between requests.
//!
//! Correctness lives in the durable authority, not here: the gate reads the
//! security revision from the PostgreSQL primary after the request starts,
//! and reconciliation reads the active document (verifying its recorded
//! ETag) and installs it only after full validation. A lost notification,
//! a dead poller, or a restarted replica all converge on the same answer
//! the next time the gate runs -- the HA state model's "notifications are
//! hints" rule, with the revision counter as the only source of truth.
//!
//! The reconcile deadline is the state model's section 6 budget (250 ms
//! bounded wait, then `503`); it is a normative budget, not operator
//! configuration, so it is a constant here.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::{
    lifecycle::GatewayLifecycle,
    middleware::rbac::{RbacState, SecurityRevisionCheckError, SecurityRevisionGate},
    storage::{PolicyControlPlane as _, PostgresPolicyStore},
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

pub(crate) struct ClusterPolicyRuntime {
    store: Arc<PostgresPolicyStore>,
    rbac_state: RbacState,
    /// Serializes reconciles so a burst of requests behind the revision
    /// frontier produces one fetch-and-compile, not one per waiter.
    reconcile_lock: Mutex<()>,
}

impl ClusterPolicyRuntime {
    pub(crate) fn new(store: Arc<PostgresPolicyStore>, rbac_state: RbacState) -> Arc<Self> {
        Arc::new(Self {
            store,
            rbac_state,
            reconcile_lock: Mutex::new(()),
        })
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
        // revision the waiter checked: revisions are monotonic and the
        // installed snapshot includes every change at or below it.
        //
        // PR 7 scope note: the security revision is global by design, but
        // policy commits are its only writer today, so the gate's
        // "snapshot revision >= counter" test terminates here. When later
        // #241 PRs advance the same counter for other resources (tokens,
        // revocations, tools), this is the seam they extend: the gate must
        // compare each resource's activation revision against the
        // snapshot, and reconcile must key the snapshot on the global
        // revision it compiled against -- otherwise a non-policy revision
        // would leave every replica in a reconcile loop it cannot win.
        self.rbac_state
            .install_revision_snapshot(active.policy, active.security_revision);
        Ok(())
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
                if let Err(error) = runtime.ensure_current_revision().await {
                    tracing::warn!(
                        reason = error.as_str(),
                        "background policy reconciliation failed; the per-request gate refuses protected traffic while behind"
                    );
                }
            }
        });
        lifecycle.register_background_task(handle);
    }
}

#[async_trait]
impl SecurityRevisionGate for ClusterPolicyRuntime {
    async fn ensure_current_revision(&self) -> Result<i64, SecurityRevisionCheckError> {
        let deadline = Instant::now() + RECONCILE_DEADLINE;
        loop {
            // The one authoritative read the strict rule requires. A
            // revision is only visible here once its transaction committed.
            // The read is inside the deadline budget too: pool acquisition
            // and a stalled primary must fail closed within the bounded
            // wait, not after the pool's own multi-second timeouts.
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SecurityRevisionCheckError::ReconcileDeadlineExceeded);
            }
            let current = tokio::time::timeout(remaining, self.store.current_security_revision())
                .await
                .map_err(|_| SecurityRevisionCheckError::ReconcileDeadlineExceeded)?
                .map_err(|error| {
                    tracing::error!(
                        error = %error,
                        "the security revision could not be read from the authority"
                    );
                    SecurityRevisionCheckError::Unavailable
                })?;
            let local = self.rbac_state.snapshot_security_revision();
            if local >= current {
                return Ok(local);
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
            let local = self.rbac_state.snapshot_security_revision();
            if local >= current {
                return Ok(local);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, self.reconcile()).await {
                Ok(Ok(())) => {} // loop: re-read the authority and confirm
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(SecurityRevisionCheckError::ReconcileDeadlineExceeded),
            }
        }
    }
}
