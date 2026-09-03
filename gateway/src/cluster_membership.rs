//! Cluster membership: the heartbeat task and the fingerprint-agreement
//! readiness gate (issue #241, PR 13).
//!
//! In cluster mode every replica keeps one row in
//! `greengateway.cluster_members` (see `storage/postgres_membership.rs`):
//! written at boot by [`ClusterMembership::register_boot`], refreshed
//! every `CLUSTER_HEARTBEAT_MS` by the task [`ClusterMembership::spawn_heartbeat`]
//! registers with the lifecycle, stamped ready once the replica is
//! serving and agreed, and stamped draining when the lifecycle cancels
//! background work. A row whose heartbeat is older than
//! `CLUSTER_MEMBER_STALE_MS` is stale; the maintenance singleton sweeps
//! it, never this task and never a request.
//!
//! **Fingerprint agreement.** After the boot row is written, and on every
//! heartbeat until it succeeds, the replica reads the live members and
//! compares their static-configuration fingerprints with its own. Any
//! live, non-draining member with a different fingerprint is logged by
//! instance ID and keeps this replica's `/readyz` at `503`
//! (`config_fingerprint_mismatch`, [`ClusterReadiness`]). The replica does
//! not exit; agreement is granted on the first heartbeat after the last
//! disagreeing member drains or goes stale. Agreement is one-way, which is
//! what keeps a mismatched newcomer from taking the serving replicas out
//! of rotation with it -- and which means a fingerprint change completes
//! on its own only where the old replicas leave without waiting for the
//! newcomer to become ready (a `Recreate` rollout, a rolling update whose
//! `maxUnavailable` covers every old replica, or an operator draining
//! them). Under a readiness-gated rolling update (Kubernetes
//! `RollingUpdate` with `maxUnavailable: 0`, the Deployment default) the
//! newcomer is never ready while an old replica serves and the old replica
//! is never terminated while the newcomer is unready, so the rollout
//! stalls at the door until the operator rolls back or forces the old
//! replicas out: the gateway cannot tell an intended change from a
//! misconfigured replica at the moment the newcomer boots, and a stalled
//! rollout is that decision handed to the operator.
//!
//! The heartbeat also carries the replica's security-revision
//! acknowledgement (`compiled` and `observed`, from the cluster security
//! runtime), so the roster shows each replica's reconciliation lag.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use uuid::Uuid;

use crate::{
    ha::ClusterReadiness,
    lifecycle::GatewayLifecycle,
    security_cluster::ClusterSecurityRuntime,
    storage::{
        ClusterMember, MemberRegistration, MemberRevisions, PostgresMembershipStore,
        RepositoryError,
    },
};

/// The policy/tools document schema range this binary enforces, in
/// major versions. The policy document's `schema_version` must start
/// with `0.` (`rbac/policy.rs`), and the tools document rides the same
/// major; the range is advertised so a rolling window can tell a
/// document-format change apart from a schema change.
pub(crate) const DOCUMENT_VERSION_RANGE: (i32, i32) = (0, 0);

/// How long the draining stamp may take once the lifecycle cancels
/// background work: bounded, so a slow authority cannot hold shutdown.
const DRAINING_STAMP_BUDGET: Duration = Duration::from_secs(5);

/// The result of one agreement check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FingerprintAgreement {
    /// Every live, non-draining member carries this replica's fingerprint
    /// (or this replica is alone).
    Agreed,
    /// These live members carry another fingerprint.
    Disagreeing(Vec<Uuid>),
}

pub(crate) struct ClusterMembership {
    store: Arc<PostgresMembershipStore>,
    registration: MemberRegistration,
    readiness: Arc<ClusterReadiness>,
    heartbeat_interval: Duration,
    stale_window: Duration,
    /// Whether `ready_at` has been stamped; the stamp is idempotent in
    /// the store, this only saves a statement per tick.
    ready_recorded: AtomicBool,
    /// The classified kind of the last failed store call, carried on the
    /// next heartbeat as `last_error_code` and cleared by a success.
    last_error_code: Mutex<Option<&'static str>>,
}

impl ClusterMembership {
    pub(crate) fn new(
        store: PostgresMembershipStore,
        registration: MemberRegistration,
        heartbeat_interval: Duration,
        stale_window: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            store: Arc::new(store),
            registration,
            readiness: ClusterReadiness::new(),
            heartbeat_interval,
            stale_window,
            ready_recorded: AtomicBool::new(false),
            last_error_code: Mutex::new(None),
        })
    }

    /// The gate `/readyz` consults.
    pub(crate) fn readiness(&self) -> Arc<ClusterReadiness> {
        Arc::clone(&self.readiness)
    }

    /// The roster and ledger store, shared with the maintenance runner
    /// (`cluster_maintenance.rs`), which sweeps stale rows and writes the
    /// fenced job ledger through it.
    pub(crate) fn store(&self) -> Arc<PostgresMembershipStore> {
        Arc::clone(&self.store)
    }

    /// Write the boot row and run the first agreement check. A row that
    /// cannot be written is a startup failure (the database was just
    /// proven reachable); a disagreement is not -- it is logged and the
    /// replica boots unready.
    pub(crate) async fn register_boot(&self) -> Result<FingerprintAgreement, RepositoryError> {
        self.store
            .heartbeat(&self.registration, MemberRevisions::default(), None)
            .await?;
        let agreement = self.check_fingerprint_agreement().await;
        // From the boot row on, so a replica that never gets past the
        // fingerprint door still has a series saying so rather than no
        // series at all -- "held at the door" and "not scraped" must not
        // look the same.
        self.publish_membership_gauges();
        agreement
    }

    /// Compare the live roster with this replica's fingerprint, granting
    /// (sticky) agreement when nobody live disagrees. Already-agreed
    /// replicas answer without a read.
    pub(crate) async fn check_fingerprint_agreement(
        &self,
    ) -> Result<FingerprintAgreement, RepositoryError> {
        if self.readiness.fingerprint_agreed() {
            return Ok(FingerprintAgreement::Agreed);
        }
        let members = self.store.members(self.stale_window).await?;
        let disagreeing = fingerprint_disagreements(
            &members,
            self.store.instance_id(),
            &self.registration.fingerprint,
        );
        if disagreeing.is_empty() {
            self.readiness.record_fingerprint_agreement();
            tracing::info!(
                live_members = members.iter().filter(|member| member.live).count(),
                "cluster mode: every live member agrees on the static-configuration fingerprint; readiness is no longer gated on it"
            );
            return Ok(FingerprintAgreement::Agreed);
        }
        for member in &members {
            if disagreeing.contains(&member.instance_id) {
                tracing::warn!(
                    member_instance_id = %member.instance_id,
                    member_fingerprint = %member.fingerprint,
                    member_binary_version = %member.binary_version,
                    own_fingerprint = %self.registration.fingerprint,
                    "cluster mode: a live member runs a different static configuration; this replica refuses readiness (config_fingerprint_mismatch) until the members agree"
                );
            }
        }
        Ok(FingerprintAgreement::Disagreeing(disagreeing))
    }

    /// The heartbeat task: every interval, refresh the row with the
    /// runtime's revisions, re-check agreement while it is withheld, and
    /// stamp readiness once the lifecycle is serving and the gate is
    /// open. On cancellation (draining or shutdown) the row is stamped
    /// draining under a bounded budget. Failures are logged, classified,
    /// and carried on the next heartbeat; the task never exits on one.
    pub(crate) fn spawn_heartbeat(
        self: &Arc<Self>,
        lifecycle: &GatewayLifecycle,
        revisions: Option<Arc<ClusterSecurityRuntime>>,
    ) {
        let membership = Arc::clone(self);
        let lifecycle_for_task = lifecycle.clone();
        let cancellation = lifecycle.background_cancellation();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(membership.heartbeat_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires at once; the boot row is already
            // written, so skip it rather than double-write.
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    () = cancellation.cancelled() => {
                        membership.stamp_draining().await;
                        return;
                    }
                }
                membership
                    .tick(&lifecycle_for_task, revisions.as_deref())
                    .await;
            }
        });
        lifecycle.register_background_task(handle);
    }

    async fn tick(&self, lifecycle: &GatewayLifecycle, revisions: Option<&ClusterSecurityRuntime>) {
        self.tick_once(lifecycle, revisions).await;
        // Published after every tick, however it ended. The failure paths
        // are the ones that matter: a heartbeat that cannot be written is
        // precisely when the age has to keep climbing in the series an
        // operator is watching, and an early return that skipped the
        // publication would freeze it at its last healthy value.
        self.publish_membership_gauges();
    }

    async fn tick_once(
        &self,
        lifecycle: &GatewayLifecycle,
        revisions: Option<&ClusterSecurityRuntime>,
    ) {
        let revisions = revisions
            .map(|runtime| MemberRevisions {
                compiled: runtime.compiled_revision(),
                observed: runtime.observed_revision(),
            })
            .unwrap_or_default();
        let carried_error = *self
            .last_error_code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match self
            .store
            .heartbeat(&self.registration, revisions, carried_error)
            .await
        {
            Ok(()) => self.note_success(),
            Err(error) => {
                self.note_failure(&error);
                tracing::warn!(error = %error, "cluster member heartbeat failed; retrying on the next interval");
                return;
            }
        }
        if !self.readiness.fingerprint_agreed() {
            if let Err(error) = self.check_fingerprint_agreement().await {
                self.note_failure(&error);
                tracing::warn!(error = %error, "cluster membership could not be read for the fingerprint check; readiness stays withheld");
                return;
            }
        }
        if self.readiness.fingerprint_agreed()
            && lifecycle.accepting_work()
            && !self.ready_recorded.load(Ordering::Acquire)
        {
            match self.store.mark_ready().await {
                Ok(()) => self.ready_recorded.store(true, Ordering::Release),
                Err(error) => {
                    self.note_failure(&error);
                    tracing::warn!(error = %error, "cluster member ready stamp failed; retrying on the next interval");
                }
            }
        }
    }

    async fn stamp_draining(&self) {
        match tokio::time::timeout(DRAINING_STAMP_BUDGET, self.store.mark_draining()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "cluster member draining stamp failed; the row goes stale instead")
            }
            Err(_) => {
                tracing::warn!(
                    "cluster member draining stamp timed out; the row goes stale instead"
                )
            }
        }
    }

    fn note_success(&self) {
        *self
            .last_error_code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        // The readiness probe (issue #241, PR 14) refuses readiness once
        // this replica's row has not been refreshed inside the stale
        // window, which is the moment the roster stops counting it live.
        self.readiness.record_heartbeat_success();
    }

    fn note_failure(&self, error: &RepositoryError) {
        *self
            .last_error_code
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(error.kind().as_str());
    }

    /// Publish this replica's two membership facts as gauges (issue #241,
    /// PR 14): how old its roster row is, and whether it is still held at
    /// the fingerprint door.
    ///
    /// Neither carries a label. The instance the age belongs to is *this*
    /// process, which the scrape target already identifies; putting the
    /// instance id in a label would mint a series per boot, and a replica
    /// set that rolls weekly would accumulate them forever.
    pub(crate) fn publish_membership_gauges(&self) {
        record_membership_gauges(
            self.readiness.heartbeat_age(),
            self.readiness.fingerprint_agreed(),
        );
    }
}

/// The emission itself, split from the task that owns the values so the
/// registry label audit can drive it (`metrics.rs`) without a database.
pub(crate) fn record_membership_gauges(heartbeat_age: Duration, fingerprint_agreed: bool) {
    ::metrics::gauge!(crate::metrics::CLUSTER_HEARTBEAT_AGE_SECONDS)
        .set(heartbeat_age.as_secs_f64());
    ::metrics::gauge!(crate::metrics::CLUSTER_CONFIG_MISMATCH).set(if fingerprint_agreed {
        0.0
    } else {
        1.0
    });
}

/// The live, non-draining members other than `own_instance` whose
/// fingerprint differs from `own_fingerprint`. Stale rows are ignored
/// (they are somebody's past, not the deployment's present) and draining
/// rows are ignored (they are leaving, and blocking on them would make a
/// rolling change wait for its own completion).
pub(crate) fn fingerprint_disagreements(
    members: &[ClusterMember],
    own_instance: Uuid,
    own_fingerprint: &str,
) -> Vec<Uuid> {
    members
        .iter()
        .filter(|member| member.live && member.draining_at.is_none())
        .filter(|member| member.instance_id != own_instance)
        .filter(|member| member.fingerprint != own_fingerprint)
        .map(|member| member.instance_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(fingerprint: &str, live: bool, draining: bool) -> ClusterMember {
        ClusterMember {
            instance_id: Uuid::new_v4(),
            boot_id: Uuid::new_v4(),
            binary_version: "0.0.0".to_owned(),
            schema_version_min: 9,
            schema_version_max: 9,
            document_version_min: 0,
            document_version_max: 0,
            fingerprint: fingerprint.to_owned(),
            started_at: "2026-01-01T00:00:00.000000Z".to_owned(),
            last_heartbeat_at: "2026-01-01T00:00:00.000000Z".to_owned(),
            heartbeat_age_secs: if live { 1.0 } else { 3_600.0 },
            ready_at: None,
            draining_at: draining.then(|| "2026-01-01T00:00:01.000000Z".to_owned()),
            compiled_security_revision: 0,
            observed_security_revision: 0,
            last_error_code: None,
            live,
        }
    }

    #[test]
    fn only_live_non_draining_other_members_can_disagree() {
        let own = member("a".repeat(64).as_str(), true, false);
        let live_other = member("b".repeat(64).as_str(), true, false);
        let stale_other = member("b".repeat(64).as_str(), false, false);
        let draining_other = member("b".repeat(64).as_str(), true, true);
        let agreeing_other = member("a".repeat(64).as_str(), true, false);
        let members = vec![
            own.clone(),
            live_other.clone(),
            stale_other,
            draining_other,
            agreeing_other,
        ];
        assert_eq!(
            fingerprint_disagreements(&members, own.instance_id, &own.fingerprint),
            vec![live_other.instance_id],
            "only the live, non-draining member with another fingerprint blocks"
        );
        let members_without_live_other = vec![member("b".repeat(64).as_str(), false, false)];
        assert!(
            fingerprint_disagreements(
                &members_without_live_other,
                own.instance_id,
                &own.fingerprint
            )
            .is_empty(),
            "a stale row is history, not a disagreement"
        );
    }

    #[test]
    fn the_readiness_gate_is_closed_until_agreement_and_then_sticky() {
        let readiness = ClusterReadiness::new();
        assert_eq!(
            readiness.blocked_reason(),
            Some(ClusterReadiness::FINGERPRINT_MISMATCH)
        );
        readiness.record_fingerprint_agreement();
        assert_eq!(readiness.blocked_reason(), None);
        readiness.record_fingerprint_agreement();
        assert!(readiness.fingerprint_agreed());
    }
}
