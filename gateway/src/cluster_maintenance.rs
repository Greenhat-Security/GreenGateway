//! The maintenance singleton: leased ownership of the deployment's periodic
//! housekeeping (issue #241, PR 13, sections 4 and 5).
//!
//! Standalone mode runs its housekeeping inline (SQLite audit retention on
//! a timer, pending-login pruning on insert). With N replicas that would
//! be N sweeps racing over shared tables, so cluster mode makes the
//! housekeeping one replica's job at a time:
//!
//! - **One lease slot** (`execution_leases`, scope `maintenance`, capacity
//!   1, TTL `CLUSTER_MAINTENANCE_LEASE_TTL_MS`) elects the leader. Every
//!   replica runs a [`MaintenanceRunner`]; each tries the slot, and the one
//!   that takes it runs the jobs until it loses the lease or the lifecycle
//!   drains. The lease is renewed exactly as a tool lease is
//!   (`tools::runtime::renew_until_lost`): a renewal that finds the lease
//!   gone, or half a TTL without one the authority could answer, cancels
//!   the loop -- and the pass in flight -- *before* the slot can be
//!   reclaimed, never after.
//! - **Jittered failover.** A replica that finds the slot held waits
//!   `interval/4 +/- up to interval/8`, the offset drawn from its instance
//!   ID ([`acquisition_backoff`]), so the survivors of a leader's crash do
//!   not stampede the authority in lockstep and one of them takes over
//!   within a bounded, staggered window after the TTL.
//! - **Fenced ledger writes.** On taking the lease the leader adopts the
//!   `maintenance_jobs` rows at its fence; every `last_started_at` and
//!   outcome write carries `WHERE fence = <its fence>` *and* requires the
//!   maintenance lease at that fence to be live on the database clock. A
//!   leader that was paused past its TTL has its late writes refused from
//!   the instant its lease lapses -- before any successor has acquired,
//!   and before one that has acquired adopts the rows -- and the runner
//!   stops the pass at the first refusal (the store answers `false`).
//! - **A dedicated advisory-lock session** per pass
//!   ([`DedicatedSession`]): one pooled connection holding
//!   `pg_try_advisory_lock(MAINTENANCE_LOCK_KEY)` for the pass's lifetime.
//!   Every job step runs its statements *on that connection*, so the lock
//!   covers the statement for as long as it runs (the server releases a
//!   session lock only once the session, and so its statement in flight,
//!   has ended) and losing the connection fails the step at once rather
//!   than at the next job. A held key means somebody else is running the
//!   pass and this one is skipped; a lost connection cancels the pass. The
//!   belt alongside the lease's braces.
//! - **Bounded, independent jobs in a fixed order.** Each job is one
//!   bounded step (`JOB_STEP_LIMIT` rows, `JOB_BUDGET` wall time) that
//!   deletes what is already dead by database time: expired JWT
//!   revocations, idle rate-limit buckets, expired pending logins, stale
//!   member rows, audit events past `AUDIT_POSTGRES_RETENTION_DAYS` (never
//!   past the retention floor, see [`AuditRetentionFloor`]), and lease rows
//!   expired for more than one TTL. A failing job is logged, recorded in the
//!   ledger with its classified code, and never blocks the next one.
//!
//! Metrics: `cluster_maintenance_leader` (1 while this replica leads),
//! `cluster_maintenance_job_runs_total{job,outcome}`, and
//! `cluster_members_live` (set by the stale sweep from the leader's read
//! of the roster).

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, LazyLock,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    connections::local_secret::LocalSecretKeyring,
    lifecycle::GatewayLifecycle,
    metrics::{
        CLUSTER_MAINTENANCE_JOB_RUNS_TOTAL, CLUSTER_MAINTENANCE_LEADER, CLUSTER_MEMBERS_LIVE,
    },
    storage::{
        postgres_audit::PostgresAuditEventStore, postgres_session::advisory_lock_key,
        DedicatedSession, JobOutcome, PostgresExecutionLeaseStore, PostgresJwtRevocationStore,
        PostgresMembershipStore, PostgresPendingLoginStore, PostgresRateLimitStore,
        RepositoryError, RepositoryErrorKind,
    },
    tools::{
        lease::{ExecutionLease, ExecutionLeaseStore, LeaseAttempt},
        runtime::renew_until_lost,
    },
};

/// The lease scope the leader slot lives in; the ledger anchors its fenced
/// writes on the live lease in this scope, so the store owns the name.
pub(crate) const MAINTENANCE_SCOPE: &str =
    crate::storage::postgres_membership::MAINTENANCE_LEASE_SCOPE;
/// The invocation label the lease row carries.
const MAINTENANCE_INVOCATION: &str = "maintenance";

/// The session advisory-lock key a pass holds, derived from its name like
/// the migration and audit stream keys and pinned by a test.
pub(crate) static MAINTENANCE_LOCK_KEY: LazyLock<i64> =
    LazyLock::new(|| advisory_lock_key("greengateway.maintenance"));

/// Rows one job step may touch. Every job's statement is `LIMIT`-bounded
/// at this; a backlog larger than it is drained one step per interval.
pub(crate) const JOB_STEP_LIMIT: u32 = 1_000;

/// Wall time one job step may take before it is recorded as `timeout` and
/// the pass moves on. The database's `statement_timeout` bounds the
/// statement itself; this bounds the job as the ledger sees it.
const JOB_BUDGET: Duration = Duration::from_secs(30);

/// The floor under the acquisition backoff, so a tiny test interval does
/// not spin the authority.
const MIN_ACQUISITION_BACKOFF: Duration = Duration::from_millis(20);

pub(crate) const JOB_JWT_REVOCATION_CLEANUP: &str = "jwt_revocation_cleanup";
pub(crate) const JOB_RATE_LIMIT_IDLE_SWEEP: &str = "rate_limit_idle_sweep";
pub(crate) const JOB_PENDING_LOGIN_PRUNE: &str = "pending_login_prune";
pub(crate) const JOB_STALE_MEMBER_SWEEP: &str = "stale_member_sweep";
pub(crate) const JOB_AUDIT_RETENTION: &str = "audit_retention";
pub(crate) const JOB_EXECUTION_LEASE_REAPER: &str = "execution_lease_reaper";

/// Every singleton job name, which is the whole vocabulary of the `job`
/// label on `greengateway_cluster_maintenance_job_runs_total` and of the
/// `task` label on `greengateway_leader_task_last_success_age_seconds`.
///
/// `the_leader_task_vocabulary_is_the_singletons_job_names` in
/// `cluster_status.rs` already keeps the status view's copy of this list
/// in step; the registry label audit uses this one.
pub(crate) const JOB_NAMES: [&str; 6] = [
    JOB_JWT_REVOCATION_CLEANUP,
    JOB_RATE_LIMIT_IDLE_SWEEP,
    JOB_PENDING_LOGIN_PRUNE,
    JOB_STALE_MEMBER_SWEEP,
    JOB_AUDIT_RETENTION,
    JOB_EXECUTION_LEASE_REAPER,
];

/// The `&'static str` this binary knows a ledger row's job name by, or
/// `None` when it does not know it.
///
/// The whole point of the round trip through a fixed list: the ledger's
/// `job` column is *database data*, and a database this gateway shares
/// with a newer one -- or that somebody edited -- can carry a name it has
/// never heard of. Recognising the name and using the *recognised
/// constant* as the label means the label can only ever be one of six
/// values, whatever the row said.
pub(crate) fn known_job_name(job: &str) -> Option<&'static str> {
    JOB_NAMES.into_iter().find(|name| *name == job)
}

/// Publish how long ago one singleton job last succeeded. `task` is a
/// [`JOB_NAMES`] entry; a ledger row naming anything else is data and is
/// dropped by [`known_job_name`] rather than turned into a label.
pub(crate) fn record_leader_task_age(task: &'static str, age_secs: f64) {
    ::metrics::gauge!(
        crate::metrics::LEADER_TASK_LAST_SUCCESS_AGE_SECONDS,
        "task" => task
    )
    .set(age_secs);
}

/// The acquisition backoff for a replica: `interval/4 +/- up to
/// interval/8`, the offset fixed by the instance ID so every replica waits
/// a different, stable amount and a leader's crash is followed by one
/// staggered takeover rather than a stampede. Always within
/// `[interval/8, 3*interval/8]` (and never under the floor).
pub(crate) fn acquisition_backoff(interval: Duration, instance_id: Uuid) -> Duration {
    let base = interval.as_secs_f64() / 4.0;
    let spread = interval.as_secs_f64() / 8.0;
    let bits = instance_id.as_u128();
    let folded = (bits as u64) ^ ((bits >> 64) as u64);
    // A position in [-1000, 1000], so the offset covers [-spread, +spread].
    let unit = (folded % 2001) as f64 - 1000.0;
    let backoff = base + spread * unit / 1000.0;
    Duration::from_secs_f64(backoff.max(0.0)).max(MIN_ACQUISITION_BACKOFF)
}

/// The lower bound audit retention must respect: the highest audit-stream
/// position every durable consumer has applied. Retention deletes only
/// events at or below it (and events that were never appended to the
/// stream); everything above stays whatever its age, so a consumer that
/// fell behind finds its events rather than a gap.
///
/// With no provider retention is bounded by age alone (the contract tests
/// use that). Cluster startup wires the discovery projector's checkpoint
/// (`discovery_projector_state`, issue #241 PR 11) as the provider: its
/// durably committed position is exactly this value.
#[async_trait]
pub(crate) trait AuditRetentionFloor: Send + Sync {
    /// The highest stream position the consumer has durably applied.
    /// `None` means it has applied nothing yet, and retention then keeps
    /// every streamed event (the safe reading); a provider that cannot be
    /// read fails the job for this pass, which retention records and
    /// retries next interval rather than guessing.
    async fn durably_consumed_position(&self) -> Result<Option<i64>, RepositoryError>;
}

/// The projector's committed checkpoint is the floor: retention deletes
/// stream positions strictly below it, which is inside the projector's own
/// contract (`minimum_retained_position` = checkpoint + 1), and a
/// checkpoint of 0 -- nothing projected yet -- frees no streamed event.
/// The read rides a pooled connection of its own, not the pass's
/// dedicated session; the checkpoint only ever advances, so a value read
/// before the delete is at most too low, never too high.
#[async_trait]
impl AuditRetentionFloor for crate::storage::postgres_discovery::PostgresDiscoveryStore {
    async fn durably_consumed_position(&self) -> Result<Option<i64>, RepositoryError> {
        Ok(Some(self.checkpoint().await?.checkpoint_position))
    }
}

/// One singleton job: a name for the ledger and the metric, and one
/// bounded step that reports how many rows it touched. The step runs its
/// statements on `client` -- the dedicated session holding the maintenance
/// advisory lock -- never on a pooled connection of its own, so the lock
/// covers the statement and a lost session fails the step in flight.
#[async_trait]
pub(crate) trait MaintenanceJob: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run_step(&self, client: &tokio_postgres::Client) -> Result<u64, RepositoryError>;
}

/// Delete JWT revocations past their expiry and leeway
/// (`PostgresJwtRevocationStore::cleanup_expired`).
pub(crate) struct JwtRevocationCleanup {
    pub(crate) store: PostgresJwtRevocationStore,
    pub(crate) limit: u32,
}

#[async_trait]
impl MaintenanceJob for JwtRevocationCleanup {
    fn name(&self) -> &'static str {
        JOB_JWT_REVOCATION_CLEANUP
    }

    async fn run_step(&self, client: &tokio_postgres::Client) -> Result<u64, RepositoryError> {
        self.store
            .cleanup_expired_with(client, self.limit as usize)
            .await
    }
}

/// Reclaim shared rate-limit buckets idle for the bucket TTL
/// (`PostgresRateLimitStore::cleanup_idle`), keeping the live count exact.
pub(crate) struct RateLimitIdleSweep {
    pub(crate) store: PostgresRateLimitStore,
    pub(crate) idle: Duration,
    pub(crate) limit: u32,
}

#[async_trait]
impl MaintenanceJob for RateLimitIdleSweep {
    fn name(&self) -> &'static str {
        JOB_RATE_LIMIT_IDLE_SWEEP
    }

    async fn run_step(&self, client: &tokio_postgres::Client) -> Result<u64, RepositoryError> {
        self.store
            .cleanup_idle_with(client, self.idle.as_secs_f64(), self.limit)
            .await
    }
}

/// Delete expired pending admin logins
/// (`PostgresPendingLoginStore::prune_expired`). Needs no keyring, so it
/// runs whether or not this replica has an admin login provider.
pub(crate) struct PendingLoginPrune {
    pub(crate) limit: u32,
}

#[async_trait]
impl MaintenanceJob for PendingLoginPrune {
    fn name(&self) -> &'static str {
        JOB_PENDING_LOGIN_PRUNE
    }

    async fn run_step(&self, client: &tokio_postgres::Client) -> Result<u64, RepositoryError> {
        PostgresPendingLoginStore::prune_expired_with(client, self.limit).await
    }
}

/// Sweep roster rows whose heartbeat is older than the stale window
/// (`PostgresMembershipStore::sweep_stale`), then publish the live count.
pub(crate) struct StaleMemberSweep {
    pub(crate) store: Arc<PostgresMembershipStore>,
    pub(crate) stale_window: Duration,
    pub(crate) limit: u32,
}

#[async_trait]
impl MaintenanceJob for StaleMemberSweep {
    fn name(&self) -> &'static str {
        JOB_STALE_MEMBER_SWEEP
    }

    async fn run_step(&self, client: &tokio_postgres::Client) -> Result<u64, RepositoryError> {
        let removed = self
            .store
            .sweep_stale_with(client, self.stale_window, self.limit)
            .await?;
        let members = self.store.members_with(client, self.stale_window).await?;
        let live = members.iter().filter(|member| member.live).count();
        ::metrics::gauge!(CLUSTER_MEMBERS_LIVE).set(live as f64);
        Ok(removed)
    }
}

/// Delete audit events older than the retention window and at or below
/// the retention floor (`PostgresAuditEventStore::prune_older_than`).
pub(crate) struct AuditRetention {
    pub(crate) store: Arc<PostgresAuditEventStore>,
    pub(crate) retention: Duration,
    pub(crate) floor: Option<Arc<dyn AuditRetentionFloor>>,
    pub(crate) limit: u32,
}

#[async_trait]
impl MaintenanceJob for AuditRetention {
    fn name(&self) -> &'static str {
        JOB_AUDIT_RETENTION
    }

    async fn run_step(&self, client: &tokio_postgres::Client) -> Result<u64, RepositoryError> {
        // The floor is read fresh every step: a consumer that advanced
        // since the last pass frees more of the tail, one that has not
        // frees nothing more. Only positions strictly below
        // `consumed + 1` -- that is, at or below the consumed position --
        // are candidates.
        let min_retained = match &self.floor {
            Some(provider) => match provider.durably_consumed_position().await? {
                Some(consumed) => Some(consumed.saturating_add(1)),
                // A provider with no position yet has consumed nothing:
                // keep every streamed event.
                None => Some(i64::MIN),
            },
            None => None,
        };
        self.store
            .prune_older_than_with(client, self.retention, min_retained, self.limit)
            .await
    }
}

/// Delete lease rows expired for longer than one TTL
/// (`PostgresExecutionLeaseStore::reap_expired`). Defensive: acquisition
/// already reclaims expired slots in place.
pub(crate) struct ExecutionLeaseReaper {
    pub(crate) store: PostgresExecutionLeaseStore,
    pub(crate) grace: Duration,
    pub(crate) limit: u32,
}

#[async_trait]
impl MaintenanceJob for ExecutionLeaseReaper {
    fn name(&self) -> &'static str {
        JOB_EXECUTION_LEASE_REAPER
    }

    async fn run_step(&self, client: &tokio_postgres::Client) -> Result<u64, RepositoryError> {
        self.store
            .reap_expired_with(client, self.grace, self.limit)
            .await
    }
}

/// What the production job list is built from.
pub(crate) struct StandardJobSources {
    pub(crate) pool: deadpool_postgres::Pool,
    pub(crate) deployment_id: String,
    pub(crate) rate_limit_keyring: LocalSecretKeyring,
    pub(crate) rate_limit_max_buckets: usize,
    pub(crate) rate_limit_idle: Duration,
    pub(crate) membership: Arc<PostgresMembershipStore>,
    pub(crate) stale_window: Duration,
    /// The durable audit store and the configured retention; retention is
    /// a job only when both exist.
    pub(crate) audit: Option<Arc<PostgresAuditEventStore>>,
    pub(crate) audit_retention: Option<Duration>,
    pub(crate) audit_floor: Option<Arc<dyn AuditRetentionFloor>>,
    /// The reaper's own lease store identity and the tool lease TTL (its
    /// grace).
    pub(crate) lease_holder: Uuid,
    pub(crate) tool_lease_ttl: Duration,
}

/// The production job list, in the fixed order the ledger and the docs
/// describe. Every step is bounded at [`JOB_STEP_LIMIT`].
pub(crate) fn standard_jobs(sources: StandardJobSources) -> Vec<Arc<dyn MaintenanceJob>> {
    let mut jobs: Vec<Arc<dyn MaintenanceJob>> = vec![
        Arc::new(JwtRevocationCleanup {
            // Cleanup is issuer-agnostic; the store's issuer is unused here.
            store: PostgresJwtRevocationStore::new(
                sources.pool.clone(),
                &sources.deployment_id,
                "-",
            ),
            limit: JOB_STEP_LIMIT,
        }),
        Arc::new(RateLimitIdleSweep {
            store: PostgresRateLimitStore::new(
                sources.pool.clone(),
                &sources.deployment_id,
                sources.rate_limit_keyring,
                sources.rate_limit_max_buckets,
            ),
            idle: sources.rate_limit_idle,
            limit: JOB_STEP_LIMIT,
        }),
        Arc::new(PendingLoginPrune {
            limit: JOB_STEP_LIMIT,
        }),
        Arc::new(StaleMemberSweep {
            store: sources.membership,
            stale_window: sources.stale_window,
            limit: JOB_STEP_LIMIT,
        }),
    ];
    if let (Some(store), Some(retention)) = (sources.audit, sources.audit_retention) {
        jobs.push(Arc::new(AuditRetention {
            store,
            retention,
            floor: sources.audit_floor,
            limit: JOB_STEP_LIMIT,
        }));
    }
    jobs.push(Arc::new(ExecutionLeaseReaper {
        store: PostgresExecutionLeaseStore::new(
            sources.pool,
            &sources.deployment_id,
            sources.lease_holder,
            sources.tool_lease_ttl,
        ),
        grace: sources.tool_lease_ttl,
        limit: JOB_STEP_LIMIT,
    }));
    jobs
}

/// How one pass ended, for the loop and for tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PassOutcome {
    /// Every job ran (some may have failed and been recorded as such).
    Completed { failed_jobs: usize },
    /// The advisory lock was held elsewhere, or no session could be
    /// opened; nothing ran.
    Skipped,
    /// A ledger write was refused by the fence: this leader is stale and
    /// must stop.
    Stale,
    /// The dedicated session's connection was lost mid-pass; the
    /// remaining jobs did not run.
    ConnectionLost,
}

/// How a one-shot `gateway maintenance-run` ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OnePassOutcome {
    /// A live leader holds the slot; nothing ran.
    LeaseHeld,
    /// The lease was lost before the pass finished; it was cancelled.
    LeaseLost { fence: i64 },
    /// The pass ran (or was refused by the fence) under `fence`.
    Ran { fence: i64, outcome: PassOutcome },
}

pub(crate) struct MaintenanceRunner {
    pool: deadpool_postgres::Pool,
    leases: Arc<dyn ExecutionLeaseStore>,
    ledger: Arc<PostgresMembershipStore>,
    jobs: Vec<Arc<dyn MaintenanceJob>>,
    interval: Duration,
    instance_id: Uuid,
    leading: AtomicBool,
    passes_completed: AtomicU64,
}

impl MaintenanceRunner {
    /// `leases` must be built with the maintenance lease TTL, not the tool
    /// lease TTL: the two are configured separately.
    pub(crate) fn new(
        pool: deadpool_postgres::Pool,
        leases: Arc<dyn ExecutionLeaseStore>,
        ledger: Arc<PostgresMembershipStore>,
        jobs: Vec<Arc<dyn MaintenanceJob>>,
        interval: Duration,
        instance_id: Uuid,
    ) -> Arc<Self> {
        Arc::new(Self {
            pool,
            leases,
            ledger,
            jobs,
            interval,
            instance_id,
            leading: AtomicBool::new(false),
            passes_completed: AtomicU64::new(0),
        })
    }

    /// Whether this replica holds the maintenance lease right now.
    #[allow(dead_code)] // observed by the PostgreSQL tests and PR 14's status view
    pub(crate) fn is_leading(&self) -> bool {
        self.leading.load(Ordering::Acquire)
    }

    /// Passes that ran every job to the end (successes and recorded
    /// failures alike) since boot.
    #[allow(dead_code)] // observed by the PostgreSQL tests and PR 14's status view
    pub(crate) fn passes_completed(&self) -> u64 {
        self.passes_completed.load(Ordering::Acquire)
    }

    pub(crate) fn job_names(&self) -> Vec<&'static str> {
        self.jobs.iter().map(|job| job.name()).collect()
    }

    /// This replica's stable acquisition backoff.
    pub(crate) fn acquisition_backoff(&self) -> Duration {
        acquisition_backoff(self.interval, self.instance_id)
    }

    /// The background task: registered with the lifecycle, cancelled when
    /// it drains (which releases the lease at once so a successor takes
    /// over without waiting for the TTL).
    pub(crate) fn spawn(self: &Arc<Self>, lifecycle: &GatewayLifecycle) {
        let runner = Arc::clone(self);
        let cancellation = lifecycle.background_cancellation();
        let handle = tokio::spawn(async move { runner.serve(cancellation).await });
        lifecycle.register_background_task(handle);
    }

    /// One bounded pass for `gateway maintenance-run`: take the lease like
    /// any leader (a live leader's slot is answered `Full`, never waited
    /// for), adopt the ledger at the fence, run one pass while the lease is
    /// renewed, and release. The pass is cancelled if the lease is lost
    /// mid-way, exactly as a leader's would be, so the one-shot can never
    /// outlive its fence.
    pub(crate) async fn run_once(&self) -> Result<OnePassOutcome, RepositoryError> {
        let lease = match self
            .leases
            .try_acquire(MAINTENANCE_SCOPE, 1, MAINTENANCE_INVOCATION)
            .await?
        {
            LeaseAttempt::Acquired(lease) => lease,
            LeaseAttempt::Full => return Ok(OnePassOutcome::LeaseHeld),
        };
        let lost = CancellationToken::new();
        let renewal = AbortOnDrop(tokio::spawn(renew_until_lost(
            Arc::clone(&self.leases),
            lease.clone(),
            lost.clone(),
        )));
        let fence = lease.fence;
        let names = self.job_names();
        let outcome = match self.ledger.adopt_jobs(&names, fence).await {
            Ok(true) => tokio::select! {
                () = lost.cancelled() => Ok(OnePassOutcome::LeaseLost { fence }),
                outcome = self.run_pass(fence) => Ok(OnePassOutcome::Ran { fence, outcome }),
            },
            Ok(false) => Ok(OnePassOutcome::Ran {
                fence,
                outcome: PassOutcome::Stale,
            }),
            Err(error) => Err(error),
        };
        drop(renewal);
        if let Err(error) = self.leases.release(&lease).await {
            tracing::warn!(
                error = %error,
                "maintenance lease release failed; the slot lapses by expiry"
            );
        }
        outcome
    }

    /// Try the lease; lead while it is held; back off with jitter while it
    /// is not. Returns when `cancellation` fires.
    pub(crate) async fn serve(self: Arc<Self>, cancellation: CancellationToken) {
        let backoff = self.acquisition_backoff();
        loop {
            let attempt = tokio::select! {
                () = cancellation.cancelled() => return,
                attempt = self.leases.try_acquire(MAINTENANCE_SCOPE, 1, MAINTENANCE_INVOCATION) => attempt,
            };
            match attempt {
                Ok(LeaseAttempt::Acquired(lease)) => {
                    self.lead(lease, &cancellation).await;
                    if cancellation.is_cancelled() {
                        return;
                    }
                }
                Ok(LeaseAttempt::Full) => {}
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "maintenance lease could not be tried; retrying after the backoff"
                    );
                }
            }
            tokio::select! {
                () = cancellation.cancelled() => return,
                () = tokio::time::sleep(backoff) => {}
            }
        }
    }

    /// Hold `lease`: adopt the ledger, run a pass at once and then every
    /// interval, stop on the first sign the lease is gone, the ledger is
    /// held at a higher fence, or the lifecycle is draining. Releases the
    /// lease on the way out (a no-op by fence if it was already lost).
    async fn lead(&self, lease: ExecutionLease, cancellation: &CancellationToken) {
        let lost = CancellationToken::new();
        // Aborted when this future ends or is dropped: a leader that dies
        // (the task aborted, the runtime torn down) stops renewing at once,
        // so its slot lapses by the TTL rather than being kept alive by an
        // orphaned renewal task.
        let renewal = AbortOnDrop(tokio::spawn(renew_until_lost(
            Arc::clone(&self.leases),
            lease.clone(),
            lost.clone(),
        )));
        self.set_leading(true);
        // The term's own clock. The lease row's age lives in the database
        // and is the authority's; what an operator wants from a metric is
        // "how long has *this* replica been leading", which resets on
        // every handover and is exactly what a leadership flapping between
        // replicas looks like.
        let held_since = Instant::now();
        crate::tools::lease::record_lease_age(
            crate::tools::lease::LEASE_SCOPE_MAINTENANCE,
            Duration::ZERO,
        );
        tracing::info!(
            fence = lease.fence,
            "maintenance lease acquired; this replica runs the singleton jobs"
        );
        let names = self.job_names();
        match self.ledger.adopt_jobs(&names, lease.fence).await {
            Ok(true) => {
                let mut ticker = tokio::time::interval(self.interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        () = lost.cancelled() => {
                            tracing::warn!(fence = lease.fence, "maintenance lease lost; this replica stops leading");
                            break;
                        }
                        () = cancellation.cancelled() => break,
                        _ = ticker.tick() => {}
                    }
                    crate::tools::lease::record_lease_age(
                        crate::tools::lease::LEASE_SCOPE_MAINTENANCE,
                        held_since.elapsed(),
                    );
                    let outcome = tokio::select! {
                        () = lost.cancelled() => {
                            tracing::warn!(fence = lease.fence, "maintenance lease lost mid-pass; the pass is cancelled");
                            break;
                        }
                        () = cancellation.cancelled() => break,
                        outcome = self.run_pass(lease.fence) => outcome,
                    };
                    self.publish_leader_task_ages().await;
                    if outcome == PassOutcome::Stale {
                        tracing::warn!(
                            fence = lease.fence,
                            "maintenance ledger is held at a higher fence; this leader is stale and stops"
                        );
                        break;
                    }
                }
            }
            Ok(false) => {
                tracing::warn!(
                    fence = lease.fence,
                    "maintenance ledger is held at a higher fence than this lease; running nothing"
                );
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "maintenance ledger could not be adopted; releasing the lease"
                );
            }
        }
        drop(renewal);
        self.set_leading(false);
        // The term is over: the age goes back to zero rather than being
        // left at its last value, which would read as "still leading" on
        // a replica that has handed the lease on.
        crate::tools::lease::record_lease_age(
            crate::tools::lease::LEASE_SCOPE_MAINTENANCE,
            Duration::ZERO,
        );
        if let Err(error) = self.leases.release(&lease).await {
            crate::tools::lease::record_lease_failure(
                crate::tools::lease::LEASE_FAILURE_RELEASE_FAILED,
            );
            tracing::warn!(
                error = %error,
                "maintenance lease release failed; the slot lapses by expiry"
            );
        }
        tracing::info!(fence = lease.fence, "maintenance lease released");
    }

    /// Publish how long ago each singleton job last succeeded, read back
    /// from the fenced ledger (issue #241, PR 14).
    ///
    /// From the ledger rather than from this leader's own memory: a job
    /// that has been failing across several leader terms must still show
    /// its true age, and a leader that has just taken over has no memory
    /// of the previous one's successes. The `task` label is the job's
    /// name, which is one of the `JOB_*` constants and cannot be anything
    /// else. A job that has never succeeded gets no series -- there is no
    /// age for a success that never happened, and `0` would claim the
    /// opposite of the truth.
    ///
    /// One read per pass on the leader only; a read that fails leaves the
    /// last published ages standing and is not worth a log line of its
    /// own beside the pass's.
    async fn publish_leader_task_ages(&self) {
        let Ok(jobs) = self.ledger.maintenance_jobs().await else {
            return;
        };
        for job in jobs {
            let Some(age) = job.last_success_age_secs else {
                continue;
            };
            // A ledger row naming a job this binary does not run -- one a
            // newer gateway added, or one written by hand -- is data, so
            // it never becomes a label.
            let Some(name) = known_job_name(&job.job) else {
                continue;
            };
            record_leader_task_age(name, age);
        }
    }

    /// One pass over every job under `fence`: open the dedicated session,
    /// then for each job in order probe the session, stamp the start,
    /// run the bounded step *on the session's connection* under its
    /// budget, and record the outcome -- stopping at the first fenced
    /// write the ledger refuses, and cancelling at the first sign the
    /// session is gone. A pass that stops for any reason but a lost
    /// session unlocks and returns its connection; a lost one is closed.
    pub(crate) async fn run_pass(&self, fence: i64) -> PassOutcome {
        let mut session = match DedicatedSession::acquire(&self.pool, *MAINTENANCE_LOCK_KEY).await {
            Ok(session) => session,
            Err(error) if error.kind() == RepositoryErrorKind::Conflict => {
                tracing::warn!(
                    fence,
                    "another session holds the maintenance advisory lock; the pass is skipped"
                );
                return PassOutcome::Skipped;
            }
            Err(error) => {
                tracing::warn!(error = %error, fence, "maintenance session could not be opened; the pass is skipped");
                return PassOutcome::Skipped;
            }
        };
        let outcome = self.run_jobs(&mut session, fence).await;
        if outcome != PassOutcome::ConnectionLost {
            if let Err(error) = session.release().await {
                tracing::warn!(error = %error, fence, "maintenance session unlock failed; the connection was closed instead");
            }
        }
        if let PassOutcome::Completed { .. } = outcome {
            self.passes_completed.fetch_add(1, Ordering::AcqRel);
        }
        outcome
    }

    /// The job loop of [`Self::run_pass`], over the session it holds.
    async fn run_jobs(&self, session: &mut DedicatedSession, fence: i64) -> PassOutcome {
        let mut failed_jobs = 0;
        for job in &self.jobs {
            let name = job.name();
            if let Err(error) = session.probe().await {
                tracing::warn!(error = %error, job = name, fence, "maintenance session lost; the pass is cancelled");
                return PassOutcome::ConnectionLost;
            }
            match self.ledger.record_job_started(name, fence).await {
                Ok(true) => {}
                Ok(false) => return PassOutcome::Stale,
                Err(error) => {
                    tracing::warn!(error = %error, job = name, fence, "maintenance job start could not be recorded; the job is skipped this pass");
                    failed_jobs += 1;
                    continue;
                }
            }
            let Some(client) = session.client() else {
                return PassOutcome::ConnectionLost;
            };
            let started = Instant::now();
            let result = tokio::time::timeout(JOB_BUDGET, job.run_step(client)).await;
            let duration_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
            let outcome = match result {
                Ok(Ok(affected)) => {
                    tracing::debug!(
                        job = name,
                        affected,
                        duration_ms,
                        "maintenance job step done"
                    );
                    JobOutcome::Success { duration_ms }
                }
                Ok(Err(error)) => {
                    // A step that failed because the session went away is
                    // not a job failure to record and move past: the lock
                    // is gone with the connection, and so is the pass.
                    if let Err(probe) = session.probe().await {
                        tracing::warn!(error = %probe, job = name, fence, duration_ms, "maintenance session lost during the job step; the pass is cancelled");
                        return PassOutcome::ConnectionLost;
                    }
                    tracing::warn!(error = %error, job = name, duration_ms, "maintenance job step failed");
                    failed_jobs += 1;
                    JobOutcome::Failure {
                        code: error.kind().as_str().to_owned(),
                        duration_ms,
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        job = name,
                        duration_ms,
                        "maintenance job step exceeded its budget"
                    );
                    failed_jobs += 1;
                    JobOutcome::Failure {
                        code: "timeout".to_owned(),
                        duration_ms,
                    }
                }
            };
            ::metrics::counter!(
                CLUSTER_MAINTENANCE_JOB_RUNS_TOTAL,
                "job" => name,
                "outcome" => match outcome {
                    JobOutcome::Success { .. } => "success",
                    JobOutcome::Failure { .. } => "failure",
                }
            )
            .increment(1);
            match self.ledger.record_job_outcome(name, fence, &outcome).await {
                Ok(true) => {}
                Ok(false) => return PassOutcome::Stale,
                Err(error) => {
                    tracing::warn!(error = %error, job = name, fence, "maintenance job outcome could not be recorded");
                }
            }
        }
        PassOutcome::Completed { failed_jobs }
    }

    fn set_leading(&self, leading: bool) {
        self.leading.store(leading, Ordering::Release);
        ::metrics::gauge!(CLUSTER_MAINTENANCE_LEADER).set(if leading { 1.0 } else { 0.0 });
    }
}

/// A spawned task that is aborted when the guard drops.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ledger's `job` column is database data, so only a name this
    /// binary recognises may become a `task` label (issue #241, PR 14).
    ///
    /// The adversarial cases are not hypothetical: a shared database gets
    /// rows from a newer gateway running jobs this one has never heard of,
    /// and a row can be edited by hand. Both must produce no series rather
    /// than a series named after whatever the row said.
    #[test]
    fn only_a_recognised_ledger_job_name_can_become_a_task_label() {
        for job in JOB_NAMES {
            assert_eq!(
                known_job_name(job),
                Some(job),
                "a job this binary runs must be recognised by name"
            );
        }
        for hostile in [
            "a_job_a_newer_gateway_runs",
            "stale_member_sweep\", instance=\"3f8c1d2e-9b47-4a6f-8e51-c07d2b93a4e6",
            "postgres://user:pass@10.0.0.5:5432/db",
            "",
        ] {
            assert_eq!(
                known_job_name(hostile),
                None,
                "an unrecognised ledger job name must never become a label: {hostile}"
            );
        }
        assert_eq!(
            JOB_NAMES.len(),
            std::collections::BTreeSet::from(JOB_NAMES).len(),
            "every job name must be distinct, or two jobs share one series"
        );
    }

    /// The runner's job list and the label vocabulary are the same set: a
    /// job added to one without the other would either be unreportable or
    /// report under a name nothing runs.
    #[test]
    fn the_label_vocabulary_is_exactly_the_jobs_the_runner_can_run() {
        let declared: std::collections::BTreeSet<&str> = JOB_NAMES.into_iter().collect();
        let known: std::collections::BTreeSet<&str> = [
            JOB_JWT_REVOCATION_CLEANUP,
            JOB_RATE_LIMIT_IDLE_SWEEP,
            JOB_PENDING_LOGIN_PRUNE,
            JOB_STALE_MEMBER_SWEEP,
            JOB_AUDIT_RETENTION,
            JOB_EXECUTION_LEASE_REAPER,
        ]
        .into_iter()
        .collect();
        assert_eq!(declared, known);
    }

    #[test]
    fn the_acquisition_backoff_is_jittered_within_bounds_and_stable_per_instance() {
        let interval = Duration::from_secs(60);
        let low = interval / 8;
        let high = interval * 3 / 8;
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..200 {
            let id = Uuid::new_v4();
            let backoff = acquisition_backoff(interval, id);
            assert!(
                backoff >= low && backoff <= high,
                "{backoff:?} outside [{low:?}, {high:?}]"
            );
            assert_eq!(
                backoff,
                acquisition_backoff(interval, id),
                "the backoff is a function of the instance id"
            );
            distinct.insert(backoff.as_millis());
        }
        assert!(
            distinct.len() > 100,
            "two hundred instances spread over the window: {} distinct",
            distinct.len()
        );
        assert_eq!(
            acquisition_backoff(Duration::from_millis(1), Uuid::nil()),
            MIN_ACQUISITION_BACKOFF,
            "a tiny interval stays above the floor"
        );
    }

    #[test]
    fn the_maintenance_lock_key_is_pinned() {
        // Two binaries must agree on the key or the belt is no belt:
        // SHA-256("greengateway.maintenance")[..8], sign bit cleared.
        assert_eq!(*MAINTENANCE_LOCK_KEY, 0x7b32_4fee_6a61_a8b7_i64);
        assert_ne!(
            *MAINTENANCE_LOCK_KEY,
            *crate::storage::postgres_audit::AUDIT_STREAM_LOCK_KEY
        );
    }
}
