//! PostgreSQL cluster-membership store (issue #241, PR 13): the roster of
//! live replicas in `cluster_members` and the singleton maintenance
//! ledger in `maintenance_jobs`.
//!
//! What is stored, and why:
//!
//! - **One `cluster_members` row per replica boot, written by that replica
//!   alone.** The row is created at boot, refreshed by the heartbeat task
//!   with the security revisions the replica has compiled and last
//!   observed, stamped when the replica becomes ready and when it begins
//!   draining, and removed only by the maintenance singleton once its
//!   heartbeat is older than the stale window ([`Self::sweep_stale`]).
//!   Request handling never touches it. Liveness is judged by database
//!   time -- `last_heartbeat_at > now() - window` -- so a replica's wall
//!   clock never decides whether another replica is live.
//! - **The static-configuration fingerprint of every member**, so a
//!   booting replica can refuse readiness while a live, non-draining
//!   member disagrees with it (HA state model invariant 14). The
//!   comparison itself lives in `cluster_membership.rs`; this store only
//!   reads the roster.
//! - **The compatibility columns** (`schema_version_*`,
//!   `document_version_*`, `binary_version`), advertised for operators and
//!   PR 14's status view; the store bounds every text column at a
//!   character boundary rather than refusing a long value.
//! - **`maintenance_jobs`**: one row per singleton job with the lease
//!   fence the current leader adopted it at. Every write of a job's
//!   timestamps carries two predicates in one statement: `fence = $fence`
//!   on the row, and *the maintenance lease at that fence is still live on
//!   the database clock* (`execution_leases`, scope
//!   [`MAINTENANCE_LEASE_SCOPE`], `expires_at > now()`). The row's fence
//!   alone is a copy taken at adoption, so it cannot see that the writer's
//!   lease lapsed or was taken over before the successor adopted the rows;
//!   anchoring on the lease row closes that window. A leader that was
//!   paused past its TTL matches no row from the instant its lease lapses
//!   -- whether or not a successor has acquired yet, and whether or not it
//!   has adopted -- and the store reports the refused write as `false` so
//!   the caller can stop.
//! - **The replica's own boot and ready instants**, remembered in memory
//!   from the first heartbeat and the ready stamp and re-supplied on every
//!   heartbeat, so a row the singleton swept while the replica was
//!   partitioned is re-created with the same `started_at` and `ready_at`
//!   rather than as a fresh, unready boot.
//!
//! Every timestamp is rendered by the database in UTC (`to_char`) rather
//! than mapped to a Rust time type: the driver is built without time
//! features, and the strings are for operators, not arithmetic. UUIDs
//! cross the driver as text for the same reason, and so do the remembered
//! instants on their way back in (`$n::text::timestamptz`).

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use uuid::Uuid;

use crate::ha::InstanceIdentity;

use super::{
    log_classified,
    postgres::{classify_pool_error, timed_operation},
    RepositoryError, RepositoryErrorKind,
};

// Every operation below is timed into
// `greengateway_database_operation_seconds` (issue #241, PR 14). The
// roster and the job ledger are the HA control plane's own store: when a
// deployment is deciding whether it is healthy, the latency of the
// statements it decides with is the first thing an operator needs, and it
// is the store whose slowness turns directly into `instance_lease_invalid`
// and a stale roster. The label is the `OPERATION_*` constant -- what was
// asked of the store -- never the statement, its parameters, or its rows.
const OPERATION_HEARTBEAT: &str = "cluster_member_heartbeat";
const OPERATION_MARK_READY: &str = "cluster_member_mark_ready";
const OPERATION_MARK_DRAINING: &str = "cluster_member_mark_draining";
const OPERATION_LIST: &str = "cluster_members_list";
const OPERATION_SWEEP: &str = "cluster_members_sweep";
const OPERATION_JOB_ADOPT: &str = "maintenance_jobs_adopt";
const OPERATION_JOB_START: &str = "maintenance_job_start";
const OPERATION_JOB_OUTCOME: &str = "maintenance_job_outcome";
const OPERATION_JOB_LIST: &str = "maintenance_jobs_list";

/// The schema's bound on the short text columns (`binary_version`,
/// `last_error_code`, `last_failure_code`); longer values are cut at a
/// character boundary for the row, never refused.
const MAX_SHORT_TEXT_BYTES: usize = 64;

/// The bound on one stale sweep, so the singleton's step stays a short
/// statement however long a deployment was partitioned.
const MAX_SWEEP_BATCH: u32 = 1_000;

/// The rendering of every timestamp column: UTC, microseconds, `Z`.
const TIMESTAMP_FORMAT: &str = "'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'";

/// The `execution_leases` scope of the maintenance singleton's one slot.
/// The ledger writes below are anchored on the live lease row in this
/// scope, so the constant lives with the ledger rather than the runner.
pub(crate) const MAINTENANCE_LEASE_SCOPE: &str = "maintenance";

/// The instants a replica remembers about its own row so a re-created
/// row (swept while the replica was partitioned) tells the truth.
#[derive(Debug, Default)]
struct RememberedStamps {
    /// `started_at` as the database rendered it on the first heartbeat.
    started_at: Option<String>,
    /// `ready_at` as the database rendered it when the stamp landed.
    ready_at: Option<String>,
}

/// What a replica advertises about itself once, at boot: everything in
/// the row that does not change between heartbeats.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberRegistration {
    /// The gateway binary version (`CARGO_PKG_VERSION`).
    pub binary_version: String,
    /// The migration-manifest range this binary accepts, `(min, max)`.
    pub schema_version: (i32, i32),
    /// The policy/tools document schema range this binary enforces,
    /// `(min, max)` in major versions.
    pub document_version: (i32, i32),
    /// The static-configuration fingerprint as 64 lowercase hex characters.
    pub fingerprint: String,
}

/// The security revisions a heartbeat carries: the watermark the replica
/// has confirmed every resource current at, and the authority's counter as
/// it last read it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemberRevisions {
    pub compiled: i64,
    pub observed: i64,
}

/// One roster row as read back, with liveness judged by the database
/// clock against the window the reader supplied.
#[derive(Clone, Debug, PartialEq)]
pub struct ClusterMember {
    pub instance_id: Uuid,
    pub boot_id: Uuid,
    pub binary_version: String,
    pub schema_version_min: i32,
    pub schema_version_max: i32,
    pub document_version_min: i32,
    pub document_version_max: i32,
    pub fingerprint: String,
    pub started_at: String,
    pub last_heartbeat_at: String,
    /// Seconds since the last heartbeat, on the database clock.
    pub heartbeat_age_secs: f64,
    pub ready_at: Option<String>,
    pub draining_at: Option<String>,
    pub compiled_security_revision: i64,
    pub observed_security_revision: i64,
    pub last_error_code: Option<String>,
    /// `last_heartbeat_at` is within the stale window the reader supplied.
    pub live: bool,
}

/// One singleton job's ledger row.
#[derive(Clone, Debug, PartialEq)]
pub struct MaintenanceJobRecord {
    pub job: String,
    /// The lease fence the rows were last adopted at.
    pub fence: i64,
    pub last_started_at: Option<String>,
    pub last_success_at: Option<String>,
    /// Seconds since `last_success_at`, on the database clock, so a reader
    /// judging whether a job is still running never subtracts its own wall
    /// clock from another machine's timestamp. `None` while the job has
    /// never succeeded.
    pub last_success_age_secs: Option<f64>,
    pub last_failure_code: Option<String>,
    pub last_duration_ms: Option<i64>,
}

/// How one run of a job ended.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)] // constructed by the maintenance singleton (PR 13, section 4) and its tests
pub enum JobOutcome {
    Success { duration_ms: i64 },
    Failure { code: String, duration_ms: i64 },
}

/// The membership store over one PostgreSQL pool, bound to one replica's
/// identity: every write names this instance, and a row for any other
/// instance is read-only here (the singleton's sweep is the one
/// exception, and it deletes by heartbeat age alone).
#[derive(Clone)]
pub struct PostgresMembershipStore {
    pool: deadpool_postgres::Pool,
    deployment_id: String,
    identity: InstanceIdentity,
    /// Shared by every clone: they are one replica's row.
    remembered: Arc<Mutex<RememberedStamps>>,
}

impl PostgresMembershipStore {
    pub fn new(
        pool: deadpool_postgres::Pool,
        deployment_id: &str,
        identity: InstanceIdentity,
    ) -> Self {
        Self {
            pool,
            deployment_id: deployment_id.to_owned(),
            identity,
            remembered: Arc::new(Mutex::new(RememberedStamps::default())),
        }
    }

    fn remembered(&self) -> std::sync::MutexGuard<'_, RememberedStamps> {
        self.remembered
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn instance_id(&self) -> Uuid {
        self.identity.instance_id()
    }

    /// Create this replica's row, or refresh it: the heartbeat. Carries
    /// the registration on every call so a row is complete however it was
    /// first written, plus the current revisions and the last classified
    /// failure code of the replica's own background work. The boot and
    /// ready instants the database rendered earlier ride along too, so a
    /// row the singleton swept during a partition comes back with the
    /// replica's real `started_at` and `ready_at` instead of a fresh,
    /// unready boot; an existing row keeps its own.
    pub async fn heartbeat(
        &self,
        registration: &MemberRegistration,
        revisions: MemberRevisions,
        last_error_code: Option<&str>,
    ) -> Result<(), RepositoryError> {
        timed_operation(
            OPERATION_HEARTBEAT,
            self.heartbeat_inner(registration, revisions, last_error_code),
        )
        .await
    }

    async fn heartbeat_inner(
        &self,
        registration: &MemberRegistration,
        revisions: MemberRevisions,
        last_error_code: Option<&str>,
    ) -> Result<(), RepositoryError> {
        if registration.fingerprint.len() != 64
            || !registration
                .fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid_data(OPERATION_HEARTBEAT));
        }
        let instance_id = self.identity.instance_id().to_string();
        let boot_id = self.identity.boot_id().to_string();
        let binary_version = match bounded_short_text(&registration.binary_version) {
            "" => "unknown",
            bounded => bounded,
        };
        let last_error_code = last_error_code
            .map(bounded_short_text)
            .filter(|code| !code.is_empty());
        let (remembered_started_at, remembered_ready_at) = {
            let remembered = self.remembered();
            (remembered.started_at.clone(), remembered.ready_at.clone())
        };
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_opt(
                &format!(
                    "INSERT INTO greengateway.cluster_members AS m
                         (deployment_id, instance_id, boot_id, binary_version,
                          schema_version_min, schema_version_max,
                          document_version_min, document_version_max, fingerprint,
                          started_at, last_heartbeat_at, ready_at,
                          compiled_security_revision, observed_security_revision, last_error_code)
                     VALUES ($1, $2::text::uuid, $3::text::uuid, $4, $5, $6, $7, $8, $9,
                             COALESCE($13::text::timestamptz, now()), now(), $14::text::timestamptz,
                             $10, $11, $12)
                     ON CONFLICT (instance_id) DO UPDATE SET
                         boot_id = EXCLUDED.boot_id,
                         binary_version = EXCLUDED.binary_version,
                         schema_version_min = EXCLUDED.schema_version_min,
                         schema_version_max = EXCLUDED.schema_version_max,
                         document_version_min = EXCLUDED.document_version_min,
                         document_version_max = EXCLUDED.document_version_max,
                         fingerprint = EXCLUDED.fingerprint,
                         last_heartbeat_at = now(),
                         ready_at = COALESCE(m.ready_at, EXCLUDED.ready_at),
                         compiled_security_revision = EXCLUDED.compiled_security_revision,
                         observed_security_revision = EXCLUDED.observed_security_revision,
                         last_error_code = EXCLUDED.last_error_code
                     WHERE m.deployment_id = EXCLUDED.deployment_id
                     RETURNING to_char(m.started_at AT TIME ZONE 'UTC', {f}) AS started_at,
                               to_char(m.ready_at AT TIME ZONE 'UTC', {f}) AS ready_at",
                    f = TIMESTAMP_FORMAT
                ),
                &[
                    &self.deployment_id,
                    &instance_id,
                    &boot_id,
                    &binary_version,
                    &registration.schema_version.0,
                    &registration.schema_version.1,
                    &registration.document_version.0,
                    &registration.document_version.1,
                    &registration.fingerprint,
                    &revisions.compiled.max(0),
                    &revisions.observed.max(0),
                    &last_error_code,
                    &remembered_started_at,
                    &remembered_ready_at,
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_HEARTBEAT))?;
        if let Some(row) = row {
            let started_at: String = column(&row, "started_at", OPERATION_HEARTBEAT)?;
            let ready_at: Option<String> = column(&row, "ready_at", OPERATION_HEARTBEAT)?;
            let mut remembered = self.remembered();
            remembered.started_at = Some(started_at);
            if ready_at.is_some() {
                remembered.ready_at = ready_at;
            }
        }
        Ok(())
    }

    /// Stamp `ready_at` (once; a repeat keeps the first instant) and count
    /// the write as a heartbeat. A row that does not exist yet is not
    /// created here: readiness without a registration is not a state the
    /// replica can be in, so the caller heartbeats first. The instant is
    /// remembered so a later heartbeat can re-create a swept row with it.
    pub async fn mark_ready(&self) -> Result<(), RepositoryError> {
        timed_operation(OPERATION_MARK_READY, self.mark_ready_inner()).await
    }

    async fn mark_ready_inner(&self) -> Result<(), RepositoryError> {
        let instance_id = self.identity.instance_id().to_string();
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_opt(
                &format!(
                    "UPDATE greengateway.cluster_members
                     SET ready_at = COALESCE(ready_at, now()), last_heartbeat_at = now()
                     WHERE deployment_id = $1 AND instance_id = $2::text::uuid
                     RETURNING to_char(ready_at AT TIME ZONE 'UTC', {f}) AS ready_at",
                    f = TIMESTAMP_FORMAT
                ),
                &[&self.deployment_id, &instance_id],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_MARK_READY))?;
        if let Some(row) = row {
            let ready_at: Option<String> = column(&row, "ready_at", OPERATION_MARK_READY)?;
            if ready_at.is_some() {
                self.remembered().ready_at = ready_at;
            }
        }
        Ok(())
    }

    /// Stamp `draining_at` (once) and count the write as a heartbeat, so a
    /// draining replica is visibly leaving rather than silently going
    /// stale.
    pub async fn mark_draining(&self) -> Result<(), RepositoryError> {
        self.stamp(
            "UPDATE greengateway.cluster_members
             SET draining_at = COALESCE(draining_at, now()), last_heartbeat_at = now()
             WHERE deployment_id = $1 AND instance_id = $2::text::uuid",
            OPERATION_MARK_DRAINING,
        )
        .await
    }

    async fn stamp(&self, statement: &str, operation: &'static str) -> Result<(), RepositoryError> {
        timed_operation(operation, async {
            let instance_id = self.identity.instance_id().to_string();
            let client = self.pool.get().await.map_err(classify_pool_error)?;
            client
                .execute(statement, &[&self.deployment_id, &instance_id])
                .await
                .map_err(|error| classify_query(error, operation))?;
            Ok(())
        })
        .await
    }

    /// Every member row of this deployment, oldest boot first, with
    /// liveness judged on the database clock against `stale_window`.
    pub async fn members(
        &self,
        stale_window: Duration,
    ) -> Result<Vec<ClusterMember>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        self.members_with(&client, stale_window).await
    }

    /// [`Self::members`] over a connection the caller holds (the
    /// maintenance singleton's dedicated session).
    pub(crate) async fn members_with(
        &self,
        client: &tokio_postgres::Client,
        stale_window: Duration,
    ) -> Result<Vec<ClusterMember>, RepositoryError> {
        timed_operation(
            OPERATION_LIST,
            self.members_with_inner(client, stale_window),
        )
        .await
    }

    async fn members_with_inner(
        &self,
        client: &tokio_postgres::Client,
        stale_window: Duration,
    ) -> Result<Vec<ClusterMember>, RepositoryError> {
        let window_secs = stale_window.as_secs_f64();
        let rows = client
            .query(
                &format!(
                    "SELECT instance_id::text AS instance_id, boot_id::text AS boot_id,
                            binary_version, schema_version_min, schema_version_max,
                            document_version_min, document_version_max, fingerprint,
                            to_char(started_at AT TIME ZONE 'UTC', {f}) AS started_at,
                            to_char(last_heartbeat_at AT TIME ZONE 'UTC', {f}) AS last_heartbeat_at,
                            GREATEST(EXTRACT(EPOCH FROM (now() - last_heartbeat_at)), 0)::double precision
                                AS heartbeat_age_secs,
                            to_char(ready_at AT TIME ZONE 'UTC', {f}) AS ready_at,
                            to_char(draining_at AT TIME ZONE 'UTC', {f}) AS draining_at,
                            compiled_security_revision, observed_security_revision, last_error_code,
                            (last_heartbeat_at > now() - make_interval(secs => $2::double precision)) AS live
                     FROM greengateway.cluster_members
                     WHERE deployment_id = $1
                     ORDER BY started_at ASC, instance_id ASC",
                    f = TIMESTAMP_FORMAT
                ),
                &[&self.deployment_id, &window_secs],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_LIST))?;
        rows.iter().map(member_from_row).collect()
    }
}

/// The maintenance singleton's surface: the stale sweep and the fenced
/// job ledger. Section 4 of PR 13 (the leased maintenance runner) is the
/// production caller; until it lands the contract tests are the only one.
#[allow(dead_code)]
impl PostgresMembershipStore {
    /// Delete up to `limit` rows whose heartbeat is at least `stale_window`
    /// old on the database clock, oldest first. For the maintenance
    /// singleton only; returns how many rows were removed. A draining
    /// member that stopped heartbeating is swept like any other -- the
    /// stamp is a courtesy to readers, not a reservation.
    pub async fn sweep_stale(
        &self,
        stale_window: Duration,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        self.sweep_stale_with(&client, stale_window, limit).await
    }

    /// [`Self::sweep_stale`] over a connection the caller holds: the
    /// singleton runs its step on the dedicated session that holds the
    /// maintenance advisory lock, so the lock covers the statement itself.
    pub(crate) async fn sweep_stale_with(
        &self,
        client: &tokio_postgres::Client,
        stale_window: Duration,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        timed_operation(
            OPERATION_SWEEP,
            self.sweep_stale_with_inner(client, stale_window, limit),
        )
        .await
    }

    async fn sweep_stale_with_inner(
        &self,
        client: &tokio_postgres::Client,
        stale_window: Duration,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        let window_secs = stale_window.as_secs_f64();
        let limit = i64::from(limit.clamp(1, MAX_SWEEP_BATCH));
        let removed = client
            .execute(
                "DELETE FROM greengateway.cluster_members
                 WHERE ctid = ANY(ARRAY(
                     SELECT ctid FROM greengateway.cluster_members
                     WHERE deployment_id = $1
                       AND last_heartbeat_at <= now() - make_interval(secs => $2::double precision)
                     ORDER BY last_heartbeat_at ASC
                     LIMIT $3))",
                &[&self.deployment_id, &window_secs, &limit],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_SWEEP))?;
        Ok(removed)
    }

    /// Adopt the named job rows at `fence`: create the ones that do not
    /// exist and raise the fence of the ones that do, never lowering it.
    /// Only a fence whose maintenance lease is live on the database clock
    /// adopts anything. Returns `true` when every named row now carries
    /// `fence` -- the leader may run the jobs -- and `false` when the lease
    /// behind `fence` is gone or at least one row is held at a higher
    /// fence by a successor, in which case this leader is stale and must
    /// run nothing.
    pub async fn adopt_jobs(&self, jobs: &[&str], fence: i64) -> Result<bool, RepositoryError> {
        timed_operation(OPERATION_JOB_ADOPT, self.adopt_jobs_inner(jobs, fence)).await
    }

    async fn adopt_jobs_inner(&self, jobs: &[&str], fence: i64) -> Result<bool, RepositoryError> {
        if jobs.is_empty() {
            return Ok(true);
        }
        let names: Vec<&str> = jobs.iter().map(|job| bounded_short_text(job)).collect();
        if names.iter().any(|job| job.is_empty()) {
            return Err(invalid_data(OPERATION_JOB_ADOPT));
        }
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let adopted = client
            .execute(
                "INSERT INTO greengateway.maintenance_jobs AS j (deployment_id, job, fence)
                 SELECT $1, name, $3 FROM unnest($2::text[]) AS names(name)
                 WHERE EXISTS (SELECT 1 FROM greengateway.execution_leases
                               WHERE deployment_id = $1 AND scope = $4 AND fence = $3
                                 AND expires_at > now())
                 ON CONFLICT (deployment_id, job) DO UPDATE SET fence = EXCLUDED.fence
                 WHERE j.fence <= EXCLUDED.fence",
                &[
                    &self.deployment_id,
                    &names,
                    &fence,
                    &MAINTENANCE_LEASE_SCOPE,
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_JOB_ADOPT))?;
        Ok(adopted == names.len() as u64)
    }

    /// Record that `job` started, only if the row is still held at
    /// `fence` and the maintenance lease at `fence` is still live on the
    /// database clock. `false` means the write was refused: the writer's
    /// lease lapsed or a successor took over, and this leader is stale.
    pub async fn record_job_started(&self, job: &str, fence: i64) -> Result<bool, RepositoryError> {
        timed_operation(
            OPERATION_JOB_START,
            self.record_job_started_inner(job, fence),
        )
        .await
    }

    async fn record_job_started_inner(
        &self,
        job: &str,
        fence: i64,
    ) -> Result<bool, RepositoryError> {
        let job = bounded_short_text(job);
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let updated = client
            .execute(
                "UPDATE greengateway.maintenance_jobs
                 SET last_started_at = now()
                 WHERE deployment_id = $1 AND job = $2 AND fence = $3
                   AND EXISTS (SELECT 1 FROM greengateway.execution_leases
                               WHERE deployment_id = $1 AND scope = $4 AND fence = $3
                                 AND expires_at > now())",
                &[&self.deployment_id, &job, &fence, &MAINTENANCE_LEASE_SCOPE],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_JOB_START))?;
        Ok(updated == 1)
    }

    /// Record how `job` ended, only if the row is still held at `fence`
    /// and the maintenance lease at `fence` is still live; `false` means
    /// the write was refused by the predicate.
    pub async fn record_job_outcome(
        &self,
        job: &str,
        fence: i64,
        outcome: &JobOutcome,
    ) -> Result<bool, RepositoryError> {
        timed_operation(
            OPERATION_JOB_OUTCOME,
            self.record_job_outcome_inner(job, fence, outcome),
        )
        .await
    }

    async fn record_job_outcome_inner(
        &self,
        job: &str,
        fence: i64,
        outcome: &JobOutcome,
    ) -> Result<bool, RepositoryError> {
        let job = bounded_short_text(job);
        let (succeeded, failure_code, duration_ms) = match outcome {
            JobOutcome::Success { duration_ms } => (true, None, *duration_ms),
            JobOutcome::Failure { code, duration_ms } => {
                (false, Some(bounded_short_text(code)), *duration_ms)
            }
        };
        let failure_code = failure_code.filter(|code| !code.is_empty());
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let updated = client
            .execute(
                "UPDATE greengateway.maintenance_jobs
                 SET last_success_at = CASE WHEN $4 THEN now() ELSE last_success_at END,
                     last_failure_code = $5,
                     last_duration_ms = $6
                 WHERE deployment_id = $1 AND job = $2 AND fence = $3
                   AND EXISTS (SELECT 1 FROM greengateway.execution_leases
                               WHERE deployment_id = $1 AND scope = $7 AND fence = $3
                                 AND expires_at > now())",
                &[
                    &self.deployment_id,
                    &job,
                    &fence,
                    &succeeded,
                    &failure_code,
                    &duration_ms.max(0),
                    &MAINTENANCE_LEASE_SCOPE,
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_JOB_OUTCOME))?;
        Ok(updated == 1)
    }

    /// Every job row of this deployment, by name.
    pub async fn maintenance_jobs(&self) -> Result<Vec<MaintenanceJobRecord>, RepositoryError> {
        timed_operation(OPERATION_JOB_LIST, self.maintenance_jobs_inner()).await
    }

    async fn maintenance_jobs_inner(&self) -> Result<Vec<MaintenanceJobRecord>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let rows = client
            .query(
                &format!(
                    "SELECT job, fence,
                            to_char(last_started_at AT TIME ZONE 'UTC', {f}) AS last_started_at,
                            to_char(last_success_at AT TIME ZONE 'UTC', {f}) AS last_success_at,
                            -- The CASE is not redundant: GREATEST ignores
                            -- NULL arguments in PostgreSQL, so a job that
                            -- has never succeeded would otherwise report
                            -- an age of zero -- \"succeeded just now\" --
                            -- instead of no age at all.
                            CASE WHEN last_success_at IS NULL THEN NULL
                                 ELSE GREATEST(EXTRACT(EPOCH FROM (now() - last_success_at)), 0)
                            END::double precision AS last_success_age_secs,
                            last_failure_code, last_duration_ms
                     FROM greengateway.maintenance_jobs
                     WHERE deployment_id = $1
                     ORDER BY job ASC",
                    f = TIMESTAMP_FORMAT
                ),
                &[&self.deployment_id],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_JOB_LIST))?;
        rows.iter()
            .map(|row| {
                Ok(MaintenanceJobRecord {
                    job: column(row, "job", OPERATION_JOB_LIST)?,
                    fence: column(row, "fence", OPERATION_JOB_LIST)?,
                    last_started_at: column(row, "last_started_at", OPERATION_JOB_LIST)?,
                    last_success_at: column(row, "last_success_at", OPERATION_JOB_LIST)?,
                    last_success_age_secs: column(
                        row,
                        "last_success_age_secs",
                        OPERATION_JOB_LIST,
                    )?,
                    last_failure_code: column(row, "last_failure_code", OPERATION_JOB_LIST)?,
                    last_duration_ms: column(row, "last_duration_ms", OPERATION_JOB_LIST)?,
                })
            })
            .collect()
    }
}

fn member_from_row(row: &tokio_postgres::Row) -> Result<ClusterMember, RepositoryError> {
    let instance_id: String = column(row, "instance_id", OPERATION_LIST)?;
    let boot_id: String = column(row, "boot_id", OPERATION_LIST)?;
    Ok(ClusterMember {
        instance_id: Uuid::parse_str(&instance_id).map_err(|_| invalid_data(OPERATION_LIST))?,
        boot_id: Uuid::parse_str(&boot_id).map_err(|_| invalid_data(OPERATION_LIST))?,
        binary_version: column(row, "binary_version", OPERATION_LIST)?,
        schema_version_min: column(row, "schema_version_min", OPERATION_LIST)?,
        schema_version_max: column(row, "schema_version_max", OPERATION_LIST)?,
        document_version_min: column(row, "document_version_min", OPERATION_LIST)?,
        document_version_max: column(row, "document_version_max", OPERATION_LIST)?,
        fingerprint: column(row, "fingerprint", OPERATION_LIST)?,
        started_at: column(row, "started_at", OPERATION_LIST)?,
        last_heartbeat_at: column(row, "last_heartbeat_at", OPERATION_LIST)?,
        heartbeat_age_secs: column(row, "heartbeat_age_secs", OPERATION_LIST)?,
        ready_at: column(row, "ready_at", OPERATION_LIST)?,
        draining_at: column(row, "draining_at", OPERATION_LIST)?,
        compiled_security_revision: column(row, "compiled_security_revision", OPERATION_LIST)?,
        observed_security_revision: column(row, "observed_security_revision", OPERATION_LIST)?,
        last_error_code: column(row, "last_error_code", OPERATION_LIST)?,
        live: column(row, "live", OPERATION_LIST)?,
    })
}

fn column<'a, T>(
    row: &'a tokio_postgres::Row,
    name: &str,
    operation: &'static str,
) -> Result<T, RepositoryError>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(name).map_err(|_| invalid_data(operation))
}

/// Cut a short text column's value at the schema bound, on a character
/// boundary.
fn bounded_short_text(value: &str) -> &str {
    if value.len() <= MAX_SHORT_TEXT_BYTES {
        return value;
    }
    let mut end = MAX_SHORT_TEXT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

#[cfg(test)]
mod tests {
    use super::bounded_short_text;

    #[test]
    fn short_text_columns_are_cut_at_a_character_boundary() {
        let long = "é".repeat(100);
        let bounded = bounded_short_text(&long);
        assert!(bounded.len() <= 64);
        assert!(bounded.chars().all(|c| c == 'é'));
        assert_eq!(bounded_short_text("1.2.3"), "1.2.3");
    }
}
