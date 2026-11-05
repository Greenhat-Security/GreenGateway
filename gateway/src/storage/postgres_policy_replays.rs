//! PostgreSQL policy replay job store (issue #243): migration 28's
//! `greengateway.policy_replay_jobs`, the durable record behind cluster-mode
//! historical replay jobs.
//!
//! A row is one job: who started it, the request it was started by, the
//! policies and window it was pinned to, its state, and -- while a replica
//! works on it -- that replica's lease and the job's last checkpoint. Every
//! replica serves every job, and any replica may run one.
//!
//! - **Admission** ([`PostgresPolicyReplayStore::create`]) takes a
//!   transaction-scoped advisory lock, prunes a bounded batch of rows past
//!   their retention, answers an idempotency key the owner already used,
//!   counts the owner's and the deployment's pending and retained jobs, and
//!   inserts the job as `admitting`. Two replicas therefore can neither both
//!   take the last slot nor both claim one key. No row is ever deleted or
//!   ended to make room: over a bound is a refusal. A job becomes `queued`
//!   ([`PostgresPolicyReplayStore::admit`]) only once its start is on the
//!   audit record; until then no worker can claim it.
//! - **Claim** ([`PostgresPolicyReplayStore::claim`]) is one statement: lock
//!   the oldest job that is queued, or running under a lease that has
//!   expired by the database clock, skipping rows another replica is
//!   claiming, and take it with a fresh fence from one sequence. A takeover
//!   therefore always carries a larger fence than the lease it replaces.
//! - **Checkpoint**, **renew** and **finish** each name the lease's holder
//!   and fence and change the row only while both still match; no row means
//!   another replica holds the job now. A checkpoint stores the stream
//!   position read through and the run's whole partial aggregate in one
//!   statement, so the two never disagree, and every checkpoint and renewal
//!   answers whether the job's cancellation was requested.
//! - **Cancel** ends a queued job at once, asks a running one to stop, and
//!   discards a finished one -- always matching the owner, so another
//!   principal's job is indistinguishable from a missing one.
//! - **Retention** ([`PostgresPolicyReplayStore::prune`]) deletes a bounded
//!   batch of finished rows past their retention and of admissions abandoned
//!   by a replica that died before recording them, and clears the results of
//!   jobs whose result has expired. Pending jobs are never pruned.
//!
//! Every time is database time (`now()`, one read per statement):
//! a replica's wall clock never decides whether a lease expired or a
//! result is still served. Errors carry a stable operation label only, never
//! SQL text, a job's documents or a DSN-derived value.

use std::{sync::LazyLock, time::Duration};

use tokio_postgres::Row;

use super::{
    log_classified,
    postgres::{checkout, classify_postgres_error, timed_operation, CheckoutClass},
    RepositoryError, RepositoryErrorKind,
};

const OPERATION_CREATE: &str = "policy_replay_job_create";
const OPERATION_PRECHECK: &str = "policy_replay_job_precheck";
const OPERATION_ADMIT: &str = "policy_replay_job_admit";
const OPERATION_GET: &str = "policy_replay_job_get";
const OPERATION_CANCEL: &str = "policy_replay_job_cancel";
const OPERATION_CLAIM: &str = "policy_replay_job_claim";
const OPERATION_RENEW: &str = "policy_replay_job_renew";
const OPERATION_CHECKPOINT: &str = "policy_replay_job_checkpoint";
const OPERATION_FINISH: &str = "policy_replay_job_finish";
const OPERATION_RELEASE: &str = "policy_replay_job_release";
const OPERATION_PRUNE: &str = "policy_replay_job_prune";

/// Serializes job admission across every replica of one deployment (one
/// database is one deployment). Transaction-scoped, so a rollback or a
/// dropped connection releases it.
static POLICY_REPLAY_CREATE_LOCK_KEY: LazyLock<i64> =
    LazyLock::new(|| super::postgres_session::advisory_lock_key("greengateway.policy-replay-jobs"));

/// The states a job is pending in: admitted or being admitted, and not
/// finished. Pending jobs hold a lease or wait for one, and are never pruned.
const PENDING_STATES: &str = "('admitting', 'queued', 'running')";

/// Every column a job's representation reads, in the order
/// [`record_from_row`] reads them; `c.now` is the statement's one clock read.
const RECORD_COLUMNS: &str = "j.job_id, j.owner_issuer, j.owner_subject, j.idempotency_key, \
     j.request_digest, j.actor_json, j.request_id, j.source_ip, j.base_etag, \
     j.candidate_source, j.candidate_etag, j.edit_count, j.candidate_draft_id, \
     j.candidate_draft_revision, j.candidate_version, j.projections, j.engine_version, \
     j.window_from, j.window_to, j.from_epoch_us, j.to_epoch_us, j.high_water, \
     j.selected_records, j.first_position, j.last_position, j.max_records, \
     j.state, j.failure, j.cancel_requested, j.scanned_records, \
     (extract(epoch FROM j.created_at) * 1000000)::bigint, \
     (extract(epoch FROM j.started_at) * 1000000)::bigint, \
     (extract(epoch FROM j.finished_at) * 1000000)::bigint, \
     (extract(epoch FROM j.result_expires_at) * 1000000)::bigint, \
     (j.result_expires_at IS NOT NULL AND j.result_expires_at <= c.now), \
     CASE WHEN j.result_expires_at > c.now THEN j.result::text END, \
     CASE WHEN j.result_expires_at > c.now THEN j.result_digest END";
/// How many columns [`RECORD_COLUMNS`] names.
const RECORD_COLUMN_COUNT: usize = 37;

/// The bounds the store enforces in SQL. The defaults are the admin
/// endpoint's; tests shrink them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PolicyReplayLimits {
    /// Jobs pending (admitting, queued or running) across the deployment.
    pub(crate) max_pending: i64,
    /// Jobs one owner holds pending.
    pub(crate) max_pending_per_owner: i64,
    /// Jobs not expired, pending or finished, across the deployment.
    pub(crate) max_retained: i64,
    /// Jobs not expired that one owner holds.
    pub(crate) max_retained_per_owner: i64,
    /// How long a finished job keeps its result.
    pub(crate) result_ttl: Duration,
    /// How long a job whose result expired still answers `expired`.
    pub(crate) expired_retention: Duration,
    /// How long an admission may wait for its start to be recorded before
    /// retention treats its replica as gone and deletes the row.
    pub(crate) admission_grace: Duration,
    /// Rows one retention pass deletes or clears at most.
    pub(crate) prune_batch: i64,
}

/// A job's owner: the canonical issuer authentication established (empty
/// when there is none) and the subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyReplayOwner {
    pub(crate) issuer: String,
    pub(crate) subject: String,
}

/// Everything fixed when a job is admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyReplayJobSpec {
    pub(crate) job_id: String,
    pub(crate) owner: PolicyReplayOwner,
    pub(crate) idempotency_key: Option<String>,
    pub(crate) request_digest: String,
    /// The admitting request's envelope, which every lifecycle event of the
    /// job carries whichever replica records it: the actor as the audit
    /// sink serializes it, the request id and the canonical client address.
    pub(crate) actor_json: String,
    pub(crate) request_id: String,
    pub(crate) source_ip: String,
    pub(crate) base_etag: String,
    pub(crate) candidate_source: String,
    pub(crate) candidate_etag: String,
    pub(crate) edit_count: i32,
    /// The draft and its revision a `draft` candidate was read as.
    pub(crate) candidate_draft: Option<(String, i64)>,
    /// The history version a `revision` candidate was read as.
    pub(crate) candidate_version: Option<i64>,
    /// The projections, comma-separated in the order the request named them.
    pub(crate) projections: String,
    /// The versions of the evaluator, the replay contexts, the checkpoint and
    /// the result the job was admitted under; a replica of another engine
    /// never runs it.
    pub(crate) engine_version: String,
    pub(crate) window_from: String,
    pub(crate) window_to: String,
    pub(crate) from_epoch_us: i64,
    pub(crate) to_epoch_us: i64,
    pub(crate) high_water: i64,
    pub(crate) selected_records: i64,
    pub(crate) first_position: Option<i64>,
    pub(crate) last_position: Option<i64>,
    pub(crate) max_records: i32,
}

/// The pinned policy documents, as the gateway serialized them: read only by
/// the replica that runs the job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyReplayDocuments {
    pub(crate) base_json: String,
    /// `None` when the candidate is the base itself.
    pub(crate) candidate_json: Option<String>,
}

/// What changes over a job's life, as the statement that read it saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyReplayJobStatus {
    /// As stored: `admitting`, `queued`, `running`, `completed`,
    /// `completed_incomplete`, `failed`, `cancelled` or `interrupted`.
    pub(crate) state: String,
    pub(crate) failure: Option<String>,
    pub(crate) cancel_requested: bool,
    pub(crate) scanned_records: i64,
    pub(crate) created_at_us: i64,
    pub(crate) started_at_us: Option<i64>,
    pub(crate) finished_at_us: Option<i64>,
    pub(crate) result_expires_at_us: Option<i64>,
    /// The job finished and its result's time has passed.
    pub(crate) result_expired: bool,
    /// The result document and its digest, while the result is served.
    pub(crate) result: Option<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyReplayJobRecord {
    pub(crate) spec: PolicyReplayJobSpec,
    pub(crate) status: PolicyReplayJobStatus,
}

/// Why an admission did not insert a job, or the job it inserted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PolicyReplayCreated {
    Created(Box<PolicyReplayJobRecord>),
    /// The owner already used the key for this exact request.
    Existing(Box<PolicyReplayJobRecord>),
    /// The owner's key names a job started by a different request.
    IdempotencyConflict,
    /// The owner, or the deployment, has as many jobs pending as it may.
    Busy,
    /// The owner, or the deployment, holds as many unexpired jobs as it may.
    QuotaExhausted,
}

/// What a cancellation did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PolicyReplayCancel {
    /// No job of this owner's has the id.
    NotFound,
    /// The job was queued and is now `cancelled`.
    Cancelled(Box<PolicyReplayJobRecord>),
    /// The job is being admitted or is running: its cancellation is
    /// recorded, and the replica running it stops before its next page.
    Requested(Box<PolicyReplayJobRecord>),
    /// The job had finished and is gone.
    Discarded,
}

/// The lease one replica holds on one running job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyReplayLease {
    pub(crate) job_id: String,
    pub(crate) fence: i64,
}

/// A job a replica claimed: everything it needs to run it.
#[derive(Debug)]
pub(crate) struct PolicyReplayClaim {
    pub(crate) record: PolicyReplayJobRecord,
    pub(crate) documents: PolicyReplayDocuments,
    pub(crate) lease: PolicyReplayLease,
    /// How many times the job has been claimed, this claim included, not
    /// counting claims given back at shutdown.
    pub(crate) claims: i32,
    /// What is left of the job's run deadline, which its first claim fixed.
    pub(crate) remaining_deadline: Duration,
    /// The last checkpoint, `None` before the first page.
    pub(crate) checkpoint: Option<String>,
}

/// Whether a lease is still held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PolicyReplayLeaseStatus {
    Held { cancel_requested: bool },
    Lost,
}

/// How a run ended, as its holder records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyReplayEnding {
    /// `completed`, `completed_incomplete`, `failed`, `cancelled` or
    /// `interrupted`.
    pub(crate) state: &'static str,
    pub(crate) failure: Option<&'static str>,
    pub(crate) scanned_records: i64,
    /// The result document and its digest, for a completed job only.
    pub(crate) result: Option<(String, String)>,
}

/// The cluster replay job store. Cheap to construct: it borrows the
/// foundation's pool and its replica's identity.
#[derive(Clone)]
pub(crate) struct PostgresPolicyReplayStore {
    pool: deadpool_postgres::Pool,
    holder: uuid::Uuid,
    lease_ttl: Duration,
    limits: PolicyReplayLimits,
}

impl PostgresPolicyReplayStore {
    /// `holder` is this replica's instance identity, the lease holder of
    /// every job it claims.
    pub(crate) fn new(
        pool: deadpool_postgres::Pool,
        holder: uuid::Uuid,
        lease_ttl: Duration,
        limits: PolicyReplayLimits,
    ) -> Self {
        Self {
            pool,
            holder,
            lease_ttl,
            limits,
        }
    }

    /// The same store as another replica, for the takeover tests.
    #[cfg(test)]
    pub(crate) fn as_holder(&self, holder: uuid::Uuid) -> Self {
        Self {
            holder,
            ..self.clone()
        }
    }

    fn holder(&self) -> String {
        self.holder.to_string()
    }

    /// Whether `owner` may start a job now, before the caller does the work
    /// of fixing a cutoff: `None` when it may, or the refusal. Advisory: the
    /// counts are read without the admission lock, and
    /// [`Self::create`] checks again under it.
    pub(crate) async fn precheck(
        &self,
        owner: &PolicyReplayOwner,
    ) -> Result<Option<PolicyReplayCreated>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_PRECHECK, async {
            let row = client
                .query_one(&counts_sql(), &[&owner.issuer, &owner.subject])
                .await
                .map_err(|error| classify(error, OPERATION_PRECHECK))?;
            self.refusal(&row, OPERATION_PRECHECK)
        })
        .await
    }

    fn refusal(
        &self,
        counts: &Row,
        operation: &'static str,
    ) -> Result<Option<PolicyReplayCreated>, RepositoryError> {
        let owner_pending: i64 = column(counts, 0, operation)?;
        let pending: i64 = column(counts, 1, operation)?;
        let owner_retained: i64 = column(counts, 2, operation)?;
        let retained: i64 = column(counts, 3, operation)?;
        if owner_pending >= self.limits.max_pending_per_owner || pending >= self.limits.max_pending
        {
            return Ok(Some(PolicyReplayCreated::Busy));
        }
        if owner_retained >= self.limits.max_retained_per_owner
            || retained >= self.limits.max_retained
        {
            return Ok(Some(PolicyReplayCreated::QuotaExhausted));
        }
        Ok(None)
    }

    /// Admit a job as `admitting`, or say why not, in one transaction under
    /// the admission lock (module docs). A refused admission still commits
    /// the retention it ran.
    pub(crate) async fn create(
        &self,
        spec: &PolicyReplayJobSpec,
        documents: &PolicyReplayDocuments,
    ) -> Result<PolicyReplayCreated, RepositoryError> {
        let mut client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_CREATE, async {
            let transaction = client
                .transaction()
                .await
                .map_err(|error| classify(error, OPERATION_CREATE))?;
            transaction
                .execute(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&*POLICY_REPLAY_CREATE_LOCK_KEY],
                )
                .await
                .map_err(|error| classify(error, OPERATION_CREATE))?;
            // Every clock below is read after the lock was granted, so a wait
            // behind another admission cannot let a count see a result as
            // unexpired that has since lapsed.
            prune_with(&transaction, &self.limits, OPERATION_CREATE).await?;
            if let Some(key) = spec.idempotency_key.as_deref() {
                let existing = transaction
                    .query_opt(
                        &format!(
                            "SELECT {RECORD_COLUMNS} FROM greengateway.policy_replay_jobs j, \
                             (SELECT now() AS now) c \
                             WHERE j.owner_issuer = $1 AND j.owner_subject = $2 \
                               AND j.idempotency_key = $3"
                        ),
                        &[&spec.owner.issuer, &spec.owner.subject, &key],
                    )
                    .await
                    .map_err(|error| classify(error, OPERATION_CREATE))?;
                if let Some(row) = existing {
                    let record = record_from_row(&row, 0, OPERATION_CREATE)?;
                    transaction
                        .commit()
                        .await
                        .map_err(|error| classify(error, OPERATION_CREATE))?;
                    return Ok(if record.spec.request_digest == spec.request_digest {
                        PolicyReplayCreated::Existing(Box::new(record))
                    } else {
                        PolicyReplayCreated::IdempotencyConflict
                    });
                }
            }
            let (draft_id, draft_revision) = match &spec.candidate_draft {
                Some((draft_id, revision)) => (Some(draft_id.as_str()), Some(*revision)),
                None => (None, None),
            };
            let counts = transaction
                .query_one(&counts_sql(), &[&spec.owner.issuer, &spec.owner.subject])
                .await
                .map_err(|error| classify(error, OPERATION_CREATE))?;
            if let Some(refusal) = self.refusal(&counts, OPERATION_CREATE)? {
                transaction
                    .commit()
                    .await
                    .map_err(|error| classify(error, OPERATION_CREATE))?;
                return Ok(refusal);
            }
            let row = transaction
                .query_one(
                    &format!(
                        "WITH c AS (SELECT now() AS now), \
                         j AS ( \
                             INSERT INTO greengateway.policy_replay_jobs ( \
                                 job_id, owner_issuer, owner_subject, idempotency_key, \
                                 request_digest, actor_json, request_id, source_ip, \
                                 base_etag, base_json, candidate_source, candidate_etag, \
                                 candidate_json, edit_count, projections, engine_version, \
                                 window_from, window_to, from_epoch_us, to_epoch_us, \
                                 high_water, selected_records, first_position, last_position, \
                                 max_records, candidate_draft_id, candidate_draft_revision, \
                                 candidate_version, state, created_at \
                             ) \
                             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                                    $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, \
                                    $25, $26, $27, $28, 'admitting', c.now \
                             FROM c \
                             RETURNING * \
                         ) \
                         SELECT {RECORD_COLUMNS} FROM j, c"
                    ),
                    &[
                        &spec.job_id,
                        &spec.owner.issuer,
                        &spec.owner.subject,
                        &spec.idempotency_key,
                        &spec.request_digest,
                        &spec.actor_json,
                        &spec.request_id,
                        &spec.source_ip,
                        &spec.base_etag,
                        &documents.base_json,
                        &spec.candidate_source,
                        &spec.candidate_etag,
                        &documents.candidate_json,
                        &spec.edit_count,
                        &spec.projections,
                        &spec.engine_version,
                        &spec.window_from,
                        &spec.window_to,
                        &spec.from_epoch_us,
                        &spec.to_epoch_us,
                        &spec.high_water,
                        &spec.selected_records,
                        &spec.first_position,
                        &spec.last_position,
                        &spec.max_records,
                        &draft_id,
                        &draft_revision,
                        &spec.candidate_version,
                    ],
                )
                .await
                .map_err(|error| classify(error, OPERATION_CREATE))?;
            let record = record_from_row(&row, 0, OPERATION_CREATE)?;
            transaction
                .commit()
                .await
                .map_err(|error| classify(error, OPERATION_CREATE))?;
            Ok(PolicyReplayCreated::Created(Box::new(record)))
        })
        .await
    }

    /// Queue a job whose start is now on the audit record. `false` when it
    /// is no longer being admitted (retention gave it up).
    pub(crate) async fn admit(&self, job_id: &str) -> Result<bool, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_ADMIT, async {
            let admitted = client
                .execute(
                    "UPDATE greengateway.policy_replay_jobs SET state = 'queued' \
                     WHERE job_id = $1 AND state = 'admitting'",
                    &[&job_id],
                )
                .await
                .map_err(|error| classify(error, OPERATION_ADMIT))?;
            Ok(admitted == 1)
        })
        .await
    }

    /// Withdraw an admission whose start could not be recorded: the job was
    /// never queued, so it never existed for anyone.
    pub(crate) async fn withdraw(&self, job_id: &str) -> Result<(), RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_ADMIT, async {
            client
                .execute(
                    "DELETE FROM greengateway.policy_replay_jobs \
                     WHERE job_id = $1 AND state = 'admitting'",
                    &[&job_id],
                )
                .await
                .map_err(|error| classify(error, OPERATION_ADMIT))?;
            Ok(())
        })
        .await
    }

    /// `owner`'s job `job_id`, or `None` when it has none by that id.
    pub(crate) async fn get(
        &self,
        owner: &PolicyReplayOwner,
        job_id: &str,
    ) -> Result<Option<PolicyReplayJobRecord>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_GET, async {
            let row = client
                .query_opt(
                    &format!(
                        "SELECT {RECORD_COLUMNS} FROM greengateway.policy_replay_jobs j, \
                         (SELECT now() AS now) c \
                         WHERE j.job_id = $1 AND j.owner_issuer = $2 AND j.owner_subject = $3"
                    ),
                    &[&job_id, &owner.issuer, &owner.subject],
                )
                .await
                .map_err(|error| classify(error, OPERATION_GET))?;
            row.map(|row| record_from_row(&row, 0, OPERATION_GET))
                .transpose()
        })
        .await
    }

    /// `owner`'s job started with idempotency key `key`, if any.
    pub(crate) async fn find_idempotent(
        &self,
        owner: &PolicyReplayOwner,
        key: &str,
    ) -> Result<Option<PolicyReplayJobRecord>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_GET, async {
            let row = client
                .query_opt(
                    &format!(
                        "SELECT {RECORD_COLUMNS} FROM greengateway.policy_replay_jobs j, \
                         (SELECT now() AS now) c \
                         WHERE j.owner_issuer = $1 AND j.owner_subject = $2 \
                           AND j.idempotency_key = $3"
                    ),
                    &[&owner.issuer, &owner.subject, &key],
                )
                .await
                .map_err(|error| classify(error, OPERATION_GET))?;
            row.map(|row| record_from_row(&row, 0, OPERATION_GET))
                .transpose()
        })
        .await
    }

    /// Cancel `owner`'s job `job_id` if it has not finished, or discard it
    /// if it has. One transaction, holding the job's row lock throughout.
    pub(crate) async fn cancel(
        &self,
        owner: &PolicyReplayOwner,
        job_id: &str,
    ) -> Result<PolicyReplayCancel, RepositoryError> {
        let mut client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_CANCEL, async {
            let transaction = client
                .transaction()
                .await
                .map_err(|error| classify(error, OPERATION_CANCEL))?;
            let state = transaction
                .query_opt(
                    "SELECT state FROM greengateway.policy_replay_jobs \
                     WHERE job_id = $1 AND owner_issuer = $2 AND owner_subject = $3 \
                     FOR UPDATE",
                    &[&job_id, &owner.issuer, &owner.subject],
                )
                .await
                .map_err(|error| classify(error, OPERATION_CANCEL))?;
            let Some(state) = state else {
                transaction
                    .commit()
                    .await
                    .map_err(|error| classify(error, OPERATION_CANCEL))?;
                return Ok(PolicyReplayCancel::NotFound);
            };
            let state: String = column(&state, 0, OPERATION_CANCEL)?;
            let outcome = match state.as_str() {
                "queued" => {
                    let row = transaction
                        .query_one(
                            &format!(
                                "WITH c AS (SELECT now() AS now), \
                                 j AS ( \
                                     UPDATE greengateway.policy_replay_jobs SET \
                                         state = 'cancelled', cancel_requested = true, \
                                         {finished} \
                                     FROM c WHERE job_id = $1 \
                                     RETURNING greengateway.policy_replay_jobs.* \
                                 ) \
                                 SELECT {RECORD_COLUMNS} FROM j, c",
                                finished = finished_columns("$2", "$3"),
                            ),
                            &[
                                &job_id,
                                &self.limits.result_ttl.as_secs_f64(),
                                &self.limits.expired_retention.as_secs_f64(),
                            ],
                        )
                        .await
                        .map_err(|error| classify(error, OPERATION_CANCEL))?;
                    PolicyReplayCancel::Cancelled(Box::new(record_from_row(
                        &row,
                        0,
                        OPERATION_CANCEL,
                    )?))
                }
                "admitting" | "running" => {
                    let row = transaction
                        .query_one(
                            &format!(
                                "WITH c AS (SELECT now() AS now), \
                                 j AS ( \
                                     UPDATE greengateway.policy_replay_jobs \
                                     SET cancel_requested = true WHERE job_id = $1 \
                                     RETURNING * \
                                 ) \
                                 SELECT {RECORD_COLUMNS} FROM j, c"
                            ),
                            &[&job_id],
                        )
                        .await
                        .map_err(|error| classify(error, OPERATION_CANCEL))?;
                    PolicyReplayCancel::Requested(Box::new(record_from_row(
                        &row,
                        0,
                        OPERATION_CANCEL,
                    )?))
                }
                _ => {
                    transaction
                        .execute(
                            "DELETE FROM greengateway.policy_replay_jobs WHERE job_id = $1",
                            &[&job_id],
                        )
                        .await
                        .map_err(|error| classify(error, OPERATION_CANCEL))?;
                    PolicyReplayCancel::Discarded
                }
            };
            transaction
                .commit()
                .await
                .map_err(|error| classify(error, OPERATION_CANCEL))?;
            Ok(outcome)
        })
        .await
    }

    /// Claim the oldest job no live lease holds, or `None` when there is
    /// none (module docs). `run_deadline` fixes the job's deadline at its
    /// first claim; a takeover keeps it.
    pub(crate) async fn claim(
        &self,
        run_deadline: Duration,
    ) -> Result<Option<PolicyReplayClaim>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_CLAIM, async {
            let row = client
                .query_opt(
                    &format!(
                        "WITH c AS (SELECT now() AS now), \
                         candidate AS ( \
                             SELECT job_id FROM greengateway.policy_replay_jobs \
                             WHERE state = 'queued' \
                                OR (state = 'running' AND lease_expires_at <= now()) \
                             ORDER BY created_at, job_id \
                             LIMIT 1 \
                             FOR UPDATE SKIP LOCKED \
                         ), \
                         j AS ( \
                             UPDATE greengateway.policy_replay_jobs AS t SET \
                                 state = 'running', \
                                 lease_holder = $1::text::uuid, \
                                 lease_fence = nextval('greengateway.policy_replay_job_fence'), \
                                 lease_expires_at = now() + make_interval(secs => $2::float8), \
                                 claims = t.claims + 1, \
                                 started_at = coalesce(t.started_at, now()), \
                                 run_deadline_at = coalesce( \
                                     t.run_deadline_at, \
                                     now() + make_interval(secs => $3::float8)) \
                             FROM candidate WHERE t.job_id = candidate.job_id \
                             RETURNING t.* \
                         ) \
                         SELECT {RECORD_COLUMNS}, j.base_json, j.candidate_json, j.lease_fence, \
                                j.claims, \
                                greatest(0, (extract(epoch FROM (j.run_deadline_at - c.now)) \
                                    * 1000)::bigint), \
                                j.checkpoint::text \
                         FROM j, c"
                    ),
                    &[
                        &self.holder(),
                        &self.lease_ttl.as_secs_f64(),
                        &run_deadline.as_secs_f64(),
                    ],
                )
                .await
                .map_err(|error| classify(error, OPERATION_CLAIM))?;
            let Some(row) = row else {
                return Ok(None);
            };
            let record = record_from_row(&row, 0, OPERATION_CLAIM)?;
            let at = RECORD_COLUMN_COUNT;
            let remaining_ms: i64 = column(&row, at + 4, OPERATION_CLAIM)?;
            Ok(Some(PolicyReplayClaim {
                lease: PolicyReplayLease {
                    job_id: record.spec.job_id.clone(),
                    fence: column(&row, at + 2, OPERATION_CLAIM)?,
                },
                record,
                documents: PolicyReplayDocuments {
                    base_json: column(&row, at, OPERATION_CLAIM)?,
                    candidate_json: column(&row, at + 1, OPERATION_CLAIM)?,
                },
                claims: column(&row, at + 3, OPERATION_CLAIM)?,
                remaining_deadline: Duration::from_millis(u64::try_from(remaining_ms).unwrap_or(0)),
                checkpoint: column(&row, at + 5, OPERATION_CLAIM)?,
            }))
        })
        .await
    }

    /// Extend `lease`, if it is still held.
    pub(crate) async fn renew(
        &self,
        lease: &PolicyReplayLease,
    ) -> Result<PolicyReplayLeaseStatus, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_RENEW, async {
            let row = client
                .query_opt(
                    "UPDATE greengateway.policy_replay_jobs \
                     SET lease_expires_at = now() + make_interval(secs => $4::float8) \
                     WHERE job_id = $1 AND lease_holder = $2::text::uuid AND lease_fence = $3 \
                       AND state = 'running' \
                     RETURNING cancel_requested",
                    &[
                        &lease.job_id,
                        &self.holder(),
                        &lease.fence,
                        &self.lease_ttl.as_secs_f64(),
                    ],
                )
                .await
                .map_err(|error| classify(error, OPERATION_RENEW))?;
            lease_status(row.as_ref(), OPERATION_RENEW)
        })
        .await
    }

    /// Store a run's progress under `lease`: the stream position read
    /// through, the rows scanned and the whole partial aggregate, in one
    /// statement that also extends the lease. Nothing is stored when the
    /// lease is no longer held.
    pub(crate) async fn checkpoint(
        &self,
        lease: &PolicyReplayLease,
        after_position: i64,
        scanned_records: i64,
        checkpoint_json: &str,
    ) -> Result<PolicyReplayLeaseStatus, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_CHECKPOINT, async {
            let row = client
                .query_opt(
                    "UPDATE greengateway.policy_replay_jobs SET \
                         cursor_position = $4, scanned_records = $5, \
                         checkpoint = $6::text::jsonb, \
                         lease_expires_at = now() + make_interval(secs => $7::float8) \
                     WHERE job_id = $1 AND lease_holder = $2::text::uuid AND lease_fence = $3 \
                       AND state = 'running' \
                     RETURNING cancel_requested",
                    &[
                        &lease.job_id,
                        &self.holder(),
                        &lease.fence,
                        &after_position,
                        &scanned_records,
                        &checkpoint_json,
                        &self.lease_ttl.as_secs_f64(),
                    ],
                )
                .await
                .map_err(|error| classify(error, OPERATION_CHECKPOINT))?;
            lease_status(row.as_ref(), OPERATION_CHECKPOINT)
        })
        .await
    }

    /// End the job `lease` holds. `false` when the lease is no longer held:
    /// another replica holds the job, and nothing changed.
    pub(crate) async fn finish(
        &self,
        lease: &PolicyReplayLease,
        ending: &PolicyReplayEnding,
    ) -> Result<bool, RepositoryError> {
        let (result, result_digest) = match &ending.result {
            Some((document, digest)) => (Some(document.as_str()), Some(digest.as_str())),
            None => (None, None),
        };
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_FINISH, async {
            let finished = client
                .execute(
                    &format!(
                        "WITH c AS (SELECT now() AS now) \
                         UPDATE greengateway.policy_replay_jobs SET \
                             state = $4, failure = $5, scanned_records = $6, \
                             result = $7::text::jsonb, result_digest = $8, \
                             lease_holder = NULL, lease_fence = NULL, lease_expires_at = NULL, \
                             cursor_position = NULL, checkpoint = NULL, \
                             {finished} \
                         FROM c \
                         WHERE job_id = $1 AND lease_holder = $2::text::uuid AND lease_fence = $3 \
                           AND state = 'running'",
                        finished = finished_columns("$9", "$10"),
                    ),
                    &[
                        &lease.job_id,
                        &self.holder(),
                        &lease.fence,
                        &ending.state,
                        &ending.failure,
                        &ending.scanned_records,
                        &result,
                        &result_digest,
                        &self.limits.result_ttl.as_secs_f64(),
                        &self.limits.expired_retention.as_secs_f64(),
                    ],
                )
                .await
                .map_err(|error| classify(error, OPERATION_FINISH))?;
            Ok(finished == 1)
        })
        .await
    }

    /// Give a job back without ending it, at shutdown: its lease expires now,
    /// so another replica claims it at once and resumes from its last
    /// checkpoint, and the claim it was given back from does not count
    /// toward the job's takeovers.
    pub(crate) async fn release(&self, lease: &PolicyReplayLease) -> Result<(), RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_RELEASE, async {
            client
                .execute(
                    "UPDATE greengateway.policy_replay_jobs SET \
                         lease_expires_at = now(), claims = greatest(claims - 1, 0) \
                     WHERE job_id = $1 AND lease_holder = $2::text::uuid AND lease_fence = $3 \
                       AND state = 'running'",
                    &[&lease.job_id, &self.holder(), &lease.fence],
                )
                .await
                .map_err(|error| classify(error, OPERATION_RELEASE))?;
            Ok(())
        })
        .await
    }

    /// One bounded retention pass (module docs). Returns how many rows it
    /// deleted or cleared.
    pub(crate) async fn prune(&self) -> Result<u64, RepositoryError> {
        let mut client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        timed_operation(OPERATION_PRUNE, async {
            let transaction = client
                .transaction()
                .await
                .map_err(|error| classify(error, OPERATION_PRUNE))?;
            let pruned = prune_with(&transaction, &self.limits, OPERATION_PRUNE).await?;
            transaction
                .commit()
                .await
                .map_err(|error| classify(error, OPERATION_PRUNE))?;
            Ok(pruned)
        })
        .await
    }
}

/// The columns a job's ending sets, with the result TTL and the expired
/// retention, in seconds, bound at `ttl` and `retention`, and `c.now` the
/// statement's clock.
fn finished_columns(ttl: &str, retention: &str) -> String {
    format!(
        "finished_at = c.now, \
         result_expires_at = c.now + make_interval(secs => {ttl}::float8), \
         expires_at = c.now + make_interval(secs => {ttl}::float8) \
             + make_interval(secs => {retention}::float8)"
    )
}

/// The owner's and the deployment's pending and unexpired jobs. `$1` and
/// `$2` are the owner.
fn counts_sql() -> String {
    format!(
        "SELECT \
             count(*) FILTER (WHERE owner_issuer = $1 AND owner_subject = $2 \
                              AND state IN {PENDING_STATES}), \
             count(*) FILTER (WHERE state IN {PENDING_STATES}), \
             count(*) FILTER (WHERE owner_issuer = $1 AND owner_subject = $2 \
                              AND (finished_at IS NULL OR result_expires_at > now())), \
             count(*) FILTER (WHERE finished_at IS NULL OR result_expires_at > now()) \
         FROM greengateway.policy_replay_jobs"
    )
}

/// The retention pass, in a transaction the caller holds.
async fn prune_with(
    client: &deadpool_postgres::Transaction<'_>,
    limits: &PolicyReplayLimits,
    operation: &'static str,
) -> Result<u64, RepositoryError> {
    let deleted = client
        .execute(
            "DELETE FROM greengateway.policy_replay_jobs WHERE job_id IN ( \
                 SELECT job_id FROM greengateway.policy_replay_jobs \
                 WHERE expires_at <= now() \
                    OR (state = 'admitting' \
                        AND created_at <= now() - make_interval(secs => $2::float8)) \
                 ORDER BY created_at, job_id \
                 LIMIT $1)",
            &[&limits.prune_batch, &limits.admission_grace.as_secs_f64()],
        )
        .await
        .map_err(|error| classify(error, operation))?;
    let cleared = client
        .execute(
            "UPDATE greengateway.policy_replay_jobs SET result = NULL, result_digest = NULL \
             WHERE job_id IN ( \
                 SELECT job_id FROM greengateway.policy_replay_jobs \
                 WHERE result IS NOT NULL AND result_expires_at <= now() \
                 ORDER BY result_expires_at, job_id \
                 LIMIT $1)",
            &[&limits.prune_batch],
        )
        .await
        .map_err(|error| classify(error, operation))?;
    Ok(deleted + cleared)
}

fn lease_status(
    row: Option<&Row>,
    operation: &'static str,
) -> Result<PolicyReplayLeaseStatus, RepositoryError> {
    match row {
        None => Ok(PolicyReplayLeaseStatus::Lost),
        Some(row) => Ok(PolicyReplayLeaseStatus::Held {
            cancel_requested: column(row, 0, operation)?,
        }),
    }
}

/// A job read from [`RECORD_COLUMNS`], starting at column `at`.
fn record_from_row(
    row: &Row,
    at: usize,
    operation: &'static str,
) -> Result<PolicyReplayJobRecord, RepositoryError> {
    let get = |index: usize| at + index;
    let result_json: Option<String> = column(row, get(35), operation)?;
    let result_digest: Option<String> = column(row, get(36), operation)?;
    let result = match (result_json, result_digest) {
        (Some(json), Some(digest)) => Some((json, digest)),
        (None, None) => None,
        _ => return Err(invalid_data(operation)),
    };
    Ok(PolicyReplayJobRecord {
        spec: PolicyReplayJobSpec {
            job_id: column(row, get(0), operation)?,
            owner: PolicyReplayOwner {
                issuer: column(row, get(1), operation)?,
                subject: column(row, get(2), operation)?,
            },
            idempotency_key: column(row, get(3), operation)?,
            request_digest: column(row, get(4), operation)?,
            actor_json: column(row, get(5), operation)?,
            request_id: column(row, get(6), operation)?,
            source_ip: column(row, get(7), operation)?,
            base_etag: column(row, get(8), operation)?,
            candidate_source: column(row, get(9), operation)?,
            candidate_etag: column(row, get(10), operation)?,
            edit_count: column(row, get(11), operation)?,
            candidate_draft: match (
                column::<Option<String>>(row, get(12), operation)?,
                column::<Option<i64>>(row, get(13), operation)?,
            ) {
                (Some(draft_id), Some(revision)) => Some((draft_id, revision)),
                (None, None) => None,
                _ => return Err(invalid_data(operation)),
            },
            candidate_version: column(row, get(14), operation)?,
            projections: column(row, get(15), operation)?,
            engine_version: column(row, get(16), operation)?,
            window_from: column(row, get(17), operation)?,
            window_to: column(row, get(18), operation)?,
            from_epoch_us: column(row, get(19), operation)?,
            to_epoch_us: column(row, get(20), operation)?,
            high_water: column(row, get(21), operation)?,
            selected_records: column(row, get(22), operation)?,
            first_position: column(row, get(23), operation)?,
            last_position: column(row, get(24), operation)?,
            max_records: column(row, get(25), operation)?,
        },
        status: PolicyReplayJobStatus {
            state: column(row, get(26), operation)?,
            failure: column(row, get(27), operation)?,
            cancel_requested: column(row, get(28), operation)?,
            scanned_records: column(row, get(29), operation)?,
            created_at_us: column(row, get(30), operation)?,
            started_at_us: column(row, get(31), operation)?,
            finished_at_us: column(row, get(32), operation)?,
            result_expires_at_us: column(row, get(33), operation)?,
            result_expired: column(row, get(34), operation)?,
            result,
        },
    })
}

/// Read one column; a row that does not decode is data this binary cannot
/// use (`InvalidData`), never a panic. The driver's decode error names the
/// column's type, not its value.
fn column<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a Row,
    index: usize,
    operation: &'static str,
) -> Result<T, RepositoryError> {
    row.try_get(index).map_err(|error| {
        tracing::error!(operation, column = index, error = %error, "replay job row failed to decode");
        invalid_data(operation)
    })
}

fn classify(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

#[cfg(test)]
#[path = "postgres_policy_replays_tests.rs"]
mod tests;
