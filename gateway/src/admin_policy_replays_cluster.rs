//! Cluster-mode replay jobs (issue #243): the PostgreSQL half of `POST`,
//! `GET` and `DELETE .../policy/replays`, and the bounded worker every
//! cluster replica runs.
//!
//! A cluster job is a row of migration 30's `greengateway.policy_replay_jobs`
//! (`storage::postgres_policy_replays`), so every replica serves every job
//! and any replica may run one. It reads the cluster audit stream
//! (`storage::postgres_audit_replay`) through the same engine, under the same
//! bounds, as a standalone job reads its log, and its result is the same
//! document.
//!
//! ## Admission
//!
//! The route validates and pins the request exactly as standalone does, then
//! asks the store whether the owner and the deployment have room, fixes the
//! cutoff on the audit stream, and admits the job in one transaction under
//! the store's advisory lock: idempotency, the per-owner and per-deployment
//! quotas of pending and unexpired jobs, and the insertion, as `admitting`.
//! Only once its `policy.replay_started` event is accepted does the job
//! become `queued`, so no worker runs a job whose start is not on the
//! record. Over any bound is `429`, and no job is ever evicted. The route's
//! evaluation slot bounds admissions in flight on this replica; it is given
//! back when the request ends, since the job may run anywhere.
//!
//! ## The worker
//!
//! Each replica runs one worker, so each runs at most one job at a time,
//! on a blocking thread. While the membership gate admits the replica it
//! claims the oldest job no live lease holds -- a queued job, or one whose
//! holder's lease expired -- under a lease of [`CLUSTER_REPLAY_LEASE_TTL`]
//! renewed every [`CLUSTER_REPLAY_RENEW_INTERVAL`], and runs it with the
//! store as its checkpoint sink: after every page the run's position and its
//! whole partial aggregate are stored in one statement under the lease's
//! fence, and that statement answers whether the job was cancelled. A worker
//! that takes a job over resumes from its last checkpoint and reads the page
//! after it, so a takeover after a lost lease counts every record exactly
//! once. The job's run deadline is fixed at its first claim and kept across
//! takeovers.
//!
//! A claimed job whose pinned documents no longer validate or reproduce
//! their ETags, whose engine version is not this build's, whose checkpoint
//! cannot be read back, or that has been claimed more than
//! [`CLUSTER_REPLAY_MAX_CLAIMS`] times, is ended `interrupted` with a stable
//! reason and `policy.replay_interrupted`: never resumed under another
//! evaluator, and never a partial result.
//!
//! ## Shutdown and draining (#239)
//!
//! The worker stops claiming as soon as the replica starts draining. A run
//! in progress is released before its next record: its lease is expired at
//! once, so another replica claims the job and resumes from its last
//! checkpoint, and that claim does not count toward the job's takeovers.
//! Data-plane readiness never depends on the worker.
//!
//! ## Retention
//!
//! An idle worker runs one bounded retention pass of the store per turn, as
//! every admission does: finished jobs past their retention are deleted,
//! expired results cleared, and admissions abandoned by a replica that died
//! before recording them removed. Pending jobs are never pruned.

use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::*;

use crate::{
    ha::ClusterReadiness,
    lifecycle::GatewayLifecycle,
    policy_replay::{
        checkpoint::CHECKPOINT_SCHEMA_VERSION,
        job::{run_resumable, ReplayCheckpoints, ReplayOutcome, RESULT_SCHEMA_VERSION},
    },
    storage::{
        policy_drafts::{candidate_from_stored, stored_candidate},
        postgres_audit_replay::PostgresReplayReader,
        postgres_policy_replays::{
            PolicyReplayCancel, PolicyReplayClaim, PolicyReplayCreated, PolicyReplayDocuments,
            PolicyReplayEnding, PolicyReplayJobRecord, PolicyReplayJobSpec, PolicyReplayLease,
            PolicyReplayLeaseStatus, PolicyReplayLimits, PolicyReplayOwner,
            PostgresPolicyReplayStore,
        },
    },
};

/// How long a worker's lease on a job lasts without a renewal or a
/// checkpoint.
pub(super) const CLUSTER_REPLAY_LEASE_TTL: Duration = Duration::from_secs(30);
/// How often a running job's lease is renewed: a third of its TTL, so a
/// renewal can be missed twice before another replica may take the job.
const CLUSTER_REPLAY_RENEW_INTERVAL: Duration = Duration::from_secs(10);
/// How often an idle worker asks for a job. An admission on its own replica
/// wakes it at once.
const CLUSTER_REPLAY_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Most claims of one job, its first included. A job claimed again after as
/// many lost leases is interrupted rather than retried without end; a claim
/// given back at shutdown does not count.
pub(super) const CLUSTER_REPLAY_MAX_CLAIMS: i32 = 3;
/// How long an admission may wait for its start to be recorded before
/// retention takes its replica for gone.
const CLUSTER_REPLAY_ADMISSION_GRACE: Duration = Duration::from_secs(60);
/// Rows one retention pass deletes or clears at most.
const CLUSTER_REPLAY_PRUNE_BATCH: i64 = 64;

/// The deployment-wide bounds of cluster jobs: as many pending as one
/// standalone replica queues, one per owner, and the standalone retention
/// bounds, now for the whole deployment.
pub(super) fn cluster_replay_limits() -> PolicyReplayLimits {
    PolicyReplayLimits {
        max_pending: i64::try_from(MAX_PENDING_POLICY_REPLAYS).unwrap_or(i64::MAX),
        max_pending_per_owner: 1,
        max_retained: i64::try_from(MAX_RETAINED_POLICY_REPLAYS).unwrap_or(i64::MAX),
        max_retained_per_owner: i64::try_from(MAX_RETAINED_POLICY_REPLAYS_PER_ACTOR)
            .unwrap_or(i64::MAX),
        result_ttl: POLICY_REPLAY_RESULT_TTL,
        expired_retention: POLICY_REPLAY_EXPIRED_RETENTION,
        admission_grace: CLUSTER_REPLAY_ADMISSION_GRACE,
        prune_batch: CLUSTER_REPLAY_PRUNE_BATCH,
    }
}

/// The engine a job is admitted under and only runs under: the evaluator's
/// semantics and context versions, the replay context's, the checkpoint's
/// and the result's.
pub(super) fn engine_version() -> String {
    format!(
        "{} {} {} {} {} {} {}",
        policy_eval::HTTP_SEMANTICS_VERSION,
        policy_eval::CONTEXT_VERSION,
        policy_eval::tools::TOOL_SEMANTICS_VERSION,
        policy_eval::tools::TOOL_CONTEXT_VERSION,
        policy_replay::REPLAY_CONTEXT_SCHEMA_VERSION,
        CHECKPOINT_SCHEMA_VERSION,
        RESULT_SCHEMA_VERSION,
    )
}

/// The cluster replay jobs of one replica: the store, what the audit stream
/// reader is built from, and the wake-up of this replica's worker.
pub(crate) struct ClusterPolicyReplays {
    store: PostgresPolicyReplayStore,
    pool: deadpool_postgres::Pool,
    settings: config::DatabaseSettings,
    wake: tokio::sync::Notify,
}

impl ClusterPolicyReplays {
    /// `settings` are the pool's own, so the reader's bounds never loosen
    /// the operator's; `holder` is this replica's instance identity.
    pub(crate) fn new(
        pool: deadpool_postgres::Pool,
        settings: &config::DatabaseSettings,
        holder: uuid::Uuid,
    ) -> Self {
        Self::with_store(
            PostgresPolicyReplayStore::new(
                pool.clone(),
                holder,
                CLUSTER_REPLAY_LEASE_TTL,
                cluster_replay_limits(),
            ),
            pool,
            settings,
        )
    }

    /// The same jobs over a store a test configured.
    pub(crate) fn with_store(
        store: PostgresPolicyReplayStore,
        pool: deadpool_postgres::Pool,
        settings: &config::DatabaseSettings,
    ) -> Self {
        Self {
            store,
            pool,
            settings: settings.clone(),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// The audit stream reader, driven by the current runtime.
    fn reader(&self) -> PostgresReplayReader {
        PostgresReplayReader::new(
            self.pool.clone(),
            &self.settings,
            tokio::runtime::Handle::current(),
        )
    }

    /// Start this replica's worker for the life of the process. It claims
    /// work only while `readiness` admits the replica, and stops when the
    /// lifecycle's background cancellation fires (draining or shutdown).
    pub(crate) fn spawn_worker(
        self: &Arc<Self>,
        lifecycle: &GatewayLifecycle,
        readiness: Option<Arc<ClusterReadiness>>,
        audit: audit::AuditLog,
    ) {
        let shutdown = lifecycle.background_cancellation();
        let replays = Arc::clone(self);
        let handle = tokio::spawn(async move {
            replays.work(shutdown, readiness, audit).await;
        });
        lifecycle.register_background_task(handle);
    }
}

/// A job's owner in the store: the canonical issuer and the subject, as
/// [`replay_owner`] keys a standalone job.
fn owner(principal: &auth::Principal) -> PolicyReplayOwner {
    PolicyReplayOwner {
        issuer: principal
            .issuer
            .as_deref()
            .and_then(auth::principal::canonical_issuer)
            .unwrap_or_default(),
        subject: principal.user_id.clone(),
    }
}

fn time_from_us(epoch_us: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(epoch_us) * 1_000).ok()
}

/// A stored job as this build reads it. `None` from [`Self::from_record`]
/// means the row is not one this build wrote.
struct ClusterJob {
    id: String,
    state: ReplayJobState,
    failure: Option<String>,
    cancel_requested: bool,
    created_at: Option<OffsetDateTime>,
    started_at: Option<OffsetDateTime>,
    finished_at: Option<OffsetDateTime>,
    result_expires_at: Option<OffsetDateTime>,
    request_digest: String,
    binding: ReplayJobBinding,
    scope: ReplayScope,
    scanned: u64,
    result: Option<ReplayJobResult>,
}

impl ClusterJob {
    fn from_record(record: &PolicyReplayJobRecord) -> Option<Self> {
        let spec = &record.spec;
        let status = &record.status;
        let result = match &status.result {
            None => None,
            Some((document, digest)) => Some(ReplayJobResult {
                document: serde_json::from_str(document).ok()?,
                digest: digest.clone(),
            }),
        };
        Some(Self {
            id: spec.job_id.clone(),
            state: ReplayJobState::from_stored(&status.state, status.result_expired)?,
            failure: status.failure.clone(),
            cancel_requested: status.cancel_requested,
            created_at: time_from_us(status.created_at_us),
            started_at: status.started_at_us.and_then(time_from_us),
            finished_at: status.finished_at_us.and_then(time_from_us),
            result_expires_at: status.result_expires_at_us.and_then(time_from_us),
            request_digest: spec.request_digest.clone(),
            binding: binding_from(spec)?,
            scope: scope_from(spec)?,
            scanned: u64::try_from(status.scanned_records).ok()?,
            result,
        })
    }

    fn view(&self) -> ReplayJobView<'_> {
        ReplayJobView {
            id: &self.id,
            state: self.state,
            failure: self.failure.as_deref(),
            cancel_requested: self.cancel_requested,
            created_at: self.created_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
            result_expires_at: self.result_expires_at,
            request_digest: &self.request_digest,
            binding: &self.binding,
            scope: &self.scope,
            scanned: self.scanned,
            result: self.result.as_ref(),
        }
    }
}

fn binding_from(spec: &PolicyReplayJobSpec) -> Option<ReplayJobBinding> {
    let (candidate_source, stored) = match (
        spec.candidate_source.as_str(),
        &spec.candidate_draft,
        spec.candidate_version,
    ) {
        ("active", None, None) => ("active", None),
        ("edits", None, None) => ("edits", None),
        ("inline", None, None) => ("inline", None),
        ("draft", Some((draft_id, revision)), None) => (
            "draft",
            Some(StoredCandidate::Draft {
                draft_id: draft_id.clone(),
                revision: *revision,
            }),
        ),
        ("revision", None, Some(version)) => {
            ("revision", Some(StoredCandidate::Revision { version }))
        }
        _ => return None,
    };
    let projections = spec
        .projections
        .split(',')
        .map(|name| match name {
            "as_authored" => Some(Projection::AsAuthored),
            "enforce_all_shadow" => Some(Projection::EnforceAllShadow),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    Some(ReplayJobBinding {
        base_etag: spec.base_etag.clone(),
        candidate_source: candidate_source.to_owned(),
        candidate_etag: spec.candidate_etag.clone(),
        edit_count: usize::try_from(spec.edit_count).ok()?,
        stored,
        projections,
    })
}

fn scope_from(spec: &PolicyReplayJobSpec) -> Option<ReplayScope> {
    Some(ReplayScope {
        from: spec.window_from.clone(),
        to: spec.window_to.clone(),
        from_epoch_us: spec.from_epoch_us,
        to_epoch_us: spec.to_epoch_us,
        cutoff: audit::query::ReplayCutoff {
            high_water: spec.high_water,
            selected: u64::try_from(spec.selected_records).ok()?,
            first_id: spec.first_position,
            last_id: spec.last_position,
        },
        max_records: usize::try_from(spec.max_records).ok()?,
    })
}

/// A job's audit envelope: the admitting request's, whichever replica
/// records the event.
struct ReplayEnvelope {
    actor: Option<audit::Actor>,
    request_id: String,
    source_ip: String,
}

impl ReplayEnvelope {
    fn of(spec: &PolicyReplayJobSpec) -> Self {
        let actor = match serde_json::from_str::<audit::Actor>(&spec.actor_json) {
            Ok(actor) => Some(actor),
            Err(_) => {
                tracing::error!(
                    "a stored replay job's actor could not be read; its lifecycle events name none"
                );
                None
            }
        };
        Self {
            actor,
            request_id: spec.request_id.clone(),
            source_ip: spec.source_ip.clone(),
        }
    }

    /// Record one lifecycle event and wait until the audit authority accepts
    /// it.
    async fn record(
        &self,
        audit: &audit::AuditLog,
        event_type: &str,
        payload: Value,
    ) -> Result<(), audit::AuditUnavailable> {
        let receipt = audit.record(audit::AuditEvent::new(
            event_type,
            self.request_id.clone(),
            self.source_ip.clone(),
            self.actor.clone(),
            payload,
        ));
        audit.confirm(receipt).await
    }
}

fn store_unavailable() -> Response {
    replay_refusal(
        StatusCode::SERVICE_UNAVAILABLE,
        "the policy replay job store is unavailable; retry later",
        "policy_replay_store_unavailable",
    )
}

fn respond(status: StatusCode, record: &PolicyReplayJobRecord, current: Option<bool>) -> Response {
    match ClusterJob::from_record(record) {
        Some(job) => respond_view(status, &job.view(), current),
        None => {
            tracing::error!("a stored policy replay job is not one this build reads");
            internal_server_error("policy replay job could not be read")
        }
    }
}

/// The pinned documents of a job, as the gateway serializes them.
fn pinned_documents(
    base: &rbac::Policy,
    candidate: Option<&rbac::Policy>,
) -> Result<PolicyReplayDocuments, storage::RepositoryError> {
    Ok(PolicyReplayDocuments {
        base_json: stored_candidate(base, "policy_replay_job_create")?.json,
        candidate_json: candidate
            .map(|candidate| stored_candidate(candidate, "policy_replay_job_create"))
            .transpose()?
            .map(|stored| stored.json),
    })
}

impl ClusterPolicyReplays {
    /// The answer for a retry of the owner's job started with idempotency
    /// key `key` -- the job, a conflict, or the store's refusal -- or `None`
    /// when the key names no job.
    pub(super) async fn answer_retry(
        &self,
        state: &PolicyAdminState,
        rbac_state: &middleware::rbac::RbacState,
        principal: &auth::Principal,
        key: &str,
        request_digest: &str,
    ) -> Option<Response> {
        match self.store.find_idempotent(&owner(principal), key).await {
            Ok(None) => None,
            Ok(Some(record)) if record.spec.request_digest == request_digest => {
                let current = base_etag_is_current(state, rbac_state, &record.spec.base_etag).await;
                Some(respond(StatusCode::OK, &record, current))
            }
            Ok(Some(_)) => Some(replay_idempotency_conflict()),
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not read its job store");
                Some(store_unavailable())
            }
        }
    }

    /// Admit a validated, pinned request as a cluster job (module docs).
    pub(super) async fn admit(
        &self,
        state: &PolicyAdminState,
        principal: &auth::Principal,
        parts: &http::request::Parts,
        prepared: PreparedReplay,
    ) -> Response {
        let owner = owner(principal);
        match self.store.precheck(&owner).await {
            Ok(None) => {}
            Ok(Some(PolicyReplayCreated::Busy)) => return replay_busy(),
            Ok(Some(_)) => return replay_quota_exhausted(),
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not read its job store");
                return store_unavailable();
            }
        }
        // The cutoff is fixed now, before the job is queued: whatever the
        // stream assigns from here on, the job never reads it.
        let cutoff = match self
            .reader()
            .cutoff(prepared.window.from_epoch_us, prepared.window.to_epoch_us)
            .await
        {
            Ok(cutoff) => cutoff,
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not read its audit stream cutoff");
                return policy_evidence_unavailable(
                    "policy replay could not read the cluster audit stream",
                );
            }
        };
        let Some(id) = new_policy_replay_job_id() else {
            tracing::error!("operating-system randomness is unavailable for a replay job id");
            return internal_server_error("policy replay job could not be created");
        };
        let documents = match pinned_documents(&prepared.base, prepared.candidate.as_ref()) {
            Ok(documents) => documents,
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not pin its policies");
                return internal_server_error("policy replay job could not be created");
            }
        };
        let actor = auth::actor_from_principal(principal);
        let Ok(actor_json) = serde_json::to_string(&actor) else {
            return internal_server_error("policy replay job could not be created");
        };
        let envelope = ReplayEnvelope {
            actor: Some(actor),
            request_id: client_ip::request_id(&parts.headers, &parts.extensions),
            source_ip: client_ip::canonical_client_ip(
                &parts.headers,
                &parts.extensions,
                &state.client_ip_policy,
            ),
        };
        let scope = ReplayScope {
            from: prepared.window.from,
            to: prepared.window.to,
            from_epoch_us: prepared.window.from_epoch_us,
            to_epoch_us: prepared.window.to_epoch_us,
            cutoff,
            max_records: prepared.request.max_records,
        };
        let binding = prepared.binding;
        let spec = PolicyReplayJobSpec {
            job_id: id.clone(),
            owner,
            idempotency_key: prepared.request.idempotency_key.clone(),
            request_digest: prepared.request.digest.clone(),
            actor_json,
            request_id: envelope.request_id.clone(),
            source_ip: envelope.source_ip.clone(),
            base_etag: binding.base_etag.clone(),
            candidate_source: binding.candidate_source.to_owned(),
            candidate_etag: binding.candidate_etag.clone(),
            edit_count: i32::try_from(binding.edit_count).unwrap_or(i32::MAX),
            candidate_draft: match &binding.stored {
                Some(StoredCandidate::Draft { draft_id, revision }) => {
                    Some((draft_id.clone(), *revision))
                }
                _ => None,
            },
            candidate_version: match &binding.stored {
                Some(StoredCandidate::Revision { version }) => Some(*version),
                _ => None,
            },
            projections: binding.projection_names().join(","),
            engine_version: engine_version(),
            window_from: scope.from.clone(),
            window_to: scope.to.clone(),
            from_epoch_us: scope.from_epoch_us,
            to_epoch_us: scope.to_epoch_us,
            high_water: scope.cutoff.high_water,
            selected_records: i64::try_from(scope.cutoff.selected).unwrap_or(i64::MAX),
            first_position: scope.cutoff.first_id,
            last_position: scope.cutoff.last_id,
            max_records: i32::try_from(scope.max_records).unwrap_or(i32::MAX),
        };
        let record = match self.store.create(&spec, &documents).await {
            Ok(PolicyReplayCreated::Created(record)) => record,
            Ok(PolicyReplayCreated::Existing(record)) => {
                return respond(StatusCode::OK, &record, None);
            }
            Ok(PolicyReplayCreated::IdempotencyConflict) => return replay_idempotency_conflict(),
            Ok(PolicyReplayCreated::Busy) => return replay_busy(),
            Ok(PolicyReplayCreated::QuotaExhausted) => return replay_quota_exhausted(),
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not admit its job");
                return store_unavailable();
            }
        };
        // A job whose start is not on the record is never queued.
        if let Err(error) = envelope
            .record(
                &state.audit,
                audit::event::POLICY_REPLAY_STARTED,
                started_payload_for(&id, &spec.request_digest, &binding, &scope),
            )
            .await
        {
            tracing::error!(error = %error, "policy replay start was not recorded; the job is not queued");
            if let Err(error) = self.store.withdraw(&id).await {
                tracing::error!(error = %error, "an unrecorded policy replay admission could not be withdrawn; retention removes it");
            }
            return replay_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "the policy replay could not be recorded; retry later",
                "policy_replay_audit_unavailable",
            );
        }
        match self.store.admit(&id).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::error!("a policy replay admission lapsed before it was queued");
                return store_unavailable();
            }
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not queue its job");
                return store_unavailable();
            }
        }
        self.wake.notify_one();
        let mut response = respond(StatusCode::ACCEPTED, &record, Some(true));
        if let Ok(location) = HeaderValue::from_str(&format!("{}/{}", parts.uri.path(), id)) {
            response.headers_mut().insert(header::LOCATION, location);
        }
        response
    }

    /// `GET`: the caller's job, from whichever replica runs it.
    pub(super) async fn read(
        &self,
        state: &PolicyAdminState,
        rbac_state: &middleware::rbac::RbacState,
        principal: &auth::Principal,
        job_id: &str,
    ) -> Response {
        match self.store.get(&owner(principal), job_id).await {
            Ok(Some(record)) => {
                let current = base_etag_is_current(state, rbac_state, &record.spec.base_etag).await;
                respond(StatusCode::OK, &record, current)
            }
            Ok(None) => replay_job_not_found(),
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not read its job store");
                store_unavailable()
            }
        }
    }

    /// `DELETE`: end a queued job at once, ask a running one to stop before
    /// its next page, or discard a finished one.
    pub(super) async fn cancel(
        &self,
        state: &PolicyAdminState,
        principal: &auth::Principal,
        job_id: &str,
    ) -> Response {
        match self.store.cancel(&owner(principal), job_id).await {
            Ok(PolicyReplayCancel::NotFound) => replay_job_not_found(),
            Ok(PolicyReplayCancel::Discarded) => StatusCode::NO_CONTENT.into_response(),
            Ok(PolicyReplayCancel::Requested(record)) => {
                respond(StatusCode::ACCEPTED, &record, None)
            }
            Ok(PolicyReplayCancel::Cancelled(record)) => {
                // The job never ran. Its state is set whether or not the event
                // is accepted, as a standalone job's is: a job without a
                // result has nothing to withhold.
                let recorded = ReplayEnvelope::of(&record.spec)
                    .record(
                        &state.audit,
                        audit::event::POLICY_REPLAY_CANCELLED,
                        json!({
                            "job_id": record.spec.job_id,
                            "scanned_records": 0,
                            "duration_ms": 0,
                        }),
                    )
                    .await;
                if let Err(error) = recorded {
                    tracing::error!(error = %error, "policy replay job's terminal audit event was not recorded");
                }
                respond(StatusCode::ACCEPTED, &record, None)
            }
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not cancel its job");
                store_unavailable()
            }
        }
    }

    /// The caller's job `job_id`, for an evidence package.
    pub(super) async fn evidence(
        &self,
        principal: &auth::Principal,
        job_id: &str,
    ) -> Result<ReplayJobEvidence, ReplayJobEvidenceRefusal> {
        if !is_policy_replay_job_id(job_id) {
            return Err(ReplayJobEvidenceRefusal::NotFound);
        }
        match self.store.get(&owner(principal), job_id).await {
            Ok(Some(record)) => match ClusterJob::from_record(&record) {
                Some(job) => evidence_from_view(&job.view()),
                None => {
                    tracing::error!("a stored policy replay job is not one this build reads");
                    Err(ReplayJobEvidenceRefusal::Unavailable)
                }
            },
            Ok(None) => Err(ReplayJobEvidenceRefusal::NotFound),
            Err(error) => {
                tracing::error!(error = %error, "policy evidence could not read the replay job store");
                Err(ReplayJobEvidenceRefusal::Unavailable)
            }
        }
    }
}

/// The checkpoint sink of a cluster run: the store, under the run's lease.
/// Called on the run's blocking thread, which waits for each statement.
struct StoredCheckpoints {
    store: PostgresPolicyReplayStore,
    lease: PolicyReplayLease,
    runtime: tokio::runtime::Handle,
}

impl ReplayCheckpoints for StoredCheckpoints {
    fn page_done(&self, after_id: i64, scanned: u64, checkpoint: &Value) -> Result<(), ReplayStop> {
        let document = serde_json::to_string(checkpoint)
            .map_err(|_| ReplayStop::Failed("checkpoint_too_large"))?;
        let scanned = i64::try_from(scanned).map_err(|_| ReplayStop::Failed("internal"))?;
        match self.runtime.block_on(self.store.checkpoint(
            &self.lease,
            after_id,
            scanned,
            &document,
        )) {
            Ok(PolicyReplayLeaseStatus::Held {
                cancel_requested: false,
            }) => Ok(()),
            Ok(PolicyReplayLeaseStatus::Held {
                cancel_requested: true,
            }) => Err(ReplayStop::Cancelled),
            Ok(PolicyReplayLeaseStatus::Lost) => Err(ReplayStop::Released),
            // Unknown whether it was stored: give the job up. Its lease lapses
            // and the next claim resumes from whichever checkpoint stands.
            Err(error) => {
                tracing::error!(error = %error, "policy replay could not store a checkpoint; releasing the job");
                Err(ReplayStop::Released)
            }
        }
    }
}

/// Run-ending failures that mean the job cannot be continued here, rather
/// than that its run failed: they end it `interrupted`.
fn interrupts(reason: &str) -> bool {
    matches!(reason, "pins_unreadable" | "checkpoint_unreadable")
}

/// The pinned policies of a claimed job, re-validated: each document must
/// still be a policy this build accepts and reproduce its recorded ETag.
fn rebuilt_pins(
    claim: &PolicyReplayClaim,
) -> Result<(rbac::Policy, Option<rbac::Policy>), ReplayStop> {
    let operation = "policy_replay_job_claim";
    let spec = &claim.record.spec;
    let base = candidate_from_stored(&claim.documents.base_json, &spec.base_etag, operation)
        .map_err(|_| ReplayStop::Failed("pins_unreadable"))?;
    let candidate = match (
        &claim.documents.candidate_json,
        spec.candidate_source.as_str(),
    ) {
        (None, "active") => None,
        (Some(json), "edits" | "inline" | "draft" | "revision") => Some(
            candidate_from_stored(json, &spec.candidate_etag, operation)
                .map_err(|_| ReplayStop::Failed("pins_unreadable"))?,
        ),
        _ => return Err(ReplayStop::Failed("pins_unreadable")),
    };
    if candidate.is_none() && spec.candidate_etag != spec.base_etag {
        return Err(ReplayStop::Failed("pins_unreadable"));
    }
    Ok((base, candidate))
}

impl ClusterPolicyReplays {
    /// The worker loop (module docs).
    async fn work(
        self: Arc<Self>,
        shutdown: CancellationToken,
        readiness: Option<Arc<ClusterReadiness>>,
        audit: audit::AuditLog,
    ) {
        let mut held_for: Option<&'static str> = None;
        while !shutdown.is_cancelled() {
            let blocked = readiness
                .as_ref()
                .and_then(|readiness| readiness.blocked_reason());
            if let Some(reason) = blocked {
                if held_for != Some(reason) {
                    tracing::warn!(
                        reason,
                        "policy replay jobs are held: this replica has not been admitted to the cluster, so it claims none"
                    );
                    held_for = Some(reason);
                }
            } else {
                held_for = None;
                match self.store.claim(REPLAY_RUN_DEADLINE).await {
                    Ok(Some(claim)) => {
                        self.run_claimed(claim, &shutdown, &audit).await;
                        continue;
                    }
                    Ok(None) => {
                        if let Err(error) = self.store.prune().await {
                            tracing::warn!(error = %error, "policy replay job retention did not run");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "policy replay worker could not claim a job");
                    }
                }
            }
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = self.wake.notified() => {}
                () = tokio::time::sleep(CLUSTER_REPLAY_POLL_INTERVAL) => {}
            }
        }
    }

    /// Run one claimed job to an ending, or give it back.
    async fn run_claimed(
        &self,
        claim: PolicyReplayClaim,
        shutdown: &CancellationToken,
        audit: &audit::AuditLog,
    ) {
        let started = Instant::now();
        let lease = claim.lease.clone();
        let envelope = ReplayEnvelope::of(&claim.record.spec);
        let scanned = claim.record.status.scanned_records;
        if claim.record.status.cancel_requested {
            self.end(
                audit,
                &envelope,
                &lease,
                scanned,
                started,
                ReplayStop::Cancelled,
            )
            .await;
            return;
        }
        let interrupted = if claim.claims > CLUSTER_REPLAY_MAX_CLAIMS {
            Some("takeover_limit")
        } else if claim.record.spec.engine_version != engine_version() {
            Some("engine_version_changed")
        } else {
            None
        };
        let (scope, projections) = match (
            interrupted,
            scope_from(&claim.record.spec),
            binding_from(&claim.record.spec),
        ) {
            (None, Some(scope), Some(binding)) => (scope, binding.projections),
            (reason, _, _) => {
                let reason = reason.unwrap_or("pins_unreadable");
                self.end(
                    audit,
                    &envelope,
                    &lease,
                    scanned,
                    started,
                    ReplayStop::Failed(reason),
                )
                .await;
                return;
            }
        };
        let control = Arc::new(ReplayControl::default());
        let renewer = self.spawn_renewer(&lease, &control);
        let watcher = {
            let control = Arc::clone(&control);
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                shutdown.cancelled().await;
                control.release();
            })
        };
        let deadline = Instant::now() + claim.remaining_deadline;
        let sink = StoredCheckpoints {
            store: self.store.clone(),
            lease: lease.clone(),
            runtime: tokio::runtime::Handle::current(),
        };
        let reader = self.reader();
        let run_control = Arc::clone(&control);
        let run_scope = scope.clone();
        let run = tokio::task::spawn_blocking(move || {
            let (base, candidate) = rebuilt_pins(&claim)?;
            let resume = match claim.checkpoint.as_deref() {
                None => None,
                Some(document) => Some(
                    serde_json::from_str::<Value>(document)
                        .map_err(|_| ReplayStop::Failed("checkpoint_unreadable"))?,
                ),
            };
            let policies = ReplayPolicies::compile(&base, candidate.as_ref(), &projections)
                .map_err(|error| {
                    tracing::error!(error = ?error, "policy replay policies could not be compiled");
                    ReplayStop::Failed("compile_failed")
                })?;
            run_resumable(
                &reader,
                &policies,
                &run_scope,
                deadline,
                &run_control,
                resume.as_ref(),
                Some(&sink),
            )
        })
        .await;
        renewer.abort();
        watcher.abort();
        let stop = match run {
            Ok(Ok(outcome)) => {
                self.publish(audit, &envelope, &lease, &scope, started, outcome)
                    .await;
                return;
            }
            Ok(Err(stop)) => stop,
            Err(error) => {
                tracing::error!(error = %error, "policy replay job did not complete");
                ReplayStop::Failed("internal")
            }
        };
        if stop == ReplayStop::Released {
            // Given back at shutdown, its lease expires now so another
            // replica resumes it at once; a lost lease is already someone
            // else's, and this changes nothing for it.
            if shutdown.is_cancelled() {
                if let Err(error) = self.store.release(&lease).await {
                    tracing::warn!(error = %error, "policy replay job could not be given back; its lease lapses instead");
                }
            }
            return;
        }
        let scanned = i64::try_from(control.scanned()).unwrap_or(i64::MAX);
        self.end(audit, &envelope, &lease, scanned, started, stop)
            .await;
    }

    /// Renew `lease` until aborted. A lost lease releases the run; a
    /// requested cancellation stops it before its next record.
    fn spawn_renewer(
        &self,
        lease: &PolicyReplayLease,
        control: &Arc<ReplayControl>,
    ) -> tokio::task::JoinHandle<()> {
        let store = self.store.clone();
        let lease = lease.clone();
        let control = Arc::clone(control);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(CLUSTER_REPLAY_RENEW_INTERVAL).await;
                match store.renew(&lease).await {
                    Ok(PolicyReplayLeaseStatus::Held { cancel_requested }) => {
                        if cancel_requested {
                            control.cancel();
                        }
                    }
                    Ok(PolicyReplayLeaseStatus::Lost) => {
                        control.release();
                        return;
                    }
                    // The next checkpoint is the guard: it stores nothing
                    // under a lease that is no longer held.
                    Err(error) => {
                        tracing::warn!(error = %error, "policy replay lease renewal failed");
                    }
                }
            }
        })
    }

    /// Publish a run's result: recorded first, then stored under the lease.
    async fn publish(
        &self,
        audit: &audit::AuditLog,
        envelope: &ReplayEnvelope,
        lease: &PolicyReplayLease,
        scope: &ReplayScope,
        started: Instant,
        outcome: ReplayOutcome,
    ) {
        let scanned = i64::try_from(outcome.scanned).unwrap_or(i64::MAX);
        let document = match serde_json::to_string(&outcome.result) {
            Ok(document) if document.len() <= MAX_POLICY_REPLAY_RESULT_BYTES => document,
            _ => {
                self.end(
                    audit,
                    envelope,
                    lease,
                    scanned,
                    started,
                    ReplayStop::Failed("result_too_large"),
                )
                .await;
                return;
            }
        };
        let state = if outcome.complete {
            ReplayJobState::Completed
        } else {
            ReplayJobState::CompletedIncomplete
        };
        // The result is published only once its completion is on the record.
        let recorded = envelope
            .record(
                audit,
                audit::event::POLICY_REPLAY_COMPLETED,
                completed_payload(
                    &lease.job_id,
                    state,
                    &outcome,
                    scope,
                    duration_millis(started.elapsed()),
                ),
            )
            .await;
        let ending = match recorded {
            Ok(()) => PolicyReplayEnding {
                state: state.as_str(),
                failure: None,
                scanned_records: scanned,
                result: Some((document, outcome.digest)),
            },
            Err(error) => {
                tracing::error!(error = %error, "policy replay job's completion was not recorded; its result is withheld");
                PolicyReplayEnding {
                    state: ReplayJobState::Failed.as_str(),
                    failure: Some("audit_unavailable"),
                    scanned_records: scanned,
                    result: None,
                }
            }
        };
        self.store_ending(lease, &ending).await;
    }

    /// End a job without a result, recording why. The ending is stored
    /// whether or not the event is accepted, as a standalone job's state is
    /// set: a job without a result has nothing to withhold.
    async fn end(
        &self,
        audit: &audit::AuditLog,
        envelope: &ReplayEnvelope,
        lease: &PolicyReplayLease,
        scanned: i64,
        started: Instant,
        stop: ReplayStop,
    ) {
        let duration_ms = duration_millis(started.elapsed());
        let (ending, event_type, payload) = match stop {
            ReplayStop::Cancelled => (
                PolicyReplayEnding {
                    state: ReplayJobState::Cancelled.as_str(),
                    failure: None,
                    scanned_records: scanned,
                    result: None,
                },
                audit::event::POLICY_REPLAY_CANCELLED,
                json!({
                    "job_id": lease.job_id,
                    "scanned_records": scanned,
                    "duration_ms": duration_ms,
                }),
            ),
            ReplayStop::Failed(reason)
                if interrupts(reason)
                    || matches!(reason, "takeover_limit" | "engine_version_changed") =>
            {
                (
                    PolicyReplayEnding {
                        state: ReplayJobState::Interrupted.as_str(),
                        failure: Some(reason),
                        scanned_records: scanned,
                        result: None,
                    },
                    audit::event::POLICY_REPLAY_INTERRUPTED,
                    json!({
                        "job_id": lease.job_id,
                        "reason": reason,
                        "scanned_records": scanned,
                    }),
                )
            }
            ReplayStop::Failed(reason) => (
                PolicyReplayEnding {
                    state: ReplayJobState::Failed.as_str(),
                    failure: Some(reason),
                    scanned_records: scanned,
                    result: None,
                },
                audit::event::POLICY_REPLAY_FAILED,
                json!({
                    "job_id": lease.job_id,
                    "reason": reason,
                    "scanned_records": scanned,
                    "duration_ms": duration_ms,
                }),
            ),
            // A released run ends nothing; its caller gives the job back.
            ReplayStop::Released => return,
        };
        if let Err(error) = envelope.record(audit, event_type, payload).await {
            tracing::error!(error = %error, "policy replay job's terminal audit event was not recorded");
        }
        self.store_ending(lease, &ending).await;
    }

    async fn store_ending(&self, lease: &PolicyReplayLease, ending: &PolicyReplayEnding) {
        match self.store.finish(lease, ending).await {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                "policy replay job's lease was lost before its ending was stored; the replica holding it now ends it"
            ),
            Err(error) => tracing::error!(
                error = %error,
                "policy replay job's ending could not be stored; its lease lapses and another replica resumes it"
            ),
        }
    }
}

#[cfg(test)]
impl ClusterPolicyReplays {
    /// The store, so a test can drive claims as another replica.
    pub(crate) fn store(&self) -> &PostgresPolicyReplayStore {
        &self.store
    }

    /// Claim and run the oldest job no live lease holds, as this replica's
    /// worker would, and report whether there was one.
    pub(crate) async fn run_one(&self, audit: &audit::AuditLog) -> bool {
        let shutdown = CancellationToken::new();
        match self.store.claim(REPLAY_RUN_DEADLINE).await {
            Ok(Some(claim)) => {
                self.run_claimed(claim, &shutdown, audit).await;
                true
            }
            Ok(None) => false,
            Err(error) => panic!("the test claim failed: {error}"),
        }
    }
}

#[cfg(test)]
#[path = "admin_policy_replays_cluster_tests.rs"]
mod tests;
