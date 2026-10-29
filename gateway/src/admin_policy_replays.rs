//! `POST /v1{ADMIN_PREFIX}/policy/replays`, and `GET` and `DELETE
//! /v1{ADMIN_PREFIX}/policy/replays/{id}` (issue #243, slice 13): start, poll
//! and cancel a bounded historical replay job.
//!
//! A job decides one window of the standalone audit log again under a
//! candidate -- the active policy itself, position-aware edits over it, or an
//! inline document -- and under the active policy it was written against,
//! through the shared policy kernel, and compares the two with each other and
//! with what was recorded. The engine is [`policy_replay::job`] and the
//! comparison [`policy_replay::impact`]; this module owns the job's
//! admission, lifecycle and records.
//!
//! Every route needs `admin:policy:read`, `admin:policy:simulate` and
//! `admin:audit:read`, checked before a body is read or a job looked up, and
//! serves a job only to the principal that started it: anyone else gets the
//! same `404` as for a job that does not exist.
//!
//! ## Lifecycle
//!
//! `queued` -> `running` -> `completed`, `completed_incomplete`, `failed` or
//! `cancelled`. A job is admitted only once its `policy.replay_started` audit
//! event is accepted, and its result is published only once its
//! `policy.replay_completed` event is; a result whose completion cannot be
//! recorded is `failed`. A result stays the answer for the policies it was
//! pinned to; once the active policy is no longer its base, every read says
//! it is `stale` for the live one. A finished job keeps its result for
//! [`POLICY_REPLAY_RESULT_TTL`], then reads `expired` with no result, and is
//! forgotten [`POLICY_REPLAY_EXPIRED_RETENTION`] later. `DELETE` cancels a job
//! that has not finished and discards one that has.
//!
//! ## Bounds
//!
//! A job is admitted as a policy test run or a simulation is: only once its
//! body is in hand, read under [`POLICY_REPLAY_BODY_DEADLINE`], and only
//! with a slot of the shared [`PolicyEvaluationLimiter`] -- at most
//! [`MAX_PENDING_POLICY_REPLAYS`] per replica and one per actor -- that the
//! replay route holds for itself. The job owns that slot from admission until
//! its evaluation ends, queued or running, and hands it to the blocking
//! thread that evaluates, so neither a dropped request nor a cancelled job
//! frees it while work continues. One job runs at a time per replica, on a
//! blocking thread over its own read-only connection to the audit log, and at
//! most [`MAX_RETAINED_POLICY_REPLAYS`] finished results are held
//! ([`MAX_RETAINED_POLICY_REPLAYS_PER_ACTOR`] per principal). Over any bound
//! is `429`; no job is ever evicted to make room for another.
//!
//! ## Standalone, and process-local
//!
//! Jobs live in this replica's memory. Shutting the application down cancels
//! them, and a restart forgets them: a job id from before it is `404`, never
//! resumed, and never a partial result. Cluster mode
//! answers every route `503 policy_replay_unsupported_in_cluster`, because a
//! replicated job needs the durable leases of #241, and a replica-local job
//! would read one replica's view of a shared audit authority.
use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError},
};

use super::*;

use policy_replay::{
    impact::ReplayPolicies,
    job::{
        ReplayControl, ReplayScope, ReplayStop, MAX_REPLAY_PAGE_BYTES, MAX_REPLAY_RECORD_BYTES,
        REPLAY_PAGE_RECORDS, REPLAY_RUN_DEADLINE,
    },
    request::{parse_request, resolve_window, ReplayRequest},
};
use policy_simulation::{request::CandidateSource, Projection};

/// Most replay jobs queued or running at once across this replica: the
/// bound of the replay route's [`PolicyEvaluationLimiter`], which also holds
/// each actor to one.
pub(super) const MAX_PENDING_POLICY_REPLAYS: usize = 4;
/// Replay jobs running at once across this replica: one, so a job never
/// competes with another for the audit log or a blocking thread.
const MAX_RUNNING_POLICY_REPLAYS: usize = 1;
/// Most jobs this replica holds that have not expired, finished or not.
pub(super) const MAX_RETAINED_POLICY_REPLAYS: usize = 32;
/// Most of those one principal holds.
pub(super) const MAX_RETAINED_POLICY_REPLAYS_PER_ACTOR: usize = 8;
/// How long a finished job keeps its result.
pub(super) const POLICY_REPLAY_RESULT_TTL: Duration = Duration::from_secs(15 * 60);
/// How long an expired job still answers `expired` before it is forgotten.
pub(super) const POLICY_REPLAY_EXPIRED_RETENTION: Duration = Duration::from_secs(60 * 60);
/// Largest replay request body, in bytes: room for a complete inline
/// candidate at the policy compiler's 1 MiB bound.
pub(super) const MAX_POLICY_REPLAY_BODY_BYTES: usize = 2 * 1024 * 1024;
/// How long a replay request's body may take to arrive. A job is admitted
/// only once its body is in hand, so a trickled upload holds no slot; this
/// also stops it holding the request open indefinitely.
pub(super) const POLICY_REPLAY_BODY_DEADLINE: Duration = Duration::from_secs(5);
/// Largest rendered result, in bytes. Results are counts keyed by stable
/// codes, with capped impact rows, and stay below it; one over it is a failed
/// job, never a cut one.
pub(super) const MAX_POLICY_REPLAY_RESULT_BYTES: usize = 512 * 1024;
/// The schema of a job's representation.
pub(super) const POLICY_REPLAY_JOB_SCHEMA_VERSION: &str = "policy-replay-job.v1";
const POLICY_REPLAY_JOB_ID_PREFIX: &str = "rpl_";
const POLICY_REPLAY_JOB_ID_HEX_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayJobState {
    Queued,
    Running,
    Completed,
    CompletedIncomplete,
    Failed,
    Cancelled,
    Expired,
}

impl ReplayJobState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::CompletedIncomplete => "completed_incomplete",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    fn is_pending(self) -> bool {
        matches!(self, Self::Queued | Self::Running)
    }
}

/// A finished job's result: the `policy-replay-results.v1` document and its
/// semantic digest.
struct ReplayJobResult {
    document: Value,
    digest: String,
}

/// What changes over a job's life. Guarded by the job's own lock, which is
/// never held across an `.await` and never taken before the registry's.
struct ReplayJobRecord {
    state: ReplayJobState,
    failure: Option<&'static str>,
    cancel_requested: bool,
    started_at: Option<OffsetDateTime>,
    finished: Option<(Instant, OffsetDateTime)>,
    result: Option<Arc<ReplayJobResult>>,
}

/// The policies a job was pinned to when it was admitted, and the
/// projections it compares them under.
struct ReplayJobBinding {
    base_etag: String,
    candidate_source: &'static str,
    candidate_etag: String,
    edit_count: usize,
    projections: Vec<Projection>,
}

impl ReplayJobBinding {
    fn projection_names(&self) -> Vec<&'static str> {
        self.projections
            .iter()
            .map(|projection| projection.as_str())
            .collect()
    }
}

struct ReplayJob {
    id: String,
    owner: String,
    idempotency_key: Option<String>,
    request_digest: String,
    created_at: OffsetDateTime,
    /// The admitting request's envelope, which every lifecycle event of the
    /// job carries.
    actor: audit::Actor,
    request_id: String,
    source_ip: String,
    binding: ReplayJobBinding,
    scope: ReplayScope,
    control: Arc<ReplayControl>,
    /// Wakes a queued job's worker when the job is cancelled.
    cancel_signal: tokio::sync::Notify,
    record: Mutex<ReplayJobRecord>,
}

impl ReplayJob {
    fn record(&self) -> MutexGuard<'_, ReplayJobRecord> {
        // Every write to the record is a whole-field assignment, so a panic
        // while it was held cannot leave it half-updated.
        self.record.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Why a job was not admitted.
enum ReplayAdmission {
    Admitted,
    /// The principal already started a job with this idempotency key and
    /// this exact request.
    Existing(Arc<ReplayJob>),
    /// The principal's key names a job started by a different request.
    IdempotencyConflict,
    /// The replica, or this principal, holds as many unexpired jobs as it may.
    QuotaExhausted,
}

/// The replay jobs of one router. Shared by the routes that start, poll and
/// cancel them.
pub(super) struct PolicyReplayJobs {
    jobs: Mutex<HashMap<String, Arc<ReplayJob>>>,
    /// Admission: the replay route's own bound on jobs queued or running,
    /// per replica and per actor, so replays never take a simulation's or a
    /// test run's slots, nor they a replay's.
    admission: Arc<PolicyEvaluationLimiter>,
    /// Which admitted job runs: one at a time, in turn.
    run_permits: Arc<tokio::sync::Semaphore>,
}

impl PolicyReplayJobs {
    pub(super) fn new() -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            admission: Arc::new(PolicyEvaluationLimiter::new(MAX_PENDING_POLICY_REPLAYS)),
            run_permits: Arc::new(tokio::sync::Semaphore::new(MAX_RUNNING_POLICY_REPLAYS)),
        }
    }

    /// The registry, swept: results past their TTL dropped, expired jobs past
    /// their retention forgotten. Bounded work: the map never holds more than
    /// twice [`MAX_RETAINED_POLICY_REPLAYS`] jobs.
    fn swept(&self, now: Instant) -> MutexGuard<'_, HashMap<String, Arc<ReplayJob>>> {
        // The map holds owned entries only; a panic while it was held cannot
        // leave it half-updated, so a poisoned lock is still a sound map.
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        let mut expired = Vec::new();
        jobs.retain(|_, job| {
            let mut record = job.record();
            let Some((finished, _)) = record.finished else {
                return true;
            };
            let age = now.saturating_duration_since(finished);
            if age >= POLICY_REPLAY_RESULT_TTL + POLICY_REPLAY_EXPIRED_RETENTION {
                return false;
            }
            if age >= POLICY_REPLAY_RESULT_TTL {
                record.state = ReplayJobState::Expired;
                record.result = None;
                expired.push((finished, job.id.clone()));
            }
            true
        });
        if expired.len() > MAX_RETAINED_POLICY_REPLAYS {
            expired.sort();
            for (_, id) in expired
                .iter()
                .take(expired.len() - MAX_RETAINED_POLICY_REPLAYS)
            {
                jobs.remove(id);
            }
        }
        jobs
    }

    fn find(&self, owner: &str, id: &str) -> Option<Arc<ReplayJob>> {
        self.swept(Instant::now())
            .get(id)
            .filter(|job| job.owner == owner)
            .cloned()
    }

    fn find_idempotent(&self, owner: &str, key: &str) -> Option<Arc<ReplayJob>> {
        self.swept(Instant::now())
            .values()
            .find(|job| job.owner == owner && job.idempotency_key.as_deref() == Some(key))
            .cloned()
    }

    /// Admit `job`, or say why not, in one critical section, so two
    /// concurrent requests can neither both pass a quota nor both claim one
    /// idempotency key.
    fn admit(&self, job: &Arc<ReplayJob>) -> ReplayAdmission {
        let mut jobs = self.swept(Instant::now());
        if let Some(key) = job.idempotency_key.as_deref() {
            if let Some(existing) = jobs.values().find(|other| {
                other.owner == job.owner && other.idempotency_key.as_deref() == Some(key)
            }) {
                return if existing.request_digest == job.request_digest {
                    ReplayAdmission::Existing(Arc::clone(existing))
                } else {
                    ReplayAdmission::IdempotencyConflict
                };
            }
        }
        if let Some(refusal) = Self::over_quota(&jobs, &job.owner) {
            return refusal;
        }
        jobs.insert(job.id.clone(), Arc::clone(job));
        ReplayAdmission::Admitted
    }

    /// Whether `owner` may hold another job now, or
    /// [`ReplayAdmission::QuotaExhausted`]. How many may be pending is the
    /// admission slot's bound, taken before this is asked.
    fn over_quota(jobs: &HashMap<String, Arc<ReplayJob>>, owner: &str) -> Option<ReplayAdmission> {
        let mut retained = 0;
        let mut owner_retained = 0;
        for other in jobs.values() {
            if other.record().state != ReplayJobState::Expired {
                retained += 1;
                owner_retained += usize::from(other.owner == owner);
            }
        }
        if retained >= MAX_RETAINED_POLICY_REPLAYS
            || owner_retained >= MAX_RETAINED_POLICY_REPLAYS_PER_ACTOR
        {
            return Some(ReplayAdmission::QuotaExhausted);
        }
        None
    }

    /// The quota check alone, before a request does the work of fixing a
    /// cutoff: a caller over its quota costs no read of the audit log.
    /// [`Self::admit`] checks again, atomically with the insertion.
    fn precheck(&self, owner: &str) -> Option<ReplayAdmission> {
        Self::over_quota(&self.swept(Instant::now()), owner)
    }

    fn remove(&self, id: &str) {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
    }
}

/// A finished replay job as a policy evidence package records it.
pub(super) struct ReplayJobEvidence {
    /// The ETag of the candidate the job replayed, which evidence binds to
    /// the publication it is about.
    pub(super) candidate_etag: String,
    /// The ETag of the active policy the job compared the candidate with.
    pub(super) base_etag: String,
    /// Whether the result is complete (`completed`, not
    /// `completed_incomplete`).
    pub(super) complete: bool,
    /// The job's section of an evidence report: its bindings, window,
    /// cutoff, limits and result, counts only.
    pub(super) view: Value,
}

/// Why a job cannot be part of an evidence package.
pub(super) enum ReplayJobEvidenceRefusal {
    /// No job of this principal's has the id, as for any replay route.
    NotFound,
    /// The job holds no result: it is pending, failed, cancelled or expired,
    /// named by its state.
    Unfinished(&'static str),
}

impl PolicyReplayJobs {
    /// The result of `principal`'s job `id`, for an evidence package. Served
    /// exactly as `GET .../policy/replays/{id}` serves a job: only to the
    /// principal that started it, and only while its result is retained.
    pub(super) fn evidence(
        &self,
        principal: &auth::Principal,
        id: &str,
    ) -> Result<ReplayJobEvidence, ReplayJobEvidenceRefusal> {
        if !is_policy_replay_job_id(id) {
            return Err(ReplayJobEvidenceRefusal::NotFound);
        }
        let Some(job) = self.find(&replay_owner(principal), id) else {
            return Err(ReplayJobEvidenceRefusal::NotFound);
        };
        let record = job.record();
        let complete = match record.state {
            ReplayJobState::Completed => true,
            ReplayJobState::CompletedIncomplete => false,
            state => return Err(ReplayJobEvidenceRefusal::Unfinished(state.as_str())),
        };
        let Some(result) = record.result.as_ref() else {
            return Err(ReplayJobEvidenceRefusal::Unfinished(record.state.as_str()));
        };
        let mut candidate = json!({
            "source": job.binding.candidate_source,
            "etag": job.binding.candidate_etag,
        });
        if job.binding.candidate_source == "edits" {
            if let Some(candidate) = candidate.as_object_mut() {
                candidate.insert("edits".to_owned(), json!(job.binding.edit_count));
            }
        }
        // The job id is left out: it names a process-local job its owner
        // can poll, and the result digest already ties the section to the
        // job's `policy.replay_completed` record.
        let view = json!({
            "included": true,
            "mode": "historical_replay",
            "state": record.state.as_str(),
            "request_digest": job.request_digest,
            "evaluator": {
                "http_semantics_version": policy_eval::HTTP_SEMANTICS_VERSION,
                "http_context_version": policy_eval::CONTEXT_VERSION,
                "tool_semantics_version": policy_eval::tools::TOOL_SEMANTICS_VERSION,
                "tool_context_version": policy_eval::tools::TOOL_CONTEXT_VERSION,
                "replay_context_version": policy_replay::REPLAY_CONTEXT_SCHEMA_VERSION,
            },
            "base": { "source": "active", "etag": job.binding.base_etag },
            "candidate": candidate,
            "projections": job.binding.projection_names(),
            "window": { "from": job.scope.from, "to": job.scope.to },
            "cutoff": {
                "high_water": job.scope.cutoff.high_water,
                "selected_records": job.scope.cutoff.selected,
            },
            "limits": {
                "max_records": job.scope.max_records,
                "deadline_ms": duration_millis(REPLAY_RUN_DEADLINE),
                "page_records": REPLAY_PAGE_RECORDS,
                "max_page_bytes": MAX_REPLAY_PAGE_BYTES,
                "max_record_bytes": MAX_REPLAY_RECORD_BYTES,
            },
            "not_replayed": policy_replay::job::NOT_REPLAYED,
            "result_digest": result.digest,
            "result": result.document,
        });
        Ok(ReplayJobEvidence {
            candidate_etag: job.binding.candidate_etag.clone(),
            base_etag: job.binding.base_etag.clone(),
            complete,
            view,
        })
    }
}

/// The application is going away: cancel every job, so a running one stops
/// before its next record instead of holding a blocking thread through
/// shutdown. Workers hold the run slot's semaphore, never the registry, so
/// the registry is dropped with the router that owns it.
impl Drop for PolicyReplayJobs {
    fn drop(&mut self) {
        let jobs = self.jobs.get_mut().unwrap_or_else(PoisonError::into_inner);
        for job in jobs.values() {
            job.control.cancel();
            job.cancel_signal.notify_one();
        }
    }
}

#[cfg(test)]
impl PolicyReplayJobs {
    /// The replay route's admission limiter, so a test can see which slots
    /// jobs and requests hold.
    pub(super) fn admission(&self) -> &Arc<PolicyEvaluationLimiter> {
        &self.admission
    }

    /// Hold this replica's run slot, so a job admitted meanwhile stays
    /// queued until the permit drops.
    pub(super) fn occupy_run_slot(&self) -> tokio::sync::OwnedSemaphorePermit {
        Arc::clone(&self.run_permits)
            .try_acquire_owned()
            .expect("the run slot is free")
    }

    /// Sweep the registry as it would be swept `elapsed` from now.
    pub(super) fn sweep_after(&self, elapsed: Duration) {
        drop(self.swept(Instant::now() + elapsed));
    }

    /// Jobs the registry holds, pending, finished or expired. Only the
    /// cluster-mode refusal test, which needs a control plane, asks.
    #[cfg(feature = "postgres")]
    pub(super) fn job_count(&self) -> usize {
        self.swept(Instant::now()).len()
    }
}

fn replay_refusal(status: StatusCode, error: &str, reason: &'static str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "reason": reason,
        })),
    )
        .into_response()
}

fn replay_invalid(diagnostics: &policy_testing::suite::Diagnostics) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "policy replay request is invalid",
            "reason": "policy_replay_invalid",
            "diagnostics": diagnostics.diagnostics,
            "diagnostics_truncated": diagnostics.truncated,
        })),
    )
        .into_response()
}

fn replay_job_not_found() -> Response {
    replay_refusal(
        StatusCode::NOT_FOUND,
        "policy replay job was not found",
        "policy_replay_job_not_found",
    )
}

/// The identity a job belongs to: the canonical issuer authentication
/// established (empty when there is none) and the subject, so two
/// credentials for one subject share one job quota.
fn replay_owner(principal: &auth::Principal) -> String {
    let issuer = principal
        .issuer
        .as_deref()
        .and_then(auth::principal::canonical_issuer)
        .unwrap_or_default();
    format!("{issuer}\u{0}{}", principal.user_id)
}

/// A fresh job identifier from operating-system randomness, or `None` when
/// the operating system cannot supply it. Never a fallback generator.
fn new_policy_replay_job_id() -> Option<String> {
    let mut random = [0_u8; POLICY_REPLAY_JOB_ID_HEX_LEN / 2];
    getrandom::fill(&mut random).ok()?;
    Some(format!(
        "{POLICY_REPLAY_JOB_ID_PREFIX}{}",
        hex::encode(random)
    ))
}

fn is_policy_replay_job_id(value: &str) -> bool {
    value
        .strip_prefix(POLICY_REPLAY_JOB_ID_PREFIX)
        .is_some_and(|hex| {
            hex.len() == POLICY_REPLAY_JOB_ID_HEX_LEN
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn rfc3339(time: Option<OffsetDateTime>) -> Value {
    time.and_then(|time| time.format(&Rfc3339).ok())
        .map_or(Value::Null, Value::String)
}

/// The three permissions every replay route needs, and standalone mode.
/// Checked before a body is read or a job looked up, so an unauthorized
/// caller learns nothing about any job.
fn authorized_replay_state<'a>(
    state: &'a PolicyAdminState,
    principal: &auth::Principal,
) -> ResponseResult<&'a middleware::rbac::RbacState> {
    let rbac_state = authorized_policy_state(state, principal, ADMIN_POLICY_READ_PERMISSION)
        .map_err(|error| Box::new(policy_admin_authz_error_response(error)))?;
    for permission in [
        ADMIN_POLICY_SIMULATE_PERMISSION,
        ADMIN_AUDIT_READ_PERMISSION,
    ] {
        if !rbac_state.principal_has_permission(principal, permission) {
            return Err(Box::new(admin_permission_denied_response(
                permission.to_owned(),
            )));
        }
    }
    #[cfg(feature = "postgres")]
    if state.control_plane.is_some() {
        return Err(Box::new(replay_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "historical policy replay is not available in cluster mode",
            "policy_replay_unsupported_in_cluster",
        )));
    }
    Ok(rbac_state)
}

/// Whether a job's result describes the live policy. A result is immutable
/// and stays the answer for the policies it was pinned to; once the active
/// policy is no longer its base it is `stale` for the live one, and must not
/// be reused as evidence about it. `unknown` when this read did not check.
fn freshness_view(base_current: Option<bool>) -> Value {
    match base_current {
        Some(true) => json!({ "state": "current" }),
        Some(false) => json!({ "state": "stale", "reason": "base_changed" }),
        None => json!({ "state": "unknown" }),
    }
}

fn job_view(job: &ReplayJob, base_current: Option<bool>) -> Value {
    let record = job.record();
    let mut base = json!({ "source": "active", "etag": job.binding.base_etag });
    if let (Some(current), Some(base)) = (base_current, base.as_object_mut()) {
        base.insert("current".to_owned(), json!(current));
    }
    let mut candidate = json!({
        "source": job.binding.candidate_source,
        "etag": job.binding.candidate_etag,
    });
    if job.binding.candidate_source == "edits" {
        if let Some(candidate) = candidate.as_object_mut() {
            candidate.insert("edits".to_owned(), json!(job.binding.edit_count));
        }
    }
    let expires_at = record.finished.and_then(|(_, finished)| {
        time::Duration::try_from(POLICY_REPLAY_RESULT_TTL)
            .ok()
            .and_then(|ttl| finished.checked_add(ttl))
    });
    let mut view = json!({
        "schema_version": POLICY_REPLAY_JOB_SCHEMA_VERSION,
        "job_id": job.id,
        "state": record.state.as_str(),
        "cancel_requested": record.cancel_requested,
        "created_at": rfc3339(Some(job.created_at)),
        "started_at": rfc3339(record.started_at),
        "finished_at": rfc3339(record.finished.map(|(_, finished)| finished)),
        "result_expires_at": rfc3339(expires_at),
        "request_digest": job.request_digest,
        "evaluator": {
            "http_semantics_version": policy_eval::HTTP_SEMANTICS_VERSION,
            "http_context_version": policy_eval::CONTEXT_VERSION,
            "tool_semantics_version": policy_eval::tools::TOOL_SEMANTICS_VERSION,
            "tool_context_version": policy_eval::tools::TOOL_CONTEXT_VERSION,
            "replay_context_version": policy_replay::REPLAY_CONTEXT_SCHEMA_VERSION,
            "gateway_version": env!("CARGO_PKG_VERSION"),
        },
        "base": base,
        "candidate": candidate,
        "freshness": freshness_view(base_current),
        "projections": job.binding.projection_names(),
        "window": { "from": job.scope.from, "to": job.scope.to },
        "cutoff": {
            "high_water": job.scope.cutoff.high_water,
            "selected_records": job.scope.cutoff.selected,
        },
        "limits": {
            "max_records": job.scope.max_records,
            "deadline_ms": duration_millis(REPLAY_RUN_DEADLINE),
            "page_records": REPLAY_PAGE_RECORDS,
            "max_page_bytes": MAX_REPLAY_PAGE_BYTES,
            "max_record_bytes": MAX_REPLAY_RECORD_BYTES,
        },
        "progress": {
            "scanned_records": job.control.scanned(),
            "selected_records": job.scope.cutoff.selected,
        },
    });
    if let Some(view) = view.as_object_mut() {
        if let Some(failure) = record.failure {
            view.insert("failure".to_owned(), json!({ "reason": failure }));
        }
        if let Some(result) = &record.result {
            view.insert("result_digest".to_owned(), json!(result.digest));
            view.insert("result".to_owned(), result.document.clone());
        }
    }
    view
}

fn job_response(status: StatusCode, job: &ReplayJob, base_current: Option<bool>) -> Response {
    let mut response = (status, Json(job_view(job, base_current))).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn lifecycle_event(job: &ReplayJob, event_type: &str, payload: Value) -> audit::AuditEvent {
    audit::AuditEvent::new(
        event_type,
        job.request_id.clone(),
        job.source_ip.clone(),
        Some(job.actor.clone()),
        payload,
    )
}

/// Record a lifecycle event and wait until the audit authority accepts it.
async fn record_lifecycle(
    audit: &audit::AuditLog,
    job: &ReplayJob,
    event_type: &str,
    payload: Value,
) -> Result<(), audit::AuditUnavailable> {
    let receipt = audit.record(lifecycle_event(job, event_type, payload));
    audit.confirm(receipt).await
}

fn started_payload(job: &ReplayJob) -> Value {
    json!({
        "job_id": job.id,
        "request_digest": job.request_digest,
        "base_etag": job.binding.base_etag,
        "candidate_source": job.binding.candidate_source,
        "candidate_etag": job.binding.candidate_etag,
        "edits": job.binding.edit_count,
        "projections": job.binding.projection_names(),
        "window_from": job.scope.from,
        "window_to": job.scope.to,
        "high_water": job.scope.cutoff.high_water,
        "selected_records": job.scope.cutoff.selected,
        "max_records": job.scope.max_records,
        "http_semantics_version": policy_eval::HTTP_SEMANTICS_VERSION,
        "tool_semantics_version": policy_eval::tools::TOOL_SEMANTICS_VERSION,
    })
}

/// Finish a job without a result, recording why. The state is set whether or
/// not the event is accepted: a job without a result has nothing to withhold.
async fn finish_without_result(
    audit: &audit::AuditLog,
    job: &ReplayJob,
    started: Instant,
    stop: ReplayStop,
) {
    let scanned = job.control.scanned();
    let duration_ms = duration_millis(started.elapsed());
    let (state, failure, recorded) = match stop {
        ReplayStop::Cancelled => (
            ReplayJobState::Cancelled,
            None,
            record_lifecycle(
                audit,
                job,
                audit::event::POLICY_REPLAY_CANCELLED,
                json!({
                    "job_id": job.id,
                    "scanned_records": scanned,
                    "duration_ms": duration_ms,
                }),
            )
            .await,
        ),
        ReplayStop::Failed(reason) => (
            ReplayJobState::Failed,
            Some(reason),
            record_lifecycle(
                audit,
                job,
                audit::event::POLICY_REPLAY_FAILED,
                json!({
                    "job_id": job.id,
                    "reason": reason,
                    "scanned_records": scanned,
                    "duration_ms": duration_ms,
                }),
            )
            .await,
        ),
    };
    if let Err(error) = recorded {
        tracing::error!(error = %error, "policy replay job's terminal audit event was not recorded");
    }
    let mut record = job.record();
    record.state = state;
    record.failure = failure;
    record.finished = Some((Instant::now(), OffsetDateTime::now_utc()));
}

/// The job's worker: wait for the replica's run slot, run the engine on a
/// blocking thread over a read-only connection, and publish what it found.
///
/// `slot` is the job's admission slot. The worker holds it while the job is
/// queued and hands it, with the run permit, to the blocking thread, so both
/// come back only once the evaluation has ended -- and before the job reads
/// as finished, so a caller who sees it finished may start another.
///
/// `base` is the active policy the job was pinned to and `candidate` the
/// policy it compares with it, `None` when the candidate is the base itself.
/// Both are compiled on the blocking thread, under every projection the job
/// asked for.
async fn run_replay_job(
    run_permits: Arc<tokio::sync::Semaphore>,
    job: Arc<ReplayJob>,
    slot: PolicyEvaluationSlot,
    base: rbac::Policy,
    candidate: Option<rbac::Policy>,
    source_path: PathBuf,
    audit: audit::AuditLog,
) {
    let started = Instant::now();
    let permit = tokio::select! {
        biased;
        () = job.cancel_signal.notified() => None,
        permit = run_permits.acquire_owned() => permit.ok(),
    };
    let Some(permit) = permit.filter(|_| !job.control.is_cancelled()) else {
        drop(slot);
        finish_without_result(&audit, &job, started, ReplayStop::Cancelled).await;
        return;
    };
    {
        let mut record = job.record();
        record.state = ReplayJobState::Running;
        record.started_at = Some(OffsetDateTime::now_utc());
    }
    let scope = job.scope.clone();
    let projections = job.binding.projections.clone();
    let control = Arc::clone(&job.control);
    let run = slot
        .run_blocking(move || {
            // The evaluation owns the run permit as it owns the admission
            // slot: the next job starts only once this one has stopped.
            let _permit = permit;
            let source =
                audit::query::AuditQueryStore::open_read_only(source_path).map_err(|error| {
                    tracing::error!(error = %error, "policy replay could not open the audit log");
                    ReplayStop::Failed("source_unavailable")
                })?;
            let policies = ReplayPolicies::compile(&base, candidate.as_ref(), &projections)
                .map_err(|error| {
                    tracing::error!(error = ?error, "policy replay policies could not be compiled");
                    ReplayStop::Failed("compile_failed")
                })?;
            let deadline = Instant::now() + REPLAY_RUN_DEADLINE;
            policy_replay::job::run(&source, &policies, &scope, deadline, &control)
        })
        .await;
    let outcome = match run {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(stop)) => {
            finish_without_result(&audit, &job, started, stop).await;
            return;
        }
        Err(error) => {
            tracing::error!(error = %error, "policy replay job did not complete");
            finish_without_result(&audit, &job, started, ReplayStop::Failed("internal")).await;
            return;
        }
    };
    let rendered = serde_json::to_vec(&outcome.result).map_or(usize::MAX, |bytes| bytes.len());
    if rendered > MAX_POLICY_REPLAY_RESULT_BYTES {
        finish_without_result(
            &audit,
            &job,
            started,
            ReplayStop::Failed("result_too_large"),
        )
        .await;
        return;
    }
    let state = if outcome.complete {
        ReplayJobState::Completed
    } else {
        ReplayJobState::CompletedIncomplete
    };
    let records = &outcome.result["records"];
    // The result is published only once its completion is on the record.
    let recorded = record_lifecycle(
        &audit,
        &job,
        audit::event::POLICY_REPLAY_COMPLETED,
        json!({
            "job_id": job.id,
            "state": state.as_str(),
            "complete": outcome.complete,
            "limitations": outcome.limitations,
            "result_digest": outcome.digest,
            "selected_records": job.scope.cutoff.selected,
            "scanned_records": outcome.scanned,
            "replayable_records": records["replayable"],
            "replayed_records": outcome.replayed,
            "impact": outcome.impact,
            "duration_ms": duration_millis(started.elapsed()),
        }),
    )
    .await;
    if let Err(error) = recorded {
        tracing::error!(error = %error, "policy replay job's completion was not recorded; its result is withheld");
        let mut record = job.record();
        record.state = ReplayJobState::Failed;
        record.failure = Some("audit_unavailable");
        record.finished = Some((Instant::now(), OffsetDateTime::now_utc()));
        return;
    }
    let mut record = job.record();
    record.state = state;
    record.result = Some(Arc::new(ReplayJobResult {
        document: outcome.result,
        digest: outcome.digest,
    }));
    record.finished = Some((Instant::now(), OffsetDateTime::now_utc()));
}

/// `POST .../policy/replays`: validate a `policy-replay.v1` request, pin its
/// window's cutoff, and queue the job.
pub(super) async fn policy_replay_create_endpoint(
    State(state): State<PolicyAdminState>,
    Extension(jobs): Extension<Arc<PolicyReplayJobs>>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_REPLAYS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state = match authorized_replay_state(&state, &principal) {
        Ok(rbac_state) => rbac_state,
        Err(response) => return *response,
    };
    let Some(query_store) = state.query_store.as_ref() else {
        return policy_evidence_unavailable("policy replay requires an audit query store");
    };
    let body_limit = state.max_body_size.min(MAX_POLICY_REPLAY_BODY_BYTES);
    let body_deadline = tokio::time::Instant::now() + POLICY_REPLAY_BODY_DEADLINE;
    let body = match read_request_body_before(body, body_limit, body_deadline).await {
        Ok(body) => body,
        Err(TimedBodyReadError::Rejected(response)) => return *response,
        Err(TimedBodyReadError::DeadlineExceeded) => {
            return replay_refusal(
                StatusCode::REQUEST_TIMEOUT,
                "the policy replay body did not arrive within its deadline",
                "policy_replay_request_timeout",
            );
        }
    };
    // A repeated member is refused before anything reads the body: a JSON
    // value keeps the last of two and says nothing, so the request digested
    // and replayed could differ from the one a reviewer read.
    if !policy_eval::input::has_unique_members(&body) {
        return replay_refusal(
            StatusCode::BAD_REQUEST,
            "policy replay body must be JSON with unique object members",
            "policy_replay_request_invalid",
        );
    }
    let Ok(document) = serde_json::from_slice::<Value>(&body) else {
        return replay_refusal(
            StatusCode::BAD_REQUEST,
            "policy replay body must be JSON",
            "policy_replay_request_invalid",
        );
    };
    let replay: ReplayRequest = match parse_request(&body, &document) {
        Ok(replay) => replay,
        Err(diagnostics) => return replay_invalid(&diagnostics),
    };
    let owner = replay_owner(&principal);
    // A retry of a request already admitted is answered before any work: it
    // starts nothing, reads no audit record, and takes no slot -- the job it
    // names may still hold this actor's. It reads only the active policy's
    // ETag, to say whether that job's result is still current.
    if let Some(key) = replay.idempotency_key.as_deref() {
        if let Some(existing) = jobs.find_idempotent(&owner, key) {
            return if existing.request_digest == replay.digest {
                let current = base_is_current(&state, rbac_state, &existing).await;
                job_response(StatusCode::OK, &existing, current)
            } else {
                replay_idempotency_conflict()
            };
        }
    }
    // Admitted once the body is in hand, so a slot bounds jobs rather than
    // uploads in flight, and one actor holds at most one. A refusal from
    // here on, before the job is queued, gives the slot back.
    let Some(slot) = jobs
        .admission
        .try_acquire(policy_evaluation_actor(&principal))
    else {
        return replay_busy();
    };
    let created_at = OffsetDateTime::now_utc();
    let window = match resolve_window(&replay, created_at) {
        Ok(window) => window,
        Err(diagnostics) => return replay_invalid(&diagnostics),
    };

    let (base, base_etag, _) = match simulation_base(&state, rbac_state).await {
        Ok(base) => base,
        Err(response) => return *response,
    };
    // The pin is required and exact, as a simulation's is: a replay
    // describes the policy its author read, or nothing.
    if replay.base_etag != base_etag {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "error": "the active policy is no longer the one this replay was written against",
                "reason": "policy_replay_base_stale",
                "current_etag": base_etag,
            })),
        )
            .into_response();
    }
    let candidate = match resolve_candidate(&state, rbac_state, &base, &replay.candidate) {
        Ok(candidate) => candidate,
        Err(CandidateRefusal::Edits(diagnostics)) => return replay_invalid(&diagnostics),
        Err(CandidateRefusal::Invalid(errors)) => return simulation_candidate_refused(errors),
        Err(CandidateRefusal::Internal) => return internal_server_error("policy replay failed"),
    };
    let candidate_etag = match candidate.as_ref().map(policy_etag) {
        None => base_etag.clone(),
        Some(Ok(etag)) => etag,
        Some(Err(error)) => {
            tracing::error!(error = %error, "failed to compute candidate policy ETag");
            return internal_server_error("policy ETag computation failed");
        }
    };

    if let Some(refusal) = jobs.precheck(&owner).and_then(admission_refusal) {
        return refusal;
    }
    // The cutoff is fixed now, before the job is queued: whatever is written
    // to the log from here on, the job never reads it.
    let cutoff = match query_store
        .replay_cutoff(window.from_epoch_us, window.to_epoch_us)
        .await
    {
        Ok(cutoff) => cutoff,
        Err(error) => {
            tracing::error!(error = %error, "policy replay could not read its audit cutoff");
            return policy_evidence_unavailable("policy replay could not read the audit log");
        }
    };
    let Some(id) = new_policy_replay_job_id() else {
        tracing::error!("operating-system randomness is unavailable for a replay job id");
        return internal_server_error("policy replay job could not be created");
    };
    let edit_count = match &replay.candidate {
        CandidateSource::Edits(edits) => edits.len(),
        _ => 0,
    };
    let job = Arc::new(ReplayJob {
        id,
        owner,
        idempotency_key: replay.idempotency_key.clone(),
        request_digest: replay.digest.clone(),
        created_at,
        actor: auth::actor_from_principal(&principal),
        request_id: client_ip::request_id(&parts.headers, &parts.extensions),
        source_ip: client_ip::canonical_client_ip(
            &parts.headers,
            &parts.extensions,
            &state.client_ip_policy,
        ),
        binding: ReplayJobBinding {
            base_etag,
            candidate_source: replay.candidate.as_str(),
            candidate_etag,
            edit_count,
            projections: replay.projections.clone(),
        },
        scope: ReplayScope {
            from: window.from,
            to: window.to,
            from_epoch_us: window.from_epoch_us,
            to_epoch_us: window.to_epoch_us,
            cutoff,
            max_records: replay.max_records,
        },
        control: Arc::new(ReplayControl::default()),
        cancel_signal: tokio::sync::Notify::new(),
        record: Mutex::new(ReplayJobRecord {
            state: ReplayJobState::Queued,
            failure: None,
            cancel_requested: false,
            started_at: None,
            finished: None,
            result: None,
        }),
    });
    if let Some(refusal) = admission_refusal(jobs.admit(&job)) {
        return refusal;
    }
    // A job whose start is not on the record is never queued.
    if let Err(error) = record_lifecycle(
        &state.audit,
        &job,
        audit::event::POLICY_REPLAY_STARTED,
        started_payload(&job),
    )
    .await
    {
        tracing::error!(error = %error, "policy replay start was not recorded; the job is not queued");
        jobs.remove(&job.id);
        return replay_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "the policy replay could not be recorded; retry later",
            "policy_replay_audit_unavailable",
        );
    }
    let source_path = query_store.sqlite_query_store().path().to_path_buf();
    tokio::spawn(run_replay_job(
        Arc::clone(&jobs.run_permits),
        Arc::clone(&job),
        slot,
        base,
        candidate,
        source_path,
        state.audit.clone(),
    ));
    let mut response = job_response(StatusCode::ACCEPTED, &job, Some(true));
    if let Ok(location) = HeaderValue::from_str(&format!("{}/{}", parts.uri.path(), job.id)) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

/// The response for an admission that did not admit, or `None` when it did.
fn admission_refusal(admission: ReplayAdmission) -> Option<Response> {
    match admission {
        ReplayAdmission::Admitted => None,
        ReplayAdmission::Existing(existing) => Some(job_response(StatusCode::OK, &existing, None)),
        ReplayAdmission::IdempotencyConflict => Some(replay_idempotency_conflict()),
        ReplayAdmission::QuotaExhausted => Some(replay_refusal(
            StatusCode::TOO_MANY_REQUESTS,
            "too many policy replay results are held; delete finished jobs or wait for them to expire",
            "policy_replay_quota_exhausted",
        )),
    }
}

/// The replay route's admission slot was refused: a job of this actor's is
/// still pending, or the replica's queue is full.
fn replay_busy() -> Response {
    replay_refusal(
        StatusCode::TOO_MANY_REQUESTS,
        "a policy replay of yours is still running, or too many are queued; retry later",
        "policy_replay_busy",
    )
}

fn replay_idempotency_conflict() -> Response {
    replay_refusal(
        StatusCode::CONFLICT,
        "this idempotency key already names a different policy replay request",
        "policy_replay_idempotency_conflict",
    )
}

/// Whether the active policy is still the one `job` was pinned to: a result
/// stays the answer for its pinned policies, but is stale for the live one.
async fn base_is_current(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    job: &ReplayJob,
) -> Option<bool> {
    simulation_base(state, rbac_state)
        .await
        .ok()
        .map(|(_, etag, _)| etag == job.binding.base_etag)
}

/// `GET .../policy/replays/{id}`: the caller's job, its progress and, once
/// finished, its result.
pub(super) async fn policy_replay_get_endpoint(
    State(state): State<PolicyAdminState>,
    Extension(jobs): Extension<Arc<PolicyReplayJobs>>,
    Path(job_id): Path<String>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(POLICY_REPLAY_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let rbac_state = match authorized_replay_state(&state, &principal) {
        Ok(rbac_state) => rbac_state,
        Err(response) => return *response,
    };
    if !is_policy_replay_job_id(&job_id) {
        return replay_job_not_found();
    }
    let Some(job) = jobs.find(&replay_owner(&principal), &job_id) else {
        return replay_job_not_found();
    };
    let current = base_is_current(&state, rbac_state, &job).await;
    job_response(StatusCode::OK, &job, current)
}

/// `DELETE .../policy/replays/{id}`: cancel a job that has not finished
/// (`202`; it stops before its next record), or discard one that has
/// (`204`).
pub(super) async fn policy_replay_delete_endpoint(
    State(state): State<PolicyAdminState>,
    Extension(jobs): Extension<Arc<PolicyReplayJobs>>,
    Path(job_id): Path<String>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(POLICY_REPLAY_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(response) = authorized_replay_state(&state, &principal) {
        return *response;
    }
    if !is_policy_replay_job_id(&job_id) {
        return replay_job_not_found();
    }
    let Some(job) = jobs.find(&replay_owner(&principal), &job_id) else {
        return replay_job_not_found();
    };
    let pending = {
        let mut record = job.record();
        let pending = record.state.is_pending();
        if pending {
            record.cancel_requested = true;
        }
        pending
    };
    if !pending {
        jobs.remove(&job.id);
        return StatusCode::NO_CONTENT.into_response();
    }
    job.control.cancel();
    job.cancel_signal.notify_one();
    job_response(StatusCode::ACCEPTED, &job, None)
}
