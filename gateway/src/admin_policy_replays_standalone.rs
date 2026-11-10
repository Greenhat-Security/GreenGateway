//! Standalone replay recovery. This journal stores the bindings used to
//! describe a job and, after its completion audit is accepted, its aggregate
//! result. The input policy, events, audit envelope and retry key never enter it.
use super::*;
use rusqlite::{params, Connection, Transaction};
use std::{fs::File, io, path::Path};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS standalone_policy_replays_v1 (
    id TEXT PRIMARY KEY NOT NULL,
    metadata BLOB NOT NULL CHECK (length(metadata) <= 16384),
    metadata_hash BLOB NOT NULL CHECK (length(metadata_hash) = 32),
    owner_digest TEXT NOT NULL CHECK (length(owner_digest) = 64),
    key_digest TEXT CHECK (length(key_digest) = 64),
    state TEXT NOT NULL CHECK (state IN ('queued','completed','completed_incomplete','failed','cancelled','interrupted','expired')),
    started_ms INTEGER,
    finished_ms INTEGER,
    scanned INTEGER NOT NULL DEFAULT 0 CHECK (scanned >= 0),
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0,1)),
    failure TEXT,
    result BLOB CHECK (length(result) <= 524800),
    CHECK ((finished_ms IS NULL) = (state = 'queued')),
    CHECK ((result IS NOT NULL) = (state IN ('completed','completed_incomplete'))),
    UNIQUE(owner_digest, key_digest)
);";

type StoreResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// An OS lock is released by process death. A second process cannot mark a
/// job interrupted while its worker still owns the same journal.
pub(super) struct Journal {
    connection: Mutex<JournalConnection>,
    _process_lock: File,
}

struct JournalConnection {
    db: Connection,
    // Each entry represents one of at most 32 durable reservations. Retrying
    // just the failed transition cannot interrupt a live worker.
    repairs: HashMap<String, Repair>,
}

enum Repair {
    DiscardAdmission,
    FailWithoutResult(i64),
}

impl JournalConnection {
    fn retry(&mut self) -> rusqlite::Result<()> {
        if self.repairs.is_empty() {
            return Ok(());
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for (id, repair) in &self.repairs {
            match repair {
                Repair::DiscardAdmission => tx.execute(
                    "DELETE FROM standalone_policy_replays_v1 WHERE id=?1 AND state='queued'", [id])?,
                Repair::FailWithoutResult(finished) => tx.execute(
                    "UPDATE standalone_policy_replays_v1 SET state='failed', failure='store_unavailable', finished_ms=?2
                     WHERE id=?1 AND state='queued'", params![id, finished])?,
            };
        }
        tx.commit()?;
        self.repairs.clear();
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredResult {
    result: ReplayJobResult,
    binding_digest: String,
}

fn metadata_digest(id: &str, bytes: &[u8]) -> Vec<u8> {
    Sha256::new()
        .chain_update(b"standalone-replay-metadata.v1\0")
        .chain_update(id)
        .chain_update(bytes)
        .finalize()
        .to_vec()
}

fn result_binding_digest(id: &str, metadata_hash: &[u8], result_digest: &str) -> String {
    hex::encode(
        Sha256::new()
            .chain_update(b"standalone-replay-result.v1\0")
            .chain_update(id)
            .chain_update(metadata_hash)
            .chain_update(result_digest)
            .finalize(),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    engine: String,
    owner_digest: String,
    key_digest: Option<String>,
    request_digest: String,
    created_ms: i64,
    binding: ReplayJobBinding,
    scope: ReplayScope,
}

fn engine() -> String {
    format!(
        "{}/{}/{}/{}/{}/{}/{}",
        env!("CARGO_PKG_VERSION"),
        policy_eval::HTTP_SEMANTICS_VERSION,
        policy_eval::CONTEXT_VERSION,
        policy_eval::tools::TOOL_SEMANTICS_VERSION,
        policy_eval::tools::TOOL_CONTEXT_VERSION,
        policy_replay::REPLAY_CONTEXT_SCHEMA_VERSION,
        policy_replay::job::RESULT_SCHEMA_VERSION,
    )
}

fn milliseconds(time: OffsetDateTime) -> i64 {
    (time.unix_timestamp_nanos() / 1_000_000) as i64
}

fn instant_from_ms(ms: i64) -> StoreResult<OffsetDateTime> {
    Ok(OffsetDateTime::from_unix_timestamp_nanos(
        i128::from(ms) * 1_000_000,
    )?)
}

fn corrupt() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid standalone policy replay journal",
    )
}

fn prune(tx: &Transaction<'_>, now: i64) -> rusqlite::Result<()> {
    let expire = now.saturating_sub(POLICY_REPLAY_RESULT_TTL.as_millis() as i64);
    let forget = expire.saturating_sub(POLICY_REPLAY_EXPIRED_RETENTION.as_millis() as i64);
    tx.execute(
        "DELETE FROM standalone_policy_replays_v1 WHERE finished_ms <= ?1",
        [forget],
    )?;
    tx.execute(
        "UPDATE standalone_policy_replays_v1 SET state='expired', result=NULL, failure=NULL
                WHERE finished_ms <= ?1 AND state <> 'expired'",
        [expire],
    )?;
    tx.execute(
        "DELETE FROM standalone_policy_replays_v1 WHERE id IN
                (SELECT id FROM standalone_policy_replays_v1 WHERE state='expired'
                 ORDER BY finished_ms DESC, id DESC LIMIT -1 OFFSET ?1)",
        [MAX_RETAINED_POLICY_REPLAYS as i64],
    )?;
    Ok(())
}

impl PolicyReplayJobs {
    pub(crate) fn start_retention(&self, lifecycle: &GatewayLifecycle) {
        let Some(journal) = self.journal.as_ref().map(Arc::downgrade) else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let stop = lifecycle.background_cancellation();
        lifecycle.register_background_task(runtime.spawn(async move {
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                }
                let Some(journal) = journal.upgrade() else {
                    break;
                };
                // Reads enforce the TTL immediately. This also clears aggregates
                // from a quiet installation whose operators never start a new job.
                let _ = journal
                    .write(None, |db| {
                        let tx =
                            db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                        prune(&tx, milliseconds(OffsetDateTime::now_utc()))?;
                        tx.commit()?;
                        Ok(())
                    })
                    .await;
            }
        }));
    }

    pub(crate) fn open(
        path: &Path,
        audit: &audit::AuditLog,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut lock_path = path.canonicalize()?.into_os_string();
        lock_path.push(".policy-replays.lock");
        let process_lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        process_lock.try_lock().map_err(|error| {
            io::Error::other(format!(
                "cannot acquire standalone policy replay journal lock: {error}"
            ))
        })?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.execute_batch(SCHEMA)?;
        let now = OffsetDateTime::now_utc();
        let now_ms = milliseconds(now);
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        prune(&tx, now_ms)?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM standalone_policy_replays_v1",
            [],
            |row| row.get(0),
        )?;
        if count > (MAX_RETAINED_POLICY_REPLAYS * 2) as i64 {
            return Err(corrupt().into());
        }
        // Check sizes in SQLite before the driver allocates for a corrupt row.
        let oversized: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM standalone_policy_replays_v1
            WHERE length(metadata)>16384 OR length(result)>524800 OR length(failure)>64 OR length(id)<>36)",
            [], |row| row.get(0))?;
        if oversized {
            return Err(corrupt().into());
        }
        let mut interrupted = {
            let mut query = tx.prepare(
                "SELECT id FROM standalone_policy_replays_v1 WHERE state='queued' ORDER BY id",
            )?;
            let rows = query.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .map(|id| (id, "standalone_restart"))
                .collect::<Vec<_>>()
        };
        tx.execute("UPDATE standalone_policy_replays_v1 SET state='interrupted', failure='standalone_restart', finished_ms=?1
                    WHERE state='queued'", [now_ms])?;
        let mut jobs = HashMap::new();
        {
            let mut query = tx.prepare(
                "SELECT id, metadata, metadata_hash, state, started_ms, finished_ms,
                    scanned, cancel_requested, failure, result, owner_digest, key_digest FROM standalone_policy_replays_v1",
            )?;
            let mut rows = query.query([])?;
            while let Some(row) = rows.next()? {
                let (job, stale_result) = recover(row, now).map_err(|_| corrupt())?;
                if stale_result {
                    interrupted.push((job.id.clone(), "engine_version_changed"));
                }
                jobs.insert(job.id.clone(), Arc::new(job));
            }
        }
        for (id, reason) in &interrupted {
            if *reason == "engine_version_changed" {
                tx.execute("UPDATE standalone_policy_replays_v1 SET state='interrupted', failure=?2, result=NULL WHERE id=?1", params![id, reason])?;
            }
        }
        tx.commit()?;
        for (id, reason) in interrupted {
            audit.emit(audit::AuditEvent::new(
                audit::event::POLICY_REPLAY_INTERRUPTED,
                "",
                "",
                None,
                json!({"job_id": id, "reason": reason}),
            ));
        }
        let mut registry = Self::new();
        registry.jobs = Mutex::new(jobs);
        registry.journal = Some(Arc::new(Journal {
            connection: Mutex::new(JournalConnection {
                db: connection,
                repairs: HashMap::new(),
            }),
            _process_lock: process_lock,
        }));
        Ok(registry)
    }
}

fn recover(row: &rusqlite::Row<'_>, now: OffsetDateTime) -> StoreResult<(ReplayJob, bool)> {
    let id: String = row.get(0)?;
    let bytes: Vec<u8> = row.get(1)?;
    let hash: Vec<u8> = row.get(2)?;
    if !is_policy_replay_job_id(&id) || bytes.len() > 16_384 || metadata_digest(&id, &bytes) != hash
    {
        return Err(corrupt().into());
    }
    let m: Metadata = serde_json::from_slice(&bytes)?;
    if m.owner_digest != row.get::<_, String>(10)?
        || m.key_digest != row.get::<_, Option<String>>(11)?
    {
        return Err(corrupt().into());
    }
    let state: String = row.get(3)?;
    let started: Option<i64> = row.get(4)?;
    let finished = instant_from_ms(row.get(5)?)?;
    let scanned = u64::try_from(row.get::<_, i64>(6)?)?;
    let cancel_requested = row.get(7)?;
    let mut failure = row.get::<_, Option<String>>(8)?;
    if !matches!(
        failure.as_deref(),
        None | Some(
            "source_unavailable"
                | "compile_failed"
                | "evaluator_failed"
                | "checkpoint_unreadable"
                | "checkpoint_too_large"
                | "result_digest_failed"
                | "result_too_large"
                | "internal"
                | "audit_unavailable"
                | "store_unavailable"
                | "standalone_restart"
                | "engine_version_changed"
        )
    ) {
        return Err(corrupt().into());
    }
    let bytes = row.get::<_, Option<Vec<u8>>>(9)?;
    let state = match state.as_str() {
        "completed" => ReplayJobState::Completed,
        "completed_incomplete" => ReplayJobState::CompletedIncomplete,
        "interrupted" => ReplayJobState::Interrupted,
        "failed" => ReplayJobState::Failed,
        "cancelled" => ReplayJobState::Cancelled,
        "expired" => ReplayJobState::Expired,
        _ => return Err(corrupt().into()),
    };
    let complete = matches!(
        state,
        ReplayJobState::Completed | ReplayJobState::CompletedIncomplete
    );
    if complete != bytes.is_some() || scanned > m.scope.max_records as u64 {
        return Err(corrupt().into());
    }
    let stale_result = complete && m.engine != engine();
    let (state, result) = if stale_result {
        failure = Some("engine_version_changed".to_owned());
        (ReplayJobState::Interrupted, None)
    } else if let Some(bytes) = bytes {
        if bytes.len() > MAX_POLICY_REPLAY_RESULT_BYTES + 512 {
            return Err(corrupt().into());
        }
        let stored: StoredResult = serde_json::from_slice(&bytes)?;
        let result = stored.result;
        let digest = canonical_json::semantic_digest(
            policy_replay::job::RESULT_MEDIA_TYPE,
            policy_replay::job::RESULT_SCHEMA_VERSION,
            &result.document,
        )
        .map_err(|_| corrupt())?;
        if digest != result.digest
            || stored.binding_digest != result_binding_digest(&id, &hash, &digest)
            || result.document["schema_version"] != policy_replay::job::RESULT_SCHEMA_VERSION
            || result.document["complete"].as_bool() != Some(state == ReplayJobState::Completed)
        {
            return Err(corrupt().into());
        }
        (state, Some(Arc::new(result)))
    } else {
        (state, None)
    };
    let age = Duration::try_from(now - finished).unwrap_or_default();
    Ok((
        ReplayJob {
            id,
            owner: m.owner_digest,
            idempotency_key: m.key_digest,
            request_digest: m.request_digest,
            created_at: instant_from_ms(m.created_ms)?,
            actor: None,
            request_id: String::new(),
            source_ip: String::new(),
            journal: None,
            binding: m.binding,
            scope: m.scope,
            control: Arc::new(ReplayControl::restored(scanned)),
            cancel_signal: tokio::sync::Notify::new(),
            record: Mutex::new(ReplayJobRecord {
                state,
                failure,
                cancel_requested,
                started_at: started.map(instant_from_ms).transpose()?,
                finished: Some(ReplayFinishTime {
                    at: finished,
                    observed: Instant::now(),
                    age_at_observation: age,
                }),
                result,
            }),
        },
        stale_result,
    ))
}

impl Journal {
    async fn write<F>(self: &Arc<Self>, repair: Option<(String, Repair)>, work: F) -> Result<(), ()>
    where
        F: FnOnce(&mut Connection) -> StoreResult<()> + Send + 'static,
    {
        let journal = Arc::clone(self);
        let outcome = tokio::task::spawn_blocking(move || {
            let mut connection = journal
                .connection
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if connection.retry().is_err() {
                tracing::error!("standalone policy replay journal repair pending");
            }
            let result = work(&mut connection.db);
            if result.is_err() {
                if let Some((id, repair)) = repair {
                    connection.repairs.insert(id, repair);
                }
            }
            result
        })
        .await;
        if !matches!(outcome, Ok(Ok(()))) {
            tracing::error!("standalone policy replay journal write failed");
            return Err(());
        }
        Ok(())
    }

    pub(super) async fn reserve(self: &Arc<Self>, job: Arc<ReplayJob>) -> Result<(), ()> {
        self.write(None, move |db| {
            let metadata = serde_json::to_vec(&Metadata {
                engine: engine(), owner_digest: job.owner.clone(), key_digest: job.idempotency_key.clone(),
                request_digest: job.request_digest.clone(), created_ms: milliseconds(job.created_at),
                binding: job.binding.clone(), scope: job.scope.clone(),
            })?;
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            prune(&tx, milliseconds(OffsetDateTime::now_utc()))?;
            let (all, owned): (i64, i64) = tx.query_row(
                "SELECT COUNT(*), COUNT(CASE WHEN owner_digest=?1 THEN 1 END)
                 FROM standalone_policy_replays_v1 WHERE state <> 'expired'", [&job.owner],
                |row| Ok((row.get(0)?, row.get(1)?)))?;
            if all >= MAX_RETAINED_POLICY_REPLAYS as i64 || owned >= MAX_RETAINED_POLICY_REPLAYS_PER_ACTOR as i64 {
                return Err(io::Error::other("standalone replay journal quota exhausted").into());
            }
            tx.execute("INSERT INTO standalone_policy_replays_v1(id, metadata, metadata_hash, owner_digest, key_digest, state)
                        VALUES (?1, ?2, ?3, ?4, ?5, 'queued')", params![job.id, metadata, metadata_digest(&job.id, &metadata), job.owner, job.idempotency_key])?;
            tx.commit()?;
            Ok(())
        }).await
    }

    pub(super) async fn remove(self: &Arc<Self>, id: String, abandon: bool) -> Result<(), ()> {
        let repair = abandon.then(|| (id.clone(), Repair::DiscardAdmission));
        self.write(repair, move |db| {
            db.execute(
                "DELETE FROM standalone_policy_replays_v1 WHERE id = ?1",
                [id],
            )?;
            Ok(())
        })
        .await
    }
}

impl ReplayJob {
    pub(super) async fn finish(
        self: &Arc<Self>,
        mut state: ReplayJobState,
        mut failure: Option<&'static str>,
        mut result: Option<Arc<ReplayJobResult>>,
    ) {
        let finished = OffsetDateTime::now_utc();
        if let Some(journal) = &self.journal {
            let job = Arc::clone(self);
            let saved = result.clone();
            let write = journal
                .write(Some((self.id.clone(), Repair::FailWithoutResult(milliseconds(finished)))), move |db| {
                    let result = if let Some(result) = saved {
                        let hash: Vec<u8> = db.query_row("SELECT metadata_hash FROM standalone_policy_replays_v1 WHERE id=?1",
                            [&job.id], |row| row.get(0))?;
                        let binding_digest = result_binding_digest(&job.id, &hash, &result.digest);
                        Some(serde_json::to_vec(&StoredResult {result: (*result).clone(), binding_digest})?)
                    } else { None };
                    let (started, cancel) = {
                        let record = job.record();
                        (record.started_at.map(milliseconds), record.cancel_requested)
                    };
                    let changed = db.execute(
                        "UPDATE standalone_policy_replays_v1 SET state=?2, failure=?3,
                     result=?4, started_ms=?5, finished_ms=?6, scanned=?7, cancel_requested=?8
                     WHERE id=?1 AND state='queued'",
                        params![
                            job.id,
                            state.as_str(),
                            failure,
                            result,
                            started,
                            milliseconds(finished),
                            i64::try_from(job.control.scanned())?,
                            cancel
                        ],
                    )?;
                    if changed != 1 {
                        return Err(corrupt().into());
                    }
                    Ok(())
                })
                .await;
            if write.is_err() {
                state = ReplayJobState::Failed;
                failure = Some("store_unavailable");
                result = None;
            }
        }
        let mut record = self.record();
        record.state = state;
        record.failure = failure.map(str::to_owned);
        record.result = result;
        record.finished = Some(ReplayFinishTime {
            at: finished,
            observed: Instant::now(),
            age_at_observation: Duration::ZERO,
        });
    }
}
