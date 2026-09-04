use std::{
    error::Error,
    fmt, io,
    path::PathBuf,
    sync::{
        mpsc::{self, RecvTimeoutError, Sender},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::{Duration as StdDuration, Instant},
};

use rusqlite::{params, Connection};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

use crate::{
    audit::{AuditEvent, AuditSink, AUDIT_SQLITE_FLUSH_ERRORS_TOTAL},
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
};

const SQLITE_BATCH_SIZE: usize = 200;
const SQLITE_FLUSH_INTERVAL: StdDuration = StdDuration::from_millis(250);
const SQLITE_PRUNE_INTERVAL: StdDuration = StdDuration::from_secs(60);

const CREATE_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    timestamp_epoch_us INTEGER,
    schema_version TEXT NOT NULL,
    request_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    user_agent TEXT,
    actor_user_id TEXT,
    actor_json TEXT,
    payload_method TEXT,
    payload_path TEXT,
    payload_status INTEGER,
    payload_matched_rule_id TEXT,
    payload_json TEXT NOT NULL
);
"#;

const CREATE_INDEXES_SQL: &str = r#"
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp_epoch_us
    ON audit_events(timestamp_epoch_us);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_user_id ON audit_events(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_payload_method ON audit_events(payload_method);
CREATE INDEX IF NOT EXISTS idx_audit_events_payload_path ON audit_events(payload_path);
CREATE INDEX IF NOT EXISTS idx_audit_events_payload_status ON audit_events(payload_status);
CREATE INDEX IF NOT EXISTS idx_audit_events_payload_matched_rule_id ON audit_events(payload_matched_rule_id);
"#;

const INSERT_EVENT_SQL: &str = r#"
INSERT INTO audit_events (
    event_id,
    event_type,
    timestamp,
    timestamp_epoch_us,
    schema_version,
    request_id,
    source_ip,
    user_agent,
    actor_user_id,
    actor_json,
    payload_method,
    payload_path,
    payload_status,
    payload_matched_rule_id,
    payload_json
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
ON CONFLICT(event_id) DO NOTHING
"#;

const DELETE_RETAINED_EVENTS_SQL: &str = r#"
DELETE FROM audit_events
WHERE timestamp_epoch_us < ?1
"#;

const BACKFILL_TIMESTAMP_EPOCH_US_SQL: &str = r#"
UPDATE audit_events
SET timestamp_epoch_us =
    CAST(ROUND((julianday(timestamp) - 2440587.5) * 86400000000.0) AS INTEGER)
WHERE timestamp_epoch_us IS NULL
  AND julianday(timestamp) IS NOT NULL
"#;

#[derive(Debug, Clone)]
pub struct SqliteSinkConfig {
    pub path: PathBuf,
    pub retention_days: Option<u32>,
}

pub struct SqliteSink {
    shared: Arc<SqliteSinkShared>,
    shutdown_tx: Mutex<Option<Sender<()>>>,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug)]
pub enum SqliteSinkError {
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Setup {
        path: PathBuf,
        source: rusqlite::Error,
    },
    ThreadSpawn {
        source: io::Error,
    },
}

impl fmt::Display for SqliteSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(
                    formatter,
                    "failed to open SQLite audit sink at {}: {source}",
                    path.display()
                )
            }
            Self::Setup { path, source } => {
                write!(
                    formatter,
                    "failed to initialize SQLite audit sink at {}: {source}",
                    path.display()
                )
            }
            Self::ThreadSpawn { source } => {
                write!(formatter, "failed to spawn SQLite audit flusher: {source}")
            }
        }
    }
}

impl Error for SqliteSinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Setup { source, .. } => Some(source),
            Self::ThreadSpawn { source } => Some(source),
        }
    }
}

impl SqliteSink {
    pub fn new(config: SqliteSinkConfig) -> Result<Self, SqliteSinkError> {
        Self::new_with_intervals(config, SQLITE_FLUSH_INTERVAL, SQLITE_PRUNE_INTERVAL)
    }

    fn new_with_intervals(
        config: SqliteSinkConfig,
        flush_interval: StdDuration,
        prune_interval: StdDuration,
    ) -> Result<Self, SqliteSinkError> {
        let connection =
            Connection::open(&config.path).map_err(|source| SqliteSinkError::Open {
                path: config.path.clone(),
                source,
            })?;
        configure_connection(&connection).map_err(|source| SqliteSinkError::Setup {
            path: config.path.clone(),
            source,
        })?;

        let shared = Arc::new(SqliteSinkShared {
            path: config.path,
            retention_days: config.retention_days,
            connection: Mutex::new(connection),
            buffer: Mutex::new(Vec::with_capacity(SQLITE_BATCH_SIZE)),
            flush_failure: Mutex::new(None),
            #[cfg(test)]
            mid_flush_hook: Mutex::new(None),
        });
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let flusher_shared = Arc::clone(&shared);
        let flusher = thread::Builder::new()
            .name("audit-sqlite-flusher".to_owned())
            .spawn(move || {
                flusher_loop(flusher_shared, shutdown_rx, flush_interval, prune_interval)
            })
            .map_err(|source| SqliteSinkError::ThreadSpawn { source })?;

        Ok(Self {
            shared,
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            flusher: Mutex::new(Some(flusher)),
        })
    }

    #[cfg(test)]
    fn flush_for_test(&self) {
        self.shared.flush_buffer();
    }

    #[cfg(test)]
    fn set_mid_flush_hook_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        *self
            .shared
            .mid_flush_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn prune_for_test(&self) {
        self.shared.prune_old_events();
    }

    fn shutdown_and_flush(&self) -> Result<(), String> {
        if let Some(shutdown_tx) = take_mutex_value(&self.shutdown_tx, "shutdown_tx", &self.shared)
        {
            let _ = shutdown_tx.send(());
        }

        if let Some(flusher) = take_mutex_value(&self.flusher, "flusher", &self.shared) {
            if flusher.join().is_err() {
                return Err("SQLite audit flusher thread panicked during shutdown".to_owned());
            }
        }

        self.shared.flush_buffer();
        self.shared
            .flush_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .map_or(Ok(()), Err)
    }
}

impl AuditSink for SqliteSink {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    fn emit(&self, event: &AuditEvent) {
        if self.shared.push_event(event.clone()) {
            self.shared.flush_buffer();
        }
    }

    fn flush(&self) -> Result<(), String> {
        self.shutdown_and_flush()
    }
}

impl Drop for SqliteSink {
    fn drop(&mut self) {
        if let Err(error) = self.shutdown_and_flush() {
            tracing::error!(
                path = %self.shared.path.display(),
                %error,
                "SQLite audit sink failed during shutdown"
            );
        }
    }
}

struct SqliteSinkShared {
    path: PathBuf,
    retention_days: Option<u32>,
    connection: Mutex<Connection>,
    buffer: Mutex<Vec<AuditEvent>>,
    flush_failure: Mutex<Option<String>>,
    // Fires once, between the drain and the INSERT, so a test can drive a
    // second flush into exactly the window the commit-ordering bug lived in
    // instead of waiting for the scheduler to reproduce it.
    #[cfg(test)]
    mid_flush_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl SqliteSinkShared {
    fn push_event(&self, event: AuditEvent) -> bool {
        let mut buffer = self.buffer_guard();
        buffer.push(event);
        buffer.len() >= SQLITE_BATCH_SIZE
    }

    fn flush_buffer(&self) {
        // The drain and the INSERT have to be one critical section. `id` is an
        // autoincrement assigned at INSERT time and it is the audit query API's
        // sort and cursor key, so when one flusher drains a batch and a later
        // batch wins the connection first, the older batch commits with the
        // higher ids and the log stops reading back in emission order. Taking
        // the connection lock before the buffer lock makes drain order and
        // commit order the same order; nothing may take these two in reverse.
        let mut connection = self.connection_guard();
        let events = {
            let mut buffer = self.buffer_guard();
            if buffer.is_empty() {
                return;
            }

            buffer.drain(..).collect::<Vec<_>>()
        };

        #[cfg(test)]
        self.run_mid_flush_hook();

        let result = write_events(&mut connection, &events);
        drop(connection);

        crate::audit::record_flush_outcome(result.is_ok());
        if let Err(err) = result {
            let mut failure = self
                .flush_failure
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if failure.is_none() {
                *failure = Some(format!("SQLite audit flush failed: {err}"));
            }
            ::metrics::counter!(
                AUDIT_SQLITE_FLUSH_ERRORS_TOTAL,
                "operation" => "flush"
            )
            .increment(1);
            tracing::error!(
                path = %self.path.display(),
                event_count = events.len(),
                error = %err,
                "failed to flush SQLite audit events; dropping batch"
            );
        }
    }

    fn prune_old_events(&self) {
        // A zero-day window puts the prune cutoff at the current instant, which
        // deletes the whole audit history on every tick rather than retaining
        // nothing new. `Config` folds `AUDIT_SQLITE_RETENTION_DAYS=0` into
        // `None` before it reaches here; this guard keeps a directly built
        // `SqliteSinkConfig` from reintroducing the erase.
        let Some(retention_days) = self.retention_days.filter(|days| *days > 0) else {
            return;
        };

        let cutoff_epoch_us = retention_cutoff_epoch_us(retention_days);
        let result = {
            let connection = self.connection_guard();
            prune_retained_events(&connection, cutoff_epoch_us)
        };

        if let Err(err) = result {
            ::metrics::counter!(
                AUDIT_SQLITE_FLUSH_ERRORS_TOTAL,
                "operation" => "retention_prune"
            )
            .increment(1);
            tracing::error!(
                path = %self.path.display(),
                error = %err,
                "failed to prune retained SQLite audit events"
            );
        }
    }

    #[cfg(test)]
    fn run_mid_flush_hook(&self) {
        // Taken rather than borrowed so the competing flush this hook starts
        // does not block on the hook's own lock.
        let hook = self
            .mid_flush_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn buffer_guard(&self) -> MutexGuard<'_, Vec<AuditEvent>> {
        match self.buffer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "audit",
                    "lock" => "sqlite_sink_buffer"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite audit sink buffer lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "audit",
                    "lock" => "sqlite_sink_connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite audit sink connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum SqliteFlushError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl fmt::Display for SqliteFlushError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(err) => write!(formatter, "SQLite error: {err}"),
            Self::Json(err) => write!(formatter, "JSON serialization error: {err}"),
        }
    }
}

impl Error for SqliteFlushError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(err) => Some(err),
            Self::Json(err) => Some(err),
        }
    }
}

impl From<rusqlite::Error> for SqliteFlushError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

impl From<serde_json::Error> for SqliteFlushError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

fn flusher_loop(
    shared: Arc<SqliteSinkShared>,
    shutdown_rx: mpsc::Receiver<()>,
    flush_interval: StdDuration,
    prune_interval: StdDuration,
) {
    let mut last_prune = Instant::now();
    loop {
        match shutdown_rx.recv_timeout(flush_interval) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                shared.flush_buffer();
                return;
            }
            Err(RecvTimeoutError::Timeout) => {
                shared.flush_buffer();
                if last_prune.elapsed() >= prune_interval {
                    shared.prune_old_events();
                    last_prune = Instant::now();
                }
            }
        }
    }
}

pub(crate) fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    // WAL plus NORMAL avoids an fsync for every commit while keeping committed
    // audit batches durable against process crashes. The tradeoff is that the
    // newest committed transaction can be lost on OS or hardware failure.
    connection.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        "#,
    )?;
    connection.execute_batch(CREATE_TABLE_SQL)?;
    ensure_audit_events_column(connection, "payload_method", "TEXT")?;
    ensure_audit_events_column(connection, "payload_matched_rule_id", "TEXT")?;
    ensure_audit_events_column(connection, "timestamp_epoch_us", "INTEGER")?;
    backfill_payload_text_column(connection, "payload_method", "method")?;
    backfill_payload_text_column(connection, "payload_matched_rule_id", "matched_rule_id")?;
    backfill_timestamp_epoch_us(connection)?;
    connection.execute_batch(CREATE_INDEXES_SQL)
}

fn ensure_audit_events_column(
    connection: &Connection,
    column_name: &str,
    column_type: &str,
) -> rusqlite::Result<()> {
    if audit_events_has_column(connection, column_name)? {
        return Ok(());
    }

    let sql = format!("ALTER TABLE audit_events ADD COLUMN {column_name} {column_type}");
    connection.execute(&sql, [])?;
    Ok(())
}

fn audit_events_has_column(connection: &Connection, column_name: &str) -> rusqlite::Result<bool> {
    let mut statement = connection.prepare("PRAGMA table_info(audit_events)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;

    for column in columns {
        if column? == column_name {
            return Ok(true);
        }
    }

    Ok(false)
}

fn backfill_payload_text_column(
    connection: &Connection,
    column_name: &str,
    payload_key: &str,
) -> rusqlite::Result<()> {
    debug_assert!(matches!(
        (column_name, payload_key),
        ("payload_method", "method") | ("payload_matched_rule_id", "matched_rule_id")
    ));

    let sql = format!(
        r#"
        UPDATE audit_events
        SET {column_name} = json_extract(payload_json, '$.{payload_key}')
        WHERE {column_name} IS NULL
          AND json_valid(payload_json)
          AND json_type(payload_json, '$.{payload_key}') = 'text'
        "#
    );
    connection.execute(&sql, [])?;
    Ok(())
}

fn backfill_timestamp_epoch_us(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute(BACKFILL_TIMESTAMP_EPOCH_US_SQL, [])?;
    Ok(())
}

fn epoch_micros(timestamp: &str) -> Option<i64> {
    OffsetDateTime::parse(timestamp, &Rfc3339)
        .ok()
        .and_then(|datetime| i64::try_from(datetime.unix_timestamp_nanos() / 1_000).ok())
}

fn retention_cutoff_epoch_us(retention_days: u32) -> i64 {
    // `OffsetDateTime`'s `Sub` is `checked_sub(..).expect(..)`, and `time` is
    // built without `large-dates`, so its floor is year -9999. Subtracting a
    // window wider than that panicked -- on the flusher thread, which also owns
    // periodic flushing, so a single out-of-range setting stopped pruning and
    // buffered-event flushing together and stayed broken until restart.
    //
    // A window reaching past the earliest representable instant cannot select
    // any stored event, so saturating to the floor prunes nothing. For an audit
    // store that is the safe direction: retain more than intended rather than
    // delete, and never take the writer down.
    match OffsetDateTime::now_utc().checked_sub(TimeDuration::days(i64::from(retention_days))) {
        // `OffsetDateTime`'s supported range fits comfortably in epoch microseconds.
        Some(cutoff) => (cutoff.unix_timestamp_nanos() / 1_000) as i64,
        None => i64::MIN,
    }
}

pub(crate) fn write_events(
    connection: &mut Connection,
    events: &[AuditEvent],
) -> Result<(), SqliteFlushError> {
    // `event_id` is the idempotency key: an ambiguous retry may replay a
    // batch, and the ON CONFLICT clause keeps storage exactly-once. This is
    // the single insert path for audit events, shared by the flusher thread
    // and the repository contract adapter.
    let transaction = connection.transaction()?;

    {
        let mut statement = transaction.prepare_cached(INSERT_EVENT_SQL)?;

        for event in events {
            let actor_user_id = event.actor.as_ref().map(|actor| actor.user_id.as_str());
            let actor_json = event
                .actor
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?;
            let payload_method = event.payload.get("method").and_then(Value::as_str);
            let payload_path = event.payload.get("path").and_then(Value::as_str);
            let payload_status = payload_status(&event.payload);
            let payload_matched_rule_id =
                event.payload.get("matched_rule_id").and_then(Value::as_str);
            let payload_json = serde_json::to_string(&event.payload)?;
            let timestamp_epoch_us = epoch_micros(event.timestamp.as_str());

            statement.execute(params![
                event.event_id.as_str(),
                event.event_type.as_str(),
                event.timestamp.as_str(),
                timestamp_epoch_us,
                event.schema_version.as_str(),
                event.request_id.as_str(),
                event.source_ip.as_str(),
                event.user_agent.as_deref(),
                actor_user_id,
                actor_json.as_deref(),
                payload_method,
                payload_path,
                payload_status,
                payload_matched_rule_id,
                payload_json.as_str(),
            ])?;
        }
    }

    transaction.commit()?;
    Ok(())
}

fn prune_retained_events(connection: &Connection, cutoff_epoch_us: i64) -> rusqlite::Result<usize> {
    // NULL epochs belong to malformed or externally inserted timestamps. They
    // do not match the range predicate and retain the previous prune semantics.
    connection.execute(DELETE_RETAINED_EVENTS_SQL, params![cutoff_epoch_us])
}

fn payload_status(payload: &Value) -> Option<i64> {
    let status = payload.get("status")?;
    let number = status
        .as_i64()
        .or_else(|| status.as_u64().and_then(|value| i64::try_from(value).ok()));

    number.or_else(|| {
        let value = status.as_f64()?;
        if value.is_finite()
            && value.fract() == 0.0
            && value >= i64::MIN as f64
            && value <= i64::MAX as f64
        {
            Some(value as i64)
        } else {
            None
        }
    })
}

fn take_mutex_value<T>(
    mutex: &Mutex<Option<T>>,
    lock_name: &'static str,
    shared: &SqliteSinkShared,
) -> Option<T> {
    match mutex.lock() {
        Ok(mut guard) => guard.take(),
        Err(poisoned) => {
            ::metrics::counter!(
                LOCK_POISON_RECOVERIES_TOTAL,
                "component" => "audit",
                "lock" => lock_name
            )
            .increment(1);
            tracing::error!(
                path = %shared.path.display(),
                lock = lock_name,
                "SQLite audit sink shutdown lock poisoned; recovering"
            );
            let mut guard = poisoned.into_inner();
            guard.take()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, time::Instant};

    use serde_json::{json, Value};

    use super::*;
    use crate::audit::{Actor, AuditEvent};

    #[test]
    fn events_survive_drop_and_reopen() {
        let db = TempDb::new("durability");

        {
            let sink = sqlite_sink(&db.path, None);
            for index in 0..10 {
                sink.emit(&test_event(
                    &format!("audit.durable.{index}"),
                    json!({ "path": format!("/durable/{index}"), "status": 200 }),
                ));
            }
        }

        let _reopened = sqlite_sink(&db.path, None);
        assert_eq!(row_count(&db.path), 10);
    }

    #[test]
    fn concurrent_flushes_commit_batches_in_emission_order() {
        let db = TempDb::new("flush-ordering");
        // Long intervals keep the background flusher out of the two flushes
        // this test sequences by hand.
        let sink = sqlite_sink_with_intervals(
            &db.path,
            None,
            StdDuration::from_secs(3_600),
            StdDuration::from_secs(3_600),
        );

        for index in 0..3 {
            sink.emit(&test_event(
                &format!("audit.order.a{index}"),
                json!({ "path": format!("/a/{index}") }),
            ));
        }

        let shared = Arc::clone(&sink.shared);
        let deferred = Arc::new(Mutex::new(None));
        let deferred_slot = Arc::clone(&deferred);
        sink.set_mid_flush_hook_for_test(move || {
            // Batch B is emitted after batch A has left the buffer, so B has to
            // commit second whichever flusher reaches the connection first.
            for index in 0..3 {
                shared.push_event(test_event(
                    &format!("audit.order.b{index}"),
                    json!({ "path": format!("/b/{index}") }),
                ));
            }

            // A competing flusher can only overtake batch A while the
            // connection sits unlocked between the drain and the INSERT.
            // Probing the lock decides the interleaving here rather than
            // leaving it to the scheduler.
            let connection_unlocked = shared.connection.try_lock().is_ok();
            let competing_shared = Arc::clone(&shared);
            let competitor = thread::spawn(move || competing_shared.flush_buffer());
            if connection_unlocked {
                competitor.join().expect("competing flush should not panic");
            } else {
                *deferred_slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(competitor);
            }
        });

        sink.flush_for_test();
        if let Some(competitor) = deferred
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            competitor.join().expect("competing flush should not panic");
        }
        drop(sink);

        assert_eq!(
            event_types_in_id_order(&db.path),
            [
                "audit.order.a0",
                "audit.order.a1",
                "audit.order.a2",
                "audit.order.b0",
                "audit.order.b1",
                "audit.order.b2",
            ]
        );
    }

    #[test]
    fn schema_creation_is_idempotent() {
        let db = TempDb::new("schema-idempotent");

        drop(sqlite_sink(&db.path, None));
        drop(sqlite_sink(&db.path, None));

        assert_eq!(row_count(&db.path), 0);
    }

    #[test]
    fn fresh_schema_includes_promoted_rule_preview_columns() {
        let db = TempDb::new("schema-promoted-columns");

        drop(sqlite_sink(&db.path, None));

        let connection = Connection::open(&db.path).expect("test database should open");
        assert!(column_exists(&connection, "payload_method"));
        assert!(column_exists(&connection, "payload_matched_rule_id"));
        assert!(index_exists(
            &connection,
            "idx_audit_events_payload_matched_rule_id"
        ));
    }

    #[test]
    fn fresh_schema_includes_timestamp_epoch_index() {
        let db = TempDb::new("schema-timestamp-epoch");

        drop(sqlite_sink(&db.path, None));

        let connection = Connection::open(&db.path).expect("test database should open");
        assert!(column_exists(&connection, "timestamp_epoch_us"));
        assert!(index_exists(
            &connection,
            "idx_audit_events_timestamp_epoch_us"
        ));
        assert!(index_exists(&connection, "idx_audit_events_timestamp"));
    }

    #[test]
    fn old_schema_migrates_promoted_rule_columns_without_losing_rows() {
        let db = TempDb::new("schema-migration-rule-columns");
        create_old_schema(&db.path);

        drop(sqlite_sink(&db.path, None));

        let connection = Connection::open(&db.path).expect("test database should open");
        assert_eq!(row_count(&db.path), 1);
        assert!(column_exists(&connection, "payload_method"));
        assert!(column_exists(&connection, "payload_matched_rule_id"));
        assert!(column_exists(&connection, "timestamp_epoch_us"));
        assert!(index_exists(
            &connection,
            "idx_audit_events_payload_matched_rule_id"
        ));
        assert!(index_exists(
            &connection,
            "idx_audit_events_timestamp_epoch_us"
        ));

        let promoted = connection
            .query_row(
                r#"
                SELECT event_id, payload_method, payload_matched_rule_id, payload_json
                FROM audit_events
                WHERE event_id = 'old-event'
                "#,
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .expect("promoted columns should query");

        assert_eq!(promoted.0, "old-event");
        assert_eq!(promoted.1.as_deref(), Some("GET"));
        assert_eq!(promoted.2.as_deref(), Some("allow-data"));
        assert!(promoted.3.contains(r#""matched_rule_id":"allow-data""#));
        assert!(event_epoch(&connection, "old-event").is_some());
    }

    #[test]
    fn timestamp_epoch_migration_and_exact_inserts_are_ordered_and_idempotent() {
        let db = TempDb::new("schema-migration-timestamp-epoch");
        create_old_schema(&db.path);

        {
            let sink = sqlite_sink(&db.path, None);
            let mut event = test_event("audit.new-epoch", json!({ "test": true }));
            event.event_id = "new-event".to_owned();
            event.timestamp = "2026-01-01T00:00:00.5Z".to_owned();
            sink.emit(&event);
            sink.flush_for_test();
        }

        let before_reopen = {
            let connection = Connection::open(&db.path).expect("test database should open");
            let old_epoch = event_epoch(&connection, "old-event")
                .expect("legacy timestamp should be backfilled");
            let new_epoch = event_epoch(&connection, "new-event")
                .expect("new timestamp should be stored at insert time");
            assert_eq!(
                new_epoch,
                epoch_micros("2026-01-01T00:00:00.5Z").expect("new timestamp should parse")
            );
            assert!(old_epoch < new_epoch);
            (old_epoch, new_epoch)
        };

        drop(sqlite_sink(&db.path, None));

        let connection = Connection::open(&db.path).expect("test database should open");
        assert_eq!(
            (
                event_epoch(&connection, "old-event").expect("legacy epoch should survive reopen"),
                event_epoch(&connection, "new-event").expect("new epoch should survive reopen"),
            ),
            before_reopen
        );
    }

    #[test]
    fn retention_prune_uses_timestamp_epoch_index() {
        let db = TempDb::new("retention-index-plan");
        drop(sqlite_sink(&db.path, None));

        let connection = Connection::open(&db.path).expect("test database should open");
        let explain_sql = format!("EXPLAIN QUERY PLAN {DELETE_RETAINED_EVENTS_SQL}");
        let mut statement = connection
            .prepare(&explain_sql)
            .expect("retention query plan should prepare");
        let plan = statement
            .query_map(params![0_i64], |row| row.get::<_, String>(3))
            .expect("retention query plan should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("retention query plan should read");
        let plan = plan.join("\n");

        assert!(
            plan.contains("USING INDEX idx_audit_events_timestamp_epoch_us"),
            "unexpected retention query plan: {plan}"
        );
        assert!(
            !plan.contains("SCAN audit_events"),
            "retention query unexpectedly scans the table: {plan}"
        );
    }

    #[test]
    fn batch_size_flushes_before_timer_fires() {
        let db = TempDb::new("batch-flush");
        let sink = sqlite_sink_with_interval(&db.path, None, StdDuration::from_secs(60));

        for index in 0..(SQLITE_BATCH_SIZE + 5) {
            sink.emit(&test_event(
                "audit.batch",
                json!({ "path": format!("/batch/{index}"), "status": 200 }),
            ));
        }

        assert_eq!(row_count(&db.path), SQLITE_BATCH_SIZE as i64);
    }

    #[test]
    fn retention_pruning_deletes_old_rows_and_keeps_new_rows() {
        let db = TempDb::new("retention");
        let _sink = sqlite_sink_with_intervals(
            &db.path,
            Some(1),
            StdDuration::from_millis(20),
            StdDuration::from_millis(20),
        );
        insert_raw_event(&db.path, "old-event", "2000-01-01T00:00:00Z");
        insert_raw_event(&db.path, "new-event", "2999-01-01T00:00:00Z");

        assert_eventually(StdDuration::from_secs(1), || {
            event_ids(&db.path) == vec!["new-event".to_owned()]
        });
    }

    #[test]
    fn a_retention_window_past_the_representable_range_prunes_nothing_instead_of_panicking() {
        // `SqliteSinkConfig` is publicly constructible, so config validation is
        // not the only way this value arrives. Before this was checked, the
        // subtraction panicked on the flusher thread -- taking periodic
        // flushing down with pruning.
        let cutoff = retention_cutoff_epoch_us(u32::MAX);

        assert_eq!(
            cutoff,
            i64::MIN,
            "an unrepresentable window must saturate to a cutoff that selects nothing"
        );
        assert!(
            cutoff < retention_cutoff_epoch_us(1),
            "the saturated cutoff must still be older than any ordinary window"
        );
    }

    #[test]
    fn zero_retention_days_disables_pruning_instead_of_erasing_the_store() {
        let db = TempDb::new("retention-zero");
        let sink = sqlite_sink_with_intervals(
            &db.path,
            Some(0),
            StdDuration::from_secs(60),
            StdDuration::from_secs(60),
        );
        insert_raw_event(&db.path, "old-event", "2000-01-01T00:00:00Z");
        insert_raw_event(&db.path, "new-event", "2999-01-01T00:00:00Z");

        sink.prune_for_test();

        assert_eq!(
            event_ids(&db.path),
            vec!["new-event".to_owned(), "old-event".to_owned()],
            "a zero-day retention window must not delete existing audit history"
        );
    }

    #[test]
    fn retention_pruning_compares_variable_precision_timestamps_chronologically() {
        let db = TempDb::new("retention-subsecond");
        drop(sqlite_sink(&db.path, None));

        insert_raw_event(&db.path, "older-event", "2024-06-01T11:59:59.5Z");
        insert_raw_event(&db.path, "cutoff-event", "2024-06-01T12:00:00Z");
        insert_raw_event(
            &db.path,
            "fractionally-newer-event",
            "2024-06-01T12:00:00.5Z",
        );
        insert_raw_event(&db.path, "later-event", "2024-06-01T12:00:01Z");

        let connection = Connection::open(&db.path).expect("test database should open");
        let cutoff_epoch_us = epoch_micros("2024-06-01T12:00:00Z").expect("cutoff should parse");
        let deleted = prune_retained_events(&connection, cutoff_epoch_us)
            .expect("retention prune should run");

        assert_eq!(deleted, 1);
        assert_eq!(
            event_ids(&db.path),
            vec![
                "cutoff-event".to_owned(),
                "fractionally-newer-event".to_owned(),
                "later-event".to_owned()
            ]
        );
    }

    #[test]
    fn epoch_micros_orders_audit_timestamp_variants() {
        let epochs = [
            "2024-06-01T12:00:00Z",
            "2024-06-01T12:00:00.123Z",
            "2024-06-01T12:00:00.123456789Z",
            "2024-06-01T12:00:00.4438138Z",
            "2024-06-01T12:00:00.5Z",
        ]
        .map(|timestamp| epoch_micros(timestamp).expect("timestamp should parse"));

        for pair in epochs.windows(2) {
            assert!(pair[0] < pair[1], "epoch microseconds should be ordered");
        }
    }

    #[test]
    fn malformed_timestamp_epoch_stays_null_and_is_not_pruned() {
        let db = TempDb::new("retention-malformed-timestamp");
        drop(sqlite_sink(&db.path, None));
        insert_raw_event(&db.path, "malformed-event", "not-a-timestamp");

        let connection = Connection::open(&db.path).expect("test database should open");
        assert_eq!(event_epoch(&connection, "malformed-event"), None);
        assert_eq!(
            prune_retained_events(&connection, i64::MAX)
                .expect("retention prune should preserve NULL epochs"),
            0
        );
        assert_eq!(event_ids(&db.path), vec!["malformed-event".to_owned()]);
    }

    #[test]
    fn prune_waits_for_prune_interval_even_when_flush_ticks_fire() {
        let db = TempDb::new("retention-cadence");
        let sink = sqlite_sink_with_intervals(
            &db.path,
            Some(1),
            StdDuration::from_millis(10),
            StdDuration::from_secs(5),
        );
        insert_raw_event(&db.path, "old-event", "2000-01-01T00:00:00Z");

        std::thread::sleep(StdDuration::from_millis(100));
        assert_eq!(event_ids(&db.path), vec!["old-event".to_owned()]);
        drop(sink);

        let _fast_prune = sqlite_sink_with_intervals(
            &db.path,
            Some(1),
            StdDuration::from_millis(10),
            StdDuration::from_millis(10),
        );
        assert_eventually(StdDuration::from_secs(1), || event_ids(&db.path).is_empty());
    }

    #[test]
    fn promoted_payload_columns_are_extracted_when_present() {
        let db = TempDb::new("payload-extraction");
        let sink = sqlite_sink_with_interval(&db.path, None, StdDuration::from_secs(60));

        sink.emit(&test_event(
            "audit.payload.present",
            json!({
                "method": "GET",
                "path": "/foo",
                "status": 200,
                "matched_rule_id": "allow-foo"
            }),
        ));
        sink.emit(&test_event(
            "audit.payload.missing",
            json!({ "test": true }),
        ));
        sink.flush_for_test();

        let connection = Connection::open(&db.path).expect("test database should open");
        let present = query_payload_columns(&connection, "audit.payload.present");
        assert_eq!(present.0.as_deref(), Some("GET"));
        assert_eq!(present.1.as_deref(), Some("/foo"));
        assert_eq!(present.2, Some(200));
        assert_eq!(present.3.as_deref(), Some("allow-foo"));

        let missing = query_payload_columns(&connection, "audit.payload.missing");
        assert_eq!(missing.0, None);
        assert_eq!(missing.1, None);
        assert_eq!(missing.2, None);
        assert_eq!(missing.3, None);
    }

    #[test]
    fn moderate_scale_batched_inserts_complete_quickly() {
        let db = TempDb::new("scale");
        let sink = sqlite_sink_with_interval(&db.path, None, StdDuration::from_secs(60));
        let event_count = 20_000;
        let started = Instant::now();

        for index in 0..event_count {
            sink.emit(&test_event(
                "audit.scale",
                json!({
                    "path": format!("/items/{}", index % 100),
                    "status": 200
                }),
            ));
        }
        sink.flush_for_test();

        assert_eq!(row_count(&db.path), event_count);
        assert!(
            started.elapsed() < StdDuration::from_secs(10),
            "batched insert sanity check took {:?}",
            started.elapsed()
        );
    }

    fn sqlite_sink(path: &Path, retention_days: Option<u32>) -> SqliteSink {
        SqliteSink::new(SqliteSinkConfig {
            path: path.to_owned(),
            retention_days,
        })
        .expect("SQLite sink should build")
    }

    fn sqlite_sink_with_interval(
        path: &Path,
        retention_days: Option<u32>,
        flush_interval: StdDuration,
    ) -> SqliteSink {
        sqlite_sink_with_intervals(path, retention_days, flush_interval, SQLITE_PRUNE_INTERVAL)
    }

    fn sqlite_sink_with_intervals(
        path: &Path,
        retention_days: Option<u32>,
        flush_interval: StdDuration,
        prune_interval: StdDuration,
    ) -> SqliteSink {
        SqliteSink::new_with_intervals(
            SqliteSinkConfig {
                path: path.to_owned(),
                retention_days,
            },
            flush_interval,
            prune_interval,
        )
        .expect("SQLite sink should build")
    }

    fn test_event(event_type: &str, payload: Value) -> AuditEvent {
        AuditEvent::new(
            event_type,
            "request-123",
            "203.0.113.10",
            Some(Actor {
                user_id: "user-123".to_owned(),
                issuer: None,
                email: None,
                roles: Some(vec!["reader".to_owned()]),
                auth_mode: "bearer_token".to_owned(),
            }),
            payload,
        )
    }

    fn row_count(path: &Path) -> i64 {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .expect("row count should query")
    }

    fn insert_raw_event(path: &Path, event_id: &str, timestamp: &str) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute(
                r#"
                INSERT INTO audit_events (
                    event_id,
                    event_type,
                    timestamp,
                    timestamp_epoch_us,
                    schema_version,
                    request_id,
                    source_ip,
                    payload_json
                ) VALUES (
                    ?1,
                    'audit.raw',
                    ?2,
                    CAST(ROUND((julianday(?2) - 2440587.5) * 86400000000.0) AS INTEGER),
                    '0.1.0',
                    'request-raw',
                    'internal',
                    '{}'
                )
                "#,
                params![event_id, timestamp],
            )
            .expect("raw event should insert");
    }

    fn create_old_schema(path: &Path) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT,
                    actor_user_id TEXT,
                    actor_json TEXT,
                    payload_path TEXT,
                    payload_status INTEGER,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);
                CREATE INDEX idx_audit_events_event_type ON audit_events(event_type);
                CREATE INDEX idx_audit_events_actor_user_id ON audit_events(actor_user_id);
                CREATE INDEX idx_audit_events_payload_path ON audit_events(payload_path);
                CREATE INDEX idx_audit_events_payload_status ON audit_events(payload_status);

                INSERT INTO audit_events (
                    event_id,
                    event_type,
                    timestamp,
                    schema_version,
                    request_id,
                    source_ip,
                    actor_user_id,
                    actor_json,
                    payload_path,
                    payload_status,
                    payload_json
                ) VALUES (
                    'old-event',
                    'http.request_observed',
                    '2026-01-01T00:00:00Z',
                    '0.1.0',
                    'request-old',
                    '203.0.113.10',
                    'user-123',
                    '{"user_id":"user-123","roles":["reader"],"auth_mode":"bearer_token"}',
                    '/data',
                    200,
                    '{"method":"GET","path":"/data","status":200,"matched_rule_id":"allow-data"}'
                );
                "#,
            )
            .expect("old schema should be created");
    }

    fn event_types_in_id_order(path: &Path) -> Vec<String> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare("SELECT event_type FROM audit_events ORDER BY id")
            .expect("event type query should prepare");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("event type query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("event type rows should read")
    }

    fn event_ids(path: &Path) -> Vec<String> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare("SELECT event_id FROM audit_events ORDER BY event_id")
            .expect("event_id query should prepare");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("event_id query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("event_id rows should read")
    }

    fn event_epoch(connection: &Connection, event_id: &str) -> Option<i64> {
        connection
            .query_row(
                "SELECT timestamp_epoch_us FROM audit_events WHERE event_id = ?1",
                params![event_id],
                |row| row.get(0),
            )
            .expect("timestamp epoch should query")
    }

    fn query_payload_columns(
        connection: &Connection,
        event_type: &str,
    ) -> (Option<String>, Option<String>, Option<i64>, Option<String>) {
        connection
            .query_row(
                r#"
                SELECT
                    payload_method,
                    payload_path,
                    payload_status,
                    payload_matched_rule_id
                FROM audit_events
                WHERE event_type = ?1
                "#,
                params![event_type],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("payload columns should query")
    }

    fn column_exists(connection: &Connection, column_name: &str) -> bool {
        let mut statement = connection
            .prepare("PRAGMA table_info(audit_events)")
            .expect("table info should prepare");
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("table info should query")
            .collect::<Result<Vec<_>, _>>()
            .expect("columns should read")
            .iter()
            .any(|column| column == column_name)
    }

    fn index_exists(connection: &Connection, index_name: &str) -> bool {
        let mut statement = connection
            .prepare("PRAGMA index_list(audit_events)")
            .expect("index list should prepare");
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("index list should query")
            .collect::<Result<Vec<_>, _>>()
            .expect("indexes should read")
            .iter()
            .any(|index| index == index_name)
    }

    fn assert_eventually(timeout: StdDuration, condition: impl Fn() -> bool) {
        let started = Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            std::thread::sleep(StdDuration::from_millis(10));
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-audit-sqlite-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = fs::remove_file(path);
            }
        }
    }
}
