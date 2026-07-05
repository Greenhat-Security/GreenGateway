use std::{
    error::Error,
    fmt, io,
    path::PathBuf,
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{config::Config, metrics::LOCK_POISON_RECOVERIES_TOTAL};

use super::{AuthMethod, Principal};

pub const PRINCIPAL_DIRECTORY_EVENTS_DROPPED_TOTAL: &str =
    "principal_directory_events_dropped_total";
pub const PRINCIPAL_DIRECTORY_SQLITE_FLUSH_ERRORS_TOTAL: &str =
    "principal_directory_sqlite_flush_errors_total";

const PRINCIPAL_DIRECTORY_CHANNEL_CAPACITY: usize = 8192;
const PRINCIPAL_DIRECTORY_BATCH_SIZE: usize = 200;
const PRINCIPAL_DIRECTORY_FLUSH_INTERVAL: StdDuration = StdDuration::from_millis(250);

const CREATE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS principal_directory (
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    auth_method TEXT NOT NULL,
    email TEXT,
    org_id TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    request_count INTEGER NOT NULL,
    PRIMARY KEY (subject, issuer, auth_method)
);
"#;

const UPSERT_PRINCIPAL_SQL: &str = r#"
INSERT INTO principal_directory (
    subject,
    issuer,
    auth_method,
    email,
    org_id,
    first_seen,
    last_seen,
    request_count
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 1)
ON CONFLICT(subject, issuer, auth_method) DO UPDATE SET
    first_seen = CASE
        WHEN julianday(principal_directory.first_seen) <= julianday(excluded.first_seen)
            THEN principal_directory.first_seen
        ELSE excluded.first_seen
    END,
    last_seen = CASE
        WHEN julianday(principal_directory.last_seen) >= julianday(excluded.last_seen)
            THEN principal_directory.last_seen
        ELSE excluded.last_seen
    END,
    request_count = principal_directory.request_count + excluded.request_count,
    email = excluded.email,
    org_id = excluded.org_id
"#;

#[derive(Clone, Default)]
pub struct PrincipalDirectory {
    inner: Option<Arc<PrincipalDirectoryInner>>,
}

struct PrincipalDirectoryInner {
    shared: Arc<PrincipalDirectoryShared>,
    tx: SyncSender<PrincipalObservation>,
    shutdown_tx: Mutex<Option<Sender<()>>>,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

struct PrincipalDirectoryShared {
    path: PathBuf,
    connection: Mutex<Connection>,
}

#[derive(Debug)]
pub enum PrincipalDirectoryError {
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

impl fmt::Display for PrincipalDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => write!(
                formatter,
                "failed to open SQLite principal directory at {}: {source}",
                path.display()
            ),
            Self::Setup { path, source } => write!(
                formatter,
                "failed to initialize SQLite principal directory at {}: {source}",
                path.display()
            ),
            Self::ThreadSpawn { source } => write!(
                formatter,
                "failed to spawn SQLite principal directory flusher: {source}"
            ),
        }
    }
}

impl Error for PrincipalDirectoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Setup { source, .. } => Some(source),
            Self::ThreadSpawn { source } => Some(source),
        }
    }
}

#[derive(Debug)]
pub enum PrincipalDirectoryQueryError {
    NotConfigured,
    InvalidCursor {
        parameter: &'static str,
    },
    Sqlite {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Json {
        context: &'static str,
        source: serde_json::Error,
    },
}

impl fmt::Display for PrincipalDirectoryQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => write!(formatter, "principal directory is not configured"),
            Self::InvalidCursor { parameter } => {
                write!(
                    formatter,
                    "invalid principal directory cursor parameter {parameter}"
                )
            }
            Self::Sqlite { path, source } => write!(
                formatter,
                "failed to query SQLite principal directory at {}: {source}",
                path.display()
            ),
            Self::Json { context, source } => {
                write!(formatter, "failed to serialize {context}: {source}")
            }
        }
    }
}

impl Error for PrincipalDirectoryQueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::NotConfigured | Self::InvalidCursor { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalTypeFilter {
    Human,
    Service,
}

#[derive(Clone, Debug)]
pub struct PrincipalDirectoryListFilters {
    pub issuer: Option<String>,
    pub auth_method: Option<String>,
    pub principal_type: Option<PrincipalTypeFilter>,
    pub last_seen_after: Option<String>,
    pub last_seen_before: Option<String>,
    pub limit: usize,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PrincipalDirectoryKey {
    pub subject: String,
    pub issuer: String,
    pub auth_method: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrincipalDirectoryRecord {
    pub subject: String,
    pub issuer: String,
    pub auth_method: String,
    pub email: Option<String>,
    pub org_id: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub request_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrincipalDirectoryListPage {
    pub principals: Vec<PrincipalDirectoryRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct PrincipalDirectoryCursor {
    last_seen: String,
    subject: String,
    issuer: String,
    auth_method: String,
}

impl PrincipalDirectory {
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    pub fn from_config(config: &Config) -> Result<Self, PrincipalDirectoryError> {
        match config.principal_sqlite_path.as_deref() {
            Some(path) => Self::open(PathBuf::from(path)),
            None => Ok(Self::disabled()),
        }
    }

    pub fn open(path: PathBuf) -> Result<Self, PrincipalDirectoryError> {
        Self::open_with_flush_interval(path, PRINCIPAL_DIRECTORY_FLUSH_INTERVAL)
    }

    fn open_with_flush_interval(
        path: PathBuf,
        flush_interval: StdDuration,
    ) -> Result<Self, PrincipalDirectoryError> {
        let connection =
            Connection::open(&path).map_err(|source| PrincipalDirectoryError::Open {
                path: path.clone(),
                source,
            })?;
        configure_connection(&connection).map_err(|source| PrincipalDirectoryError::Setup {
            path: path.clone(),
            source,
        })?;
        let shared = Arc::new(PrincipalDirectoryShared {
            path: path.clone(),
            connection: Mutex::new(connection),
        });

        let (tx, rx) =
            mpsc::sync_channel::<PrincipalObservation>(PRINCIPAL_DIRECTORY_CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let flusher_shared = Arc::clone(&shared);
        let flusher = thread::Builder::new()
            .name("principal-directory-sqlite-flusher".to_owned())
            .spawn(move || flusher_loop(flusher_shared, rx, shutdown_rx, flush_interval))
            .map_err(|source| PrincipalDirectoryError::ThreadSpawn { source })?;

        Ok(Self {
            inner: Some(Arc::new(PrincipalDirectoryInner {
                shared,
                tx,
                shutdown_tx: Mutex::new(Some(shutdown_tx)),
                flusher: Mutex::new(Some(flusher)),
            })),
        })
    }

    pub fn observe(&self, principal: &Principal) {
        let Some(inner) = &self.inner else {
            return;
        };

        inner.observe(PrincipalObservation::from_principal(principal));
    }

    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    pub fn list(
        &self,
        filters: &PrincipalDirectoryListFilters,
    ) -> Result<PrincipalDirectoryListPage, PrincipalDirectoryQueryError> {
        let Some(inner) = &self.inner else {
            return Err(PrincipalDirectoryQueryError::NotConfigured);
        };

        inner.shared.list(filters)
    }

    pub fn get(
        &self,
        key: &PrincipalDirectoryKey,
    ) -> Result<Option<PrincipalDirectoryRecord>, PrincipalDirectoryQueryError> {
        let Some(inner) = &self.inner else {
            return Err(PrincipalDirectoryQueryError::NotConfigured);
        };

        inner.shared.get(key)
    }
}

impl PrincipalDirectoryInner {
    fn observe(&self, observation: PrincipalObservation) {
        match self.tx.try_send(observation) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                ::metrics::counter!(
                    PRINCIPAL_DIRECTORY_EVENTS_DROPPED_TOTAL,
                    "reason" => "full"
                )
                .increment(1);
            }
            Err(TrySendError::Disconnected(_)) => {
                ::metrics::counter!(
                    PRINCIPAL_DIRECTORY_EVENTS_DROPPED_TOTAL,
                    "reason" => "disconnected"
                )
                .increment(1);
            }
        }
    }
}

impl PrincipalDirectoryShared {
    fn list(
        &self,
        filters: &PrincipalDirectoryListFilters,
    ) -> Result<PrincipalDirectoryListPage, PrincipalDirectoryQueryError> {
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<PrincipalDirectoryCursor>("cursor", value))
            .transpose()?;
        let (sql, params) = build_principal_list_query(filters, cursor.as_ref());
        let rows = {
            let connection = self.connection_guard();
            let mut statement = connection.prepare(&sql).map_err(|source| {
                PrincipalDirectoryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                }
            })?;
            let rows = statement
                .query_map(params_from_iter(params.iter()), principal_record_from_row)
                .map_err(|source| PrincipalDirectoryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| PrincipalDirectoryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            rows
        };

        let mut principals = rows;
        let has_more = principals.len() > filters.limit;
        if has_more {
            principals.truncate(filters.limit);
        }
        let next_cursor = if has_more {
            principals
                .last()
                .map(|record| {
                    encode_cursor(&PrincipalDirectoryCursor {
                        last_seen: record.last_seen.clone(),
                        subject: record.subject.clone(),
                        issuer: record.issuer.clone(),
                        auth_method: record.auth_method.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };

        Ok(PrincipalDirectoryListPage {
            principals,
            next_cursor,
        })
    }

    fn get(
        &self,
        key: &PrincipalDirectoryKey,
    ) -> Result<Option<PrincipalDirectoryRecord>, PrincipalDirectoryQueryError> {
        let connection = self.connection_guard();
        connection
            .query_row(
                r#"
                SELECT subject, issuer, auth_method, email, org_id, first_seen, last_seen, request_count
                FROM principal_directory
                WHERE subject = ?1 AND issuer = ?2 AND auth_method = ?3
                "#,
                params![
                    key.subject.as_str(),
                    key.issuer.as_str(),
                    key.auth_method.as_str()
                ],
                principal_record_from_row,
            )
            .optional()
            .map_err(|source| PrincipalDirectoryQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "principal_directory",
                    "lock" => "connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite principal directory connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

impl Drop for PrincipalDirectoryInner {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = take_mutex_value(&self.shutdown_tx, "shutdown_tx", self) {
            let _ = shutdown_tx.send(());
        }

        if let Some(flusher) = take_mutex_value(&self.flusher, "flusher", self) {
            if flusher.join().is_err() {
                tracing::error!(
                    path = %self.shared.path.display(),
                    "SQLite principal directory flusher thread panicked during shutdown"
                );
            }
        }
    }
}

#[derive(Clone, Debug)]
struct PrincipalObservation {
    subject: String,
    issuer: String,
    auth_method: String,
    email: Option<String>,
    org_id: Option<String>,
    seen_at: String,
}

impl PrincipalObservation {
    fn from_principal(principal: &Principal) -> Self {
        Self {
            subject: principal.user_id.clone(),
            issuer: principal.issuer.clone().unwrap_or_default(),
            auth_method: auth_method_label(&principal.auth_method).to_owned(),
            email: principal.email.clone(),
            org_id: principal.org_id.clone(),
            seen_at: now_rfc3339(),
        }
    }
}

fn flusher_loop(
    shared: Arc<PrincipalDirectoryShared>,
    rx: Receiver<PrincipalObservation>,
    shutdown_rx: Receiver<()>,
    flush_interval: StdDuration,
) {
    let mut buffer = Vec::with_capacity(PRINCIPAL_DIRECTORY_BATCH_SIZE);

    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(observation) => {
                push_observation(&shared, &mut buffer, observation);
                drain_available_observations(&shared, &rx, &mut buffer);
            }
            Err(RecvTimeoutError::Timeout) => {
                flush_buffer(&shared, &mut buffer);
            }
            Err(RecvTimeoutError::Disconnected) => {
                flush_buffer(&shared, &mut buffer);
                return;
            }
        }

        match shutdown_rx.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                drain_available_observations(&shared, &rx, &mut buffer);
                flush_buffer(&shared, &mut buffer);
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
}

fn drain_available_observations(
    shared: &PrincipalDirectoryShared,
    rx: &Receiver<PrincipalObservation>,
    buffer: &mut Vec<PrincipalObservation>,
) {
    loop {
        match rx.try_recv() {
            Ok(observation) => push_observation(shared, buffer, observation),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn push_observation(
    shared: &PrincipalDirectoryShared,
    buffer: &mut Vec<PrincipalObservation>,
    observation: PrincipalObservation,
) {
    buffer.push(observation);

    if buffer.len() >= PRINCIPAL_DIRECTORY_BATCH_SIZE {
        flush_buffer(shared, buffer);
    }
}

fn flush_buffer(shared: &PrincipalDirectoryShared, buffer: &mut Vec<PrincipalObservation>) {
    if buffer.is_empty() {
        return;
    }

    let result = {
        let mut connection = shared.connection_guard();
        write_observations(&mut connection, buffer)
    };

    if let Err(err) = result {
        ::metrics::counter!(
            PRINCIPAL_DIRECTORY_SQLITE_FLUSH_ERRORS_TOTAL,
            "operation" => "flush"
        )
        .increment(1);
        tracing::error!(
            path = %shared.path.display(),
            observation_count = buffer.len(),
            error = %err,
            "failed to flush SQLite principal directory observations; dropping batch"
        );
    }

    buffer.clear();
}

fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        "#,
    )?;
    connection.execute_batch(CREATE_SCHEMA_SQL)
}

fn write_observations(
    connection: &mut Connection,
    observations: &[PrincipalObservation],
) -> rusqlite::Result<()> {
    let transaction = connection.transaction()?;

    {
        let mut statement = transaction.prepare_cached(UPSERT_PRINCIPAL_SQL)?;

        for observation in observations {
            statement.execute(params![
                observation.subject.as_str(),
                observation.issuer.as_str(),
                observation.auth_method.as_str(),
                observation.email.as_deref(),
                observation.org_id.as_deref(),
                observation.seen_at.as_str(),
            ])?;
        }
    }

    transaction.commit()
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC timestamp should format as RFC 3339")
}

fn auth_method_label(auth_method: &AuthMethod) -> &'static str {
    match auth_method {
        AuthMethod::Cookie => "cookie",
        AuthMethod::Bearer => "bearer",
        AuthMethod::ServiceToken => "service_token",
    }
}

fn build_principal_list_query(
    filters: &PrincipalDirectoryListFilters,
    cursor: Option<&PrincipalDirectoryCursor>,
) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT subject, issuer, auth_method, email, org_id, first_seen, last_seen, request_count
        FROM principal_directory
        "#,
    );
    let mut clauses = Vec::new();
    let mut params = Vec::new();

    if let Some(issuer) = &filters.issuer {
        clauses.push("issuer = ?");
        params.push(SqlValue::Text(issuer.clone()));
    }
    if let Some(auth_method) = &filters.auth_method {
        clauses.push("auth_method = ?");
        params.push(SqlValue::Text(auth_method.clone()));
    }
    if let Some(principal_type) = filters.principal_type {
        match principal_type {
            PrincipalTypeFilter::Human => {
                clauses.push("auth_method IN ('bearer', 'cookie')");
            }
            PrincipalTypeFilter::Service => {
                clauses.push("auth_method = 'service_token'");
            }
        }
    }
    if let Some(last_seen_after) = &filters.last_seen_after {
        clauses.push("julianday(last_seen) >= julianday(?)");
        params.push(SqlValue::Text(last_seen_after.clone()));
    }
    if let Some(last_seen_before) = &filters.last_seen_before {
        clauses.push("julianday(last_seen) <= julianday(?)");
        params.push(SqlValue::Text(last_seen_before.clone()));
    }
    if let Some(cursor) = cursor {
        clauses.push(
            r#"
            (
                julianday(last_seen) < julianday(?)
                OR (
                    julianday(last_seen) = julianday(?)
                    AND (
                        subject > ?
                        OR (subject = ? AND issuer > ?)
                        OR (subject = ? AND issuer = ? AND auth_method > ?)
                    )
                )
            )
            "#,
        );
        params.push(SqlValue::Text(cursor.last_seen.clone()));
        params.push(SqlValue::Text(cursor.last_seen.clone()));
        params.push(SqlValue::Text(cursor.subject.clone()));
        params.push(SqlValue::Text(cursor.subject.clone()));
        params.push(SqlValue::Text(cursor.issuer.clone()));
        params.push(SqlValue::Text(cursor.subject.clone()));
        params.push(SqlValue::Text(cursor.issuer.clone()));
        params.push(SqlValue::Text(cursor.auth_method.clone()));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }

    sql.push_str(
        " ORDER BY julianday(last_seen) DESC, subject ASC, issuer ASC, auth_method ASC LIMIT ?",
    );
    params.push(SqlValue::Integer(query_limit(filters.limit)));

    (sql, params)
}

fn principal_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PrincipalDirectoryRecord> {
    let request_count: i64 = row.get(7)?;
    Ok(PrincipalDirectoryRecord {
        subject: row.get(0)?,
        issuer: row.get(1)?,
        auth_method: row.get(2)?,
        email: row.get(3)?,
        org_id: row.get(4)?,
        first_seen: row.get(5)?,
        last_seen: row.get(6)?,
        request_count: u64::try_from(request_count).unwrap_or(0),
    })
}

fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String, PrincipalDirectoryQueryError> {
    let json = serde_json::to_vec(cursor).map_err(|source| PrincipalDirectoryQueryError::Json {
        context: "cursor",
        source,
    })?;

    Ok(hex::encode(json))
}

fn decode_cursor<T: DeserializeOwned>(
    parameter: &'static str,
    value: &str,
) -> Result<T, PrincipalDirectoryQueryError> {
    let bytes = hex::decode(value)
        .map_err(|_| PrincipalDirectoryQueryError::InvalidCursor { parameter })?;
    serde_json::from_slice(&bytes)
        .map_err(|_| PrincipalDirectoryQueryError::InvalidCursor { parameter })
}

fn query_limit(limit: usize) -> i64 {
    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
}

fn take_mutex_value<T>(
    mutex: &Mutex<Option<T>>,
    lock_name: &'static str,
    inner: &PrincipalDirectoryInner,
) -> Option<T> {
    match mutex.lock() {
        Ok(mut guard) => guard.take(),
        Err(poisoned) => {
            ::metrics::counter!(
                LOCK_POISON_RECOVERIES_TOTAL,
                "component" => "principal_directory",
                "lock" => lock_name
            )
            .increment(1);
            tracing::error!(
                path = %inner.shared.path.display(),
                lock = lock_name,
                "SQLite principal directory shutdown lock poisoned; recovering"
            );
            let mut guard = poisoned.into_inner();
            guard.take()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, time::Duration};

    use rusqlite::Connection;

    use super::*;

    #[test]
    fn upsert_inserts_fresh_principal_row() {
        let mut connection = Connection::open_in_memory().expect("in-memory db should open");
        configure_connection(&connection).expect("principal schema should initialize");

        write_observations(
            &mut connection,
            &[observation(
                "user-123",
                Some("https://issuer.example.test/"),
                "bearer",
                Some("first@example.test"),
                Some("org-a"),
                "2026-01-01T00:00:00Z",
            )],
        )
        .expect("principal observation should upsert");

        assert_eq!(
            principal_rows(&connection),
            vec![PrincipalRow {
                subject: "user-123".to_owned(),
                issuer: "https://issuer.example.test/".to_owned(),
                auth_method: "bearer".to_owned(),
                email: Some("first@example.test".to_owned()),
                org_id: Some("org-a".to_owned()),
                first_seen: "2026-01-01T00:00:00Z".to_owned(),
                last_seen: "2026-01-01T00:00:00Z".to_owned(),
                request_count: 1,
            }]
        );
    }

    #[test]
    fn upsert_repeats_increment_count_and_refresh_latest_profile_fields() {
        let mut connection = Connection::open_in_memory().expect("in-memory db should open");
        configure_connection(&connection).expect("principal schema should initialize");

        write_observations(
            &mut connection,
            &[
                observation(
                    "user-123",
                    Some("https://issuer.example.test/"),
                    "bearer",
                    Some("old@example.test"),
                    Some("org-old"),
                    "2026-01-01T00:00:00Z",
                ),
                observation(
                    "user-123",
                    Some("https://issuer.example.test/"),
                    "bearer",
                    Some("new@example.test"),
                    Some("org-new"),
                    "2026-01-01T00:05:00Z",
                ),
            ],
        )
        .expect("principal observations should upsert");

        assert_eq!(
            principal_rows(&connection),
            vec![PrincipalRow {
                subject: "user-123".to_owned(),
                issuer: "https://issuer.example.test/".to_owned(),
                auth_method: "bearer".to_owned(),
                email: Some("new@example.test".to_owned()),
                org_id: Some("org-new".to_owned()),
                first_seen: "2026-01-01T00:00:00Z".to_owned(),
                last_seen: "2026-01-01T00:05:00Z".to_owned(),
                request_count: 2,
            }]
        );
    }

    #[test]
    fn composite_key_keeps_same_subject_distinct_by_issuer_and_auth_method() {
        let mut connection = Connection::open_in_memory().expect("in-memory db should open");
        configure_connection(&connection).expect("principal schema should initialize");

        write_observations(
            &mut connection,
            &[
                observation(
                    "shared-subject",
                    Some("https://issuer-a.example.test/"),
                    "bearer",
                    None,
                    None,
                    "2026-01-01T00:00:00Z",
                ),
                observation(
                    "shared-subject",
                    Some("https://issuer-b.example.test/"),
                    "bearer",
                    None,
                    None,
                    "2026-01-01T00:00:01Z",
                ),
                observation(
                    "shared-subject",
                    None,
                    "service_token",
                    None,
                    None,
                    "2026-01-01T00:00:02Z",
                ),
            ],
        )
        .expect("distinct principal observations should upsert");

        let rows = principal_rows(&connection);
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().any(|row| {
            row.subject == "shared-subject"
                && row.issuer == "https://issuer-a.example.test/"
                && row.auth_method == "bearer"
        }));
        assert!(rows.iter().any(|row| {
            row.subject == "shared-subject"
                && row.issuer == "https://issuer-b.example.test/"
                && row.auth_method == "bearer"
        }));
        assert!(rows.iter().any(|row| {
            row.subject == "shared-subject"
                && row.issuer.is_empty()
                && row.auth_method == "service_token"
        }));
    }

    #[test]
    fn list_filters_principals_by_issuer_auth_method_type_and_activity_window() {
        let directory = seeded_directory(
            "list-filters",
            &[
                observation(
                    "alpha",
                    Some("https://issuer-a.example.test/"),
                    "bearer",
                    Some("alpha@example.test"),
                    Some("org-a"),
                    "2026-01-04T00:00:00Z",
                ),
                observation(
                    "bravo",
                    Some("https://issuer-a.example.test/"),
                    "service_token",
                    None,
                    Some("org-a"),
                    "2026-01-03T00:00:00Z",
                ),
                observation(
                    "charlie",
                    Some("https://issuer-b.example.test/"),
                    "cookie",
                    Some("charlie@example.test"),
                    Some("org-b"),
                    "2026-01-02T00:00:00Z",
                ),
                observation(
                    "delta",
                    Some("https://issuer-a.example.test/"),
                    "bearer",
                    None,
                    None,
                    "2026-01-01T00:00:00Z",
                ),
            ],
        );

        let issuer_page = directory
            .list(&PrincipalDirectoryListFilters {
                issuer: Some("https://issuer-a.example.test/".to_owned()),
                auth_method: None,
                principal_type: None,
                last_seen_after: None,
                last_seen_before: None,
                limit: 50,
                cursor: None,
            })
            .expect("issuer-filtered principals should query");
        assert_eq!(
            record_subjects(&issuer_page.principals),
            vec!["alpha", "bravo", "delta"]
        );

        let service_page = directory
            .list(&PrincipalDirectoryListFilters {
                issuer: None,
                auth_method: Some("service_token".to_owned()),
                principal_type: None,
                last_seen_after: None,
                last_seen_before: None,
                limit: 50,
                cursor: None,
            })
            .expect("auth-method-filtered principals should query");
        assert_eq!(record_subjects(&service_page.principals), vec!["bravo"]);

        let human_page = directory
            .list(&PrincipalDirectoryListFilters {
                issuer: None,
                auth_method: None,
                principal_type: Some(PrincipalTypeFilter::Human),
                last_seen_after: None,
                last_seen_before: None,
                limit: 50,
                cursor: None,
            })
            .expect("human principals should query");
        assert_eq!(
            record_subjects(&human_page.principals),
            vec!["alpha", "charlie", "delta"]
        );

        let combined_page = directory
            .list(&PrincipalDirectoryListFilters {
                issuer: Some("https://issuer-a.example.test/".to_owned()),
                auth_method: Some("bearer".to_owned()),
                principal_type: Some(PrincipalTypeFilter::Human),
                last_seen_after: Some("2026-01-01T12:00:00Z".to_owned()),
                last_seen_before: Some("2026-01-04T12:00:00Z".to_owned()),
                limit: 50,
                cursor: None,
            })
            .expect("combined principal filters should query");
        assert_eq!(record_subjects(&combined_page.principals), vec!["alpha"]);
    }

    #[test]
    fn list_paginates_with_stable_opaque_cursor() {
        let directory = seeded_directory(
            "list-pagination",
            &[
                observation("alpha", None, "bearer", None, None, "2026-01-03T00:00:00Z"),
                observation("bravo", None, "bearer", None, None, "2026-01-02T00:00:00Z"),
                observation(
                    "charlie",
                    None,
                    "bearer",
                    None,
                    None,
                    "2026-01-02T00:00:00Z",
                ),
                observation("delta", None, "bearer", None, None, "2026-01-01T00:00:00Z"),
            ],
        );

        let first_page = directory
            .list(&PrincipalDirectoryListFilters {
                issuer: None,
                auth_method: None,
                principal_type: None,
                last_seen_after: None,
                last_seen_before: None,
                limit: 2,
                cursor: None,
            })
            .expect("first principal page should query");
        assert_eq!(
            record_subjects(&first_page.principals),
            vec!["alpha", "bravo"]
        );
        let cursor = first_page
            .next_cursor
            .expect("first page should include cursor");

        let second_page = directory
            .list(&PrincipalDirectoryListFilters {
                issuer: None,
                auth_method: None,
                principal_type: None,
                last_seen_after: None,
                last_seen_before: None,
                limit: 2,
                cursor: Some(cursor),
            })
            .expect("second principal page should query");
        assert_eq!(
            record_subjects(&second_page.principals),
            vec!["charlie", "delta"]
        );
        assert!(second_page.next_cursor.is_none());
    }

    #[test]
    fn get_returns_one_principal_by_exact_composite_key() {
        let directory = seeded_directory(
            "get-one",
            &[
                observation(
                    "shared",
                    Some("https://issuer-a.example.test/"),
                    "bearer",
                    Some("a@example.test"),
                    None,
                    "2026-01-01T00:00:00Z",
                ),
                observation(
                    "shared",
                    Some("https://issuer-b.example.test/"),
                    "bearer",
                    Some("b@example.test"),
                    None,
                    "2026-01-01T00:01:00Z",
                ),
            ],
        );

        let record = directory
            .get(&PrincipalDirectoryKey {
                subject: "shared".to_owned(),
                issuer: "https://issuer-b.example.test/".to_owned(),
                auth_method: "bearer".to_owned(),
            })
            .expect("principal detail should query")
            .expect("principal should exist");

        assert_eq!(record.email.as_deref(), Some("b@example.test"));
        assert_eq!(record.issuer, "https://issuer-b.example.test/");
    }

    #[test]
    fn sink_flushes_observations_asynchronously() {
        let db = TempDb::new("async-flush");
        let directory = PrincipalDirectory::open_with_flush_interval(
            db.path.clone(),
            Duration::from_millis(20),
        )
        .expect("principal directory should open");

        directory.observe(&crate::auth::Principal {
            user_id: "async-user".to_owned(),
            issuer: Some("https://issuer.example.test/".to_owned()),
            email: Some("async@example.test".to_owned()),
            org_id: Some("org-async".to_owned()),
            roles: vec!["member".to_owned()],
            session_id: "session-async".to_owned(),
            auth_method: crate::auth::AuthMethod::Bearer,
        });

        assert_eventually(Duration::from_secs(1), || row_count(&db.path) == 1);
    }

    fn seeded_directory(test_name: &str, observations: &[PrincipalObservation]) -> SeededDirectory {
        let db = TempDb::new(test_name);
        let directory = PrincipalDirectory::open_with_flush_interval(
            db.path.clone(),
            Duration::from_millis(20),
        )
        .expect("principal directory should open");
        {
            let shared = &directory
                .inner
                .as_ref()
                .expect("directory should be enabled")
                .shared;
            let mut connection = shared.connection_guard();
            write_observations(&mut connection, observations)
                .expect("principal observations should seed");
        }
        SeededDirectory { directory, _db: db }
    }

    fn record_subjects(records: &[PrincipalDirectoryRecord]) -> Vec<&str> {
        records
            .iter()
            .map(|record| record.subject.as_str())
            .collect()
    }

    struct SeededDirectory {
        directory: PrincipalDirectory,
        _db: TempDb,
    }

    impl std::ops::Deref for SeededDirectory {
        type Target = PrincipalDirectory;

        fn deref(&self) -> &Self::Target {
            &self.directory
        }
    }

    fn observation(
        subject: &str,
        issuer: Option<&str>,
        auth_method: &str,
        email: Option<&str>,
        org_id: Option<&str>,
        seen_at: &str,
    ) -> PrincipalObservation {
        PrincipalObservation {
            subject: subject.to_owned(),
            issuer: issuer.unwrap_or_default().to_owned(),
            auth_method: auth_method.to_owned(),
            email: email.map(str::to_owned),
            org_id: org_id.map(str::to_owned),
            seen_at: seen_at.to_owned(),
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct PrincipalRow {
        subject: String,
        issuer: String,
        auth_method: String,
        email: Option<String>,
        org_id: Option<String>,
        first_seen: String,
        last_seen: String,
        request_count: i64,
    }

    fn principal_rows(connection: &Connection) -> Vec<PrincipalRow> {
        let mut statement = connection
            .prepare(
                r#"
                SELECT subject, issuer, auth_method, email, org_id, first_seen, last_seen, request_count
                FROM principal_directory
                ORDER BY subject, issuer, auth_method
                "#,
            )
            .expect("principal row query should prepare");

        statement
            .query_map([], |row| {
                Ok(PrincipalRow {
                    subject: row.get(0)?,
                    issuer: row.get(1)?,
                    auth_method: row.get(2)?,
                    email: row.get(3)?,
                    org_id: row.get(4)?,
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                    request_count: row.get(7)?,
                })
            })
            .expect("principal row query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("principal rows should read")
    }

    fn row_count(path: &Path) -> i64 {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .query_row("SELECT COUNT(*) FROM principal_directory", [], |row| {
                row.get(0)
            })
            .expect("row count should query")
    }

    fn assert_eventually(timeout: Duration, condition: impl Fn() -> bool) {
        let started = std::time::Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }

    struct TempDb {
        path: std::path::PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-principal-directory-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = std::path::PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
