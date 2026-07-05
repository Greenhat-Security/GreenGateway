use std::{
    error::Error,
    fmt, io,
    path::{Path, PathBuf},
    sync::{
        mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TryRecvError, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use rusqlite::{params, Connection};
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
    path: PathBuf,
    tx: SyncSender<PrincipalObservation>,
    shutdown_tx: Mutex<Option<Sender<()>>>,
    flusher: Mutex<Option<JoinHandle<()>>>,
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

        let (tx, rx) =
            mpsc::sync_channel::<PrincipalObservation>(PRINCIPAL_DIRECTORY_CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let flusher_path = path.clone();
        let flusher = thread::Builder::new()
            .name("principal-directory-sqlite-flusher".to_owned())
            .spawn(move || flusher_loop(flusher_path, connection, rx, shutdown_rx, flush_interval))
            .map_err(|source| PrincipalDirectoryError::ThreadSpawn { source })?;

        Ok(Self {
            inner: Some(Arc::new(PrincipalDirectoryInner {
                path,
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

impl Drop for PrincipalDirectoryInner {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = take_mutex_value(&self.shutdown_tx, "shutdown_tx", self) {
            let _ = shutdown_tx.send(());
        }

        if let Some(flusher) = take_mutex_value(&self.flusher, "flusher", self) {
            if flusher.join().is_err() {
                tracing::error!(
                    path = %self.path.display(),
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
    path: PathBuf,
    mut connection: Connection,
    rx: Receiver<PrincipalObservation>,
    shutdown_rx: Receiver<()>,
    flush_interval: StdDuration,
) {
    let mut buffer = Vec::with_capacity(PRINCIPAL_DIRECTORY_BATCH_SIZE);

    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(observation) => {
                push_observation(&path, &mut connection, &mut buffer, observation);
                drain_available_observations(&path, &mut connection, &rx, &mut buffer);
            }
            Err(RecvTimeoutError::Timeout) => {
                flush_buffer(&path, &mut connection, &mut buffer);
            }
            Err(RecvTimeoutError::Disconnected) => {
                flush_buffer(&path, &mut connection, &mut buffer);
                return;
            }
        }

        match shutdown_rx.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => {
                drain_available_observations(&path, &mut connection, &rx, &mut buffer);
                flush_buffer(&path, &mut connection, &mut buffer);
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
}

fn drain_available_observations(
    path: &Path,
    connection: &mut Connection,
    rx: &Receiver<PrincipalObservation>,
    buffer: &mut Vec<PrincipalObservation>,
) {
    loop {
        match rx.try_recv() {
            Ok(observation) => push_observation(path, connection, buffer, observation),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
        }
    }
}

fn push_observation(
    path: &Path,
    connection: &mut Connection,
    buffer: &mut Vec<PrincipalObservation>,
    observation: PrincipalObservation,
) {
    buffer.push(observation);

    if buffer.len() >= PRINCIPAL_DIRECTORY_BATCH_SIZE {
        flush_buffer(path, connection, buffer);
    }
}

fn flush_buffer(path: &Path, connection: &mut Connection, buffer: &mut Vec<PrincipalObservation>) {
    if buffer.is_empty() {
        return;
    }

    if let Err(err) = write_observations(connection, buffer) {
        ::metrics::counter!(
            PRINCIPAL_DIRECTORY_SQLITE_FLUSH_ERRORS_TOTAL,
            "operation" => "flush"
        )
        .increment(1);
        tracing::error!(
            path = %path.display(),
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
                path = %inner.path.display(),
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
