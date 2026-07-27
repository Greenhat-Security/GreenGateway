use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use super::{
    model::{
        ConnectionAuthentication, ConnectionId, ConnectionManagementSource, ConnectionWrite,
        DiscoveryConfig, CONNECTION_SCHEMA_VERSION, MAX_CATALOG_ENTRIES, MAX_CONNECTIONS,
        MAX_CREDENTIALS, MAX_STATUS_HISTORY_ROWS,
    },
    status::{
        ConnectionOperationalState, ConnectionRevisions, ConnectionStatusReason,
        SafeAuthenticationKind, SafeConnectionStatus, SafeConnectionSummary,
    },
};

const CONFIGURE_SQL: &str = r#"
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
"#;

const CREATE_MIGRATIONS_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS connection_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"#;

const MIGRATION_1_SQL: &str = r#"
CREATE TABLE connection_records (
    id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    source TEXT NOT NULL CHECK (source = 'managed'),
    spec_json TEXT NOT NULL,
    connection_revision INTEGER NOT NULL CHECK (connection_revision >= 1),
    credential_revision INTEGER NOT NULL CHECK (credential_revision >= 0),
    tls_revision INTEGER NOT NULL CHECK (tls_revision >= 0),
    discovery_revision INTEGER NOT NULL CHECK (discovery_revision >= 0),
    status_revision INTEGER NOT NULL CHECK (status_revision >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (length(id) BETWEEN 1 AND 128)
);

CREATE TABLE connection_credential_bindings (
    connection_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    secret_id TEXT NOT NULL,
    binding_version INTEGER NOT NULL CHECK (binding_version >= 1),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (connection_id, purpose),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE TABLE connection_dependencies (
    connection_id TEXT NOT NULL,
    consumer_kind TEXT NOT NULL,
    consumer_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (connection_id, consumer_kind, consumer_id),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE RESTRICT
);

CREATE INDEX idx_connection_dependencies_connection
ON connection_dependencies(connection_id, consumer_kind, consumer_id);
"#;

const MIGRATION_2_SQL: &str = r#"
CREATE TABLE connection_status_history (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    state TEXT NOT NULL,
    reason TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    latency_ms INTEGER,
    catalog_age_secs INTEGER,
    catalog_entry_count INTEGER,
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_connection_status_revision
ON connection_status_history(connection_id, status_revision);

CREATE INDEX idx_connection_status_latest
ON connection_status_history(connection_id, status_revision DESC);
"#;

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: MIGRATION_1_SQL,
    },
    Migration {
        version: 2,
        sql: MIGRATION_2_SQL,
    },
];

const SOURCE_MANAGED: &str = "managed";
const MAX_DEPENDENCY_FIELD_BYTES: usize = 256;

#[derive(Clone, Copy)]
struct Migration {
    version: u32,
    sql: &'static str,
}

#[derive(Clone)]
pub struct SqliteConnectionStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
    maximum_connections: usize,
}

pub trait ConnectionStore: Send + Sync {
    fn count(&self) -> Result<usize, ConnectionStoreError>;
    fn list(&self) -> Result<Vec<StoredConnection>, ConnectionStoreError>;
    fn get(&self, id: &ConnectionId) -> Result<Option<StoredConnection>, ConnectionStoreError>;
    fn create(&self, candidate: ConnectionWrite) -> Result<StoredConnection, ConnectionStoreError>;
    fn replace(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        candidate: ConnectionWrite,
    ) -> Result<StoredConnection, ConnectionStoreError>;
    fn delete(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
    ) -> Result<(), ConnectionStoreError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionEtag(String);

impl ConnectionEtag {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn for_record(id: &ConnectionId, revisions: &ConnectionRevisions) -> Self {
        Self(format!(
            "\"connection:{}:c{}:k{}:t{}:d{}\"",
            id.as_str(),
            revisions.connection,
            revisions.credential,
            revisions.tls,
            revisions.discovery
        ))
    }
}

impl fmt::Display for ConnectionEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredConnection {
    pub id: ConnectionId,
    pub write: ConnectionWrite,
    pub revisions: ConnectionRevisions,
    pub created_at: String,
    pub updated_at: String,
}

impl StoredConnection {
    pub fn etag(&self) -> ConnectionEtag {
        ConnectionEtag::for_record(&self.id, &self.revisions)
    }

    pub fn safe_summary(&self, status: Option<SafeConnectionStatus>) -> SafeConnectionSummary {
        let status = status.unwrap_or({
            if self.write.enabled {
                SafeConnectionStatus {
                    state: ConnectionOperationalState::Unknown,
                    reason: ConnectionStatusReason::NotTested,
                    observed_at: None,
                    latency_ms: None,
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                }
            } else {
                SafeConnectionStatus {
                    state: ConnectionOperationalState::Disabled,
                    reason: ConnectionStatusReason::Disabled,
                    observed_at: None,
                    latency_ms: None,
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                }
            }
        });
        SafeConnectionSummary {
            id: self.id.clone(),
            display_name: self.write.display_name.clone(),
            enabled: self.write.enabled,
            kind: self.write.kind,
            source: ConnectionManagementSource::Managed,
            read_only: false,
            authentication: safe_authentication_kind(&self.write.authentication),
            endpoint_count: 1,
            revisions: self.revisions.clone(),
            status,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionDependencyKind {
    ProxyRoute,
    ManualTool,
    ManagedTool,
    ControlPlane,
}

impl ConnectionDependencyKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProxyRoute => "proxy_route",
            Self::ManualTool => "manual_tool",
            Self::ManagedTool => "managed_tool",
            Self::ControlPlane => "control_plane",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionStatusUpdate {
    pub state: ConnectionOperationalState,
    pub reason: ConnectionStatusReason,
    pub latency_ms: Option<u64>,
    pub catalog_age_secs: Option<u64>,
    pub catalog_entry_count: Option<usize>,
}

#[derive(Debug)]
pub enum ConnectionStoreError {
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Sqlite {
        path: PathBuf,
        operation: &'static str,
        source: rusqlite::Error,
    },
    Json {
        operation: &'static str,
        source: serde_json::Error,
    },
    Validation {
        problems: Vec<String>,
    },
    CorruptRecord {
        id: String,
        reason: &'static str,
    },
    UnsupportedSchema {
        version: u32,
    },
    InvalidMigrationHistory,
    LimitExceeded {
        resource: &'static str,
        maximum: usize,
    },
    NotFound {
        id: String,
    },
    Conflict {
        id: String,
        current: ConnectionEtag,
    },
    DependencyConflict {
        id: String,
        count: usize,
    },
    RevisionOverflow {
        id: String,
    },
}

impl fmt::Display for ConnectionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => write!(
                formatter,
                "failed to open configured connection SQLite store at {}: {source}",
                path.display()
            ),
            Self::Sqlite {
                path,
                operation,
                source,
            } => write!(
                formatter,
                "connection SQLite {operation} failed at {}: {source}",
                path.display()
            ),
            Self::Json { operation, source } => {
                write!(
                    formatter,
                    "connection {operation} serialization failed: {source}"
                )
            }
            Self::Validation { problems } => write!(
                formatter,
                "connection candidate failed validation: {}",
                problems.join("; ")
            ),
            Self::CorruptRecord { id, reason } => {
                write!(formatter, "stored connection '{id}' is invalid: {reason}")
            }
            Self::UnsupportedSchema { version } => write!(
                formatter,
                "connection SQLite schema version {version} is newer or unknown"
            ),
            Self::InvalidMigrationHistory => formatter.write_str(
                "connection SQLite migration history is not a contiguous ordered prefix",
            ),
            Self::LimitExceeded { resource, maximum } => {
                write!(formatter, "{resource} limit of {maximum} has been reached")
            }
            Self::NotFound { id } => write!(formatter, "connection '{id}' was not found"),
            Self::Conflict { id, current } => write!(
                formatter,
                "connection '{id}' changed; current ETag is {current}"
            ),
            Self::DependencyConflict { id, count } => write!(
                formatter,
                "connection '{id}' is referenced by {count} retained control-plane records"
            ),
            Self::RevisionOverflow { id } => {
                write!(
                    formatter,
                    "connection '{id}' revision cannot be incremented"
                )
            }
        }
    }
}

impl Error for ConnectionStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Sqlite { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl SqliteConnectionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ConnectionStoreError> {
        Self::open_with_maximum(path, MAX_CONNECTIONS)
    }

    pub fn open_with_maximum(
        path: impl AsRef<Path>,
        maximum_connections: usize,
    ) -> Result<Self, ConnectionStoreError> {
        if maximum_connections > MAX_CONNECTIONS {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "managed connections",
                maximum: MAX_CONNECTIONS,
            });
        }
        let path = path.as_ref().to_path_buf();
        let mut connection =
            Connection::open(&path).map_err(|source| ConnectionStoreError::Open {
                path: path.clone(),
                source,
            })?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|source| sqlite_error(&path, "configuration", source))?;
        connection
            .execute_batch(CONFIGURE_SQL)
            .map_err(|source| sqlite_error(&path, "configuration", source))?;
        run_migrations(&mut connection, &path, MIGRATIONS)?;
        validate_schema(&connection, &path)?;

        Ok(Self {
            path,
            connection: Arc::new(Mutex::new(connection)),
            maximum_connections,
        })
    }

    pub fn maximum_connections(&self) -> usize {
        self.maximum_connections
    }

    pub fn add_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        validate_dependency_id(consumer_id)?;
        let now = utc_timestamp()?;
        let connection = self.connection_guard();
        connection
            .execute(
                r#"
                INSERT INTO connection_dependencies (
                    connection_id, consumer_kind, consumer_id, created_at
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(connection_id, consumer_kind, consumer_id) DO NOTHING
                "#,
                params![id.as_str(), kind.as_str(), consumer_id, now],
            )
            .map_err(|source| sqlite_error(&self.path, "dependency insert", source))?;
        Ok(())
    }

    pub fn remove_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        validate_dependency_id(consumer_id)?;
        let connection = self.connection_guard();
        connection
            .execute(
                r#"
                DELETE FROM connection_dependencies
                WHERE connection_id = ?1 AND consumer_kind = ?2 AND consumer_id = ?3
                "#,
                params![id.as_str(), kind.as_str(), consumer_id],
            )
            .map_err(|source| sqlite_error(&self.path, "dependency delete", source))?;
        Ok(())
    }

    pub fn append_status(
        &self,
        id: &ConnectionId,
        update: ConnectionStatusUpdate,
    ) -> Result<SafeConnectionStatus, ConnectionStoreError> {
        if update
            .catalog_entry_count
            .is_some_and(|count| count > MAX_CATALOG_ENTRIES)
        {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection catalog entries",
                maximum: MAX_CATALOG_ENTRIES,
            });
        }
        let observed_at = utc_timestamp()?;
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "status transaction", source))?;
        let current_revision = load_status_revision(&transaction, &self.path, id)?;
        let status_revision = increment_revision(id, current_revision)?;
        let latency_ms = optional_u64_to_i64(update.latency_ms, "latency_ms")?;
        let catalog_age_secs = optional_u64_to_i64(update.catalog_age_secs, "catalog_age_secs")?;
        let catalog_entry_count = update
            .catalog_entry_count
            .map(|value| {
                i64::try_from(value).map_err(|_| ConnectionStoreError::LimitExceeded {
                    resource: "connection catalog entries",
                    maximum: MAX_CATALOG_ENTRIES,
                })
            })
            .transpose()?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_status_history (
                    connection_id, status_revision, state, reason, observed_at,
                    latency_ms, catalog_age_secs, catalog_entry_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    id.as_str(),
                    u64_to_i64(id, status_revision)?,
                    state_as_str(update.state),
                    reason_as_str(update.reason),
                    observed_at,
                    latency_ms,
                    catalog_age_secs,
                    catalog_entry_count,
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "status insert", source))?;
        transaction
            .execute(
                "UPDATE connection_records SET status_revision = ?1 WHERE id = ?2",
                params![u64_to_i64(id, status_revision)?, id.as_str()],
            )
            .map_err(|source| sqlite_error(&self.path, "status revision update", source))?;
        transaction
            .execute(
                r#"
                DELETE FROM connection_status_history
                WHERE sequence IN (
                    SELECT sequence
                    FROM connection_status_history
                    ORDER BY sequence DESC
                    LIMIT -1 OFFSET ?1
                )
                "#,
                params![i64::try_from(MAX_STATUS_HISTORY_ROWS).unwrap_or(i64::MAX)],
            )
            .map_err(|source| sqlite_error(&self.path, "status history pruning", source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "status transaction commit", source))?;

        Ok(SafeConnectionStatus {
            state: update.state,
            reason: update.reason,
            observed_at: Some(observed_at),
            latency_ms: update.latency_ms,
            catalog_age_secs: update.catalog_age_secs,
            catalog_entry_count: update.catalog_entry_count,
        })
    }

    pub fn latest_status(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<SafeConnectionStatus>, ConnectionStoreError> {
        let connection = self.connection_guard();
        connection
            .query_row(
                r#"
                SELECT state, reason, observed_at, latency_ms, catalog_age_secs,
                       catalog_entry_count
                FROM connection_status_history
                WHERE connection_id = ?1
                ORDER BY status_revision DESC
                LIMIT 1
                "#,
                params![id.as_str()],
                raw_status_from_row,
            )
            .optional()
            .map_err(|source| sqlite_error(&self.path, "status query", source))?
            .map(|raw| raw.into_safe_status(id))
            .transpose()
    }

    pub fn status_history(
        &self,
        id: &ConnectionId,
        limit: usize,
    ) -> Result<Vec<SafeConnectionStatus>, ConnectionStoreError> {
        let limit = limit.min(MAX_STATUS_HISTORY_ROWS);
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT state, reason, observed_at, latency_ms, catalog_age_secs,
                       catalog_entry_count
                FROM connection_status_history
                WHERE connection_id = ?1
                ORDER BY status_revision DESC
                LIMIT ?2
                "#,
            )
            .map_err(|source| sqlite_error(&self.path, "status history prepare", source))?;
        let rows = statement
            .query_map(
                params![id.as_str(), i64::try_from(limit).unwrap_or(i64::MAX)],
                raw_status_from_row,
            )
            .map_err(|source| sqlite_error(&self.path, "status history query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(&self.path, "status history read", source))?;
        rows.into_iter()
            .map(|raw| raw.into_safe_status(id))
            .collect()
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite connection-store lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

impl ConnectionStore for SqliteConnectionStore {
    fn count(&self) -> Result<usize, ConnectionStoreError> {
        let connection = self.connection_guard();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM connection_records", [], |row| {
                row.get(0)
            })
            .map_err(|source| sqlite_error(&self.path, "count", source))?;
        usize::try_from(count).map_err(|_| ConnectionStoreError::CorruptRecord {
            id: "<collection>".to_owned(),
            reason: "negative or oversized record count",
        })
    }

    fn list(&self) -> Result<Vec<StoredConnection>, ConnectionStoreError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT id, schema_version, source, spec_json, connection_revision,
                       credential_revision, tls_revision, discovery_revision,
                       status_revision, created_at, updated_at
                FROM connection_records
                ORDER BY id ASC
                "#,
            )
            .map_err(|source| sqlite_error(&self.path, "list prepare", source))?;
        let rows = statement
            .query_map([], RawStoredConnection::from_row)
            .map_err(|source| sqlite_error(&self.path, "list query", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| sqlite_error(&self.path, "list read", source))?;
        let records = rows
            .into_iter()
            .map(|raw| raw.into_stored())
            .collect::<Result<Vec<_>, _>>()?;
        for record in &records {
            validate_record_bindings(&connection, &self.path, record)?;
        }
        Ok(records)
    }

    fn get(&self, id: &ConnectionId) -> Result<Option<StoredConnection>, ConnectionStoreError> {
        let connection = self.connection_guard();
        let record = load_raw_by_id(&connection, &self.path, id)?
            .map(RawStoredConnection::into_stored)
            .transpose()?;
        if let Some(record) = record.as_ref() {
            validate_record_bindings(&connection, &self.path, record)?;
        }
        Ok(record)
    }

    fn create(&self, candidate: ConnectionWrite) -> Result<StoredConnection, ConnectionStoreError> {
        let candidate = validate_candidate(candidate)?;
        let spec_json =
            serde_json::to_string(&candidate).map_err(|source| ConnectionStoreError::Json {
                operation: "candidate",
                source,
            })?;
        let id = ConnectionId::new_managed();
        let now = utc_timestamp()?;
        let revisions = initial_revisions(&candidate);

        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "create transaction", source))?;
        let count: i64 = transaction
            .query_row("SELECT COUNT(*) FROM connection_records", [], |row| {
                row.get(0)
            })
            .map_err(|source| sqlite_error(&self.path, "create count", source))?;
        if usize::try_from(count).unwrap_or(usize::MAX) >= self.maximum_connections {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "managed connections",
                maximum: self.maximum_connections,
            });
        }
        ensure_binding_capacity(&transaction, &self.path, None, 0, binding_count(&candidate))?;
        transaction
            .execute(
                r#"
                INSERT INTO connection_records (
                    id, schema_version, source, spec_json, connection_revision,
                    credential_revision, tls_revision, discovery_revision,
                    status_revision, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
                "#,
                params![
                    id.as_str(),
                    CONNECTION_SCHEMA_VERSION,
                    SOURCE_MANAGED,
                    spec_json,
                    u64_to_i64(&id, revisions.connection)?,
                    u64_to_i64(&id, revisions.credential)?,
                    u64_to_i64(&id, revisions.tls)?,
                    u64_to_i64(&id, revisions.discovery)?,
                    u64_to_i64(&id, revisions.status)?,
                    now,
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "create insert", source))?;
        replace_bindings(&transaction, &self.path, &id, &candidate, &revisions, &now)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "create commit", source))?;

        Ok(StoredConnection {
            id,
            write: candidate,
            revisions,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    fn replace(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        candidate: ConnectionWrite,
    ) -> Result<StoredConnection, ConnectionStoreError> {
        let candidate = validate_candidate(candidate)?;
        let spec_json =
            serde_json::to_string(&candidate).map_err(|source| ConnectionStoreError::Json {
                operation: "candidate",
                source,
            })?;
        let now = utc_timestamp()?;

        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "replace transaction", source))?;
        let current = load_raw_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?
            .into_stored()?;
        validate_record_bindings(&transaction, &self.path, &current)?;
        ensure_etag(id, expected, &current)?;
        if current.write == candidate {
            transaction
                .commit()
                .map_err(|source| sqlite_error(&self.path, "replace no-op commit", source))?;
            return Ok(current);
        }

        ensure_binding_capacity(
            &transaction,
            &self.path,
            Some(id),
            binding_count(&current.write),
            binding_count(&candidate),
        )?;
        let revisions = replacement_revisions(id, &current, &candidate)?;
        transaction
            .execute(
                r#"
                UPDATE connection_records
                SET spec_json = ?1,
                    connection_revision = ?2,
                    credential_revision = ?3,
                    tls_revision = ?4,
                    discovery_revision = ?5,
                    updated_at = ?6
                WHERE id = ?7
                "#,
                params![
                    spec_json,
                    u64_to_i64(id, revisions.connection)?,
                    u64_to_i64(id, revisions.credential)?,
                    u64_to_i64(id, revisions.tls)?,
                    u64_to_i64(id, revisions.discovery)?,
                    now,
                    id.as_str(),
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "replace update", source))?;
        replace_bindings(&transaction, &self.path, id, &candidate, &revisions, &now)?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "replace commit", source))?;

        Ok(StoredConnection {
            id: id.clone(),
            write: candidate,
            revisions,
            created_at: current.created_at,
            updated_at: now,
        })
    }

    fn delete(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
    ) -> Result<(), ConnectionStoreError> {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "delete transaction", source))?;
        let current = load_raw_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?
            .into_stored()?;
        validate_record_bindings(&transaction, &self.path, &current)?;
        ensure_etag(id, expected, &current)?;
        let dependency_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM connection_dependencies WHERE connection_id = ?1",
                params![id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, "dependency count", source))?;
        if dependency_count > 0 {
            return Err(ConnectionStoreError::DependencyConflict {
                id: id.to_string(),
                count: usize::try_from(dependency_count).unwrap_or(usize::MAX),
            });
        }
        transaction
            .execute(
                "DELETE FROM connection_records WHERE id = ?1",
                params![id.as_str()],
            )
            .map_err(|source| sqlite_error(&self.path, "delete", source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "delete commit", source))?;
        Ok(())
    }
}

fn run_migrations(
    connection: &mut Connection,
    path: &Path,
    migrations: &[Migration],
) -> Result<(), ConnectionStoreError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| sqlite_error(path, "migration transaction", source))?;
    transaction
        .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
        .map_err(|source| sqlite_error(path, "migration table", source))?;
    let mut statement = transaction
        .prepare("SELECT version FROM connection_schema_migrations ORDER BY version ASC")
        .map_err(|source| sqlite_error(path, "migration query prepare", source))?;
    let applied = statement
        .query_map([], |row| row.get::<_, u32>(0))
        .map_err(|source| sqlite_error(path, "migration query", source))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|source| sqlite_error(path, "migration read", source))?;
    drop(statement);

    let known = migrations
        .iter()
        .map(|migration| migration.version)
        .collect::<BTreeSet<_>>();
    if let Some(version) = applied.iter().find(|version| !known.contains(version)) {
        return Err(ConnectionStoreError::UnsupportedSchema { version: *version });
    }
    if migrations
        .iter()
        .enumerate()
        .any(|(index, migration)| migration.version != u32::try_from(index + 1).unwrap_or(u32::MAX))
        || applied
            .iter()
            .copied()
            .ne(1..=u32::try_from(applied.len()).unwrap_or(u32::MAX))
    {
        return Err(ConnectionStoreError::InvalidMigrationHistory);
    }

    for migration in migrations {
        if applied.contains(&migration.version) {
            continue;
        }
        transaction
            .execute_batch(migration.sql)
            .map_err(|source| sqlite_error(path, "migration apply", source))?;
        transaction
            .execute(
                "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![migration.version, utc_timestamp()?],
            )
            .map_err(|source| sqlite_error(path, "migration record", source))?;
    }
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, "migration commit", source))
}

fn validate_schema(connection: &Connection, path: &Path) -> Result<(), ConnectionStoreError> {
    for query in [
        "SELECT id, schema_version, source, spec_json, connection_revision, credential_revision, tls_revision, discovery_revision, status_revision, created_at, updated_at FROM connection_records LIMIT 0",
        "SELECT connection_id, purpose, secret_id, binding_version, updated_at FROM connection_credential_bindings LIMIT 0",
        "SELECT connection_id, consumer_kind, consumer_id, created_at FROM connection_dependencies LIMIT 0",
        "SELECT sequence, connection_id, status_revision, state, reason, observed_at, latency_ms, catalog_age_secs, catalog_entry_count FROM connection_status_history LIMIT 0",
    ] {
        connection
            .prepare(query)
            .map_err(|source| sqlite_error(path, "schema validation", source))?;
    }
    let foreign_key_error: Option<String> = connection
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()
        .map_err(|source| sqlite_error(path, "foreign-key validation", source))?;
    if foreign_key_error.is_some() {
        return Err(ConnectionStoreError::CorruptRecord {
            id: "<schema>".to_owned(),
            reason: "foreign-key validation failed",
        });
    }
    Ok(())
}

fn load_raw_by_id(
    connection: &Connection,
    path: &Path,
    id: &ConnectionId,
) -> Result<Option<RawStoredConnection>, ConnectionStoreError> {
    connection
        .query_row(
            r#"
            SELECT id, schema_version, source, spec_json, connection_revision,
                   credential_revision, tls_revision, discovery_revision,
                   status_revision, created_at, updated_at
            FROM connection_records
            WHERE id = ?1
            "#,
            params![id.as_str()],
            RawStoredConnection::from_row,
        )
        .optional()
        .map_err(|source| sqlite_error(path, "record query", source))
}

struct RawStoredConnection {
    id: String,
    schema_version: String,
    source: String,
    spec_json: String,
    connection_revision: i64,
    credential_revision: i64,
    tls_revision: i64,
    discovery_revision: i64,
    status_revision: i64,
    created_at: String,
    updated_at: String,
}

impl RawStoredConnection {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            schema_version: row.get(1)?,
            source: row.get(2)?,
            spec_json: row.get(3)?,
            connection_revision: row.get(4)?,
            credential_revision: row.get(5)?,
            tls_revision: row.get(6)?,
            discovery_revision: row.get(7)?,
            status_revision: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
        })
    }

    fn into_stored(self) -> Result<StoredConnection, ConnectionStoreError> {
        let id = ConnectionId::parse(self.id.clone()).map_err(|_| {
            ConnectionStoreError::CorruptRecord {
                id: self.id.clone(),
                reason: "invalid connection ID",
            }
        })?;
        if Uuid::parse_str(id.as_str()).is_err() {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "managed connection ID is not a UUID",
            });
        }
        if self.schema_version != CONNECTION_SCHEMA_VERSION {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "unsupported connection document schema version",
            });
        }
        if self.source != SOURCE_MANAGED {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "managed store row has a non-managed source",
            });
        }
        let write: ConnectionWrite = serde_json::from_str(&self.spec_json).map_err(|_| {
            ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "connection document is not valid strict JSON",
            }
        })?;
        let write = write
            .validated()
            .map_err(|_| ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "connection document no longer passes validation",
            })?;
        Ok(StoredConnection {
            id: id.clone(),
            write,
            revisions: ConnectionRevisions {
                connection: revision_from_i64(&id, self.connection_revision, false)?,
                credential: revision_from_i64(&id, self.credential_revision, true)?,
                tls: revision_from_i64(&id, self.tls_revision, true)?,
                discovery: revision_from_i64(&id, self.discovery_revision, true)?,
                status: revision_from_i64(&id, self.status_revision, true)?,
            },
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

struct RawStatus {
    state: String,
    reason: String,
    observed_at: String,
    latency_ms: Option<i64>,
    catalog_age_secs: Option<i64>,
    catalog_entry_count: Option<i64>,
}

impl RawStatus {
    fn into_safe_status(
        self,
        id: &ConnectionId,
    ) -> Result<SafeConnectionStatus, ConnectionStoreError> {
        Ok(SafeConnectionStatus {
            state: parse_state(&self.state).ok_or_else(|| ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "unknown safe status state",
            })?,
            reason: parse_reason(&self.reason).ok_or_else(|| {
                ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "unknown safe status reason",
                }
            })?,
            observed_at: Some(self.observed_at),
            latency_ms: optional_i64_to_u64(id, self.latency_ms)?,
            catalog_age_secs: optional_i64_to_u64(id, self.catalog_age_secs)?,
            catalog_entry_count: self
                .catalog_entry_count
                .map(|value| {
                    usize::try_from(value).map_err(|_| ConnectionStoreError::CorruptRecord {
                        id: id.to_string(),
                        reason: "invalid catalog entry count",
                    })
                })
                .transpose()?,
        })
    }
}

fn raw_status_from_row(row: &Row<'_>) -> rusqlite::Result<RawStatus> {
    Ok(RawStatus {
        state: row.get(0)?,
        reason: row.get(1)?,
        observed_at: row.get(2)?,
        latency_ms: row.get(3)?,
        catalog_age_secs: row.get(4)?,
        catalog_entry_count: row.get(5)?,
    })
}

fn replace_bindings(
    transaction: &Transaction<'_>,
    path: &Path,
    id: &ConnectionId,
    write: &ConnectionWrite,
    revisions: &ConnectionRevisions,
    now: &str,
) -> Result<(), ConnectionStoreError> {
    transaction
        .execute(
            "DELETE FROM connection_credential_bindings WHERE connection_id = ?1",
            params![id.as_str()],
        )
        .map_err(|source| sqlite_error(path, "binding replacement", source))?;

    for (purpose, secret_id, version) in expected_bindings(write, revisions) {
        transaction
            .execute(
                r#"
                INSERT INTO connection_credential_bindings (
                    connection_id, purpose, secret_id, binding_version, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![
                    id.as_str(),
                    purpose,
                    secret_id,
                    u64_to_i64(id, version.max(1))?,
                    now
                ],
            )
            .map_err(|source| sqlite_error(path, "binding insert", source))?;
    }
    Ok(())
}

fn validate_record_bindings(
    connection: &Connection,
    path: &Path,
    record: &StoredConnection,
) -> Result<(), ConnectionStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT purpose, secret_id, binding_version
            FROM connection_credential_bindings
            WHERE connection_id = ?1
            ORDER BY purpose ASC
            "#,
        )
        .map_err(|source| sqlite_error(path, "binding validation prepare", source))?;
    let actual = statement
        .query_map(params![record.id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|source| sqlite_error(path, "binding validation query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "binding validation read", source))?;
    let mut expected = expected_bindings(&record.write, &record.revisions)
        .into_iter()
        .map(|(purpose, secret_id, version)| {
            Ok((
                purpose.to_owned(),
                secret_id.to_owned(),
                u64_to_i64(&record.id, version.max(1))?,
            ))
        })
        .collect::<Result<Vec<_>, ConnectionStoreError>>()?;
    expected.sort();
    if actual != expected {
        return Err(ConnectionStoreError::CorruptRecord {
            id: record.id.to_string(),
            reason: "credential binding rows do not match the stored connection document",
        });
    }
    Ok(())
}

fn expected_bindings<'a>(
    write: &'a ConnectionWrite,
    revisions: &ConnectionRevisions,
) -> Vec<(&'static str, &'a str, u64)> {
    let mut bindings = Vec::new();
    match &write.authentication {
        ConnectionAuthentication::None => {}
        ConnectionAuthentication::HeaderApiKey {
            secret_id: Some(secret_id),
            ..
        }
        | ConnectionAuthentication::StaticBearer {
            secret_id: Some(secret_id),
        } => bindings.push((
            "http_authentication",
            secret_id.as_str(),
            revisions.credential,
        )),
        ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: Some(secret_id),
            ..
        } => bindings.push((
            "oauth_client_secret",
            secret_id.as_str(),
            revisions.credential,
        )),
        ConnectionAuthentication::HeaderApiKey {
            secret_id: None, ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: None }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: None,
            ..
        } => {}
    }
    if let Some(secret_id) = write.tls.ca_bundle_alias.as_deref() {
        bindings.push(("tls_ca_bundle", secret_id, revisions.tls));
    }
    if let Some(secret_id) = write.tls.client_certificate_id.as_deref() {
        bindings.push(("tls_client_certificate", secret_id, revisions.tls));
    }
    if let Some(secret_id) = write.tls.client_private_key_id.as_deref() {
        bindings.push(("tls_client_private_key", secret_id, revisions.tls));
    }
    bindings
}

fn binding_count(write: &ConnectionWrite) -> usize {
    let authentication = match &write.authentication {
        ConnectionAuthentication::None
        | ConnectionAuthentication::HeaderApiKey {
            secret_id: None, ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: None }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: None,
            ..
        } => 0,
        ConnectionAuthentication::HeaderApiKey {
            secret_id: Some(_), ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: Some(_) }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: Some(_),
            ..
        } => 1,
    };
    authentication
        + usize::from(write.tls.ca_bundle_alias.is_some())
        + usize::from(write.tls.client_certificate_id.is_some())
        + usize::from(write.tls.client_private_key_id.is_some())
}

fn ensure_binding_capacity(
    transaction: &Transaction<'_>,
    path: &Path,
    replaced_id: Option<&ConnectionId>,
    replaced_binding_count: usize,
    candidate_binding_count: usize,
) -> Result<(), ConnectionStoreError> {
    let persisted: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM connection_credential_bindings",
            [],
            |row| row.get(0),
        )
        .map_err(|source| sqlite_error(path, "binding count", source))?;
    let persisted =
        usize::try_from(persisted).map_err(|_| ConnectionStoreError::CorruptRecord {
            id: "<bindings>".to_owned(),
            reason: "negative or oversized binding count",
        })?;
    if let Some(id) = replaced_id {
        let record_bindings: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM connection_credential_bindings WHERE connection_id = ?1",
                params![id.as_str()],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(path, "record binding count", source))?;
        if usize::try_from(record_bindings).ok() != Some(replaced_binding_count) {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "credential binding rows do not match the stored connection document",
            });
        }
    }
    let total = persisted
        .checked_sub(replaced_binding_count)
        .and_then(|count| count.checked_add(candidate_binding_count))
        .ok_or_else(|| ConnectionStoreError::CorruptRecord {
            id: "<bindings>".to_owned(),
            reason: "binding count is inconsistent with its connection record",
        })?;
    if total > MAX_CREDENTIALS {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection credential bindings",
            maximum: MAX_CREDENTIALS,
        });
    }
    Ok(())
}

fn validate_candidate(candidate: ConnectionWrite) -> Result<ConnectionWrite, ConnectionStoreError> {
    candidate
        .validated()
        .map_err(|errors| ConnectionStoreError::Validation {
            problems: errors
                .into_iter()
                .map(|error| format!("{}:{}", error.field, error.code))
                .collect(),
        })
}

fn initial_revisions(write: &ConnectionWrite) -> ConnectionRevisions {
    ConnectionRevisions {
        connection: 1,
        credential: u64::from(has_credential_binding(write)),
        tls: u64::from(!write.tls.is_empty()),
        discovery: u64::from(write.discovery.is_some()),
        status: 0,
    }
}

fn replacement_revisions(
    id: &ConnectionId,
    current: &StoredConnection,
    candidate: &ConnectionWrite,
) -> Result<ConnectionRevisions, ConnectionStoreError> {
    let credential_changed = sensitive_credential_fields_changed(&current.write, candidate);
    Ok(ConnectionRevisions {
        connection: increment_revision(id, current.revisions.connection)?,
        credential: if credential_changed {
            increment_revision(id, current.revisions.credential)?
        } else {
            current.revisions.credential
        },
        tls: if current.write.tls != candidate.tls {
            increment_revision(id, current.revisions.tls)?
        } else {
            current.revisions.tls
        },
        discovery: if current.write.discovery != candidate.discovery {
            increment_revision(id, current.revisions.discovery)?
        } else {
            current.revisions.discovery
        },
        status: current.revisions.status,
    })
}

fn sensitive_credential_fields_changed(
    current: &ConnectionWrite,
    candidate: &ConnectionWrite,
) -> bool {
    current.authentication != candidate.authentication
        || current.tls != candidate.tls
        || ((has_credential_binding(current) || has_credential_binding(candidate))
            && current.endpoint != candidate.endpoint)
        || (discovery_uses_authentication(current.discovery.as_ref())
            || discovery_uses_authentication(candidate.discovery.as_ref()))
            && current.discovery != candidate.discovery
}

fn has_credential_binding(write: &ConnectionWrite) -> bool {
    !matches!(write.authentication, ConnectionAuthentication::None) || !write.tls.is_empty()
}

fn discovery_uses_authentication(discovery: Option<&DiscoveryConfig>) -> bool {
    match discovery {
        Some(DiscoveryConfig::ManagedOpenapi {
            use_connection_authentication,
            ..
        })
        | Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication,
        }) => *use_connection_authentication,
        None => false,
    }
}

fn safe_authentication_kind(authentication: &ConnectionAuthentication) -> SafeAuthenticationKind {
    match authentication {
        ConnectionAuthentication::None => SafeAuthenticationKind::None,
        ConnectionAuthentication::HeaderApiKey { .. } => SafeAuthenticationKind::HeaderApiKey,
        ConnectionAuthentication::StaticBearer { .. } => SafeAuthenticationKind::StaticBearer,
        ConnectionAuthentication::OAuth2ClientCredentials { .. } => {
            SafeAuthenticationKind::Oauth2ClientCredentials
        }
    }
}

fn ensure_etag(
    id: &ConnectionId,
    expected: &ConnectionEtag,
    current: &StoredConnection,
) -> Result<(), ConnectionStoreError> {
    let actual = current.etag();
    if expected == &actual {
        Ok(())
    } else {
        Err(ConnectionStoreError::Conflict {
            id: id.to_string(),
            current: actual,
        })
    }
}

fn load_status_revision(
    transaction: &Transaction<'_>,
    path: &Path,
    id: &ConnectionId,
) -> Result<u64, ConnectionStoreError> {
    let revision = transaction
        .query_row(
            "SELECT status_revision FROM connection_records WHERE id = ?1",
            params![id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|source| sqlite_error(path, "status revision query", source))?
        .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
    revision_from_i64(id, revision, true)
}

fn validate_dependency_id(value: &str) -> Result<(), ConnectionStoreError> {
    if value.is_empty() || value.len() > MAX_DEPENDENCY_FIELD_BYTES || value.contains('\0') {
        Err(ConnectionStoreError::Validation {
            problems: vec![format!(
                "dependency consumer_id must contain 1-{MAX_DEPENDENCY_FIELD_BYTES} bytes without NUL"
            )],
        })
    } else {
        Ok(())
    }
}

fn increment_revision(id: &ConnectionId, revision: u64) -> Result<u64, ConnectionStoreError> {
    revision
        .checked_add(1)
        .ok_or_else(|| ConnectionStoreError::RevisionOverflow { id: id.to_string() })
}

fn revision_from_i64(
    id: &ConnectionId,
    value: i64,
    zero_allowed: bool,
) -> Result<u64, ConnectionStoreError> {
    let value = u64::try_from(value).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: id.to_string(),
        reason: "negative revision",
    })?;
    if !zero_allowed && value == 0 {
        return Err(ConnectionStoreError::CorruptRecord {
            id: id.to_string(),
            reason: "zero connection revision",
        });
    }
    Ok(value)
}

fn u64_to_i64(id: &ConnectionId, value: u64) -> Result<i64, ConnectionStoreError> {
    i64::try_from(value).map_err(|_| ConnectionStoreError::RevisionOverflow { id: id.to_string() })
}

fn optional_u64_to_i64(
    value: Option<u64>,
    field: &'static str,
) -> Result<Option<i64>, ConnectionStoreError> {
    value
        .map(|value| {
            i64::try_from(value).map_err(|_| ConnectionStoreError::Validation {
                problems: vec![format!("{field} is too large")],
            })
        })
        .transpose()
}

fn optional_i64_to_u64(
    id: &ConnectionId,
    value: Option<i64>,
) -> Result<Option<u64>, ConnectionStoreError> {
    value
        .map(|value| {
            u64::try_from(value).map_err(|_| ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "negative safe status count",
            })
        })
        .transpose()
}

fn state_as_str(state: ConnectionOperationalState) -> &'static str {
    match state {
        ConnectionOperationalState::Unknown => "unknown",
        ConnectionOperationalState::Configured => "configured",
        ConnectionOperationalState::Healthy => "healthy",
        ConnectionOperationalState::Degraded => "degraded",
        ConnectionOperationalState::Unavailable => "unavailable",
        ConnectionOperationalState::Disabled => "disabled",
    }
}

fn parse_state(value: &str) -> Option<ConnectionOperationalState> {
    match value {
        "unknown" => Some(ConnectionOperationalState::Unknown),
        "configured" => Some(ConnectionOperationalState::Configured),
        "healthy" => Some(ConnectionOperationalState::Healthy),
        "degraded" => Some(ConnectionOperationalState::Degraded),
        "unavailable" => Some(ConnectionOperationalState::Unavailable),
        "disabled" => Some(ConnectionOperationalState::Disabled),
        _ => None,
    }
}

fn reason_as_str(reason: ConnectionStatusReason) -> &'static str {
    match reason {
        ConnectionStatusReason::NotTested => "not_tested",
        ConnectionStatusReason::LegacyConfigured => "legacy_configured",
        ConnectionStatusReason::Disabled => "disabled",
        ConnectionStatusReason::TestSucceeded => "test_succeeded",
        ConnectionStatusReason::RequestFailed => "request_failed",
        ConnectionStatusReason::EgressDenied => "egress_denied",
        ConnectionStatusReason::SecretUnavailable => "secret_unavailable",
        ConnectionStatusReason::InvalidResponse => "invalid_response",
        ConnectionStatusReason::CatalogStale => "catalog_stale",
    }
}

fn parse_reason(value: &str) -> Option<ConnectionStatusReason> {
    match value {
        "not_tested" => Some(ConnectionStatusReason::NotTested),
        "legacy_configured" => Some(ConnectionStatusReason::LegacyConfigured),
        "disabled" => Some(ConnectionStatusReason::Disabled),
        "test_succeeded" => Some(ConnectionStatusReason::TestSucceeded),
        "request_failed" => Some(ConnectionStatusReason::RequestFailed),
        "egress_denied" => Some(ConnectionStatusReason::EgressDenied),
        "secret_unavailable" => Some(ConnectionStatusReason::SecretUnavailable),
        "invalid_response" => Some(ConnectionStatusReason::InvalidResponse),
        "catalog_stale" => Some(ConnectionStatusReason::CatalogStale),
        _ => None,
    }
}

fn utc_timestamp() -> Result<String, ConnectionStoreError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| ConnectionStoreError::CorruptRecord {
            id: "<clock>".to_owned(),
            reason: "failed to format UTC timestamp",
        })
}

fn sqlite_error(
    path: &Path,
    operation: &'static str,
    source: rusqlite::Error,
) -> ConnectionStoreError {
    ConnectionStoreError::Sqlite {
        path: path.to_path_buf(),
        operation,
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    use super::*;

    fn candidate() -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": "Billing API",
            "enabled": false,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {
                "type": "static_bearer",
                "secret_id": "billing-token"
            },
            "tls": {},
            "discovery": {
                "type": "managed_openapi",
                "path": "/openapi.json",
                "use_connection_authentication": true
            }
        }))
        .expect("candidate should deserialize")
    }

    struct TemporaryDatabase {
        path: PathBuf,
    }

    impl TemporaryDatabase {
        fn new(name: &str) -> Self {
            Self {
                path: std::env::temp_dir().join(format!(
                    "greengateway-connection-{name}-{}.sqlite",
                    Uuid::new_v4()
                )),
            }
        }
    }

    impl Drop for TemporaryDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let _ = fs::remove_file(format!("{}-wal", self.path.display()));
            let _ = fs::remove_file(format!("{}-shm", self.path.display()));
        }
    }

    fn temporary_store(name: &str) -> (TemporaryDatabase, PathBuf, SqliteConnectionStore) {
        let database = TemporaryDatabase::new(name);
        let path = database.path.clone();
        let store = SqliteConnectionStore::open(&path).expect("store should open");
        (database, path, store)
    }

    #[test]
    fn migrations_are_ordered_idempotent_and_restart_safe() {
        let (_directory, path, store) = temporary_store("migration");
        assert_eq!(store.count().expect("count should work"), 0);
        drop(store);

        let reopened = SqliteConnectionStore::open(&path).expect("reopen should be idempotent");
        let connection = reopened.connection_guard();
        let versions = connection
            .prepare("SELECT version FROM connection_schema_migrations ORDER BY version")
            .expect("migration query should prepare")
            .query_map([], |row| row.get::<_, u32>(0))
            .expect("migration query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("migration rows should read");
        assert_eq!(versions, vec![1, 2]);
    }

    #[test]
    fn failed_migration_rolls_back_every_schema_change() {
        let mut connection = Connection::open_in_memory().expect("memory database should open");
        let path = Path::new(":memory:");
        let migrations = [
            Migration {
                version: 1,
                sql: "CREATE TABLE connection_test_one (id INTEGER PRIMARY KEY);",
            },
            Migration {
                version: 2,
                sql: "CREATE TABLE connection_test_two (id INTEGER PRIMARY KEY); INVALID SQL;",
            },
        ];

        assert!(run_migrations(&mut connection, path, &migrations).is_err());
        let table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'connection_%'",
                [],
                |row| row.get(0),
            )
            .expect("schema catalog query should work");
        assert_eq!(table_count, 0, "failed migration must roll back all DDL");
    }

    #[test]
    fn non_contiguous_migration_history_fails_closed() {
        let mut connection = Connection::open_in_memory().expect("memory database should open");
        connection
            .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
            .expect("migration table should create");
        connection
            .execute(
                "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (2, ?1)",
                params![utc_timestamp().expect("timestamp should format")],
            )
            .expect("test migration marker should insert");

        assert!(matches!(
            run_migrations(&mut connection, Path::new(":memory:"), MIGRATIONS),
            Err(ConnectionStoreError::InvalidMigrationHistory)
        ));
        let versions: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM connection_schema_migrations",
                [],
                |row| row.get(0),
            )
            .expect("existing migration history should remain");
        assert_eq!(versions, 1);
    }

    #[test]
    fn create_replace_restart_and_etag_conflict_are_transactional() {
        let (_directory, path, store) = temporary_store("crud");
        let created = store.create(candidate()).expect("create should succeed");
        assert_eq!(created.revisions.connection, 1);
        assert_eq!(created.revisions.credential, 1);
        assert_eq!(created.revisions.discovery, 1);
        let stale_etag = created.etag();

        let mut replacement = created.write.clone();
        replacement.description = Some("Updated".to_owned());
        let replaced = store
            .replace(&created.id, &stale_etag, replacement)
            .expect("replace should succeed");
        assert_eq!(replaced.revisions.connection, 2);
        assert_eq!(replaced.revisions.credential, 1);
        assert_eq!(replaced.revisions.discovery, 1);
        assert!(matches!(
            store.replace(&created.id, &stale_etag, replaced.write.clone()),
            Err(ConnectionStoreError::Conflict { .. })
        ));

        drop(store);
        let reopened = SqliteConnectionStore::open(path).expect("store should reopen");
        assert_eq!(
            reopened
                .get(&created.id)
                .expect("get should succeed")
                .expect("record should exist"),
            replaced
        );
    }

    #[test]
    fn validation_and_sql_failure_leave_prior_record_and_bindings_unchanged() {
        let (_directory, _path, store) = temporary_store("rollback");
        let created = store.create(candidate()).expect("create should succeed");

        let mut invalid = created.write.clone();
        invalid.endpoint.base_url = "http://billing.example.test".to_owned();
        assert!(matches!(
            store.replace(&created.id, &created.etag(), invalid),
            Err(ConnectionStoreError::Validation { .. })
        ));

        {
            let connection = store.connection_guard();
            connection
                .execute_batch(
                    r#"
                    CREATE TRIGGER fail_binding_insert
                    BEFORE INSERT ON connection_credential_bindings
                    BEGIN
                        SELECT RAISE(ABORT, 'forced binding failure');
                    END;
                    "#,
                )
                .expect("failure trigger should install");
        }
        let mut replacement = created.write.clone();
        replacement.display_name = "Replacement".to_owned();
        assert!(matches!(
            store.replace(&created.id, &created.etag(), replacement),
            Err(ConnectionStoreError::Sqlite { .. })
        ));

        let persisted = store
            .get(&created.id)
            .expect("get should succeed")
            .expect("record should remain");
        assert_eq!(persisted, created);
        let connection = store.connection_guard();
        let binding: String = connection
            .query_row(
                "SELECT secret_id FROM connection_credential_bindings WHERE connection_id = ?1",
                params![created.id.as_str()],
                |row| row.get(0),
            )
            .expect("original binding should remain");
        assert_eq!(binding, "billing-token");
    }

    #[test]
    fn dependencies_block_delete_without_cascading() {
        let (_directory, _path, store) = temporary_store("dependencies");
        let created = store.create(candidate()).expect("create should succeed");
        store
            .add_dependency(
                &created.id,
                ConnectionDependencyKind::ManualTool,
                "billing.get",
            )
            .expect("dependency should insert");

        assert!(matches!(
            store.delete(&created.id, &created.etag()),
            Err(ConnectionStoreError::DependencyConflict { count: 1, .. })
        ));
        assert!(store
            .get(&created.id)
            .expect("get should succeed")
            .is_some());

        store
            .remove_dependency(
                &created.id,
                ConnectionDependencyKind::ManualTool,
                "billing.get",
            )
            .expect("dependency should remove");
        store
            .delete(&created.id, &created.etag())
            .expect("unreferenced connection should delete");
        assert!(store
            .get(&created.id)
            .expect("get should succeed")
            .is_none());
    }

    #[test]
    fn credential_binding_rows_are_hard_bounded() {
        let (_directory, _path, store) = temporary_store("binding-limit");
        let created = store.create(candidate()).expect("create should succeed");
        {
            let mut connection = store.connection_guard();
            let transaction = connection
                .transaction()
                .expect("seed transaction should begin");
            for index in 1..MAX_CREDENTIALS {
                transaction
                    .execute(
                        r#"
                        INSERT INTO connection_credential_bindings (
                            connection_id, purpose, secret_id, binding_version, updated_at
                        ) VALUES (?1, ?2, ?3, 1, ?4)
                        "#,
                        params![
                            created.id.as_str(),
                            format!("test-purpose-{index}"),
                            format!("test-secret-{index}"),
                            utc_timestamp().expect("timestamp should format")
                        ],
                    )
                    .expect("bounded test binding should insert");
            }
            transaction
                .commit()
                .expect("seed transaction should commit");
        }

        assert!(matches!(
            store.create(candidate()),
            Err(ConnectionStoreError::LimitExceeded {
                resource: "connection credential bindings",
                maximum: MAX_CREDENTIALS,
            })
        ));
        assert_eq!(store.count().expect("count should work"), 1);
    }

    #[test]
    fn status_history_is_safe_revisioned_and_globally_bounded() {
        let (_directory, path, store) = temporary_store("status");
        let created = store.create(candidate()).expect("create should succeed");
        let update = ConnectionStatusUpdate {
            state: ConnectionOperationalState::Healthy,
            reason: ConnectionStatusReason::TestSucceeded,
            latency_ms: Some(12),
            catalog_age_secs: Some(4),
            catalog_entry_count: Some(3),
        };
        let status = store
            .append_status(&created.id, update)
            .expect("status should append");
        assert_eq!(status.latency_ms, Some(12));
        let loaded = store
            .get(&created.id)
            .expect("get should succeed")
            .expect("record should exist");
        assert_eq!(loaded.revisions.status, 1);
        let serialized =
            serde_json::to_string(&loaded.safe_summary(Some(status))).expect("should serialize");
        assert!(!serialized.contains("billing-token"));
        assert!(!serialized.contains("billing.example.test"));

        {
            let mut connection = store.connection_guard();
            let transaction = connection
                .transaction()
                .expect("history seed transaction should begin");
            for revision in 2..=u64::try_from(MAX_STATUS_HISTORY_ROWS + 1)
                .expect("history limit should fit u64")
            {
                transaction
                    .execute(
                        r#"
                        INSERT INTO connection_status_history (
                            connection_id, status_revision, state, reason, observed_at
                        ) VALUES (?1, ?2, 'degraded', 'request_failed', ?3)
                        "#,
                        params![
                            created.id.as_str(),
                            u64_to_i64(&created.id, revision)
                                .expect("test revision should fit SQLite"),
                            utc_timestamp().expect("timestamp should format")
                        ],
                    )
                    .expect("history seed row should insert");
            }
            transaction
                .execute(
                    "UPDATE connection_records SET status_revision = ?1 WHERE id = ?2",
                    params![
                        i64::try_from(MAX_STATUS_HISTORY_ROWS + 1)
                            .expect("history limit should fit SQLite"),
                        created.id.as_str()
                    ],
                )
                .expect("history revision should update");
            transaction
                .commit()
                .expect("history seed transaction should commit");
        }
        store
            .append_status(
                &created.id,
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: Some(8),
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                },
            )
            .expect("bounded append should succeed");

        let connection = Connection::open(path).expect("database should open");
        let row_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM connection_status_history",
                [],
                |row| row.get(0),
            )
            .expect("status count should query");
        assert_eq!(
            row_count,
            i64::try_from(MAX_STATUS_HISTORY_ROWS).expect("history limit should fit SQLite")
        );
    }

    #[test]
    fn configured_path_that_cannot_be_opened_fails_closed() {
        let directory = std::env::temp_dir().join(format!(
            "greengateway-connection-directory-{}",
            Uuid::new_v4()
        ));
        fs::create_dir(&directory).expect("temp directory should create");
        let error = match SqliteConnectionStore::open(&directory) {
            Ok(_) => panic!("opening a directory as SQLite must fail"),
            Err(error) => error,
        };
        fs::remove_dir(&directory).expect("empty temp directory should remove");
        assert!(matches!(
            error,
            ConnectionStoreError::Open { .. } | ConnectionStoreError::Sqlite { .. }
        ));
    }

    #[test]
    fn corrupt_persisted_document_fails_closed_and_is_not_returned() {
        let (_directory, path, store) = temporary_store("corrupt");
        let created = store.create(candidate()).expect("create should succeed");
        drop(store);
        let connection = Connection::open(&path).expect("database should open");
        connection
            .execute(
                "UPDATE connection_records SET spec_json = ?1 WHERE id = ?2",
                params![r#"{"enabled":true}"#, created.id.as_str()],
            )
            .expect("test corruption should write");
        drop(connection);

        let reopened = SqliteConnectionStore::open(&path).expect("schema remains valid");
        assert!(matches!(
            reopened.get(&created.id),
            Err(ConnectionStoreError::CorruptRecord { .. })
        ));
        assert!(fs::metadata(path).is_ok());
    }

    #[test]
    fn mismatched_persisted_binding_fails_closed() {
        let (_directory, _path, store) = temporary_store("corrupt-binding");
        let created = store.create(candidate()).expect("create should succeed");
        {
            let connection = store.connection_guard();
            connection
                .execute(
                    r#"
                    UPDATE connection_credential_bindings
                    SET secret_id = 'different-secret'
                    WHERE connection_id = ?1
                    "#,
                    params![created.id.as_str()],
                )
                .expect("test corruption should write");
        }

        assert!(matches!(
            store.get(&created.id),
            Err(ConnectionStoreError::CorruptRecord {
                reason: "credential binding rows do not match the stored connection document",
                ..
            })
        ));
    }
}
