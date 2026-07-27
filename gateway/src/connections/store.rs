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
        MAX_CREDENTIALS, MAX_MANAGED_SPEC_BYTES, MAX_STATUS_HISTORY_ROWS,
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
    spec_json TEXT NOT NULL CHECK (length(CAST(spec_json AS BLOB)) BETWEEN 2 AND 2097152),
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
    consumer_kind TEXT NOT NULL CHECK (
        consumer_kind IN ('proxy_route', 'manual_tool', 'managed_tool', 'control_plane')
    ),
    consumer_id TEXT NOT NULL CHECK (
        length(CAST(consumer_id AS BLOB)) BETWEEN 1 AND 256
        AND instr(consumer_id, char(0)) = 0
    ),
    created_at TEXT NOT NULL,
    PRIMARY KEY (connection_id, consumer_kind, consumer_id),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE RESTRICT
);

CREATE INDEX idx_connection_dependencies_connection
ON connection_dependencies(connection_id, consumer_kind, consumer_id);
"#;

const MIGRATION_2_SQL: &str = r#"
CREATE TABLE connection_current_status (
    connection_id TEXT PRIMARY KEY,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision INTEGER NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision INTEGER NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision INTEGER NOT NULL CHECK (observed_discovery_revision >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'request_failed', 'egress_denied', 'secret_unavailable',
            'invalid_response', 'catalog_stale'
        )
    ),
    observed_at TEXT NOT NULL CHECK (length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 64),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs INTEGER CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count INTEGER CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
    FOREIGN KEY (connection_id) REFERENCES connection_records(id) ON DELETE CASCADE
);

CREATE TABLE connection_status_history (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    status_revision INTEGER NOT NULL CHECK (status_revision >= 1),
    observed_connection_revision INTEGER NOT NULL CHECK (observed_connection_revision >= 1),
    observed_credential_revision INTEGER NOT NULL CHECK (observed_credential_revision >= 0),
    observed_tls_revision INTEGER NOT NULL CHECK (observed_tls_revision >= 0),
    observed_discovery_revision INTEGER NOT NULL CHECK (observed_discovery_revision >= 0),
    state TEXT NOT NULL CHECK (
        state IN ('unknown', 'configured', 'healthy', 'degraded', 'unavailable', 'disabled')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'not_tested', 'legacy_configured', 'disabled', 'test_succeeded',
            'request_failed', 'egress_denied', 'secret_unavailable',
            'invalid_response', 'catalog_stale'
        )
    ),
    observed_at TEXT NOT NULL CHECK (length(CAST(observed_at AS BLOB)) BETWEEN 1 AND 64),
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    catalog_age_secs INTEGER CHECK (catalog_age_secs IS NULL OR catalog_age_secs >= 0),
    catalog_entry_count INTEGER CHECK (
        catalog_entry_count IS NULL OR catalog_entry_count BETWEEN 0 AND 4096
    ),
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
pub const MAX_CONNECTION_DEPENDENCIES: usize = 4_096;

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
        validate_persisted_state(&mut connection, &path, maximum_connections)?;

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
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|source| sqlite_error(&self.path, "dependency transaction", source))?;
        let exists: bool = transaction
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM connection_dependencies
                    WHERE connection_id = ?1 AND consumer_kind = ?2 AND consumer_id = ?3
                )
                "#,
                params![id.as_str(), kind.as_str(), consumer_id],
                |row| row.get(0),
            )
            .map_err(|source| sqlite_error(&self.path, "dependency lookup", source))?;
        if exists {
            transaction
                .commit()
                .map_err(|source| sqlite_error(&self.path, "dependency no-op commit", source))?;
            return Ok(());
        }
        let dependency_count = count_rows(
            &transaction,
            &self.path,
            "connection dependencies",
            "SELECT COUNT(*) FROM connection_dependencies",
        )?;
        if dependency_count >= MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }
        transaction
            .execute(
                r#"
                INSERT INTO connection_dependencies (
                    connection_id, consumer_kind, consumer_id, created_at
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![id.as_str(), kind.as_str(), consumer_id, now],
            )
            .map_err(|source| sqlite_error(&self.path, "dependency insert", source))?;
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "dependency commit", source))?;
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
        expected: &ConnectionEtag,
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
        let current = load_raw_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?
            .into_stored()?;
        validate_record_bindings(&transaction, &self.path, &current)?;
        ensure_etag(id, expected, &current)?;
        let status_revision = increment_revision(id, current.revisions.status)?;
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
                    connection_id, status_revision, observed_connection_revision,
                    observed_credential_revision, observed_tls_revision,
                    observed_discovery_revision, state, reason, observed_at,
                    latency_ms, catalog_age_secs, catalog_entry_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                "#,
                params![
                    id.as_str(),
                    u64_to_i64(id, status_revision)?,
                    u64_to_i64(id, current.revisions.connection)?,
                    u64_to_i64(id, current.revisions.credential)?,
                    u64_to_i64(id, current.revisions.tls)?,
                    u64_to_i64(id, current.revisions.discovery)?,
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
                r#"
                INSERT INTO connection_current_status (
                    connection_id, status_revision, observed_connection_revision,
                    observed_credential_revision, observed_tls_revision,
                    observed_discovery_revision, state, reason, observed_at,
                    latency_ms, catalog_age_secs, catalog_entry_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                ON CONFLICT(connection_id) DO UPDATE SET
                    status_revision = excluded.status_revision,
                    observed_connection_revision = excluded.observed_connection_revision,
                    observed_credential_revision = excluded.observed_credential_revision,
                    observed_tls_revision = excluded.observed_tls_revision,
                    observed_discovery_revision = excluded.observed_discovery_revision,
                    state = excluded.state,
                    reason = excluded.reason,
                    observed_at = excluded.observed_at,
                    latency_ms = excluded.latency_ms,
                    catalog_age_secs = excluded.catalog_age_secs,
                    catalog_entry_count = excluded.catalog_entry_count
                "#,
                params![
                    id.as_str(),
                    u64_to_i64(id, status_revision)?,
                    u64_to_i64(id, current.revisions.connection)?,
                    u64_to_i64(id, current.revisions.credential)?,
                    u64_to_i64(id, current.revisions.tls)?,
                    u64_to_i64(id, current.revisions.discovery)?,
                    state_as_str(update.state),
                    reason_as_str(update.reason),
                    observed_at,
                    latency_ms,
                    catalog_age_secs,
                    catalog_entry_count,
                ],
            )
            .map_err(|source| sqlite_error(&self.path, "current status upsert", source))?;
        let current_status_count = count_rows(
            &transaction,
            &self.path,
            "current connection statuses",
            "SELECT COUNT(*) FROM connection_current_status",
        )?;
        let retained_history = MAX_STATUS_HISTORY_ROWS
            .checked_sub(current_status_count)
            .ok_or(ConnectionStoreError::LimitExceeded {
                resource: "safe connection status rows",
                maximum: MAX_STATUS_HISTORY_ROWS,
            })?;
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
                params![i64::try_from(retained_history).unwrap_or(i64::MAX)],
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
                FROM connection_current_status
                WHERE connection_id = ?1
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
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, "list transaction", source))?;
        let records = load_all_records(&transaction, &self.path)?;
        for record in &records {
            validate_record_bindings(&transaction, &self.path, record)?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "list commit", source))?;
        Ok(records)
    }

    fn get(&self, id: &ConnectionId) -> Result<Option<StoredConnection>, ConnectionStoreError> {
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction()
            .map_err(|source| sqlite_error(&self.path, "get transaction", source))?;
        let record = load_raw_by_id(&transaction, &self.path, id)?
            .map(RawStoredConnection::into_stored)
            .transpose()?;
        if let Some(record) = record.as_ref() {
            validate_record_bindings(&transaction, &self.path, record)?;
        }
        transaction
            .commit()
            .map_err(|source| sqlite_error(&self.path, "get commit", source))?;
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
        transaction
            .execute(
                "DELETE FROM connection_current_status WHERE connection_id = ?1",
                params![id.as_str()],
            )
            .map_err(|source| {
                sqlite_error(&self.path, "stale current status invalidation", source)
            })?;
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
    validate_schema(&transaction, path)?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, "migration commit", source))
}

fn validate_schema(connection: &Connection, path: &Path) -> Result<(), ConnectionStoreError> {
    for query in [
        "SELECT id, schema_version, source, spec_json, connection_revision, credential_revision, tls_revision, discovery_revision, status_revision, created_at, updated_at FROM connection_records LIMIT 0",
        "SELECT connection_id, purpose, secret_id, binding_version, updated_at FROM connection_credential_bindings LIMIT 0",
        "SELECT connection_id, consumer_kind, consumer_id, created_at FROM connection_dependencies LIMIT 0",
        "SELECT connection_id, status_revision, observed_connection_revision, observed_credential_revision, observed_tls_revision, observed_discovery_revision, state, reason, observed_at, latency_ms, catalog_age_secs, catalog_entry_count FROM connection_current_status LIMIT 0",
        "SELECT sequence, connection_id, status_revision, observed_connection_revision, observed_credential_revision, observed_tls_revision, observed_discovery_revision, state, reason, observed_at, latency_ms, catalog_age_secs, catalog_entry_count FROM connection_status_history LIMIT 0",
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

fn validate_persisted_state(
    connection: &mut Connection,
    path: &Path,
    maximum_connections: usize,
) -> Result<(), ConnectionStoreError> {
    let transaction = connection
        .transaction()
        .map_err(|source| sqlite_error(path, "startup validation transaction", source))?;
    let connection_count = count_rows(
        &transaction,
        path,
        "managed connections",
        "SELECT COUNT(*) FROM connection_records",
    )?;
    if connection_count > maximum_connections {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "managed connections",
            maximum: maximum_connections,
        });
    }
    let binding_count = count_rows(
        &transaction,
        path,
        "connection credential bindings",
        "SELECT COUNT(*) FROM connection_credential_bindings",
    )?;
    if binding_count > MAX_CREDENTIALS {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection credential bindings",
            maximum: MAX_CREDENTIALS,
        });
    }
    let dependency_count = count_rows(
        &transaction,
        path,
        "connection dependencies",
        "SELECT COUNT(*) FROM connection_dependencies",
    )?;
    if dependency_count > MAX_CONNECTION_DEPENDENCIES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection dependencies",
            maximum: MAX_CONNECTION_DEPENDENCIES,
        });
    }
    let current_status_count = count_rows(
        &transaction,
        path,
        "current connection statuses",
        "SELECT COUNT(*) FROM connection_current_status",
    )?;
    let history_count = count_rows(
        &transaction,
        path,
        "connection status history",
        "SELECT COUNT(*) FROM connection_status_history",
    )?;
    if current_status_count
        .checked_add(history_count)
        .is_none_or(|count| count > MAX_STATUS_HISTORY_ROWS)
    {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "safe connection status rows",
            maximum: MAX_STATUS_HISTORY_ROWS,
        });
    }

    ensure_no_invalid_rows(
        &transaction,
        path,
        "current status integrity",
        r#"
        SELECT COUNT(*)
        FROM connection_current_status AS status
        JOIN connection_records AS record ON record.id = status.connection_id
        WHERE status.status_revision != record.status_revision
           OR status.observed_connection_revision != record.connection_revision
           OR status.observed_credential_revision != record.credential_revision
           OR status.observed_tls_revision != record.tls_revision
           OR status.observed_discovery_revision != record.discovery_revision
           OR status.catalog_entry_count < 0
           OR status.catalog_entry_count > 4096
        "#,
        "current connection status is stale or invalid",
    )?;
    ensure_no_invalid_rows(
        &transaction,
        path,
        "status history integrity",
        r#"
        SELECT COUNT(*)
        FROM connection_status_history AS status
        JOIN connection_records AS record ON record.id = status.connection_id
        WHERE status.status_revision > record.status_revision
           OR status.observed_connection_revision > record.connection_revision
           OR status.observed_credential_revision > record.credential_revision
           OR status.observed_tls_revision > record.tls_revision
           OR status.observed_discovery_revision > record.discovery_revision
           OR status.catalog_entry_count < 0
           OR status.catalog_entry_count > 4096
        "#,
        "connection status history contains an impossible revision or count",
    )?;

    let records = load_all_records(&transaction, path)?;
    for record in &records {
        validate_record_bindings(&transaction, path, record)?;
    }
    validate_safe_status_rows(
        &transaction,
        path,
        "connection_current_status",
        "current status startup validation",
    )?;
    validate_safe_status_rows(
        &transaction,
        path,
        "connection_status_history",
        "status history startup validation",
    )?;
    transaction
        .commit()
        .map_err(|source| sqlite_error(path, "startup validation commit", source))
}

fn load_all_records(
    connection: &Connection,
    path: &Path,
) -> Result<Vec<StoredConnection>, ConnectionStoreError> {
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
        .map_err(|source| sqlite_error(path, "list prepare", source))?;
    let rows = statement
        .query_map([], RawStoredConnection::from_row)
        .map_err(|source| sqlite_error(path, "list query", source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, "list read", source))?;
    rows.into_iter()
        .map(RawStoredConnection::into_stored)
        .collect()
}

fn count_rows(
    connection: &Connection,
    path: &Path,
    resource: &'static str,
    query: &'static str,
) -> Result<usize, ConnectionStoreError> {
    let count: i64 = connection
        .query_row(query, [], |row| row.get(0))
        .map_err(|source| sqlite_error(path, "persisted bound validation", source))?;
    usize::try_from(count).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: format!("<{resource}>"),
        reason: "negative or oversized persisted row count",
    })
}

fn ensure_no_invalid_rows(
    connection: &Connection,
    path: &Path,
    operation: &'static str,
    query: &'static str,
    reason: &'static str,
) -> Result<(), ConnectionStoreError> {
    let count: i64 = connection
        .query_row(query, [], |row| row.get(0))
        .map_err(|source| sqlite_error(path, operation, source))?;
    if count == 0 {
        Ok(())
    } else {
        Err(ConnectionStoreError::CorruptRecord {
            id: "<status>".to_owned(),
            reason,
        })
    }
}

fn validate_safe_status_rows(
    connection: &Connection,
    path: &Path,
    table: &'static str,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    let query = format!(
        "SELECT connection_id, state, reason, observed_at, latency_ms, \
         catalog_age_secs, catalog_entry_count FROM {table}"
    );
    let mut statement = connection
        .prepare(&query)
        .map_err(|source| sqlite_error(path, operation, source))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                RawStatus {
                    state: row.get(1)?,
                    reason: row.get(2)?,
                    observed_at: row.get(3)?,
                    latency_ms: row.get(4)?,
                    catalog_age_secs: row.get(5)?,
                    catalog_entry_count: row.get(6)?,
                },
            ))
        })
        .map_err(|source| sqlite_error(path, operation, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| sqlite_error(path, operation, source))?;
    for (raw_id, status) in rows {
        let id = ConnectionId::parse(raw_id.clone()).map_err(|_| {
            ConnectionStoreError::CorruptRecord {
                id: raw_id,
                reason: "status row has an invalid connection ID",
            }
        })?;
        status.into_safe_status(&id)?;
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
        if self.spec_json.len() > MAX_MANAGED_SPEC_BYTES {
            return Err(ConnectionStoreError::CorruptRecord {
                id: id.to_string(),
                reason: "connection document exceeds the managed specification limit",
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
    fn final_schema_validation_rolls_back_migration_from_damaged_applied_prefix() {
        let mut connection = Connection::open_in_memory().expect("memory database should open");
        connection
            .execute_batch(CREATE_MIGRATIONS_TABLE_SQL)
            .expect("migration table should create");
        connection
            .execute_batch("CREATE TABLE connection_records (id TEXT PRIMARY KEY);")
            .expect("damaged applied schema should create");
        connection
            .execute(
                "INSERT INTO connection_schema_migrations (version, applied_at) VALUES (1, ?1)",
                params![utc_timestamp().expect("timestamp should format")],
            )
            .expect("applied marker should insert");

        assert!(run_migrations(&mut connection, Path::new(":memory:"), MIGRATIONS).is_err());
        let version_two_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM connection_schema_migrations WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .expect("migration marker query should work");
        let status_table_count: i64 = connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM sqlite_master
                WHERE type = 'table'
                  AND name IN ('connection_current_status', 'connection_status_history')
                "#,
                [],
                |row| row.get(0),
            )
            .expect("schema catalog query should work");
        assert_eq!(version_two_count, 0);
        assert_eq!(
            status_table_count, 0,
            "schema validation failure must roll back migration DDL"
        );
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
    fn dependencies_are_transactionally_bounded_and_idempotent() {
        let (_directory, path, store) = temporary_store("dependency-limit");
        let created = store.create(candidate()).expect("create should succeed");
        {
            let mut connection = store.connection_guard();
            let transaction = connection
                .transaction()
                .expect("seed transaction should begin");
            for index in 0..MAX_CONNECTION_DEPENDENCIES {
                transaction
                    .execute(
                        r#"
                        INSERT INTO connection_dependencies (
                            connection_id, consumer_kind, consumer_id, created_at
                        ) VALUES (?1, 'manual_tool', ?2, ?3)
                        "#,
                        params![
                            created.id.as_str(),
                            format!("consumer-{index}"),
                            utc_timestamp().expect("timestamp should format")
                        ],
                    )
                    .expect("bounded dependency should insert");
            }
            transaction
                .commit()
                .expect("seed transaction should commit");
        }

        store
            .add_dependency(
                &created.id,
                ConnectionDependencyKind::ManualTool,
                "consumer-0",
            )
            .expect("existing dependency should remain an idempotent success");
        assert!(matches!(
            store.add_dependency(
                &created.id,
                ConnectionDependencyKind::ManualTool,
                "one-too-many"
            ),
            Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            })
        ));
        {
            let connection = store.connection_guard();
            connection
                .execute(
                    r#"
                    INSERT INTO connection_dependencies (
                        connection_id, consumer_kind, consumer_id, created_at
                    ) VALUES (?1, 'manual_tool', 'one-too-many', ?2)
                    "#,
                    params![
                        created.id.as_str(),
                        utc_timestamp().expect("timestamp should format")
                    ],
                )
                .expect("direct corruption should bypass the application bound");
        }
        drop(store);
        assert!(matches!(
            SqliteConnectionStore::open(path),
            Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            })
        ));
    }

    #[test]
    fn credential_binding_rows_are_hard_bounded() {
        let (_directory, path, store) = temporary_store("binding-limit");
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

        {
            let connection = store.connection_guard();
            connection
                .execute(
                    r#"
                    INSERT INTO connection_credential_bindings (
                        connection_id, purpose, secret_id, binding_version, updated_at
                    ) VALUES (?1, 'one-too-many', 'one-too-many', 1, ?2)
                    "#,
                    params![
                        created.id.as_str(),
                        utc_timestamp().expect("timestamp should format")
                    ],
                )
                .expect("direct corruption should bypass the application bound");
        }
        drop(store);
        assert!(matches!(
            SqliteConnectionStore::open(path),
            Err(ConnectionStoreError::LimitExceeded {
                resource: "connection credential bindings",
                maximum: MAX_CREDENTIALS,
            })
        ));
    }

    #[test]
    fn status_observations_are_bound_to_the_tested_config_revision() {
        let (_directory, _path, store) = temporary_store("status-etag");
        let created = store.create(candidate()).expect("create should succeed");
        let stale_etag = created.etag();
        let healthy = ConnectionStatusUpdate {
            state: ConnectionOperationalState::Healthy,
            reason: ConnectionStatusReason::TestSucceeded,
            latency_ms: Some(5),
            catalog_age_secs: None,
            catalog_entry_count: None,
        };
        store
            .append_status(&created.id, &stale_etag, healthy.clone())
            .expect("initial observation should append");

        let mut replacement = created.write.clone();
        replacement.display_name = "Billing API v2".to_owned();
        let replaced = store
            .replace(&created.id, &stale_etag, replacement)
            .expect("replacement should succeed");
        assert!(
            store
                .latest_status(&created.id)
                .expect("latest status query should succeed")
                .is_none(),
            "reconfiguration must invalidate the prior current observation"
        );
        assert!(matches!(
            store.append_status(&created.id, &stale_etag, healthy.clone()),
            Err(ConnectionStoreError::Conflict { .. })
        ));
        assert!(
            store
                .latest_status(&created.id)
                .expect("latest status query should succeed")
                .is_none(),
            "a late stale test must not mark the replacement healthy"
        );
        store
            .append_status(&created.id, &replaced.etag(), healthy)
            .expect("observation for the replacement should append");
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
            .append_status(&created.id, &created.etag(), update)
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
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at
                        ) VALUES (
                            ?1, ?2, 1, 1, 0, 1, 'degraded', 'request_failed', ?3
                        )
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
                &created.etag(),
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
        let history_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM connection_status_history",
                [],
                |row| row.get(0),
            )
            .expect("status count should query");
        assert_eq!(
            history_count,
            i64::try_from(MAX_STATUS_HISTORY_ROWS - 1).expect("history limit should fit SQLite")
        );
        let current_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM connection_current_status",
                [],
                |row| row.get(0),
            )
            .expect("current status count should query");
        assert_eq!(current_count, 1);
    }

    #[test]
    fn global_history_pruning_preserves_every_connections_current_status() {
        let (_directory, _path, store) = temporary_store("status-fairness");
        let quiet = store
            .create(candidate())
            .expect("quiet connection should create");
        let mut noisy_candidate = candidate();
        noisy_candidate.display_name = "Noisy API".to_owned();
        let noisy = store
            .create(noisy_candidate)
            .expect("noisy connection should create");
        let quiet_status = ConnectionStatusUpdate {
            state: ConnectionOperationalState::Healthy,
            reason: ConnectionStatusReason::TestSucceeded,
            latency_ms: Some(3),
            catalog_age_secs: None,
            catalog_entry_count: None,
        };
        store
            .append_status(&quiet.id, &quiet.etag(), quiet_status)
            .expect("quiet status should append");
        store
            .append_status(
                &noisy.id,
                &noisy.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Degraded,
                    reason: ConnectionStatusReason::RequestFailed,
                    latency_ms: None,
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                },
            )
            .expect("initial noisy status should append");

        {
            let mut connection = store.connection_guard();
            let transaction = connection
                .transaction()
                .expect("history seed transaction should begin");
            for revision in
                2..=u64::try_from(MAX_STATUS_HISTORY_ROWS).expect("history limit should fit u64")
            {
                transaction
                    .execute(
                        r#"
                        INSERT INTO connection_status_history (
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at
                        ) VALUES (
                            ?1, ?2, 1, 1, 0, 1, 'degraded', 'request_failed', ?3
                        )
                        "#,
                        params![
                            noisy.id.as_str(),
                            u64_to_i64(&noisy.id, revision)
                                .expect("test revision should fit SQLite"),
                            utc_timestamp().expect("timestamp should format")
                        ],
                    )
                    .expect("noisy history row should insert");
            }
            let seeded_revision =
                i64::try_from(MAX_STATUS_HISTORY_ROWS).expect("history limit should fit SQLite");
            transaction
                .execute(
                    "UPDATE connection_records SET status_revision = ?1 WHERE id = ?2",
                    params![seeded_revision, noisy.id.as_str()],
                )
                .expect("noisy record revision should update");
            transaction
                .execute(
                    r#"
                    UPDATE connection_current_status
                    SET status_revision = ?1
                    WHERE connection_id = ?2
                    "#,
                    params![seeded_revision, noisy.id.as_str()],
                )
                .expect("noisy current revision should update");
            transaction
                .commit()
                .expect("history seed transaction should commit");
        }
        store
            .append_status(
                &noisy.id,
                &noisy.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: Some(4),
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                },
            )
            .expect("bounded noisy append should succeed");

        let quiet_latest = store
            .latest_status(&quiet.id)
            .expect("quiet latest query should succeed")
            .expect("quiet current status must be retained");
        assert_eq!(quiet_latest.state, ConnectionOperationalState::Healthy);
        let connection = store.connection_guard();
        let total_status_rows: i64 = connection
            .query_row(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM connection_current_status)
                    + (SELECT COUNT(*) FROM connection_status_history)
                "#,
                [],
                |row| row.get(0),
            )
            .expect("total status rows should query");
        assert_eq!(
            total_status_rows,
            i64::try_from(MAX_STATUS_HISTORY_ROWS).expect("status limit should fit SQLite")
        );
    }

    #[test]
    fn persisted_status_row_bound_is_enforced_on_restart() {
        let (_directory, path, store) = temporary_store("status-restart-limit");
        let created = store.create(candidate()).expect("create should succeed");
        store
            .append_status(
                &created.id,
                &created.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: None,
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                },
            )
            .expect("initial status should append");
        {
            let mut connection = store.connection_guard();
            let transaction = connection
                .transaction()
                .expect("status corruption transaction should begin");
            for revision in
                2..=u64::try_from(MAX_STATUS_HISTORY_ROWS).expect("status limit should fit u64")
            {
                transaction
                    .execute(
                        r#"
                        INSERT INTO connection_status_history (
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at
                        ) VALUES (
                            ?1, ?2, 1, 1, 0, 1, 'healthy', 'test_succeeded', ?3
                        )
                        "#,
                        params![
                            created.id.as_str(),
                            u64_to_i64(&created.id, revision)
                                .expect("test revision should fit SQLite"),
                            utc_timestamp().expect("timestamp should format")
                        ],
                    )
                    .expect("over-limit status row should insert");
            }
            let latest_revision =
                i64::try_from(MAX_STATUS_HISTORY_ROWS).expect("status limit should fit SQLite");
            transaction
                .execute(
                    "UPDATE connection_records SET status_revision = ?1 WHERE id = ?2",
                    params![latest_revision, created.id.as_str()],
                )
                .expect("record status revision should update");
            transaction
                .execute(
                    "UPDATE connection_current_status SET status_revision = ?1 WHERE connection_id = ?2",
                    params![latest_revision, created.id.as_str()],
                )
                .expect("current status revision should update");
            transaction
                .commit()
                .expect("status corruption transaction should commit");
        }
        drop(store);

        assert!(matches!(
            SqliteConnectionStore::open(path),
            Err(ConnectionStoreError::LimitExceeded {
                resource: "safe connection status rows",
                maximum: MAX_STATUS_HISTORY_ROWS,
            })
        ));
    }

    #[test]
    fn persisted_catalog_count_bound_is_enforced_on_restart() {
        let (_directory, path, store) = temporary_store("catalog-restart-limit");
        let created = store.create(candidate()).expect("create should succeed");
        store
            .append_status(
                &created.id,
                &created.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: None,
                    catalog_age_secs: None,
                    catalog_entry_count: Some(1),
                },
            )
            .expect("initial status should append");
        drop(store);

        let connection = Connection::open(&path).expect("database should open");
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("test corruption pragma should enable");
        connection
            .execute(
                "UPDATE connection_current_status SET catalog_entry_count = ?1 WHERE connection_id = ?2",
                params![
                    i64::try_from(MAX_CATALOG_ENTRIES + 1)
                        .expect("catalog test count should fit SQLite"),
                    created.id.as_str()
                ],
            )
            .expect("invalid catalog count should be written for the corruption test");
        connection
            .execute_batch("PRAGMA ignore_check_constraints = OFF;")
            .expect("test corruption pragma should disable");
        drop(connection);

        assert!(matches!(
            SqliteConnectionStore::open(path),
            Err(ConnectionStoreError::CorruptRecord {
                reason: "current connection status is stale or invalid",
                ..
            })
        ));
    }

    #[test]
    fn configured_managed_connection_bound_is_enforced_on_restart() {
        let (_directory, path, store) = temporary_store("record-restart-limit");
        store
            .create(candidate())
            .expect("first record should create");
        let mut second = candidate();
        second.display_name = "Second API".to_owned();
        store.create(second).expect("second record should create");
        drop(store);

        assert!(matches!(
            SqliteConnectionStore::open_with_maximum(path, 1),
            Err(ConnectionStoreError::LimitExceeded {
                resource: "managed connections",
                maximum: 1,
            })
        ));
    }

    #[test]
    fn record_and_bindings_are_read_from_one_wal_snapshot() {
        let (_directory, path, first_store) = temporary_store("read-snapshot");
        let created = first_store
            .create(candidate())
            .expect("connection should create");
        let second_store =
            SqliteConnectionStore::open(&path).expect("second store handle should open");

        let mut first_connection = first_store.connection_guard();
        let read_transaction = first_connection
            .transaction()
            .expect("deferred read transaction should begin");
        let old_record = load_raw_by_id(&read_transaction, &path, &created.id)
            .expect("old record should load")
            .expect("old record should exist")
            .into_stored()
            .expect("old record should validate");

        let mut replacement = created.write.clone();
        replacement.authentication = ConnectionAuthentication::StaticBearer {
            secret_id: Some("billing-token-v2".to_owned()),
        };
        let replaced = second_store
            .replace(&created.id, &created.etag(), replacement)
            .expect("concurrent replacement should commit in WAL mode");
        validate_record_bindings(&read_transaction, &path, &old_record)
            .expect("binding validation must use the original read snapshot");
        read_transaction
            .commit()
            .expect("read transaction should commit");
        drop(first_connection);

        assert_eq!(
            first_store
                .get(&created.id)
                .expect("subsequent get should succeed")
                .expect("record should remain"),
            replaced
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

        assert!(matches!(
            SqliteConnectionStore::open(&path),
            Err(ConnectionStoreError::CorruptRecord { .. })
        ));
        assert!(fs::metadata(path).is_ok());
    }

    #[test]
    fn mismatched_persisted_binding_fails_closed() {
        let (_directory, path, store) = temporary_store("corrupt-binding");
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

        drop(store);
        assert!(matches!(
            SqliteConnectionStore::open(path),
            Err(ConnectionStoreError::CorruptRecord {
                reason: "credential binding rows do not match the stored connection document",
                ..
            })
        ));
    }
}
