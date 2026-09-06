//! PostgreSQL managed-connection records store (issue #241, PR 8).
//!
//! The record layer of the #240 connection store against migration 6's
//! tables: the same validation, per-axis revision, and compare-and-swap
//! semantics the SQLite store establishes, with the HA state model's
//! additions -- every committed mutation appends an immutable
//! specification version, advances the shared security revision and the
//! connections resource's high-water mark, and writes a durable outbox
//! row identifying the connection (identifiers and revisions only).
//!
//! Concurrency is the authority's, on two levels. Per connection,
//! `SELECT ... FOR UPDATE` on the record row serializes writers; the etag
//! precondition is re-verified inside that lock, so two writers
//! presenting the same expected etag produce exactly one winner and one
//! [`ConnectionStoreError::Conflict`]. Across connections, every mutating
//! transaction opens by locking the singleton
//! `connection_state_revision` row (`begin_mutation`), which is what
//! makes the *global* bounds -- record count, credential bindings,
//! catalog entries and bytes, dependencies -- hold: under READ COMMITTED
//! a `COUNT(*)` taken outside that lock is a hint, not an authority, and
//! two racing creators would both read `maximum - 1` and both commit.
//! Readers take neither lock; they run on one `REPEATABLE READ` snapshot
//! (`begin_snapshot`) so a record and the rows it is validated against
//! are always read from the same instant.
//!
//! Catalog, status, and dependency surfaces are not on this store yet;
//! they arrive with the remaining PR 8 wiring. The record layer is
//! complete and independently tested.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::storage::{
    postgres_policy,
    postgres_tool_names::{self, ToolNameReservationError},
};

use super::store::{
    binding_count, decode_enum_source_values, encode_enum_source_values, ensure_etag,
    expected_bindings, increment_revision, initial_revisions, managed_tool_dependency_id,
    optional_i64_to_u64, optional_u64_to_i64, parse_reason, parse_state, persisted_revision,
    reason_as_str, replacement_revisions, revision_from_i64, state_as_str,
    supports_managed_mcp_catalog, supports_managed_openapi_catalog, u64_to_i64, utc_timestamp,
    valid_enum_source_timestamp, valid_overlay_local_name, valid_sha256_hex,
    validate_activity_timestamp, validate_candidate, validate_dependency_id, validate_mcp_catalog,
    validate_openapi_catalog_entries, validate_openapi_overlay_write, validate_openapi_spec,
    ConnectionActivityTimes, ConnectionDependency, ConnectionDependencyKind, ConnectionEtag,
    ConnectionStatusUpdate, ConnectionStoreError, ExportedConnectionStatuses,
    PersistedConnectionStatus, StoredConnection, StoredEnumSourceRevision, StoredEnumSourceValue,
    StoredEnumSourceValueWrite, StoredMcpCatalog, StoredMcpCatalogEntry, StoredMcpResource,
    StoredMcpResourceTemplate, StoredOpenApiCatalog, StoredOpenApiCatalogEntry,
    StoredOpenApiInventoryCatalog, StoredOpenApiOverlay, StoredOpenApiSourceReports,
    StoredOverlayWrite, MAX_CONNECTION_DEPENDENCIES, MAX_OPENAPI_ENUM_SOURCES, SOURCE_MANAGED,
};
use super::{
    model::{ConnectionId, ConnectionWrite, MAX_CONNECTIONS, MAX_CREDENTIALS},
    status::{ConnectionRevisions, ConnectionStatusReason, SafeConnectionStatus},
};

const OPERATION_VALIDATE: &str = "startup_validation";
const OPERATION_LIST: &str = "record_list";
const OPERATION_GET: &str = "record_get";
const OPERATION_CREATE: &str = "record_create";
const OPERATION_REPLACE: &str = "record_replace";
const OPERATION_DELETE: &str = "record_delete";
const OPERATION_STATE_REVISION: &str = "connection_state_revision_read";
const OPERATION_ENUM_SOURCE_VALUES: &str = "enum_source_values";

/// The record row as persisted. `spec_json` is the authoritative
/// specification document; the per-axis revisions derive the etag.
struct RawConnectionRow {
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

impl RawConnectionRow {
    fn from_row(row: &tokio_postgres::Row) -> Result<Self, ConnectionStoreError> {
        const REASON: &str = "connection record column does not decode as its schema type";
        // The ID decodes first so every later failure can name the row it
        // came from; before that there is no identity to report.
        let id: String = column(row, 0, "<connection-record>", REASON)?;
        Ok(Self {
            schema_version: column(row, 1, &id, REASON)?,
            source: column(row, 2, &id, REASON)?,
            spec_json: column(row, 3, &id, REASON)?,
            connection_revision: column(row, 4, &id, REASON)?,
            credential_revision: column(row, 5, &id, REASON)?,
            tls_revision: column(row, 6, &id, REASON)?,
            discovery_revision: column(row, 7, &id, REASON)?,
            status_revision: column(row, 8, &id, REASON)?,
            created_at: column(row, 9, &id, REASON)?,
            updated_at: column(row, 10, &id, REASON)?,
            id,
        })
    }

    fn into_stored(self) -> Result<StoredConnection, ConnectionStoreError> {
        let id = ConnectionId::parse(self.id.clone()).map_err(|_| {
            ConnectionStoreError::CorruptRecord {
                id: self.id.clone(),
                reason: "invalid connection ID",
            }
        })?;
        if self.schema_version != super::model::CONNECTION_SCHEMA_VERSION {
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
        if self.spec_json.len() > super::model::MAX_MANAGED_SPEC_BYTES {
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
        let write =
            write
                .validated_persisted_v0()
                .map_err(|_| ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "connection document no longer passes validation",
                })?;
        Ok(StoredConnection {
            revisions: ConnectionRevisions {
                connection: persisted(&id, self.connection_revision, false)?,
                credential: persisted(&id, self.credential_revision, true)?,
                tls: persisted(&id, self.tls_revision, true)?,
                discovery: persisted(&id, self.discovery_revision, true)?,
                status: persisted(&id, self.status_revision, true)?,
            },
            id,
            write,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn id_uuid(id: &ConnectionId) -> Result<uuid::Uuid, ConnectionStoreError> {
    uuid::Uuid::parse_str(id.as_str()).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: id.to_string(),
        reason: "managed connection ID is not a UUID",
    })
}

fn persisted(
    id: &ConnectionId,
    value: i64,
    zero_allowed: bool,
) -> Result<u64, ConnectionStoreError> {
    super::store::revision_from_i64(id, value, zero_allowed)
}

// ==== Column decoding ====
//
// `tokio_postgres::Row::get` PANICS on a type mismatch or an
// out-of-range index. The SQLite reference decodes through
// `rusqlite::Row::get`, which returns a `Result`, and turns every decode
// failure into a typed `ConnectionStoreError` -- a store whose entire
// contract is to fail closed must not convert schema drift into a
// process abort. `column` and `scalar` are the ONLY decode path in this
// file; nothing below calls `Row::get` directly.

/// A value this schema stores for one identified durable row. A row that
/// no longer decodes is corruption, so it fails closed exactly like the
/// reference's other `CorruptRecord` paths (store.rs `into_stored`,
/// `into_safe_status`).
fn column<'a, T>(
    row: &'a tokio_postgres::Row,
    index: usize,
    id: &str,
    reason: &'static str,
) -> Result<T, ConnectionStoreError>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(index).map_err(|error| {
        tracing::error!(
            connection_id = id,
            index,
            reason,
            error = %error,
            "connection PostgreSQL column did not decode"
        );
        ConnectionStoreError::CorruptRecord {
            id: id.to_owned(),
            reason,
        }
    })
}

/// A value a query computes rather than stores -- `COUNT(*)`, `SUM(...)`,
/// `EXISTS(...)`, `RETURNING`. There is no record to call corrupt, so a
/// decode failure is a store failure, which is how the reference
/// classifies it too: `count_rows` sends its decode error through
/// `sqlite_error` to `ConnectionStoreError::Sqlite`, whose PostgreSQL
/// analogue is `Postgres`.
fn scalar<'a, T>(
    row: &'a tokio_postgres::Row,
    index: usize,
    operation: &'static str,
) -> Result<T, ConnectionStoreError>
where
    T: tokio_postgres::types::FromSql<'a>,
{
    row.try_get(index)
        .map_err(|error| pg_error(operation, error))
}

/// The PostgreSQL managed-connection record store. Cheap to construct;
/// borrows the foundation's pool.
pub struct PostgresConnectionStore {
    pool: deadpool_postgres::Pool,
    maximum_connections: usize,
}

impl PostgresConnectionStore {
    /// A `maximum_connections` above the hard ceiling is a
    /// misconfiguration and is REFUSED, not silently clamped, matching
    /// the reference (`SqliteConnectionStore::open_with_maximum`,
    /// store.rs). Clamping would let a deployment believe it had a
    /// capacity it does not have; a store that fails closed says so at
    /// construction instead.
    pub fn new(
        pool: deadpool_postgres::Pool,
        maximum_connections: usize,
    ) -> Result<Self, ConnectionStoreError> {
        if maximum_connections > MAX_CONNECTIONS {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "managed connections",
                maximum: MAX_CONNECTIONS,
            });
        }
        Ok(Self {
            pool,
            maximum_connections,
        })
    }

    /// The connections resource's activation high-water mark: the number
    /// the security gate's `ConnectionsResource` compares its compiled
    /// snapshot against.
    pub async fn state_revision(&self) -> Result<i64, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_STATE_REVISION))?;
        let row = client
            .query_opt(
                "SELECT last_revision FROM greengateway.connection_state_revision WHERE singleton",
                &[],
            )
            .await
            .map_err(|error| pg_error(OPERATION_STATE_REVISION, error))?;
        match row {
            Some(row) => scalar::<i64>(&row, 0, OPERATION_STATE_REVISION),
            None => Err(ConnectionStoreError::CorruptRecord {
                id: "<connection-state>".to_owned(),
                reason: "the connection state revision row is missing",
            }),
        }
    }

    pub async fn count(&self) -> Result<usize, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_LIST))?;
        count_records(&client).await
    }

    pub async fn list(&self) -> Result<Vec<StoredConnection>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_LIST))?;
        // One snapshot for the records and their binding validation: a
        // replacement committing between the two reads must not make a
        // healthy record read as corrupt (store.rs `list`).
        begin_snapshot(&client, OPERATION_LIST).await?;
        let outcome: Result<Vec<StoredConnection>, ConnectionStoreError> = async {
            let records = load_all_records(&client, OPERATION_LIST).await?;
            for record in &records {
                validate_bindings(&client, record).await?;
            }
            Ok(records)
        }
        .await;
        finish_read(&client, OPERATION_LIST, outcome).await
    }

    pub async fn get(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredConnection>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_GET))?;
        // One snapshot for the record and its binding validation
        // (store.rs `get`, and its
        // `record_and_bindings_are_read_from_one_wal_snapshot` test).
        begin_snapshot(&client, OPERATION_GET).await?;
        let outcome: Result<Option<StoredConnection>, ConnectionStoreError> = async {
            let record = load_record(&client, id, OPERATION_GET).await?;
            match record {
                Some(record) => {
                    validate_bindings(&client, &record).await?;
                    Ok(Some(record))
                }
                None => Ok(None),
            }
        }
        .await;
        finish_read(&client, OPERATION_GET, outcome).await
    }

    /// Create a managed connection: capacity-checked, validated, and
    /// committed with its first immutable specification version, the
    /// derived credential bindings, and the shared-state bumps (security
    /// revision, connections high-water mark, outbox row).
    pub async fn create(
        &self,
        candidate: ConnectionWrite,
        actor_user_id: &str,
        collection: Option<super::store::CollectionCheck<'_>>,
    ) -> Result<StoredConnection, ConnectionStoreError> {
        let candidate = validate_candidate(candidate)?;
        let spec_json =
            serde_json::to_string(&candidate).map_err(|source| ConnectionStoreError::Json {
                operation: "candidate",
                source,
            })?;
        let id = ConnectionId::new_managed();
        let now = utc_timestamp()?;
        let revisions = initial_revisions(&candidate);

        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_CREATE))?;
        begin_mutation(&client, OPERATION_CREATE).await?;
        // The outcome pattern (postgres_documents'): any failure rolls the
        // transaction back explicitly, releasing row locks immediately and
        // returning a clean connection to the pool instead of leaving an
        // aborted transaction on it.
        let outcome: Result<StoredConnection, ConnectionStoreError> = async {
            // The cross-replica half of the caller's `If-Match`: re-derive
            // the collection ETag from the authority's records, under the
            // singleton lock every mutation takes, so two replicas that
            // both passed their local check with the same ETag produce one
            // create and one conflict rather than two creates.
            if let Some(check) = collection.as_ref() {
                let records = load_all_records(&client, OPERATION_CREATE).await?;
                let current = (check.compute)(
                    &records
                        .into_iter()
                        .map(|record| (record.id.clone(), record))
                        .collect(),
                );
                if current != check.expected_etag {
                    return Err(ConnectionStoreError::CollectionConflict { current });
                }
            }
            let count = count_records(&client).await?;
            if count >= self.maximum_connections {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "managed connections",
                    maximum: self.maximum_connections,
                });
            }
            ensure_binding_capacity(&client, None, 0, binding_count(&candidate)).await?;
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_records (
                        id, schema_version, source, spec_json, connection_revision,
                        credential_revision, tls_revision, discovery_revision,
                        status_revision, created_at, updated_at
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
                    "#,
                    &[
                        &id.as_str(),
                        &super::model::CONNECTION_SCHEMA_VERSION,
                        &SOURCE_MANAGED,
                        &spec_json,
                        &u64_to_i64(&id, revisions.connection)?,
                        &u64_to_i64(&id, revisions.credential)?,
                        &u64_to_i64(&id, revisions.tls)?,
                        &u64_to_i64(&id, revisions.discovery)?,
                        &u64_to_i64(&id, revisions.status)?,
                        &now,
                    ],
                )
                .await
                .map_err(|error| pg_error(OPERATION_CREATE, error))?;
            replace_bindings(&client, &id, &candidate, &revisions, &now).await?;
            append_version(
                &client,
                &id,
                revisions.connection,
                &spec_json,
                actor_user_id,
            )
            .await?;
            bump_connection_state(
                &client,
                RESOURCE_CONNECTION,
                &id,
                None,
                revisions.connection,
            )
            .await?;
            Ok(StoredConnection {
                id: id.clone(),
                write: candidate.clone(),
                revisions,
                created_at: now.clone(),
                updated_at: now.clone(),
            })
        }
        .await;
        match outcome {
            Ok(stored) => {
                commit(&client, OPERATION_CREATE).await?;
                Ok(stored)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    /// Replace a connection's specification under its etag
    /// compare-and-swap, computing the per-axis revisions exactly the way
    /// the SQLite store does, and committing version/bindings/outbox in
    /// the same transaction. An identical candidate is a committed no-op
    /// that returns the current record unchanged.
    pub async fn replace(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        candidate: ConnectionWrite,
        actor_user_id: &str,
    ) -> Result<StoredConnection, ConnectionStoreError> {
        let candidate = validate_candidate(candidate)?;
        let spec_json =
            serde_json::to_string(&candidate).map_err(|source| ConnectionStoreError::Json {
                operation: "candidate",
                source,
            })?;
        let now = utc_timestamp()?;

        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_REPLACE))?;
        begin_mutation(&client, OPERATION_REPLACE).await?;
        let outcome: Result<StoredConnection, ConnectionStoreError> = async {
            let current = load_record_for_update(&client, id, OPERATION_REPLACE)
                .await?
                .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
            validate_bindings(&client, &current).await?;
            ensure_etag(id, expected, &current)?;
            if current.write == candidate {
                return Ok(current);
            }
            if managed_catalog_kind_changed(&current, &candidate) {
                let managed_tool_count_row = client
                    .query_one(
                        r#"
                        SELECT COUNT(*)
                        FROM greengateway.connection_dependencies
                        WHERE connection_id = $1::text::uuid AND consumer_kind = 'managed_tool'
                        "#,
                        &[&id.as_str()],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_REPLACE, error))?;
                let managed_tool_count: i64 = scalar(&managed_tool_count_row, 0, OPERATION_REPLACE)?;
                if managed_tool_count > 0 {
                    return Err(ConnectionStoreError::DependencyConflict {
                        id: id.to_string(),
                        count: usize::try_from(managed_tool_count).unwrap_or(usize::MAX),
                    });
                }
                for table in [
                    "greengateway.connection_mcp_catalogs",
                    "greengateway.connection_openapi_catalogs",
                    "greengateway.connection_openapi_overlays",
                    "greengateway.connection_enum_source_values",
                ] {
                    client
                        .execute(
                            &format!("DELETE FROM {table} WHERE connection_id = $1::text::uuid"),
                            &[&id.as_str()],
                        )
                        .await
                        .map_err(|error| pg_error(OPERATION_REPLACE, error))?;
                }
            }
            ensure_binding_capacity(
                &client,
                Some(id),
                binding_count(&current.write),
                binding_count(&candidate),
            )
            .await?;
            let revisions = replacement_revisions(id, &current, &candidate)?;
            client
                .execute(
                    r#"
                    UPDATE greengateway.connection_records
                    SET spec_json = $1,
                        connection_revision = $2,
                        credential_revision = $3,
                        tls_revision = $4,
                        discovery_revision = $5,
                        updated_at = $6
                    WHERE id = $7::text::uuid
                    "#,
                    &[
                        &spec_json,
                        &u64_to_i64(id, revisions.connection)?,
                        &u64_to_i64(id, revisions.credential)?,
                        &u64_to_i64(id, revisions.tls)?,
                        &u64_to_i64(id, revisions.discovery)?,
                        &now,
                        &id.as_str(),
                    ],
                )
                .await
                .map_err(|error| pg_error(OPERATION_REPLACE, error))?;
            client
                .execute(
                    "DELETE FROM greengateway.connection_current_status WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_REPLACE, error))?;
            replace_bindings(&client, id, &candidate, &revisions, &now).await?;
            append_version(
                &client,
                id,
                revisions.connection,
                &spec_json,
                actor_user_id,
            )
            .await?;
            bump_connection_state(
                &client,
                RESOURCE_CONNECTION,
                id,
                Some(current.revisions.connection),
                revisions.connection,
            )
            .await?;
            Ok(StoredConnection {
                id: id.clone(),
                write: candidate,
                revisions,
                created_at: current.created_at,
                updated_at: now.clone(),
            })
        }
        .await;
        match outcome {
            Ok(stored) => {
                commit(&client, OPERATION_REPLACE).await?;
                Ok(stored)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    /// Delete a connection under its etag compare-and-swap. A connection
    /// still referenced by dependency rows is refused; deletes cascade to
    /// versions, bindings, catalogs, and status rows in the same commit
    /// as the state/outbox bumps.
    pub async fn delete(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        _actor_user_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_DELETE))?;
        begin_mutation(&client, OPERATION_DELETE).await?;
        let outcome: Result<(), ConnectionStoreError> = async {
            let current = load_record_for_update(&client, id, OPERATION_DELETE)
                .await?
                .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
            validate_bindings(&client, &current).await?;
            ensure_etag(id, expected, &current)?;
            let dependency_count_row = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DELETE, error))?;
            let dependency_count: i64 = scalar(&dependency_count_row, 0, OPERATION_DELETE)?;
            if dependency_count > 0 {
                return Err(ConnectionStoreError::DependencyConflict {
                    id: id.to_string(),
                    count: usize::try_from(dependency_count).unwrap_or(usize::MAX),
                });
            }
            // The outbox row precedes the cascade delete: version 0 marks a
            // deletion (specification versions start at 1). The version
            // rows cascade with the record, as they do in the standalone
            // store; the deletion is attributed by the admin audit event
            // the handler records with its actor, which is why the actor
            // is not written here. Any tool names the record's catalogs
            // held are released in the same transaction.
            bump_connection_state(&client, RESOURCE_CONNECTION, id, Some(current.revisions.connection), 0)
                .await?;
            postgres_tool_names::release_tool_names(&client, id.as_str())
                .await
                .map_err(|error| pg_error(OPERATION_DELETE, error))?;
            client
                .execute(
                    "DELETE FROM greengateway.connection_records WHERE id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DELETE, error))?;
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {
                commit(&client, OPERATION_DELETE).await?;
                Ok(())
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }
}

// ==== Catalog, status, and dependency surfaces (the remaining PR 8 port) ====

const OPERATION_MCP_CATALOG: &str = "mcp_catalog_replace";
const OPERATION_MCP_READ: &str = "mcp_catalog_read";
const OPERATION_OPENAPI_CATALOG: &str = "openapi_catalog_replace";
const OPERATION_OPENAPI_READ: &str = "openapi_catalog_read";
const OPERATION_STATUS: &str = "status_append";
const OPERATION_STATUS_READ: &str = "status_read";
const OPERATION_DEPS: &str = "dependency_write";
const OPERATION_DEPS_READ: &str = "dependency_read";
const OPERATION_ACTIVITY_READ: &str = "connection_activity_read";

impl PostgresConnectionStore {
    /// Every stored MCP catalog (startup load and the reconciler). Reads
    /// validate counts and revisions exactly like the SQLite loader; a
    /// corrupt catalog fails closed instead of loading.
    pub async fn mcp_catalogs(&self) -> Result<Vec<StoredMcpCatalog>, ConnectionStoreError> {
        self.read_mcp_catalogs(None).await
    }

    pub async fn mcp_catalog(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredMcpCatalog>, ConnectionStoreError> {
        Ok(self.read_mcp_catalogs(Some(id)).await?.into_iter().next())
    }

    async fn read_mcp_catalogs(
        &self,
        requested: Option<&ConnectionId>,
    ) -> Result<Vec<StoredMcpCatalog>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_MCP_READ))?;
        // One snapshot for the aggregate byte preflight, the header rows,
        // and every child query they are checked against: a catalog
        // replacement committing between the header read and its entry
        // read would otherwise report a count mismatch on a healthy
        // catalog. The SQLite loader holds the store's connection for the
        // whole of `load_mcp_catalogs`, which is the same guarantee.
        begin_snapshot(&client, OPERATION_MCP_READ).await?;
        let outcome = load_mcp_catalogs(&client, requested).await;
        finish_read(&client, OPERATION_MCP_READ, outcome).await
    }

    /// Replace a connection's MCP catalog under its etag compare-and-swap:
    /// global entry/byte capacity checks, catalog-revision increment, the
    /// per-entry managed-tool dependency replacement, and -- the cluster
    /// addition -- the shared security revision, the connections
    /// high-water mark, and the outbox row, all in the one transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn replace_mcp_catalog(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        entries: &[StoredMcpCatalogEntry],
        resources: &[StoredMcpResource],
        resource_templates: &[StoredMcpResourceTemplate],
        expected_catalog_revision: u64,
        actor_user_id: &str,
    ) -> Result<StoredMcpCatalog, ConnectionStoreError> {
        let validated = validate_mcp_catalog(id, entries, resources, resource_templates)?;
        let now = utc_timestamp()?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_MCP_CATALOG))?;
        begin_mutation(&client, OPERATION_MCP_CATALOG).await?;
        let outcome: Result<StoredMcpCatalog, ConnectionStoreError> = async {
            let current = load_record_for_update(&client, id, OPERATION_MCP_CATALOG)
                .await?
                .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
            validate_bindings(&client, &current).await?;
            ensure_etag(id, expected, &current)?;
            if !supports_managed_mcp_catalog(&current.write) {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![
                        "MCP catalogs require a managed MCP streamable HTTP Connection".to_owned(),
                    ],
                });
            }

            let retained_row = client
                .query_one(
                    r#"
                    SELECT
                        (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_entries
                         WHERE connection_id != $1::text::uuid)
                      + (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_resources
                         WHERE connection_id != $1::text::uuid)
                      + (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_resource_templates
                         WHERE connection_id != $1::text::uuid)
                      + (SELECT COUNT(*) FROM greengateway.connection_openapi_catalog_entries)
                    "#,
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
            let retained: i64 = scalar(&retained_row, 0, OPERATION_MCP_CATALOG)?;
            let candidate_count = entries
                .len()
                .saturating_add(resources.len())
                .saturating_add(resource_templates.len());
            if usize::try_from(retained).unwrap_or(usize::MAX).saturating_add(candidate_count)
                > super::model::MAX_CATALOG_ENTRIES
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection catalog entries",
                    maximum: super::model::MAX_CATALOG_ENTRIES,
                });
            }
            let retained_bytes =
                mcp_catalog_bytes(&client, Some(id), OPERATION_MCP_CATALOG).await?;
            if retained_bytes
                .checked_add(validated.stored_bytes)
                .is_none_or(|total| total > super::store::MAX_MANAGED_MCP_CATALOG_BYTES)
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection MCP catalog bytes",
                    maximum: super::store::MAX_MANAGED_MCP_CATALOG_BYTES,
                });
            }

            let previous_revision = client
                .query_opt(
                    "SELECT catalog_revision FROM greengateway.connection_mcp_catalogs \
                     WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?
                .map(|row| {
                    column::<i64>(
                        &row,
                        0,
                        id.as_str(),
                        "MCP catalog revision does not decode as its schema type",
                    )
                })
                .transpose()?;
            let previous_revision = previous_revision
                .map(|revision| persisted_revision(id, revision, "invalid MCP catalog revision"))
                .transpose()?
                .unwrap_or_default();
            // The catalog's own compare-and-swap. The connection ETag above
            // does not move on a catalog replacement, and the per-process
            // refresh guard does not reach other replicas, so two replicas
            // can both discover from the same prior catalog; without this,
            // whichever commits LAST wins, and a slower, older discovery
            // result would replace the newer one. `0` means "no catalog
            // yet", exactly as the OpenAPI path's expected revision does.
            if previous_revision != expected_catalog_revision {
                return Err(ConnectionStoreError::Conflict {
                    id: id.to_string(),
                    current: current.etag(),
                });
            }
            let catalog_revision = increment_revision(id, previous_revision)?;

            client
                .execute(
                    "DELETE FROM greengateway.connection_dependencies \
                     WHERE connection_id = $1::text::uuid AND consumer_kind = 'managed_tool'",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
            let retained_dependencies_row = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies",
                    &[],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
            let retained_dependencies: i64 = scalar(&retained_dependencies_row, 0, OPERATION_MCP_CATALOG)?;
            if usize::try_from(retained_dependencies).unwrap_or(usize::MAX).saturating_add(entries.len())
                > MAX_CONNECTION_DEPENDENCIES
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection dependencies",
                    maximum: MAX_CONNECTION_DEPENDENCIES,
                });
            }

            client
                .execute(
                    "DELETE FROM greengateway.connection_mcp_catalogs WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_mcp_catalogs (
                        connection_id, catalog_revision, observed_etag, refreshed_at, entry_count,
                        resource_count, resource_template_count, actor_user_id
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8)
                    "#,
                    &[
                        &id.as_str(),
                        &u64_to_i64(id, catalog_revision)?,
                        &expected.as_str(),
                        &now,
                        &usize_to_i64(entries.len()),
                        &usize_to_i64(resources.len()),
                        &usize_to_i64(resource_templates.len()),
                        &actor_user_id,
                    ],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;

            for (ordinal, ((entry, input_schema_json), annotations_json)) in entries
                .iter()
                .zip(validated.encoded_tool_schemas.iter())
                .zip(validated.encoded_tool_annotations.iter())
                .enumerate()
            {
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_mcp_catalog_entries (
                            connection_id, remote_tool_name, title, description,
                            input_schema_json, annotations_json, ordinal
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
                        "#,
                        &[
                            &id.as_str(),
                            &entry.remote_tool_name,
                            &entry.title,
                            &entry.description,
                            &input_schema_json,
                            &annotations_json,
                            &usize_to_i64(ordinal),
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_dependencies (
                            connection_id, consumer_kind, consumer_id, created_at
                        ) VALUES ($1::text::uuid, 'managed_tool', $2, $3)
                        "#,
                        &[&id.as_str(), &managed_tool_dependency_id(id, &entry.remote_tool_name), &now],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
            }

            for (ordinal, resource) in resources.iter().enumerate() {
                let size = resource
                    .size
                    .map(|size| {
                        i64::try_from(size).map_err(|_| ConnectionStoreError::Validation {
                            problems: vec![format!(
                                "MCP resource {ordinal} size exceeds the durable integer range"
                            )],
                        })
                    })
                    .transpose()?;
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_mcp_catalog_resources (
                            connection_id, uri, name, title, description, mime_type, size, ordinal
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8)
                        "#,
                        &[
                            &id.as_str(),
                            &resource.uri,
                            &resource.name,
                            &resource.title,
                            &resource.description,
                            &resource.mime_type,
                            &size,
                            &usize_to_i64(ordinal),
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
            }

            for (ordinal, resource_template) in resource_templates.iter().enumerate() {
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_mcp_catalog_resource_templates (
                            connection_id, uri_template, name, title, description, mime_type, ordinal
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
                        "#,
                        &[
                            &id.as_str(),
                            &resource_template.uri_template,
                            &resource_template.name,
                            &resource_template.title,
                            &resource_template.description,
                            &resource_template.mime_type,
                            &usize_to_i64(ordinal),
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
            }

            // The registry names a proxied tool "<connection id>:<remote
            // name>"; the reservation is made in that form.
            reserve_catalog_tool_names(
                &client,
                postgres_tool_names::LANE_MCP,
                id,
                entries
                    .iter()
                    .map(|entry| format!("{}:{}", id.as_str(), entry.remote_tool_name)),
                OPERATION_MCP_CATALOG,
            )
            .await?;
            bump_connection_state(
                &client,
                RESOURCE_CONNECTION_CATALOG,
                id,
                Some(previous_revision),
                catalog_revision,
            )
            .await?;
            Ok(StoredMcpCatalog {
                connection_id: id.clone(),
                catalog_revision,
                observed_etag: expected.clone(),
                refreshed_at: now.clone(),
                entries: entries.to_vec(),
                resources: resources.to_vec(),
                resource_templates: resource_templates.to_vec(),
            })
        }
        .await;
        match outcome {
            Ok(catalog) => {
                commit(&client, OPERATION_MCP_CATALOG).await?;
                Ok(catalog)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    pub async fn openapi_catalogs(
        &self,
    ) -> Result<Vec<StoredOpenApiCatalog>, ConnectionStoreError> {
        self.read_openapi_catalogs(None).await
    }

    /// Read the catalog/overlay pair from one repeatable-read snapshot.
    /// Both tables are committed together and must be reconciled together;
    /// separate snapshots can observe opposite sides of a concurrent
    /// overlay publication and spuriously withdraw a healthy runtime lane.
    pub async fn openapi_catalogs_with_overlays(
        &self,
    ) -> Result<(Vec<StoredOpenApiCatalog>, Vec<StoredOpenApiOverlay>), ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_OPENAPI_READ))?;
        begin_snapshot(&client, OPERATION_OPENAPI_READ).await?;
        let outcome = async {
            let catalogs = load_openapi_catalogs(&client, None).await?;
            let overlays = load_openapi_overlays(&client, None).await?;
            Ok((catalogs, overlays))
        }
        .await;
        finish_read(&client, OPERATION_OPENAPI_READ, outcome).await
    }

    pub async fn openapi_catalog_with_overlay(
        &self,
        id: &ConnectionId,
    ) -> Result<(Option<StoredOpenApiCatalog>, Option<StoredOpenApiOverlay>), ConnectionStoreError>
    {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_OPENAPI_READ))?;
        begin_snapshot(&client, OPERATION_OPENAPI_READ).await?;
        let outcome = async {
            let catalog = load_openapi_catalogs(&client, Some(id))
                .await?
                .into_iter()
                .next();
            let overlay = load_openapi_overlays(&client, Some(id))
                .await?
                .into_iter()
                .next();
            Ok((catalog, overlay))
        }
        .await;
        finish_read(&client, OPERATION_OPENAPI_READ, outcome).await
    }

    pub async fn openapi_inventory_catalogs(
        &self,
    ) -> Result<Vec<StoredOpenApiInventoryCatalog>, ConnectionStoreError> {
        Ok(self
            .read_openapi_catalogs(None)
            .await?
            .into_iter()
            .map(|catalog| StoredOpenApiInventoryCatalog {
                connection_id: catalog.connection_id,
                spec_revision: catalog.spec_revision,
                catalog_revision: catalog.catalog_revision,
                observed_etag: catalog.observed_etag,
                spec_digest: catalog.spec_digest,
                refreshed_at: catalog.refreshed_at,
                entries: catalog.entries,
            })
            .collect())
    }

    pub async fn openapi_catalog(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredOpenApiCatalog>, ConnectionStoreError> {
        Ok(self
            .read_openapi_catalogs(Some(id))
            .await?
            .into_iter()
            .next())
    }

    pub async fn openapi_overlays(
        &self,
    ) -> Result<Vec<StoredOpenApiOverlay>, ConnectionStoreError> {
        self.read_openapi_overlays(None).await
    }

    pub async fn openapi_overlay(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredOpenApiOverlay>, ConnectionStoreError> {
        Ok(self
            .read_openapi_overlays(Some(id))
            .await?
            .into_iter()
            .next())
    }

    async fn read_openapi_overlays(
        &self,
        requested: Option<&ConnectionId>,
    ) -> Result<Vec<StoredOpenApiOverlay>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_OPENAPI_READ))?;
        begin_snapshot(&client, OPERATION_OPENAPI_READ).await?;
        let outcome = load_openapi_overlays(&client, requested).await;
        finish_read(&client, OPERATION_OPENAPI_READ, outcome).await
    }

    pub async fn enum_source_values(
        &self,
    ) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
        self.read_enum_source_values(None).await
    }

    pub async fn enum_source_values_for_connection(
        &self,
        id: &ConnectionId,
    ) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
        self.read_enum_source_values(Some(id)).await
    }

    pub async fn enum_source_revisions(
        &self,
    ) -> Result<Vec<StoredEnumSourceRevision>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_ENUM_SOURCE_VALUES))?;
        begin_snapshot(&client, OPERATION_ENUM_SOURCE_VALUES).await?;
        let maximum = self
            .maximum_connections
            .saturating_mul(MAX_OPENAPI_ENUM_SOURCES);
        let outcome = load_enum_source_revisions(&client, maximum).await;
        finish_read(&client, OPERATION_ENUM_SOURCE_VALUES, outcome).await
    }

    pub async fn enum_source_value(
        &self,
        id: &ConnectionId,
        source_id: &str,
    ) -> Result<Option<StoredEnumSourceValue>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_ENUM_SOURCE_VALUES))?;
        load_enum_source_value(&client, id, source_id).await
    }

    async fn read_enum_source_values(
        &self,
        requested: Option<&ConnectionId>,
    ) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_ENUM_SOURCE_VALUES))?;
        begin_snapshot(&client, OPERATION_ENUM_SOURCE_VALUES).await?;
        let outcome = load_enum_source_values(&client, requested).await;
        let values = finish_read(&client, OPERATION_ENUM_SOURCE_VALUES, outcome).await?;
        let maximum = if requested.is_some() {
            MAX_OPENAPI_ENUM_SOURCES
        } else {
            self.maximum_connections
                .saturating_mul(MAX_OPENAPI_ENUM_SOURCES)
        };
        if values.len() > maximum {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection enum source values",
                maximum,
            });
        }
        Ok(values)
    }

    /// Publish one dynamic enum LKG under its source and Connection fences.
    ///
    /// This intentionally does not take the global Connection mutation lock or
    /// emit a security outbox event: enum refresh is data-plane cache state,
    /// not a catalog/policy mutation. Row locks on the Connection, overlay and
    /// source serialize it against replacement/pruning without consuming the
    /// catalog refresh semaphore.
    pub async fn replace_enum_source_value(
        &self,
        write: &StoredEnumSourceValueWrite,
        expected_values_revision: u64,
    ) -> Result<StoredEnumSourceValue, ConnectionStoreError> {
        let values_json = encode_enum_source_values(write)?;
        if write.expected_values_revision != expected_values_revision {
            return Err(ConnectionStoreError::Validation {
                problems: vec![
                    "enum source expected values revision does not match the fetched candidate"
                        .to_owned(),
                ],
            });
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_ENUM_SOURCE_VALUES))?;
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?;
        let outcome: Result<StoredEnumSourceValue, ConnectionStoreError> = async {
            // `SELECT .. FOR UPDATE` cannot lock a row that does not exist.
            // Serialize the `(connection, source)` key first so two replicas
            // racing the initial revision cannot both observe revision zero
            // and let `ON CONFLICT` overwrite the winner with revision one.
            let lock_name = format!(
                "greengateway:enum-source:{}:{}",
                write.connection_id, write.source_id
            );
            client
                .execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    &[&lock_name],
                )
                .await
                .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?;
            let record = client
                .query_opt(
                    r#"
                    SELECT connection_revision, credential_revision
                    FROM greengateway.connection_records
                    WHERE id = $1::text::uuid
                    FOR SHARE
                    "#,
                    &[&write.connection_id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?
                .ok_or_else(|| ConnectionStoreError::NotFound {
                    id: write.connection_id.to_string(),
                })?;
            let current_connection_revision: i64 = column(
                &record,
                0,
                write.connection_id.as_str(),
                "enum source Connection revision does not decode as bigint",
            )?;
            let current_credential_revision: i64 = column(
                &record,
                1,
                write.connection_id.as_str(),
                "enum source credential revision does not decode as bigint",
            )?;
            let overlay = client
                .query_opt(
                    r#"
                    SELECT overlay_revision
                    FROM greengateway.connection_openapi_overlays
                    WHERE connection_id = $1::text::uuid
                    FOR SHARE
                    "#,
                    &[&write.connection_id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?;
            let current_overlay_revision = match overlay {
                Some(row) => persisted_revision(
                    &write.connection_id,
                    column(
                        &row,
                        0,
                        write.connection_id.as_str(),
                        "enum source overlay revision does not decode as bigint",
                    )?,
                    "invalid enum source overlay revision",
                )?,
                None => 0,
            };
            let previous = client
                .query_opt(
                    r#"
                    SELECT values_revision, source_digest
                    FROM greengateway.connection_enum_source_values
                    WHERE connection_id = $1::text::uuid AND source_id = $2
                    FOR UPDATE
                    "#,
                    &[&write.connection_id.as_str(), &write.source_id],
                )
                .await
                .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?;
            let current_values_revision = match previous {
                Some(ref row) => persisted_revision(
                    &write.connection_id,
                    column(
                        row,
                        0,
                        write.connection_id.as_str(),
                        "enum source values revision does not decode as bigint",
                    )?,
                    "invalid enum source values revision",
                )?,
                None => 0,
            };
            let current_source_digest = previous
                .as_ref()
                .map(|row| {
                    column::<String>(
                        row,
                        1,
                        write.connection_id.as_str(),
                        "enum source digest does not decode as text",
                    )
                })
                .transpose()?;
            if current_values_revision != expected_values_revision
                || current_source_digest
                    .as_ref()
                    .is_some_and(|source_digest| source_digest != &write.source_digest)
                || current_overlay_revision != write.overlay_revision
                || revision_from_i64(&write.connection_id, current_connection_revision, false)?
                    != write.connection_revision
                || revision_from_i64(&write.connection_id, current_credential_revision, true)?
                    != write.credential_revision
            {
                return Err(ConnectionStoreError::EnumSourceConflict {
                    id: write.connection_id.to_string(),
                    source_id: write.source_id.clone(),
                    current_values_revision,
                });
            }
            let values_revision =
                increment_revision(&write.connection_id, current_values_revision)?;
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_enum_source_values (
                        connection_id, source_id, overlay_revision, source_digest,
                        values_revision, connection_revision, credential_revision,
                        credential_generation_digest, values_json, resolved_at
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (connection_id, source_id) DO UPDATE SET
                        overlay_revision = excluded.overlay_revision,
                        source_digest = excluded.source_digest,
                        values_revision = excluded.values_revision,
                        connection_revision = excluded.connection_revision,
                        credential_revision = excluded.credential_revision,
                        credential_generation_digest = excluded.credential_generation_digest,
                        values_json = excluded.values_json,
                        resolved_at = excluded.resolved_at
                    "#,
                    &[
                        &write.connection_id.as_str(),
                        &write.source_id,
                        &u64_to_i64(&write.connection_id, write.overlay_revision)?,
                        &write.source_digest,
                        &u64_to_i64(&write.connection_id, values_revision)?,
                        &u64_to_i64(&write.connection_id, write.connection_revision)?,
                        &u64_to_i64(&write.connection_id, write.credential_revision)?,
                        &write.credential_generation_digest,
                        &values_json,
                        &write.resolved_at,
                    ],
                )
                .await
                .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?;
            Ok(StoredEnumSourceValue {
                connection_id: write.connection_id.clone(),
                source_id: write.source_id.clone(),
                overlay_revision: write.overlay_revision,
                source_digest: write.source_digest.clone(),
                values_revision,
                connection_revision: write.connection_revision,
                credential_revision: write.credential_revision,
                credential_generation_digest: write.credential_generation_digest.clone(),
                values: write.values.clone(),
                labels: write.labels.clone(),
                resolved_at: write.resolved_at.clone(),
            })
        }
        .await;
        match outcome {
            Ok(stored) => {
                commit(&client, OPERATION_ENUM_SOURCE_VALUES).await?;
                Ok(stored)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    async fn read_openapi_catalogs(
        &self,
        requested: Option<&ConnectionId>,
    ) -> Result<Vec<StoredOpenApiCatalog>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_OPENAPI_READ))?;
        // One snapshot for the header rows and the entry rows their
        // `entry_count` is checked against (store.rs
        // `load_openapi_catalogs` holds the connection across both).
        begin_snapshot(&client, OPERATION_OPENAPI_READ).await?;
        let outcome = load_openapi_catalogs(&client, requested).await;
        finish_read(&client, OPERATION_OPENAPI_READ, outcome).await
    }

    /// Replace a connection's OpenAPI catalog under the triple
    /// compare-and-swap (connection etag, spec revision, catalog revision)
    /// with digest revalidation, matching the SQLite store's semantics and
    /// adding the shared-state bumps in the same transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn replace_openapi_catalog(
        &self,
        id: &ConnectionId,
        expected_connection_etag: &ConnectionEtag,
        expected_spec_revision: u64,
        expected_catalog_revision: u64,
        spec: &str,
        spec_digest: &str,
        entries: &[StoredOpenApiCatalogEntry],
        actor_user_id: &str,
    ) -> Result<StoredOpenApiCatalog, ConnectionStoreError> {
        self.replace_openapi_catalog_with_overlay(
            id,
            expected_connection_etag,
            expected_spec_revision,
            expected_catalog_revision,
            spec,
            spec_digest,
            entries,
            None,
            0,
            actor_user_id,
            &[],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn replace_openapi_catalog_with_overlay(
        &self,
        id: &ConnectionId,
        expected_connection_etag: &ConnectionEtag,
        expected_spec_revision: u64,
        expected_catalog_revision: u64,
        spec: &str,
        spec_digest: &str,
        entries: &[StoredOpenApiCatalogEntry],
        overlay: Option<&StoredOverlayWrite>,
        compiled_overlay_revision: u64,
        actor_user_id: &str,
        policy_protected_names: &[String],
    ) -> Result<StoredOpenApiCatalog, ConnectionStoreError> {
        self.replace_openapi_catalog_with_overlay_and_enum_values(
            id,
            expected_connection_etag,
            expected_spec_revision,
            expected_catalog_revision,
            spec,
            spec_digest,
            entries,
            overlay,
            compiled_overlay_revision,
            actor_user_id,
            policy_protected_names,
            &[],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn replace_openapi_catalog_with_overlay_and_enum_values(
        &self,
        id: &ConnectionId,
        expected_connection_etag: &ConnectionEtag,
        expected_spec_revision: u64,
        expected_catalog_revision: u64,
        spec: &str,
        spec_digest: &str,
        entries: &[StoredOpenApiCatalogEntry],
        overlay: Option<&StoredOverlayWrite>,
        compiled_overlay_revision: u64,
        actor_user_id: &str,
        policy_protected_names: &[String],
        enum_values: &[StoredEnumSourceValueWrite],
    ) -> Result<StoredOpenApiCatalog, ConnectionStoreError> {
        validate_openapi_spec(spec, spec_digest)?;
        if let Some(overlay) = overlay {
            validate_openapi_overlay_write(overlay)?;
        }
        let encoded_entries = validate_openapi_catalog_entries(entries)?;
        let normalized_entries = encoded_entries
            .iter()
            .map(|entry| entry.entry.clone())
            .collect::<Vec<_>>();
        let now = utc_timestamp()?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_OPENAPI_CATALOG))?;
        begin_mutation(&client, OPERATION_OPENAPI_CATALOG).await?;
        let outcome: Result<StoredOpenApiCatalog, ConnectionStoreError> = async {
            if overlay.is_some() {
                postgres_policy::acquire_policy_overlay_lock(&client)
                    .await
                    .map_err(|_| pg_unavailable(OPERATION_OPENAPI_CATALOG))?;
                let authoritative_policy_names =
                    postgres_policy::active_policy_tool_names_in(&client)
                        .await
                        .map_err(|_| pg_unavailable(OPERATION_OPENAPI_CATALOG))?;
                if let Some(tool_name) = policy_protected_names
                    .iter()
                    .find(|name| authoritative_policy_names.contains(name.as_str()))
                {
                    return Err(ConnectionStoreError::ToolNameConflict {
                        id: id.to_string(),
                        tool_name: tool_name.clone(),
                        lane: "policy".to_owned(),
                        owner_id: "active-policy".to_owned(),
                    });
                }
            }
            let current = load_record_for_update(&client, id, OPERATION_OPENAPI_CATALOG)
                .await?
                .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
            validate_bindings(&client, &current).await?;

            let previous = client
                .query_opt(
                    r#"
                    SELECT spec_revision, catalog_revision, spec_digest, overlay_revision
                    FROM greengateway.connection_openapi_catalogs
                    WHERE connection_id = $1::text::uuid
                    "#,
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            let (
                previous_spec_revision,
                previous_catalog_revision,
                previous_digest,
                previous_overlay_revision,
            ) =
                match previous {
                    Some(row) => {
                        const REASON: &str =
                            "OpenAPI catalog column does not decode as its schema type";
                        (
                            persisted_revision(
                                id,
                                column(&row, 0, id.as_str(), REASON)?,
                                "invalid OpenAPI spec revision",
                            )?,
                            persisted_revision(
                                id,
                                column(&row, 1, id.as_str(), REASON)?,
                                "invalid OpenAPI catalog revision",
                            )?,
                            Some(column::<String>(&row, 2, id.as_str(), REASON)?),
                            revision_from_i64(
                                id,
                                column(&row, 3, id.as_str(), REASON)?,
                                true,
                            )?,
                        )
                    }
                    None => (0, 0, None, 0),
                };
            if let Err(error) = ensure_etag(id, expected_connection_etag, &current) {
                return if overlay.is_some() {
                    Err(ConnectionStoreError::OverlayConflict {
                        id: id.to_string(),
                        current_connection_revision: current.revisions.connection,
                        current_catalog_revision: previous_catalog_revision,
                        current_overlay_revision: previous_overlay_revision,
                    })
                } else {
                    Err(error)
                };
            }
            if !supports_managed_openapi_catalog(&current.write) {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![
                        "OpenAPI catalogs require a managed HTTP API OpenAPI Connection".to_owned(),
                    ],
                });
            }
            if expected_spec_revision != previous_spec_revision
                || expected_catalog_revision != previous_catalog_revision
            {
                return if overlay.is_some() {
                    Err(ConnectionStoreError::OverlayConflict {
                        id: id.to_string(),
                        current_connection_revision: current.revisions.connection,
                        current_catalog_revision: previous_catalog_revision,
                        current_overlay_revision: previous_overlay_revision,
                    })
                } else {
                    Err(ConnectionStoreError::Conflict {
                        id: id.to_string(),
                        current: current.etag(),
                    })
                };
            }

            let retained_row = client
                .query_one(
                    r#"
                    SELECT
                        (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_entries)
                      + (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_resources)
                      + (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_resource_templates)
                      + (SELECT COUNT(*) FROM greengateway.connection_openapi_catalog_entries
                         WHERE connection_id != $1::text::uuid)
                    "#,
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            let retained: i64 = scalar(&retained_row, 0, OPERATION_OPENAPI_CATALOG)?;
            if usize::try_from(retained).unwrap_or(usize::MAX).saturating_add(entries.len())
                > super::model::MAX_CATALOG_ENTRIES
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection catalog entries",
                    maximum: super::model::MAX_CATALOG_ENTRIES,
                });
            }
            let retained_definition_bytes_row = client
                .query_one(
                    r#"
                    -- Verbatim stored bytes, so this retained sum and the
                    -- candidate sum below measure the same thing: serde_json's
                    -- compact encoding. See the column comment in migration
                    -- 0006 for why the column is text and not jsonb.
                    SELECT COALESCE(SUM(octet_length(definition_json)), 0)
                    FROM greengateway.connection_openapi_catalog_entries
                    WHERE connection_id != $1::text::uuid
                    "#,
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            let retained_definition_bytes: i64 = scalar(&retained_definition_bytes_row, 0, OPERATION_OPENAPI_CATALOG)?;
            let candidate_definition_bytes =
                encoded_entries.iter().fold(0_usize, |total, entry| {
                    total.saturating_add(entry.definition_json.len())
                });
            if usize::try_from(retained_definition_bytes).unwrap_or(usize::MAX)
                .checked_add(candidate_definition_bytes)
                .is_none_or(|total| total > super::model::MAX_MANAGED_OPENAPI_CATALOG_BYTES)
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection OpenAPI catalog definition bytes",
                    maximum: super::model::MAX_MANAGED_OPENAPI_CATALOG_BYTES,
                });
            }

            let spec_revision = if previous_digest.as_deref() == Some(spec_digest) {
                previous_spec_revision
            } else {
                increment_revision(id, previous_spec_revision)?
            };
            let catalog_revision = increment_revision(id, previous_catalog_revision)?;

            client
                .execute(
                    "DELETE FROM greengateway.connection_dependencies \
                     WHERE connection_id = $1::text::uuid AND consumer_kind = 'managed_tool'",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            let retained_dependencies_row = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies",
                    &[],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            let retained_dependencies: i64 = scalar(&retained_dependencies_row, 0, OPERATION_OPENAPI_CATALOG)?;
            if usize::try_from(retained_dependencies).unwrap_or(usize::MAX).saturating_add(entries.len())
                > MAX_CONNECTION_DEPENDENCIES
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection dependencies",
                    maximum: MAX_CONNECTION_DEPENDENCIES,
                });
            }

            client
                .execute(
                    "DELETE FROM greengateway.connection_openapi_catalogs WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_openapi_catalogs (
                        connection_id, spec_revision, catalog_revision, observed_etag,
                        spec_digest, spec, refreshed_at, entry_count, actor_user_id
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
                    "#,
                    &[
                        &id.as_str(),
                        &u64_to_i64(id, spec_revision)?,
                        &u64_to_i64(id, catalog_revision)?,
                        &expected_connection_etag.as_str(),
                        &spec_digest,
                        &spec,
                        &now,
                        &usize_to_i64(entries.len()),
                        &actor_user_id,
                    ],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;

            for (ordinal, encoded) in encoded_entries.iter().enumerate() {
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_openapi_catalog_entries (
                            connection_id, tool_name, operation_id,
                            selected_scheme_names_json, definition_json, ordinal
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6)
                        "#,
                        &[
                            &id.as_str(),
                            &encoded.entry.tool_name,
                            &encoded.entry.operation_id,
                            &encoded.selected_scheme_names_json,
                            &encoded.definition_json,
                            &usize_to_i64(ordinal),
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_dependencies (
                            connection_id, consumer_kind, consumer_id, created_at
                        ) VALUES ($1::text::uuid, 'managed_tool', $2, $3)
                        "#,
                        &[&id.as_str(), &encoded.entry.tool_name, &now],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            }

            let overlay_revision = write_openapi_overlay(
                &client,
                id,
                overlay,
                compiled_overlay_revision,
                current.revisions.connection,
                previous_catalog_revision,
                actor_user_id,
                &now,
            )
            .await?;
            write_catalog_enum_source_values(
                &client,
                id,
                &current,
                overlay_revision,
                enum_values,
            )
            .await?;
            client
                .execute(
                    "UPDATE greengateway.connection_openapi_catalogs \
                     SET overlay_revision = $1 WHERE connection_id = $2::text::uuid",
                    &[&u64_to_i64(id, overlay_revision)?, &id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;

            reserve_catalog_tool_names(
                &client,
                postgres_tool_names::LANE_OPENAPI,
                id,
                encoded_entries
                    .iter()
                    .map(|encoded| encoded.entry.tool_name.clone()),
                OPERATION_OPENAPI_CATALOG,
            )
            .await?;
            bump_connection_state(
                &client,
                RESOURCE_CONNECTION_CATALOG,
                id,
                Some(previous_catalog_revision),
                catalog_revision,
            )
            .await?;
            Ok(StoredOpenApiCatalog {
                connection_id: id.clone(),
                spec_revision,
                catalog_revision,
                observed_etag: expected_connection_etag.clone(),
                spec_digest: spec_digest.to_owned(),
                spec: spec.to_owned(),
                refreshed_at: now.clone(),
                entries: normalized_entries,
                overlay_revision,
            })
        }
        .await;
        match outcome {
            Ok(catalog) => {
                commit(&client, OPERATION_OPENAPI_CATALOG).await?;
                Ok(catalog)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    // ==== Status (observational: no security-revision bumps) ====

    pub async fn append_status(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
    ) -> Result<SafeConnectionStatus, ConnectionStoreError> {
        self.append_status_inner(id, expected, update)
            .await
            .map(|(status, _)| status)
    }

    /// The control plane's snapshot-updating variant: returns the updated
    /// record alongside the status so the runtime map can be republished.
    pub async fn append_status_before(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
    ) -> Result<(SafeConnectionStatus, StoredConnection), ConnectionStoreError> {
        self.append_status_inner(id, expected, update).await
    }

    async fn append_status_inner(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
    ) -> Result<(SafeConnectionStatus, StoredConnection), ConnectionStoreError> {
        if update
            .catalog_entry_count
            .is_some_and(|count| count > super::model::MAX_CATALOG_ENTRIES)
        {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection catalog entries",
                maximum: super::model::MAX_CATALOG_ENTRIES,
            });
        }
        let observed_at = utc_timestamp()?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_STATUS))?;
        // Status is observational and does not advance the security
        // revision, but its global history prune (and the current-status
        // count that sizes it) is a global aggregate exactly like the
        // capacity checks, and the SQLite store serializes it the same way
        // (store.rs `append_status_with_connection` opens Immediate).
        begin_mutation(&client, OPERATION_STATUS).await?;
        let outcome: Result<(SafeConnectionStatus, StoredConnection), ConnectionStoreError> =
            async {
                let current = load_record_for_update(&client, id, OPERATION_STATUS)
                    .await?
                    .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
                validate_bindings(&client, &current).await?;
                ensure_etag(id, expected, &current)?;
                let status_revision = increment_revision(id, current.revisions.status)?;
                let latency_ms = optional_u64_to_i64(update.latency_ms, "latency_ms")?;
                let catalog_age_secs =
                    optional_u64_to_i64(update.catalog_age_secs, "catalog_age_secs")?;
                let catalog_entry_count = update
                    .catalog_entry_count
                    .map(|value| {
                        i64::try_from(value).map_err(|_| ConnectionStoreError::LimitExceeded {
                            resource: "connection catalog entries",
                            maximum: super::model::MAX_CATALOG_ENTRIES,
                        })
                    })
                    .transpose()?;
                let ambiguous_failure = matches!(
                    update.reason,
                    ConnectionStatusReason::RequestFailed
                        | ConnectionStatusReason::EgressDenied
                        | ConnectionStatusReason::SecretUnavailable
                        | ConnectionStatusReason::InvalidResponse
                );
                let last_test_at = (update.reason == ConnectionStatusReason::TestSucceeded
                    || (ambiguous_failure && update.catalog_entry_count.is_none()))
                .then_some(observed_at.as_str());
                let last_refresh_at = (matches!(
                    update.reason,
                    ConnectionStatusReason::CatalogRefreshed | ConnectionStatusReason::CatalogStale
                ) || (ambiguous_failure
                    && update.catalog_entry_count.is_some()))
                .then_some(observed_at.as_str());
                let state = state_as_str(update.state);
                let reason = reason_as_str(update.reason);

                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_status_history (
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at,
                            latency_ms, catalog_age_secs, catalog_entry_count
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                        "#,
                        &[
                            &id.as_str(),
                            &u64_to_i64(id, status_revision)?,
                            &u64_to_i64(id, current.revisions.connection)?,
                            &u64_to_i64(id, current.revisions.credential)?,
                            &u64_to_i64(id, current.revisions.tls)?,
                            &u64_to_i64(id, current.revisions.discovery)?,
                            &state,
                            &reason,
                            &observed_at,
                            &latency_ms,
                            &catalog_age_secs,
                            &catalog_entry_count,
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_STATUS, error))?;
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_current_status (
                            connection_id, status_revision, observed_connection_revision,
                            observed_credential_revision, observed_tls_revision,
                            observed_discovery_revision, state, reason, observed_at,
                            latency_ms, catalog_age_secs, catalog_entry_count
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
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
                        &[
                            &id.as_str(),
                            &u64_to_i64(id, status_revision)?,
                            &u64_to_i64(id, current.revisions.connection)?,
                            &u64_to_i64(id, current.revisions.credential)?,
                            &u64_to_i64(id, current.revisions.tls)?,
                            &u64_to_i64(id, current.revisions.discovery)?,
                            &state,
                            &reason,
                            &observed_at,
                            &latency_ms,
                            &catalog_age_secs,
                            &catalog_entry_count,
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_STATUS, error))?;
                // The global bound covers every persisted status row, and
                // a connection's current-status row is never pruned, so the
                // history budget must reserve one slot per live connection
                // before trimming. Without the reservation history
                // over-retains by exactly the number of connections and the
                // restart preflight's `current + history <=
                // MAX_STATUS_HISTORY_ROWS` no longer holds (store.rs
                // append_status computes the same `retained_history`).
                let current_status_count_row = client
                    .query_one(
                        "SELECT COUNT(*) FROM greengateway.connection_current_status",
                        &[],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_STATUS, error))?;
                let current_status_count: i64 =
                    scalar(&current_status_count_row, 0, OPERATION_STATUS)?;
                let retained_history = super::model::MAX_STATUS_HISTORY_ROWS
                    .checked_sub(usize::try_from(current_status_count).unwrap_or(usize::MAX))
                    .ok_or(ConnectionStoreError::LimitExceeded {
                        resource: "safe connection status rows",
                        maximum: super::model::MAX_STATUS_HISTORY_ROWS,
                    })?;
                client
                    .execute(
                        r#"
                        UPDATE greengateway.connection_records
                        SET status_revision = $1,
                            last_test_at = COALESCE($2, last_test_at),
                            last_refresh_at = COALESCE($3, last_refresh_at)
                        WHERE id = $4::text::uuid
                        "#,
                        &[
                            &u64_to_i64(id, status_revision)?,
                            &last_test_at,
                            &last_refresh_at,
                            &id.as_str(),
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_STATUS, error))?;
                // Global history pruning: keep the newest
                // `retained_history` rows across every connection, leaving
                // room for each connection's retained current-status row.
                client
                    .execute(
                        r#"
                        DELETE FROM greengateway.connection_status_history
                        WHERE sequence IN (
                            SELECT sequence
                            FROM greengateway.connection_status_history
                            ORDER BY sequence DESC
                            OFFSET $1
                        )
                        "#,
                        &[&usize_to_i64(retained_history)],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_STATUS, error))?;

                let status = SafeConnectionStatus {
                    state: update.state,
                    reason: update.reason,
                    observed_at: Some(observed_at),
                    latency_ms: update.latency_ms,
                    catalog_age_secs: update.catalog_age_secs,
                    catalog_entry_count: update.catalog_entry_count,
                };
                let mut updated = current;
                updated.revisions.status = status_revision;
                Ok((status, updated))
            }
            .await;
        match outcome {
            Ok(result) => {
                commit(&client, OPERATION_STATUS).await?;
                Ok(result)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    pub async fn latest_status(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<SafeConnectionStatus>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_STATUS_READ))?;
        let row = client
            .query_opt(
                r#"
                SELECT state, reason, observed_at, latency_ms, catalog_age_secs, catalog_entry_count
                FROM greengateway.connection_current_status
                WHERE connection_id = $1::text::uuid
                "#,
                &[&id.as_str()],
            )
            .await
            .map_err(|error| pg_error(OPERATION_STATUS_READ, error))?;
        row.map(|row| safe_status_from_row(&row, id)).transpose()
    }

    /// The latest safe status of each listed Connection in one round
    /// trip. See the SQLite store's `latest_statuses`.
    pub async fn latest_statuses(
        &self,
        ids: &[ConnectionId],
    ) -> Result<BTreeMap<ConnectionId, SafeConnectionStatus>, ConnectionStoreError> {
        let mut statuses = BTreeMap::new();
        if ids.is_empty() {
            return Ok(statuses);
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_STATUS_READ))?;
        let id_texts = ids.iter().map(ConnectionId::as_str).collect::<Vec<_>>();
        // The status columns come first so `safe_status_from_row`'s indices
        // hold; the owner id rides last.
        let rows = client
            .query(
                r#"
                SELECT state, reason, observed_at, latency_ms, catalog_age_secs,
                       catalog_entry_count, connection_id::text
                FROM greengateway.connection_current_status
                WHERE connection_id = ANY($1::text[]::uuid[])
                "#,
                &[&id_texts],
            )
            .await
            .map_err(|error| pg_error(OPERATION_STATUS_READ, error))?;
        for row in &rows {
            let id_text: String = column(row, 6, "<status>", "status owner id does not decode")?;
            let id = ConnectionId::parse(id_text.clone()).map_err(|_| {
                ConnectionStoreError::CorruptRecord {
                    id: id_text,
                    reason: "invalid status owner ID",
                }
            })?;
            let status = safe_status_from_row(row, &id)?;
            statuses.insert(id, status);
        }
        Ok(statuses)
    }

    /// The authority's status revision for each of `ids`: a status write on
    /// another replica advances no security revision, so this replica's
    /// runtime record keeps the revision it last reconciled; the views read
    /// this instead, so `revisions.status` agrees with the status row they
    /// show (issue #241, PR 8 review round 6).
    pub async fn status_revisions(
        &self,
        ids: &[ConnectionId],
    ) -> Result<BTreeMap<ConnectionId, u64>, ConnectionStoreError> {
        let mut revisions = BTreeMap::new();
        if ids.is_empty() {
            return Ok(revisions);
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_STATUS_READ))?;
        let id_texts = ids.iter().map(ConnectionId::as_str).collect::<Vec<_>>();
        let rows = client
            .query(
                "SELECT id::text, status_revision FROM greengateway.connection_records WHERE id = ANY($1::text[]::uuid[])",
                &[&id_texts],
            )
            .await
            .map_err(|error| pg_error(OPERATION_STATUS_READ, error))?;
        for row in &rows {
            let id_text: String = column(row, 0, "<status>", "status owner id does not decode")?;
            let id = ConnectionId::parse(id_text.clone()).map_err(|_| {
                ConnectionStoreError::CorruptRecord {
                    id: id_text.clone(),
                    reason: "invalid status owner ID",
                }
            })?;
            let revision: i64 = column(row, 1, &id_text, "status revision does not decode")?;
            let revision =
                u64::try_from(revision).map_err(|_| ConnectionStoreError::CorruptRecord {
                    id: id_text,
                    reason: "negative status revision",
                })?;
            revisions.insert(id, revision);
        }
        Ok(revisions)
    }

    pub async fn status_history(
        &self,
        id: &ConnectionId,
        limit: usize,
    ) -> Result<Vec<SafeConnectionStatus>, ConnectionStoreError> {
        let limit = limit.min(super::model::MAX_STATUS_HISTORY_ROWS);
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_STATUS_READ))?;
        let rows = client
            .query(
                r#"
                SELECT state, reason, observed_at, latency_ms, catalog_age_secs, catalog_entry_count
                FROM greengateway.connection_status_history
                WHERE connection_id = $1::text::uuid
                ORDER BY status_revision DESC
                LIMIT $2
                "#,
                &[&id.as_str(), &(usize_to_i64(limit))],
            )
            .await
            .map_err(|error| pg_error(OPERATION_STATUS_READ, error))?;
        rows.iter()
            .map(|row| safe_status_from_row(row, id))
            .collect()
    }

    // ==== Dependencies (derived state: no security-revision bumps) ====

    pub async fn add_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        validate_dependency_id(consumer_id)?;
        let now = utc_timestamp()?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_DEPS))?;
        begin_mutation(&client, OPERATION_DEPS).await?;
        let outcome: Result<(), ConnectionStoreError> = async {
            let exists_row = client
                .query_one(
                    r#"
                    SELECT EXISTS(
                        SELECT 1 FROM greengateway.connection_dependencies
                        WHERE connection_id = $1::text::uuid
                          AND consumer_kind = $2 AND consumer_id = $3
                    )
                    "#,
                    &[&id.as_str(), &kind.as_str(), &consumer_id],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?;
            let exists: bool = scalar(&exists_row, 0, OPERATION_DEPS)?;
            if exists {
                return Ok(());
            }
            let count_row = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies",
                    &[],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?;
            let count: i64 = scalar(&count_row, 0, OPERATION_DEPS)?;
            if usize::try_from(count).unwrap_or(usize::MAX) >= MAX_CONNECTION_DEPENDENCIES {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection dependencies",
                    maximum: MAX_CONNECTION_DEPENDENCIES,
                });
            }
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_dependencies (
                        connection_id, consumer_kind, consumer_id, created_at
                    ) VALUES ($1::text::uuid, $2, $3, $4)
                    "#,
                    &[&id.as_str(), &kind.as_str(), &consumer_id, &now],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?;
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {
                commit(&client, OPERATION_DEPS).await?;
                Ok(())
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    pub async fn remove_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        validate_dependency_id(consumer_id)?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_DEPS))?;
        client
            .execute(
                r#"
                DELETE FROM greengateway.connection_dependencies
                WHERE connection_id = $1::text::uuid AND consumer_kind = $2 AND consumer_id = $3
                "#,
                &[&id.as_str(), &kind.as_str(), &consumer_id],
            )
            .await
            .map_err(|error| pg_error(OPERATION_DEPS, error))?;
        Ok(())
    }

    pub async fn replace_dependencies_for_kind(
        &self,
        kind: ConnectionDependencyKind,
        desired: &[(ConnectionId, String)],
        source_revision: i64,
    ) -> Result<(), ConnectionStoreError> {
        if desired.len() > MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }
        let mut unique = BTreeSet::new();
        for (connection_id, consumer_id) in desired {
            validate_dependency_id(consumer_id)?;
            if !unique.insert((connection_id.as_str(), consumer_id.as_str())) {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![
                        "connection dependency set contains duplicate consumers".to_owned()
                    ],
                });
            }
        }
        let now = utc_timestamp()?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_DEPS))?;
        begin_mutation(&client, OPERATION_DEPS).await?;
        let outcome: Result<(), ConnectionStoreError> = async {
            // Replicas flush their derived sets independently. A set derived
            // from an older tools document than the one whose guards are
            // already here is stale, and replacing them would let an admin
            // delete remove a Connection the authoritative document still
            // references. Ties replace (a re-flush of the same document).
            let newest_row = client
                .query_one(
                    "SELECT COALESCE(MAX(source_revision), 0) FROM greengateway.connection_dependencies WHERE consumer_kind = $1",
                    &[&kind.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?;
            let newest: i64 = scalar(&newest_row, 0, OPERATION_DEPS)?;
            if newest > source_revision {
                tracing::debug!(
                    consumer_kind = kind.as_str(),
                    newest,
                    source_revision,
                    "connection dependency flush is stale; keeping the newer document's guards"
                );
                return Ok(());
            }
            client
                .execute(
                    "DELETE FROM greengateway.connection_dependencies WHERE consumer_kind = $1",
                    &[&kind.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?;
            let retained_row = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies",
                    &[],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?;
            let retained: i64 = scalar(&retained_row, 0, OPERATION_DEPS)?;
            if usize::try_from(retained).unwrap_or(usize::MAX).saturating_add(desired.len())
                > MAX_CONNECTION_DEPENDENCIES
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection dependencies",
                    maximum: MAX_CONNECTION_DEPENDENCIES,
                });
            }
            for (connection_id, consumer_id) in desired {
                let exists_row = client
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM greengateway.connection_records WHERE id = $1::text::uuid)",
                        &[&connection_id.as_str()],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_DEPS, error))?;
                let exists: bool = scalar(&exists_row, 0, OPERATION_DEPS)?;
                if !exists {
                    return Err(ConnectionStoreError::NotFound {
                        id: connection_id.to_string(),
                    });
                }
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_dependencies (
                            connection_id, consumer_kind, consumer_id, created_at, source_revision
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5)
                        "#,
                        &[
                            &connection_id.as_str(),
                            &kind.as_str(),
                            &consumer_id,
                            &now,
                            &source_revision,
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_DEPS, error))?;
            }
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {
                commit(&client, OPERATION_DEPS).await?;
                Ok(())
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    pub async fn dependencies(
        &self,
        id: &ConnectionId,
    ) -> Result<Vec<ConnectionDependency>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_DEPS_READ))?;
        // One snapshot for the existence check and the rows it guards, so
        // a delete landing between them cannot return an empty list for a
        // connection this read has already decided exists (store.rs
        // `dependencies` opens a transaction for exactly this pair).
        begin_snapshot(&client, OPERATION_DEPS_READ).await?;
        let outcome = load_dependencies(&client, id).await;
        finish_read(&client, OPERATION_DEPS_READ, outcome).await
    }

    pub async fn dependency_counts(
        &self,
    ) -> Result<BTreeMap<ConnectionId, usize>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_DEPS_READ))?;
        let rows = client
            .query(
                r#"
                SELECT connection_id::text, COUNT(*)
                FROM greengateway.connection_dependencies
                GROUP BY connection_id
                "#,
                &[],
            )
            .await
            .map_err(|error| pg_error(OPERATION_DEPS_READ, error))?;
        const REASON: &str = "dependency count column does not decode as its schema type";
        let mut counts = BTreeMap::new();
        for row in rows {
            let raw_id: String = column(&row, 0, "<dependency-counts>", REASON)?;
            let id = parse_catalog_id(&raw_id)?;
            let count: i64 = column(&row, 1, &raw_id, REASON)?;
            // Fail closed on an unrepresentable count and on one that
            // exceeds the bound, exactly like the SQLite reader
            // (store.rs `dependency_counts`): saturating to `usize::MAX`
            // would turn a corrupt row into a plausible-looking number and
            // skip the bound entirely.
            let count =
                usize::try_from(count).map_err(|_| ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "invalid dependency count",
                })?;
            if count > MAX_CONNECTION_DEPENDENCIES {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection dependencies",
                    maximum: MAX_CONNECTION_DEPENDENCIES,
                });
            }
            counts.insert(id, count);
        }
        Ok(counts)
    }

    /// The per-connection activity timestamps the control plane decorates
    /// its listings with, keyed by connection.
    ///
    /// The SQLite counterpart (`SqliteConnectionStore::activity_times`)
    /// bounds the read at `MAX_CONNECTIONS + 1` rows and refuses the whole
    /// result if the extra row came back, rather than silently serving a
    /// truncated map from a store that has already exceeded its own
    /// capacity; both timestamps are re-parsed as RFC 3339 on the way out,
    /// so a row written out of band fails closed as corruption instead of
    /// reaching a caller as an opaque string. This reproduces both.
    pub async fn activity_times(
        &self,
    ) -> Result<BTreeMap<ConnectionId, ConnectionActivityTimes>, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_ACTIVITY_READ))?;
        // `id` is a uuid here and TEXT in SQLite, but the canonical text
        // form is fixed-width lowercase hex, so uuid order and the
        // reference's `ORDER BY id ASC` agree row for row -- which is what
        // decides who survives the bound below.
        let rows = client
            .query(
                r#"
                SELECT id::text, last_test_at, last_refresh_at
                FROM greengateway.connection_records
                ORDER BY id ASC
                LIMIT $1
                "#,
                &[&usize_to_i64(MAX_CONNECTIONS.saturating_add(1))],
            )
            .await
            .map_err(|error| pg_error(OPERATION_ACTIVITY_READ, error))?;
        if rows.len() > MAX_CONNECTIONS {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection activity metadata",
                maximum: MAX_CONNECTIONS,
            });
        }
        rows.iter()
            .map(|row| {
                const REASON: &str =
                    "connection activity column does not decode as its schema type";
                let raw: String = column(row, 0, "<connection-activity>", REASON)?;
                let parsed = ConnectionId::parse(raw.clone())
                    .map_err(|_| corrupt_id(&raw, "invalid activity owner ID"))?;
                let last_test_at: Option<String> = column(row, 1, &raw, REASON)?;
                let last_refresh_at: Option<String> = column(row, 2, &raw, REASON)?;
                validate_activity_timestamp(&parsed, last_test_at.as_deref())?;
                validate_activity_timestamp(&parsed, last_refresh_at.as_deref())?;
                Ok((
                    parsed,
                    ConnectionActivityTimes {
                        last_test_at,
                        last_refresh_at,
                    },
                ))
            })
            .collect()
    }

    /// Both status tables as PERSISTED: the mirror of the SQLite store's
    /// `exported_statuses`, for the standalone-to-cluster import's
    /// validation pass (issue #241, PR 15, step 8).
    ///
    /// `latest_status`/`status_history` return the SAFE projection, which
    /// drops the revision columns and ages `catalog_age_secs` forward on
    /// every read. A checksum computed over that could never equal the
    /// source's -- it changes with the clock. This returns the rows.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(crate) async fn exported_statuses(
        &self,
    ) -> Result<ExportedConnectionStatuses, ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_STATUS_READ))?;
        let current = exported_status_rows(
            &client,
            r#"
            SELECT connection_id::text, status_revision, observed_connection_revision,
                   observed_credential_revision, observed_tls_revision,
                   observed_discovery_revision, state, reason, observed_at,
                   latency_ms, catalog_age_secs, catalog_entry_count
            FROM greengateway.connection_current_status
            ORDER BY connection_id ASC
            LIMIT $1
            "#,
        )
        .await?;
        let history = exported_status_rows(
            &client,
            r#"
            SELECT connection_id::text, status_revision, observed_connection_revision,
                   observed_credential_revision, observed_tls_revision,
                   observed_discovery_revision, state, reason, observed_at,
                   latency_ms, catalog_age_secs, catalog_entry_count
            FROM greengateway.connection_status_history
            ORDER BY connection_id ASC, status_revision ASC
            LIMIT $1
            "#,
        )
        .await?;
        Ok(ExportedConnectionStatuses { current, history })
    }

    /// The load-time integrity preflight: the async twin of the SQLite
    /// store's `validate_persisted_state`, which `open` runs on every
    /// open (store.rs). PostgreSQL had no equivalent, so a replica
    /// started serving whatever happened to be in the tables and a
    /// violated invariant surfaced per request, if at all.
    ///
    /// STARTUP MUST CALL THIS ONCE -- after migrations, before the store
    /// is published to the runtime -- and MUST abort the boot on an
    /// error rather than degrade. Every invariant checked here is one the
    /// writers in this file maintain unconditionally, so a violation
    /// means this database is not the one this build wrote, and a store
    /// whose contract is to fail closed must not serve from it. (The call
    /// belongs to the boot sequence in main.rs and is not wired here.)
    ///
    /// Every query is bounded. The aggregates and the integrity checks
    /// are single-row whatever they join. Each row scan runs only after
    /// the count that bounds it has been checked against its ceiling on
    /// this same snapshot -- records and catalogs are bounded that way --
    /// and the activity, status and managed-tool-dependency scans carry
    /// an explicit LIMIT on top, so they stay bounded even if the
    /// aggregate that precedes them is itself the thing that is wrong.
    pub async fn validate_persisted_state(&self) -> Result<(), ConnectionStoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_VALIDATE))?;
        // One snapshot for the whole preflight. The cross-table
        // invariants below -- a catalog's counters against its own rows,
        // managed-tool dependencies against catalog entries -- are only
        // meaningful against a single consistent view, and another
        // replica may be committing while this one boots: under read
        // committed a catalog replace landing between two of these reads
        // would be reported as corruption and would abort a healthy boot.
        begin_snapshot(&client, OPERATION_VALIDATE).await?;
        let outcome = self.validate_within(&client).await;
        finish_read(&client, OPERATION_VALIDATE, outcome).await
    }

    async fn validate_within(
        &self,
        client: &deadpool_postgres::Object,
    ) -> Result<(), ConnectionStoreError> {
        let counts = client
            .query_one(
                r#"
                SELECT
                    (SELECT COUNT(*) FROM greengateway.connection_records),
                    (SELECT COUNT(*) FROM greengateway.connection_credential_bindings),
                    (SELECT COUNT(*) FROM greengateway.connection_dependencies),
                    (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_entries)
                  + (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_resources)
                  + (SELECT COUNT(*) FROM greengateway.connection_mcp_catalog_resource_templates)
                  + (SELECT COUNT(*) FROM greengateway.connection_openapi_catalog_entries),
                    (SELECT COUNT(*) FROM greengateway.connection_current_status)
                  + (SELECT COUNT(*) FROM greengateway.connection_status_history),
                    (SELECT COALESCE(SUM(octet_length(definition_json)), 0)
                     FROM greengateway.connection_openapi_catalog_entries),
                    (SELECT COUNT(*) FROM greengateway.connection_enum_source_values)
                "#,
                &[],
            )
            .await
            .map_err(|error| pg_error(OPERATION_VALIDATE, error))?;

        // The persisted bounds, in the reference's order. The record
        // count gates every row scan below, so it is checked first.
        let records_count = counted(&counts, 0, "<connections>")?;
        if records_count > self.maximum_connections {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "managed connections",
                maximum: self.maximum_connections,
            });
        }
        if counted(&counts, 1, "<bindings>")? > MAX_CREDENTIALS {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection credential bindings",
                maximum: MAX_CREDENTIALS,
            });
        }
        // The reference also bounds connection_local_secrets. That table
        // has no PostgreSQL counterpart -- the local keyring is bound to
        // CONNECTIONS_SQLITE_PATH, which cluster mode rejects (migration
        // 0006's header) -- so there is nothing here to bound.
        let dependencies_count = counted(&counts, 2, "<dependencies>")?;
        if dependencies_count > MAX_CONNECTION_DEPENDENCIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection dependencies",
                maximum: MAX_CONNECTION_DEPENDENCIES,
            });
        }
        if counted(&counts, 3, "<catalog-entries>")? > super::model::MAX_CATALOG_ENTRIES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection catalog entries",
                maximum: super::model::MAX_CATALOG_ENTRIES,
            });
        }
        // Current status plus history against ONE budget: a
        // current-status row is never pruned, so the two together are
        // what the writer's pruning has to keep under the bound.
        if counted(&counts, 4, "<status>")? > super::model::MAX_STATUS_HISTORY_ROWS {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "safe connection status rows",
                maximum: super::model::MAX_STATUS_HISTORY_ROWS,
            });
        }
        if counted(&counts, 5, "<openapi-catalogs>")?
            > super::model::MAX_MANAGED_OPENAPI_CATALOG_BYTES
        {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection OpenAPI catalog definition bytes",
                maximum: super::model::MAX_MANAGED_OPENAPI_CATALOG_BYTES,
            });
        }
        let maximum_enum_rows = self
            .maximum_connections
            .saturating_mul(MAX_OPENAPI_ENUM_SOURCES);
        if counted(&counts, 6, "<openapi-enum-source-values>")? > maximum_enum_rows {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection enum source values",
                maximum: maximum_enum_rows,
            });
        }
        if mcp_catalog_bytes(client, None, OPERATION_VALIDATE).await?
            > super::store::MAX_MANAGED_MCP_CATALOG_BYTES
        {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection MCP catalog bytes",
                maximum: super::store::MAX_MANAGED_MCP_CATALOG_BYTES,
            });
        }

        // The set-shaped invariants. Migration 0006 already CHECKs some
        // of these per row, which is precisely why they are re-checked
        // here: a constraint can be dropped out of band, and this
        // preflight exists to catch a database that no longer matches
        // the schema this build wrote.
        ensure_no_invalid_rows(
            client,
            "<current-status>",
            r#"
            SELECT COUNT(*)
            FROM greengateway.connection_current_status AS status
            JOIN greengateway.connection_records AS record ON record.id = status.connection_id
            WHERE status.status_revision != record.status_revision
               OR status.observed_connection_revision != record.connection_revision
               OR status.observed_credential_revision != record.credential_revision
               OR status.observed_tls_revision != record.tls_revision
               OR status.observed_discovery_revision != record.discovery_revision
               OR status.catalog_entry_count < 0
               OR status.catalog_entry_count > 4096
            "#,
            "current connection status is stale or invalid",
        )
        .await?;
        ensure_no_invalid_rows(
            client,
            "<mcp-catalogs>",
            r#"
            SELECT COUNT(*)
            FROM greengateway.connection_mcp_catalogs AS catalog
            JOIN greengateway.connection_records AS record ON record.id = catalog.connection_id
            WHERE catalog.entry_count != (
                    SELECT COUNT(*)
                    FROM greengateway.connection_mcp_catalog_entries AS entry
                    WHERE entry.connection_id = catalog.connection_id
                  )
               OR catalog.resource_count != (
                    SELECT COUNT(*)
                    FROM greengateway.connection_mcp_catalog_resources AS resource
                    WHERE resource.connection_id = catalog.connection_id
                  )
               OR catalog.resource_template_count != (
                    SELECT COUNT(*)
                    FROM greengateway.connection_mcp_catalog_resource_templates AS template
                    WHERE template.connection_id = catalog.connection_id
                  )
               OR catalog.entry_count + catalog.resource_count
                    + catalog.resource_template_count > 4096
               OR catalog.catalog_revision < 1
               OR catalog.entry_count < 0
               OR catalog.entry_count > 4096
               OR catalog.resource_count < 0
               OR catalog.resource_count > 4096
               OR catalog.resource_template_count < 0
               OR catalog.resource_template_count > 4096
            "#,
            "stored MCP catalog metadata is inconsistent",
        )
        .await?;
        ensure_no_invalid_rows(
            client,
            "<openapi-catalogs>",
            r#"
            SELECT COUNT(*)
            FROM greengateway.connection_openapi_catalogs AS catalog
            JOIN greengateway.connection_records AS record ON record.id = catalog.connection_id
            WHERE catalog.entry_count != (
                    SELECT COUNT(*)
                    FROM greengateway.connection_openapi_catalog_entries AS entry
                    WHERE entry.connection_id = catalog.connection_id
                  )
               OR catalog.spec_revision < 1
               OR catalog.catalog_revision < 1
               OR catalog.entry_count < 0
               OR catalog.entry_count > 4096
               OR octet_length(catalog.spec) < 1
               OR octet_length(catalog.spec) > 2097152
               OR octet_length(catalog.spec_digest) != 64
               OR catalog.spec_digest !~ '^[0-9a-f]+$'
            "#,
            "stored OpenAPI catalog metadata is inconsistent",
        )
        .await?;
        ensure_no_invalid_rows(
            client,
            "<openapi-enum-source-values>",
            r#"
            SELECT COUNT(*)
            FROM greengateway.connection_enum_source_values
            WHERE credential_generation_digest IS NOT NULL
              AND (
                    octet_length(credential_generation_digest) != 64
                 OR credential_generation_digest !~ '^[0-9a-f]+$'
              )
            "#,
            "stored OpenAPI enum credential generation digest is invalid",
        )
        .await?;
        ensure_no_invalid_rows(
            client,
            "<catalogs>",
            r#"
            SELECT COUNT(*)
            FROM greengateway.connection_mcp_catalogs AS mcp
            JOIN greengateway.connection_openapi_catalogs AS openapi
              ON openapi.connection_id = mcp.connection_id
            "#,
            "a Connection owns more than one managed catalog kind",
        )
        .await?;
        ensure_no_invalid_rows(
            client,
            "<status-history>",
            r#"
            SELECT COUNT(*)
            FROM greengateway.connection_status_history AS status
            JOIN greengateway.connection_records AS record ON record.id = status.connection_id
            WHERE status.status_revision > record.status_revision
               OR status.observed_connection_revision > record.connection_revision
               OR status.observed_credential_revision > record.credential_revision
               OR status.observed_tls_revision > record.tls_revision
               OR status.observed_discovery_revision > record.discovery_revision
               OR status.catalog_entry_count < 0
               OR status.catalog_entry_count > 4096
            "#,
            "connection status history contains an impossible revision or count",
        )
        .await?;

        // Every record decodes, still validates, and agrees with its
        // derived credential bindings.
        let records = load_all_records(client, OPERATION_VALIDATE).await?;
        for record in &records {
            validate_bindings(client, record).await?;
        }
        validate_activity_rows(client, records_count).await?;
        // Both status tables decode into a SafeConnectionStatus: an
        // unknown state, an unknown reason or a negative count fails
        // closed at load instead of at the first read that touches it.
        validate_status_rows(client, "greengateway.connection_current_status").await?;
        validate_status_rows(client, "greengateway.connection_status_history").await?;

        // Every stored catalog loads, and belongs to a Connection whose
        // specification still declares that managed catalog kind.
        let mcp_catalogs = load_mcp_catalogs(client, None).await?;
        let openapi_catalogs = load_openapi_catalogs(client, None).await?;
        let openapi_overlays = load_openapi_overlays(client, None).await?;
        let enum_source_values = load_enum_source_values(client, None).await?;
        let record_by_id = records
            .iter()
            .map(|record| (record.id.clone(), record))
            .collect::<BTreeMap<_, _>>();
        for catalog in &mcp_catalogs {
            if record_by_id
                .get(&catalog.connection_id)
                .is_none_or(|record| !supports_managed_mcp_catalog(&record.write))
            {
                return Err(corrupt(
                    &catalog.connection_id,
                    "MCP catalog owner is not a compatible managed MCP Connection",
                ));
            }
        }
        for catalog in &openapi_catalogs {
            if record_by_id
                .get(&catalog.connection_id)
                .is_none_or(|record| !supports_managed_openapi_catalog(&record.write))
            {
                return Err(corrupt(
                    &catalog.connection_id,
                    "OpenAPI catalog owner is not a compatible managed OpenAPI Connection",
                ));
            }
        }
        let overlay_by_id = openapi_overlays
            .iter()
            .map(|overlay| (&overlay.connection_id, overlay))
            .collect::<BTreeMap<_, _>>();
        for catalog in &openapi_catalogs {
            match overlay_by_id.get(&catalog.connection_id) {
                Some(overlay) if overlay.overlay_revision == catalog.overlay_revision => {}
                None if catalog.overlay_revision == 0 => {}
                _ => {
                    return Err(corrupt(
                        &catalog.connection_id,
                        "OpenAPI catalog and overlay revisions do not agree",
                    ));
                }
            }
        }
        if openapi_overlays.iter().any(|overlay| {
            !openapi_catalogs
                .iter()
                .any(|catalog| catalog.connection_id == overlay.connection_id)
        }) {
            return Err(ConnectionStoreError::CorruptRecord {
                id: "<openapi-overlays>".to_owned(),
                reason: "OpenAPI overlay has no durable catalog",
            });
        }
        for row in &enum_source_values {
            let Some(record) = record_by_id.get(&row.connection_id) else {
                return Err(corrupt(
                    &row.connection_id,
                    "enum source value owner is missing",
                ));
            };
            let overlay_matches = overlay_by_id
                .get(&row.connection_id)
                .is_some_and(|overlay| overlay.overlay_revision == row.overlay_revision);
            if !supports_managed_openapi_catalog(&record.write)
                || !overlay_matches
                || row.connection_revision > record.revisions.connection
                || row.credential_revision > record.revisions.credential
            {
                return Err(corrupt(
                    &row.connection_id,
                    "enum source values do not match their OpenAPI overlay generation",
                ));
            }
        }
        validate_managed_catalog_dependencies(
            client,
            dependencies_count,
            &mcp_catalogs,
            &openapi_catalogs,
        )
        .await
    }

    pub fn maximum_connections(&self) -> usize {
        self.maximum_connections
    }
}

/// One bounded aggregate from the preflight's counts row, as a `usize`.
/// Mirrors the reference's `count_rows` (store.rs): the decode is a store
/// failure, a negative or oversized total is corruption.
fn counted(
    row: &tokio_postgres::Row,
    index: usize,
    resource: &'static str,
) -> Result<usize, ConnectionStoreError> {
    let value: i64 = scalar(row, index, OPERATION_VALIDATE)?;
    usize::try_from(value).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: resource.to_owned(),
        reason: "negative or oversized persisted row count",
    })
}

/// Fail closed when a bounded integrity query finds any offending row --
/// the reference's `ensure_no_invalid_rows` (store.rs). `query` is a
/// literal from this module returning a single `COUNT(*)`, so it is
/// bounded whatever it joins.
async fn ensure_no_invalid_rows(
    client: &deadpool_postgres::Object,
    scope: &'static str,
    query: &'static str,
    reason: &'static str,
) -> Result<(), ConnectionStoreError> {
    let row = client
        .query_one(query, &[])
        .await
        .map_err(|error| pg_error(OPERATION_VALIDATE, error))?;
    let offending: i64 = scalar(&row, 0, OPERATION_VALIDATE)?;
    if offending == 0 {
        Ok(())
    } else {
        Err(corrupt_id(scope, reason))
    }
}

/// Every persisted activity timestamp parses as RFC 3339 -- the
/// reference's `validate_connection_activity_rows` (store.rs). Bounded by
/// the record count the caller has already checked against the ceiling.
async fn validate_activity_rows(
    client: &deadpool_postgres::Object,
    records_count: usize,
) -> Result<(), ConnectionStoreError> {
    const REASON: &str = "connection activity column does not decode as its schema type";
    let rows = client
        .query(
            r#"
            SELECT id::text, last_test_at, last_refresh_at
            FROM greengateway.connection_records
            WHERE last_test_at IS NOT NULL OR last_refresh_at IS NOT NULL
            ORDER BY id ASC
            LIMIT $1
            "#,
            &[&usize_to_i64(records_count.saturating_add(1))],
        )
        .await
        .map_err(|error| pg_error(OPERATION_VALIDATE, error))?;
    if rows.len() > records_count {
        return Err(corrupt_id(
            "<connection-activity>",
            "more activity rows than connection records",
        ));
    }
    for row in &rows {
        let raw: String = column(row, 0, "<connection-activity>", REASON)?;
        let id = ConnectionId::parse(raw.clone())
            .map_err(|_| corrupt_id(&raw, "activity row has an invalid connection ID"))?;
        let last_test_at: Option<String> = column(row, 1, &raw, REASON)?;
        let last_refresh_at: Option<String> = column(row, 2, &raw, REASON)?;
        validate_activity_timestamp(&id, last_test_at.as_deref())?;
        validate_activity_timestamp(&id, last_refresh_at.as_deref())?;
    }
    Ok(())
}

/// One status table as PERSISTED, for `exported_statuses`. `query` is a
/// literal from this module and takes the row bound as `$1`, exactly as
/// the SQLite store's `exported_status_rows` does; the bound is the same
/// ceiling, so a table past it refuses rather than being silently
/// truncated into an export that would then digest to the wrong value.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
async fn exported_status_rows(
    client: &deadpool_postgres::Object,
    query: &'static str,
) -> Result<Vec<PersistedConnectionStatus>, ConnectionStoreError> {
    const REASON: &str = "status export column does not decode as its schema type";
    let rows = client
        .query(
            query,
            &[&usize_to_i64(
                super::model::MAX_STATUS_HISTORY_ROWS.saturating_add(1),
            )],
        )
        .await
        .map_err(|error| pg_error(OPERATION_STATUS_READ, error))?;
    if rows.len() > super::model::MAX_STATUS_HISTORY_ROWS {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "safe connection status rows",
            maximum: super::model::MAX_STATUS_HISTORY_ROWS,
        });
    }
    rows.iter()
        .map(|row| {
            let raw: String = column(row, 0, "<connection-status>", REASON)?;
            let id = ConnectionId::parse(raw.clone())
                .map_err(|_| corrupt_id(&raw, "status row has an invalid connection ID"))?;
            let status_revision: i64 = column(row, 1, &raw, REASON)?;
            let observed_connection: i64 = column(row, 2, &raw, REASON)?;
            let observed_credential: i64 = column(row, 3, &raw, REASON)?;
            let observed_tls: i64 = column(row, 4, &raw, REASON)?;
            let observed_discovery: i64 = column(row, 5, &raw, REASON)?;
            let state: String = column(row, 6, &raw, REASON)?;
            let reason: String = column(row, 7, &raw, REASON)?;
            let observed_at: String = column(row, 8, &raw, REASON)?;
            let latency_ms: Option<i64> = column(row, 9, &raw, REASON)?;
            let catalog_age_secs: Option<i64> = column(row, 10, &raw, REASON)?;
            let catalog_entry_count: Option<i64> = column(row, 11, &raw, REASON)?;
            Ok(PersistedConnectionStatus {
                status_revision: persisted_revision(
                    &id,
                    status_revision,
                    "invalid status revision",
                )?,
                observed_connection_revision: revision_from_i64(&id, observed_connection, false)?,
                observed_credential_revision: revision_from_i64(&id, observed_credential, true)?,
                observed_tls_revision: revision_from_i64(&id, observed_tls, true)?,
                observed_discovery_revision: revision_from_i64(&id, observed_discovery, true)?,
                state: parse_state(&state)
                    .ok_or_else(|| corrupt(&id, "unknown safe status state"))?,
                reason: parse_reason(&reason)
                    .ok_or_else(|| corrupt(&id, "unknown safe status reason"))?,
                observed_at,
                latency_ms: optional_i64_to_u64(&id, latency_ms)?,
                catalog_age_secs: optional_i64_to_u64(&id, catalog_age_secs)?,
                catalog_entry_count: optional_i64_to_u64(&id, catalog_entry_count)?,
                connection_id: id,
            })
        })
        .collect()
}

/// Every row of a status table decodes into a `SafeConnectionStatus` --
/// the reference's `validate_safe_status_rows` (store.rs). `table` is a
/// literal from this module, never caller input; the LIMIT holds even if
/// the aggregate bound the caller checked has been violated.
async fn validate_status_rows(
    client: &deadpool_postgres::Object,
    table: &'static str,
) -> Result<(), ConnectionStoreError> {
    const REASON: &str = "status column does not decode as its schema type";
    let query = format!(
        "SELECT state, reason, observed_at, latency_ms, catalog_age_secs, \
         catalog_entry_count, connection_id::text FROM {table} LIMIT $1"
    );
    let rows = client
        .query(
            query.as_str(),
            &[&usize_to_i64(
                super::model::MAX_STATUS_HISTORY_ROWS.saturating_add(1),
            )],
        )
        .await
        .map_err(|error| pg_error(OPERATION_VALIDATE, error))?;
    if rows.len() > super::model::MAX_STATUS_HISTORY_ROWS {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "safe connection status rows",
            maximum: super::model::MAX_STATUS_HISTORY_ROWS,
        });
    }
    for row in &rows {
        let raw: String = column(row, 6, "<connection-status>", REASON)?;
        let id = ConnectionId::parse(raw.clone())
            .map_err(|_| corrupt_id(&raw, "status row has an invalid connection ID"))?;
        safe_status_from_row(row, &id)?;
    }
    Ok(())
}

/// Every `managed_tool` dependency row corresponds to a durable catalog
/// entry, and every durable catalog entry has its row -- the reference's
/// `validate_managed_catalog_dependencies` (store.rs), which derives the
/// expected keys exactly this way: the MCP key is the Connection ID
/// joined to the remote tool name (`managed_tool_dependency_id`, the same
/// helper both writers use), the OpenAPI key is the tool name.
async fn validate_managed_catalog_dependencies(
    client: &deadpool_postgres::Object,
    dependencies_count: usize,
    mcp_catalogs: &[StoredMcpCatalog],
    openapi_catalogs: &[StoredOpenApiCatalog],
) -> Result<(), ConnectionStoreError> {
    const REASON: &str = "managed tool dependency column does not decode as its schema type";
    let mut expected = BTreeSet::new();
    for catalog in mcp_catalogs {
        for entry in &catalog.entries {
            expected.insert((
                catalog.connection_id.to_string(),
                managed_tool_dependency_id(&catalog.connection_id, &entry.remote_tool_name),
            ));
        }
    }
    for catalog in openapi_catalogs {
        for entry in &catalog.entries {
            expected.insert((catalog.connection_id.to_string(), entry.tool_name.clone()));
        }
    }
    let rows = client
        .query(
            r#"
            SELECT connection_id::text, consumer_id
            FROM greengateway.connection_dependencies
            WHERE consumer_kind = 'managed_tool'
            ORDER BY connection_id ASC, consumer_id ASC
            LIMIT $1
            "#,
            &[&usize_to_i64(dependencies_count.saturating_add(1))],
        )
        .await
        .map_err(|error| pg_error(OPERATION_VALIDATE, error))?;
    if rows.len() > dependencies_count {
        return Err(corrupt_id(
            "<catalog-dependencies>",
            "more managed tool dependencies than dependency rows",
        ));
    }
    let mut actual = BTreeSet::new();
    for row in &rows {
        let owner: String = column(row, 0, "<catalog-dependencies>", REASON)?;
        let consumer: String = column(row, 1, &owner, REASON)?;
        actual.insert((owner, consumer));
    }
    if actual == expected {
        Ok(())
    } else {
        Err(corrupt_id(
            "<catalog-dependencies>",
            "managed tool dependencies do not match durable catalog entries",
        ))
    }
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn parse_catalog_id(raw: &str) -> Result<ConnectionId, ConnectionStoreError> {
    ConnectionId::parse(raw).map_err(|_| corrupt_id(raw, "invalid catalog connection ID"))
}

fn corrupt_id(id: &str, reason: &'static str) -> ConnectionStoreError {
    ConnectionStoreError::CorruptRecord {
        id: id.to_owned(),
        reason,
    }
}

fn corrupt(id: &ConnectionId, reason: &'static str) -> ConnectionStoreError {
    ConnectionStoreError::CorruptRecord {
        id: id.to_string(),
        reason,
    }
}

fn parse_etag(raw: &str) -> Result<ConnectionEtag, ConnectionStoreError> {
    // ETags are stored and compared verbatim; round-trip through the
    // newtype without inventing a parser that could accept non-canonical
    // forms (the SQLite store stores the same opaque string).
    Ok(ConnectionEtag::from_stored(raw.to_owned()))
}

fn safe_status_from_row(
    row: &tokio_postgres::Row,
    id: &ConnectionId,
) -> Result<SafeConnectionStatus, ConnectionStoreError> {
    const REASON: &str = "safe status column does not decode as its schema type";
    let state = parse_state(&column::<String>(row, 0, id.as_str(), REASON)?)
        .ok_or_else(|| corrupt(id, "unknown status state"))?;
    let reason = parse_reason(&column::<String>(row, 1, id.as_str(), REASON)?)
        .ok_or_else(|| corrupt(id, "unknown status reason"))?;
    let optional = |value: Option<i64>| {
        value
            .map(|v| u64::try_from(v).map_err(|_| corrupt(id, "negative safe status count")))
            .transpose()
    };
    Ok(SafeConnectionStatus {
        state,
        reason,
        observed_at: Some(column(row, 2, id.as_str(), REASON)?),
        latency_ms: optional(column(row, 3, id.as_str(), REASON)?)?,
        catalog_age_secs: optional(column(row, 4, id.as_str(), REASON)?)?,
        // The SQLite reader raises `CorruptRecord { reason: "invalid
        // catalog entry count" }` for a count it cannot represent
        // (store.rs `RawStatus::into_safe_status`); saturating instead
        // would hand a caller a fabricated `usize::MAX` entry count.
        catalog_entry_count: optional(column(row, 5, id.as_str(), REASON)?)?
            .map(|count| {
                usize::try_from(count).map_err(|_| corrupt(id, "invalid catalog entry count"))
            })
            .transpose()?,
    })
}

/// The MCP catalog bytes already retained across the whole store,
/// optionally excluding one connection (the one a replacement is about to
/// rewrite).
///
/// Three tables, not one. The candidate side of the comparison --
/// `validate_mcp_catalog`'s `stored_bytes` in store.rs -- charges entries,
/// resources AND resource templates against the single
/// `MAX_MANAGED_MCP_CATALOG_BYTES` budget, so summing entries alone would
/// measure a different quantity than the value it is added to: every
/// resource and template already stored would be free, and the budget could
/// be overrun without the check ever tripping. The arithmetic below mirrors
/// `mcp_catalog_bytes` in store.rs term for term -- including the flat 8
/// bytes charged for a resource that carries a size, and the zero charged
/// for each absent optional column.
///
/// `octet_length` measures the stored bytes directly because the JSON
/// columns are `text`, not `jsonb`: what is summed here is byte for byte
/// what serde_json wrote, which is what the candidate side counts. See the
/// column comments in migration 0006.
async fn mcp_catalog_bytes(
    client: &deadpool_postgres::Object,
    excluded: Option<&ConnectionId>,
    operation: &'static str,
) -> Result<usize, ConnectionStoreError> {
    let filter = if excluded.is_some() {
        "WHERE connection_id != $1::text::uuid"
    } else {
        ""
    };
    let query = format!(
        r#"
        SELECT
            (SELECT COALESCE(SUM(
                 octet_length(remote_tool_name)
               + COALESCE(octet_length(title), 0)
               + octet_length(description)
               + octet_length(input_schema_json)
               + COALESCE(octet_length(annotations_json), 0)
             ), 0)
             FROM greengateway.connection_mcp_catalog_entries {filter})
          + (SELECT COALESCE(SUM(
                 octet_length(uri)
               + octet_length(name)
               + COALESCE(octet_length(title), 0)
               + COALESCE(octet_length(description), 0)
               + COALESCE(octet_length(mime_type), 0)
               + CASE WHEN size IS NULL THEN 0 ELSE 8 END
             ), 0)
             FROM greengateway.connection_mcp_catalog_resources {filter})
          + (SELECT COALESCE(SUM(
                 octet_length(uri_template)
               + octet_length(name)
               + COALESCE(octet_length(title), 0)
               + COALESCE(octet_length(description), 0)
               + COALESCE(octet_length(mime_type), 0)
             ), 0)
             FROM greengateway.connection_mcp_catalog_resource_templates {filter})
        "#
    );
    let row = match excluded {
        Some(id) => client.query_one(query.as_str(), &[&id.as_str()]).await,
        None => client.query_one(query.as_str(), &[]).await,
    }
    .map_err(|error| pg_error(operation, error))?;
    let bytes: i64 = scalar(&row, 0, operation)?;
    usize::try_from(bytes)
        .map_err(|_| corrupt_id("<mcp-catalogs>", "invalid MCP catalog byte count"))
}

/// Total stored definition bytes across every managed OpenAPI catalog.
/// Verbatim stored bytes, so this measures exactly what the candidate side
/// measures (serde_json's compact encoding); see the column comment in
/// migration 0006 for why `definition_json` is `text` and not `jsonb`.
async fn openapi_definition_bytes(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<usize, ConnectionStoreError> {
    let row = client
        .query_one(
            r#"
            SELECT COALESCE(SUM(octet_length(definition_json)), 0)
            FROM greengateway.connection_openapi_catalog_entries
            "#,
            &[],
        )
        .await
        .map_err(|error| pg_error(operation, error))?;
    let bytes: i64 = scalar(&row, 0, operation)?;
    usize::try_from(bytes).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: "<openapi-catalogs>".to_owned(),
        reason: "negative or oversized stored OpenAPI definition byte total",
    })
}

/// The MCP catalog read, on the CALLER'S client and inside whatever
/// snapshot the caller has already opened. `read_mcp_catalogs` wraps this
/// in its own snapshot for ordinary reads; the restart preflight calls it
/// directly so its catalog reads and the dependency rows it checks them
/// against come from one consistent view.
async fn load_mcp_catalogs(
    client: &deadpool_postgres::Object,
    requested: Option<&ConnectionId>,
) -> Result<Vec<StoredMcpCatalog>, ConnectionStoreError> {
    let retained_bytes = mcp_catalog_bytes(client, None, OPERATION_MCP_READ).await?;
    if retained_bytes > super::store::MAX_MANAGED_MCP_CATALOG_BYTES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection MCP catalog bytes",
            maximum: super::store::MAX_MANAGED_MCP_CATALOG_BYTES,
        });
    }
    let rows = match requested {
        Some(id) => {
            client
                .query(
                    r#"
                SELECT connection_id::text, catalog_revision, observed_etag, refreshed_at,
                       entry_count, resource_count, resource_template_count
                FROM greengateway.connection_mcp_catalogs
                WHERE connection_id = $1::text::uuid
                ORDER BY connection_id
                "#,
                    &[&id.as_str()],
                )
                .await
        }
        None => {
            client
                .query(
                    r#"
                SELECT connection_id::text, catalog_revision, observed_etag, refreshed_at,
                       entry_count, resource_count, resource_template_count
                FROM greengateway.connection_mcp_catalogs
                ORDER BY connection_id
                "#,
                    &[],
                )
                .await
        }
    }
    .map_err(|error| pg_error(OPERATION_MCP_READ, error))?;

    const REASON: &str = "MCP catalog column does not decode as its schema type";
    let mut catalogs = Vec::with_capacity(rows.len());
    for row in &rows {
        let raw_id: String = column(row, 0, "<mcp-catalog>", REASON)?;
        let connection_id = parse_catalog_id(&raw_id)?;
        let catalog_revision = persisted_revision(
            &connection_id,
            column(row, 1, &raw_id, REASON)?,
            "invalid MCP catalog revision",
        )?;
        if catalog_revision == 0 {
            return Err(corrupt(&connection_id, "invalid MCP catalog revision"));
        }
        let entry_count: i64 = column(row, 4, &raw_id, REASON)?;
        let resource_count: i64 = column(row, 5, &raw_id, REASON)?;
        let template_count: i64 = column(row, 6, &raw_id, REASON)?;
        let total = entry_count
            .saturating_add(resource_count)
            .saturating_add(template_count);
        if total < 0
            || usize::try_from(total).unwrap_or(usize::MAX) > super::model::MAX_CATALOG_ENTRIES
        {
            return Err(corrupt(&connection_id, "invalid MCP catalog entry count"));
        }
        let entries = load_mcp_entries(client, &connection_id).await?;
        if entries.len() != usize::try_from(entry_count).unwrap_or(usize::MAX) {
            return Err(corrupt(&connection_id, "MCP catalog entry count mismatch"));
        }
        let resources = load_mcp_resources(client, &connection_id).await?;
        if resources.len() != usize::try_from(resource_count).unwrap_or(usize::MAX) {
            return Err(corrupt(&connection_id, "MCP resource count mismatch"));
        }
        let resource_templates = load_mcp_resource_templates(client, &connection_id).await?;
        if resource_templates.len() != usize::try_from(template_count).unwrap_or(usize::MAX) {
            return Err(corrupt(
                &connection_id,
                "MCP resource template count mismatch",
            ));
        }
        // What the standalone loader does: a persisted catalog is
        // re-validated before it is served. Rows edited out of band, or a
        // constraint dropped, must surface as corruption here rather than
        // as invalid tools in the registry or the capability inventory.
        validate_mcp_catalog(&connection_id, &entries, &resources, &resource_templates)
            .map_err(|_| corrupt(&connection_id, "persisted MCP catalog fails validation"))?;
        catalogs.push(StoredMcpCatalog {
            connection_id,
            catalog_revision,
            observed_etag: parse_etag(&column::<String>(row, 2, &raw_id, REASON)?)?,
            refreshed_at: column(row, 3, &raw_id, REASON)?,
            entries,
            resources,
            resource_templates,
        });
    }
    Ok(catalogs)
}

/// The OpenAPI catalog read, on the CALLER'S client and inside the
/// caller's snapshot; see `load_mcp_catalogs`.
async fn load_openapi_overlays(
    client: &deadpool_postgres::Object,
    requested: Option<&ConnectionId>,
) -> Result<Vec<StoredOpenApiOverlay>, ConnectionStoreError> {
    let rows = match requested {
        Some(id) => {
            client
                .query(
                    r#"
                    SELECT connection_id::text, schema_version, overlay_revision,
                           overlay_json, source_reports_json, updated_at
                    FROM greengateway.connection_openapi_overlays
                    WHERE connection_id = $1::text::uuid
                    ORDER BY connection_id
                    "#,
                    &[&id.as_str()],
                )
                .await
        }
        None => {
            client
                .query(
                    r#"
                    SELECT connection_id::text, schema_version, overlay_revision,
                           overlay_json, source_reports_json, updated_at
                    FROM greengateway.connection_openapi_overlays
                    ORDER BY connection_id
                    "#,
                    &[],
                )
                .await
        }
    }
    .map_err(|error| pg_error(OPERATION_OPENAPI_READ, error))?;

    const REASON: &str = "OpenAPI overlay column does not decode as its schema type";
    rows.iter()
        .map(|row| {
            let raw_id: String = column(row, 0, "<openapi-overlay>", REASON)?;
            let connection_id = parse_catalog_id(&raw_id)?;
            let schema_version: String = column(row, 1, &raw_id, REASON)?;
            let overlay_revision = persisted_revision(
                &connection_id,
                column(row, 2, &raw_id, REASON)?,
                "invalid OpenAPI overlay revision",
            )?;
            if overlay_revision == 0 {
                return Err(corrupt(&connection_id, "invalid OpenAPI overlay revision"));
            }
            let overlay_json: String = column(row, 3, &raw_id, REASON)?;
            let source_reports_json: Option<String> = column(row, 4, &raw_id, REASON)?;
            validate_openapi_overlay_write(&StoredOverlayWrite::Put {
                schema_version: schema_version.clone(),
                overlay_json: overlay_json.clone(),
                source_reports_json: source_reports_json.clone().unwrap_or_else(|| {
                    StoredOpenApiSourceReports::empty()
                        .canonical_json()
                        .expect("the fixed empty source report snapshot serializes")
                }),
                expected_overlay_revision: 0,
            })
            .map_err(|_| corrupt(&connection_id, "stored OpenAPI overlay fails validation"))?;
            Ok(StoredOpenApiOverlay {
                connection_id,
                schema_version,
                overlay_revision,
                overlay_json,
                source_reports_json,
                updated_at: column(row, 5, &raw_id, REASON)?,
            })
        })
        .collect()
}

async fn load_enum_source_revisions(
    client: &deadpool_postgres::Object,
    maximum: usize,
) -> Result<Vec<StoredEnumSourceRevision>, ConnectionStoreError> {
    let limit = i64::try_from(maximum.saturating_add(1)).unwrap_or(i64::MAX);
    let rows = client
        .query(
            r#"
            SELECT connection_id::text, source_id, overlay_revision, source_digest,
                   values_revision, connection_revision, credential_revision,
                   credential_generation_digest
            FROM greengateway.connection_enum_source_values
            ORDER BY connection_id, source_id
            LIMIT $1
            "#,
            &[&limit],
        )
        .await
        .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?;
    if rows.len() > maximum {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection enum source values",
            maximum,
        });
    }
    const REASON: &str = "enum source revision column does not decode as its schema type";
    rows.iter()
        .map(|row| {
            let raw_id: String = column(row, 0, "<enum-source-revision>", REASON)?;
            let connection_id = parse_catalog_id(&raw_id)?;
            let source_id: String = column(row, 1, &raw_id, REASON)?;
            let source_digest: String = column(row, 3, &raw_id, REASON)?;
            let credential_generation_digest: Option<String> = column(row, 7, &raw_id, REASON)?;
            if !valid_overlay_local_name(&source_id)
                || !valid_sha256_hex(&source_digest)
                || credential_generation_digest
                    .as_deref()
                    .is_some_and(|digest| !valid_sha256_hex(digest))
            {
                return Err(ConnectionStoreError::CorruptRecord {
                    id: raw_id,
                    reason: "invalid enum source provenance",
                });
            }
            Ok(StoredEnumSourceRevision {
                connection_id: connection_id.clone(),
                source_id,
                overlay_revision: persisted_revision(
                    &connection_id,
                    column(row, 2, &raw_id, REASON)?,
                    "invalid enum source overlay revision",
                )?,
                source_digest,
                values_revision: persisted_revision(
                    &connection_id,
                    column(row, 4, &raw_id, REASON)?,
                    "invalid enum source values revision",
                )?,
                connection_revision: persisted_revision(
                    &connection_id,
                    column(row, 5, &raw_id, REASON)?,
                    "invalid enum source connection revision",
                )?,
                credential_revision: revision_from_i64(
                    &connection_id,
                    column(row, 6, &raw_id, REASON)?,
                    true,
                )?,
                credential_generation_digest,
            })
        })
        .collect()
}

async fn load_enum_source_values(
    client: &deadpool_postgres::Object,
    requested: Option<&ConnectionId>,
) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
    let rows = match requested {
        Some(id) => {
            client
                .query(
                    r#"
                    SELECT connection_id::text, source_id, overlay_revision, source_digest,
                           values_revision, connection_revision, credential_revision,
                           credential_generation_digest, values_json, resolved_at
                    FROM greengateway.connection_enum_source_values
                    WHERE connection_id = $1::text::uuid
                    ORDER BY connection_id, source_id
                    "#,
                    &[&id.as_str()],
                )
                .await
        }
        None => {
            client
                .query(
                    r#"
                    SELECT connection_id::text, source_id, overlay_revision, source_digest,
                           values_revision, connection_revision, credential_revision,
                           credential_generation_digest, values_json, resolved_at
                    FROM greengateway.connection_enum_source_values
                    ORDER BY connection_id, source_id
                    "#,
                    &[],
                )
                .await
        }
    }
    .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?;

    rows.iter().map(decode_pg_enum_source_row).collect()
}

async fn load_enum_source_value(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    source_id: &str,
) -> Result<Option<StoredEnumSourceValue>, ConnectionStoreError> {
    client
        .query_opt(
            r#"
            SELECT connection_id::text, source_id, overlay_revision, source_digest,
                   values_revision, connection_revision, credential_revision,
                   credential_generation_digest, values_json, resolved_at
            FROM greengateway.connection_enum_source_values
            WHERE connection_id = $1::text::uuid AND source_id = $2
            "#,
            &[&id.as_str(), &source_id],
        )
        .await
        .map_err(|error| pg_error(OPERATION_ENUM_SOURCE_VALUES, error))?
        .as_ref()
        .map(decode_pg_enum_source_row)
        .transpose()
}

fn decode_pg_enum_source_row(
    row: &tokio_postgres::Row,
) -> Result<StoredEnumSourceValue, ConnectionStoreError> {
    const REASON: &str = "enum source value column does not decode as its schema type";
    let raw_id: String = column(row, 0, "<enum-source-value>", REASON)?;
    let connection_id = parse_catalog_id(&raw_id)?;
    let source_id: String = column(row, 1, &raw_id, REASON)?;
    let overlay_revision = persisted_revision(
        &connection_id,
        column(row, 2, &raw_id, REASON)?,
        "invalid enum source overlay revision",
    )?;
    let source_digest: String = column(row, 3, &raw_id, REASON)?;
    let values_revision = persisted_revision(
        &connection_id,
        column(row, 4, &raw_id, REASON)?,
        "invalid enum source values revision",
    )?;
    let connection_revision = persisted_revision(
        &connection_id,
        column(row, 5, &raw_id, REASON)?,
        "invalid enum source connection revision",
    )?;
    let credential_revision =
        revision_from_i64(&connection_id, column(row, 6, &raw_id, REASON)?, true)?;
    let credential_generation_digest: Option<String> = column(row, 7, &raw_id, REASON)?;
    let values_json: String = column(row, 8, &raw_id, REASON)?;
    let resolved_at: String = column(row, 9, &raw_id, REASON)?;
    if !valid_overlay_local_name(&source_id)
        || !valid_sha256_hex(&source_digest)
        || credential_generation_digest
            .as_deref()
            .is_some_and(|digest| !valid_sha256_hex(digest))
        || !valid_enum_source_timestamp(&resolved_at)
    {
        return Err(ConnectionStoreError::CorruptRecord {
            id: raw_id,
            reason: "invalid enum source provenance",
        });
    }
    let document = decode_enum_source_values(&values_json).map_err(|_| {
        ConnectionStoreError::CorruptRecord {
            id: connection_id.to_string(),
            reason: "invalid enum source values",
        }
    })?;
    Ok(StoredEnumSourceValue {
        connection_id,
        source_id,
        overlay_revision,
        source_digest,
        values_revision,
        connection_revision,
        credential_revision,
        credential_generation_digest,
        values: document.values,
        labels: document.labels,
        resolved_at,
    })
}

async fn write_catalog_enum_source_values(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    current: &StoredConnection,
    overlay_revision: u64,
    writes: &[StoredEnumSourceValueWrite],
) -> Result<(), ConnectionStoreError> {
    if writes.len() > MAX_OPENAPI_ENUM_SOURCES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection enum sources",
            maximum: MAX_OPENAPI_ENUM_SOURCES,
        });
    }
    let mut source_ids = BTreeSet::new();
    for write in writes {
        if &write.connection_id != id
            || write.overlay_revision != overlay_revision
            || write.connection_revision != current.revisions.connection
            || write.credential_revision != current.revisions.credential
            || !source_ids.insert(write.source_id.as_str())
        {
            return Err(ConnectionStoreError::Validation {
                problems: vec![
                    "resolved enum source values do not match the catalog generation".to_owned(),
                ],
            });
        }
        let values_json = encode_enum_source_values(write)?;
        let previous = client
            .query_opt(
                "SELECT values_revision, source_digest FROM greengateway.connection_enum_source_values WHERE connection_id = $1::text::uuid AND source_id = $2 FOR UPDATE",
                &[&id.as_str(), &write.source_id],
            )
            .await
            .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
        let current_source_digest = previous
            .as_ref()
            .map(|row| {
                column::<String>(
                    row,
                    1,
                    id.as_str(),
                    "enum source digest does not decode as text",
                )
            })
            .transpose()?;
        if current_source_digest
            .as_ref()
            .is_some_and(|source_digest| source_digest != &write.source_digest)
        {
            return Err(ConnectionStoreError::Validation {
                problems: vec![
                    "resolved enum source values do not match the stored source generation"
                        .to_owned(),
                ],
            });
        }
        let current_values_revision = match previous {
            Some(row) => persisted_revision(
                id,
                column(
                    &row,
                    0,
                    id.as_str(),
                    "enum source values revision does not decode as bigint",
                )?,
                "invalid enum source values revision",
            )?,
            None => 0,
        };
        if current_values_revision != write.expected_values_revision {
            return Err(ConnectionStoreError::EnumSourceConflict {
                id: id.to_string(),
                source_id: write.source_id.clone(),
                current_values_revision,
            });
        }
        let values_revision = increment_revision(id, current_values_revision)?;
        let overlay_revision = u64_to_i64(id, write.overlay_revision)?;
        let values_revision = u64_to_i64(id, values_revision)?;
        let connection_revision = u64_to_i64(id, write.connection_revision)?;
        let credential_revision = u64_to_i64(id, write.credential_revision)?;
        client
            .execute(
                r#"
                INSERT INTO greengateway.connection_enum_source_values (
                    connection_id, source_id, overlay_revision, source_digest,
                    values_revision, connection_revision, credential_revision,
                    credential_generation_digest, values_json, resolved_at
                ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (connection_id, source_id) DO UPDATE SET
                    overlay_revision = excluded.overlay_revision,
                    source_digest = excluded.source_digest,
                    values_revision = excluded.values_revision,
                    connection_revision = excluded.connection_revision,
                    credential_revision = excluded.credential_revision,
                    credential_generation_digest = excluded.credential_generation_digest,
                    values_json = excluded.values_json,
                    resolved_at = excluded.resolved_at
                "#,
                &[
                    &id.as_str(),
                    &write.source_id,
                    &overlay_revision,
                    &write.source_digest,
                    &values_revision,
                    &connection_revision,
                    &credential_revision,
                    &write.credential_generation_digest,
                    &values_json,
                    &write.resolved_at,
                ],
            )
            .await
            .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // One argument per independently fenced catalog/overlay axis.
async fn write_openapi_overlay(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    overlay: Option<&StoredOverlayWrite>,
    compiled_overlay_revision: u64,
    current_connection_revision: u64,
    current_catalog_revision: u64,
    actor_user_id: &str,
    now: &str,
) -> Result<u64, ConnectionStoreError> {
    let current = client
        .query_opt(
            "SELECT overlay_revision FROM greengateway.connection_openapi_overlays \
             WHERE connection_id = $1::text::uuid",
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
    let current_revision = match current {
        Some(row) => persisted_revision(
            id,
            column(
                &row,
                0,
                id.as_str(),
                "OpenAPI overlay revision does not decode as bigint",
            )?,
            "invalid OpenAPI overlay revision",
        )?,
        None => 0,
    };
    let Some(write) = overlay else {
        if compiled_overlay_revision != current_revision {
            return Err(ConnectionStoreError::OverlayConflict {
                id: id.to_string(),
                current_connection_revision,
                current_catalog_revision,
                current_overlay_revision: current_revision,
            });
        }
        return Ok(current_revision);
    };
    let expected_overlay_revision = match write {
        StoredOverlayWrite::Put {
            expected_overlay_revision,
            ..
        }
        | StoredOverlayWrite::Delete {
            expected_overlay_revision,
        }
        | StoredOverlayWrite::Reports {
            expected_overlay_revision,
            ..
        } => *expected_overlay_revision,
    };
    if expected_overlay_revision != current_revision {
        return Err(ConnectionStoreError::OverlayConflict {
            id: id.to_string(),
            current_connection_revision,
            current_catalog_revision,
            current_overlay_revision: current_revision,
        });
    }
    let expected_compiled_revision = match write {
        StoredOverlayWrite::Put { .. } => increment_revision(id, current_revision)?,
        StoredOverlayWrite::Delete { .. } => 0,
        StoredOverlayWrite::Reports { .. } => current_revision,
    };
    if compiled_overlay_revision != expected_compiled_revision {
        return Err(ConnectionStoreError::Validation {
            problems: vec![
                "compiled OpenAPI overlay revision does not match the resulting overlay".to_owned(),
            ],
        });
    }

    match write {
        StoredOverlayWrite::Put {
            schema_version,
            overlay_json,
            source_reports_json,
            ..
        } => {
            // Any source declaration can change while retaining its
            // source_id. Pruning in this transaction prevents stale values
            // from crossing an overlay revision or tenant-specific source
            // plan.
            client
                .execute(
                    "DELETE FROM greengateway.connection_enum_source_values \
                     WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;

            let next_revision = expected_compiled_revision;
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_openapi_overlays (
                        connection_id, schema_version, overlay_revision, overlay_json,
                        source_reports_json, actor_user_id, updated_at
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (connection_id) DO UPDATE SET
                        schema_version = excluded.schema_version,
                        overlay_revision = excluded.overlay_revision,
                        overlay_json = excluded.overlay_json,
                        source_reports_json = excluded.source_reports_json,
                        actor_user_id = excluded.actor_user_id,
                        updated_at = excluded.updated_at
                    "#,
                    &[
                        &id.as_str(),
                        schema_version,
                        &u64_to_i64(id, next_revision)?,
                        overlay_json,
                        source_reports_json,
                        &actor_user_id,
                        &now,
                    ],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            Ok(next_revision)
        }
        StoredOverlayWrite::Delete { .. } => {
            client
                .execute(
                    "DELETE FROM greengateway.connection_enum_source_values \
                     WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            client
                .execute(
                    "DELETE FROM greengateway.connection_openapi_overlays \
                     WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            Ok(0)
        }
        StoredOverlayWrite::Reports {
            source_reports_json,
            ..
        } => {
            if current_revision == 0 {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![
                        "OpenAPI source reports cannot be stored without an overlay".to_owned()
                    ],
                });
            }
            let changed = client
                .execute(
                    r#"
                    UPDATE greengateway.connection_openapi_overlays
                    SET source_reports_json = $1, actor_user_id = $2, updated_at = $3
                    WHERE connection_id = $4::text::uuid
                    "#,
                    &[source_reports_json, &actor_user_id, &now, &id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            if changed != 1 {
                return Err(ConnectionStoreError::CorruptRecord {
                    id: id.to_string(),
                    reason: "OpenAPI overlay disappeared during source report update",
                });
            }
            Ok(current_revision)
        }
    }
}

async fn load_openapi_catalogs(
    client: &deadpool_postgres::Object,
    requested: Option<&ConnectionId>,
) -> Result<Vec<StoredOpenApiCatalog>, ConnectionStoreError> {
    // The same aggregate bound the MCP loader above enforces, and for the
    // same reason: the SQLite reference refuses to serve an over-budget
    // catalog set on every read (store.rs `load_openapi_catalogs` and
    // `load_openapi_inventory_catalogs`), not only at startup. Boot alone
    // is not enough -- another replica can commit between this replica's
    // preflight and this read.
    let retained_definition_bytes =
        openapi_definition_bytes(client, OPERATION_OPENAPI_READ).await?;
    if retained_definition_bytes > super::model::MAX_MANAGED_OPENAPI_CATALOG_BYTES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection OpenAPI catalog definition bytes",
            maximum: super::model::MAX_MANAGED_OPENAPI_CATALOG_BYTES,
        });
    }
    let rows = match requested {
        Some(id) => {
            client
                .query(
                    r#"
                SELECT connection_id::text, spec_revision, catalog_revision, observed_etag,
                       spec_digest, spec, refreshed_at, entry_count, overlay_revision
                FROM greengateway.connection_openapi_catalogs
                WHERE connection_id = $1::text::uuid
                ORDER BY connection_id
                "#,
                    &[&id.as_str()],
                )
                .await
        }
        None => {
            client
                .query(
                    r#"
                SELECT connection_id::text, spec_revision, catalog_revision, observed_etag,
                       spec_digest, spec, refreshed_at, entry_count, overlay_revision
                FROM greengateway.connection_openapi_catalogs
                ORDER BY connection_id
                "#,
                    &[],
                )
                .await
        }
    }
    .map_err(|error| pg_error(OPERATION_OPENAPI_READ, error))?;

    const REASON: &str = "OpenAPI catalog column does not decode as its schema type";
    let mut catalogs = Vec::with_capacity(rows.len());
    for row in &rows {
        let raw_id: String = column(row, 0, "<openapi-catalog>", REASON)?;
        let connection_id = parse_catalog_id(&raw_id)?;
        let spec_revision = persisted_revision(
            &connection_id,
            column(row, 1, &raw_id, REASON)?,
            "invalid OpenAPI spec revision",
        )?;
        let catalog_revision = persisted_revision(
            &connection_id,
            column(row, 2, &raw_id, REASON)?,
            "invalid OpenAPI catalog revision",
        )?;
        if spec_revision == 0 || catalog_revision == 0 {
            return Err(corrupt(&connection_id, "invalid OpenAPI catalog revision"));
        }
        // The spec column holds the verbatim bytes the publisher signed
        // and spec_digest is the SHA-256 over exactly those bytes, so
        // every read re-verifies the pair and fails closed on a tampered
        // or truncated row -- the same guard the SQLite store applies on
        // every catalog read (store.rs read_openapi_catalogs).
        let spec_digest: String = column(row, 4, &raw_id, REASON)?;
        let spec: String = column(row, 5, &raw_id, REASON)?;
        validate_openapi_spec(&spec, &spec_digest)
            .map_err(|_| corrupt(&connection_id, "invalid stored OpenAPI spec or digest"))?;
        let entry_count: i64 = column(row, 7, &raw_id, REASON)?;
        if entry_count < 0
            || usize::try_from(entry_count).unwrap_or(usize::MAX)
                > super::model::MAX_CATALOG_ENTRIES
        {
            return Err(corrupt(
                &connection_id,
                "invalid OpenAPI catalog entry count",
            ));
        }
        let (entries, stored_json) = load_openapi_entries(client, &connection_id).await?;
        let overlay_revision =
            revision_from_i64(&connection_id, column(row, 8, &raw_id, REASON)?, true)?;
        if entries.len() != usize::try_from(entry_count).unwrap_or(usize::MAX) {
            return Err(corrupt(
                &connection_id,
                "OpenAPI catalog entry count mismatch",
            ));
        }
        // Re-validate and compare canonical encodings, as the standalone
        // loader does: an entry whose stored JSON is not what this binary
        // would write for it was edited out of band and is corruption, not
        // a catalog to activate.
        let encoded = validate_openapi_catalog_entries(&entries)
            .map_err(|_| corrupt(&connection_id, "persisted OpenAPI catalog fails validation"))?;
        for (encoded, (selected_json, definition_json)) in encoded.iter().zip(&stored_json) {
            if &encoded.selected_scheme_names_json != selected_json
                || &encoded.definition_json != definition_json
            {
                return Err(corrupt(
                    &connection_id,
                    "persisted OpenAPI catalog entry is not in canonical form",
                ));
            }
        }
        catalogs.push(StoredOpenApiCatalog {
            connection_id,
            spec_revision,
            catalog_revision,
            observed_etag: parse_etag(&column::<String>(row, 3, &raw_id, REASON)?)?,
            spec_digest,
            spec,
            refreshed_at: column(row, 6, &raw_id, REASON)?,
            entries,
            overlay_revision,
        });
    }
    Ok(catalogs)
}

async fn load_mcp_entries(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
) -> Result<Vec<StoredMcpCatalogEntry>, ConnectionStoreError> {
    let rows = client
        .query(
            r#"
            SELECT remote_tool_name, title, description, input_schema_json,
                   annotations_json, ordinal
            FROM greengateway.connection_mcp_catalog_entries
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_MCP_READ, error))?;
    const REASON: &str = "MCP catalog entry column does not decode as its schema type";
    ensure_contiguous_ordinals(&rows, 5, id, "MCP catalog entries")?;
    rows.iter()
        .map(|row| {
            let input_schema: Value =
                serde_json::from_str(&column::<String>(row, 3, id.as_str(), REASON)?)
                    .map_err(|_| corrupt(id, "MCP catalog entry schema is not valid JSON"))?;
            let annotations = column::<Option<String>>(row, 4, id.as_str(), REASON)?
                .map(|annotations| {
                    serde_json::from_str(&annotations).map_err(|_| {
                        corrupt(id, "MCP catalog entry annotations are not valid JSON")
                    })
                })
                .transpose()?;
            Ok(StoredMcpCatalogEntry {
                remote_tool_name: column(row, 0, id.as_str(), REASON)?,
                title: column(row, 1, id.as_str(), REASON)?,
                description: column(row, 2, id.as_str(), REASON)?,
                input_schema,
                annotations,
            })
        })
        .collect()
}

async fn load_mcp_resources(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
) -> Result<Vec<StoredMcpResource>, ConnectionStoreError> {
    let rows = client
        .query(
            r#"
            SELECT uri, name, title, description, mime_type, size, ordinal
            FROM greengateway.connection_mcp_catalog_resources
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_MCP_READ, error))?;
    const REASON: &str = "MCP resource column does not decode as its schema type";
    ensure_contiguous_ordinals(&rows, 6, id, "MCP resources")?;
    rows.iter()
        .map(|row| {
            Ok(StoredMcpResource {
                uri: column(row, 0, id.as_str(), REASON)?,
                name: column(row, 1, id.as_str(), REASON)?,
                title: column(row, 2, id.as_str(), REASON)?,
                description: column(row, 3, id.as_str(), REASON)?,
                mime_type: column(row, 4, id.as_str(), REASON)?,
                // A negative persisted size is corruption, not a resource
                // of size `u64::MAX`: the SQLite loader raises
                // `CorruptRecord { reason: "invalid MCP resource size" }`
                // for the same row and this must too.
                size: column::<Option<i64>>(row, 5, id.as_str(), REASON)?
                    .map(|size| {
                        u64::try_from(size).map_err(|_| corrupt(id, "invalid MCP resource size"))
                    })
                    .transpose()?,
            })
        })
        .collect()
}

async fn load_mcp_resource_templates(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
) -> Result<Vec<StoredMcpResourceTemplate>, ConnectionStoreError> {
    let rows = client
        .query(
            r#"
            SELECT uri_template, name, title, description, mime_type, ordinal
            FROM greengateway.connection_mcp_catalog_resource_templates
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_MCP_READ, error))?;
    const REASON: &str = "MCP resource template column does not decode as its schema type";
    ensure_contiguous_ordinals(&rows, 5, id, "MCP resource templates")?;
    rows.iter()
        .map(|row| {
            Ok(StoredMcpResourceTemplate {
                uri_template: column(row, 0, id.as_str(), REASON)?,
                name: column(row, 1, id.as_str(), REASON)?,
                title: column(row, 2, id.as_str(), REASON)?,
                description: column(row, 3, id.as_str(), REASON)?,
                mime_type: column(row, 4, id.as_str(), REASON)?,
            })
        })
        .collect()
}

/// The entries plus the JSON exactly as stored (selected schemes,
/// definition), so the loader can compare them with the canonical encoding.
async fn load_openapi_entries(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
) -> Result<(Vec<StoredOpenApiCatalogEntry>, Vec<(String, String)>), ConnectionStoreError> {
    let rows = client
        .query(
            r#"
            SELECT tool_name, operation_id, selected_scheme_names_json, definition_json, ordinal
            FROM greengateway.connection_openapi_catalog_entries
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_OPENAPI_READ, error))?;
    ensure_contiguous_ordinals(&rows, 4, id, "OpenAPI catalog entries")?;
    let mut entries = Vec::with_capacity(rows.len());
    let mut stored_json = Vec::with_capacity(rows.len());
    for row in &rows {
        const REASON: &str = "OpenAPI catalog entry column does not decode as its schema type";
        let selected_json: String = column(row, 2, id.as_str(), REASON)?;
        let definition_json: String = column(row, 3, id.as_str(), REASON)?;
        let selected: Vec<String> = serde_json::from_str(&selected_json)
            .map_err(|_| corrupt(id, "OpenAPI selected schemes are not valid JSON"))?;
        let definition: Value = serde_json::from_str(&definition_json)
            .map_err(|_| corrupt(id, "OpenAPI tool definition is not valid JSON"))?;
        entries.push(StoredOpenApiCatalogEntry {
            tool_name: column(row, 0, id.as_str(), REASON)?,
            operation_id: column(row, 1, id.as_str(), REASON)?,
            selected_scheme_names: selected,
            definition,
        });
        stored_json.push((selected_json, definition_json));
    }
    Ok((entries, stored_json))
}

/// Persisted catalog rows are written with ordinals 0..n; a gap or a
/// duplicate means a row was edited out of band or a constraint dropped.
fn ensure_contiguous_ordinals(
    rows: &[tokio_postgres::Row],
    ordinal_column: usize,
    id: &ConnectionId,
    what: &'static str,
) -> Result<(), ConnectionStoreError> {
    for (index, row) in rows.iter().enumerate() {
        let ordinal: i64 = row
            .try_get(ordinal_column)
            .map_err(|_| corrupt(id, "persisted catalog ordinal does not decode"))?;
        if usize::try_from(ordinal).ok() != Some(index) {
            let _ = what;
            return Err(corrupt(id, "persisted catalog ordinals are not contiguous"));
        }
    }
    Ok(())
}

/// One connection's dependency rows, bounded and sorted. The caller runs
/// this inside a snapshot: the existence check and the rows it guards
/// have to describe the same instant, or a concurrent delete turns a
/// `NotFound` into an empty list (or the reverse).
async fn load_dependencies(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
) -> Result<Vec<ConnectionDependency>, ConnectionStoreError> {
    let exists_row = client
        .query_one(
            "SELECT EXISTS(\
             SELECT 1 FROM greengateway.connection_records WHERE id = $1::text::uuid)",
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_DEPS_READ, error))?;
    let exists: bool = scalar(&exists_row, 0, OPERATION_DEPS_READ)?;
    if !exists {
        return Err(ConnectionStoreError::NotFound { id: id.to_string() });
    }
    let rows = client
        .query(
            r#"
            SELECT consumer_kind, consumer_id
            FROM greengateway.connection_dependencies
            WHERE connection_id = $1::text::uuid
            ORDER BY consumer_kind ASC, consumer_id ASC
            LIMIT $2
            "#,
            &[
                &id.as_str(),
                &(usize_to_i64(MAX_CONNECTION_DEPENDENCIES + 1)),
            ],
        )
        .await
        .map_err(|error| pg_error(OPERATION_DEPS_READ, error))?;
    if rows.len() > MAX_CONNECTION_DEPENDENCIES {
        return Err(ConnectionStoreError::LimitExceeded {
            resource: "connection dependencies",
            maximum: MAX_CONNECTION_DEPENDENCIES,
        });
    }
    const REASON: &str = "dependency column does not decode as its schema type";
    rows.iter()
        .map(|row| {
            let raw_kind: String = column(row, 0, id.as_str(), REASON)?;
            let kind = ConnectionDependencyKind::parse(&raw_kind)
                .ok_or_else(|| corrupt(id, "unknown dependency kind"))?;
            Ok(ConnectionDependency {
                kind,
                consumer_id: column(row, 1, id.as_str(), REASON)?,
            })
        })
        .collect()
}

/// Which managed-catalog kind a specification supports; `None` when the
/// two sides of a replacement agree (no cleanup required).
fn managed_catalog_kind_changed(current: &StoredConnection, candidate: &ConnectionWrite) -> bool {
    let kind_of = |write: &ConnectionWrite| {
        if write.kind == super::model::ConnectionKind::McpStreamableHttp
            && matches!(
                &write.discovery,
                Some(super::model::DiscoveryConfig::ManagedMcp { .. })
            )
        {
            1
        } else if write.kind == super::model::ConnectionKind::HttpApi
            && matches!(
                &write.discovery,
                Some(super::model::DiscoveryConfig::ManagedOpenapi { .. })
            )
        {
            2
        } else {
            0
        }
    };
    kind_of(&current.write) != kind_of(candidate)
}

async fn count_records(client: &deadpool_postgres::Object) -> Result<usize, ConnectionStoreError> {
    let count_row = client
        .query_one("SELECT COUNT(*) FROM greengateway.connection_records", &[])
        .await
        .map_err(|error| pg_error(OPERATION_LIST, error))?;
    let count: i64 = scalar(&count_row, 0, OPERATION_LIST)?;
    usize::try_from(count).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: "<collection>".to_owned(),
        reason: "negative or oversized record count",
    })
}

/// Every record, ordered by ID. The reference orders the same way
/// (`load_all_records`, store.rs: `ORDER BY id ASC` over the TEXT ID) and
/// its `list` is that function verbatim; ordering by `created_at` instead
/// would put two records written in the same timestamp granularity in an
/// order the reference never produces. `id` is a `uuid` here, whose
/// comparison is over the same 16 bytes that the canonical lowercase text
/// form spells out at fixed positions, so the two orderings agree and the
/// primary-key index still serves this.
async fn load_all_records(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<Vec<StoredConnection>, ConnectionStoreError> {
    let rows = client
        .query(
            r#"
            SELECT id::text, schema_version, source, spec_json, connection_revision,
                   credential_revision, tls_revision, discovery_revision,
                   status_revision, created_at, updated_at
            FROM greengateway.connection_records
            ORDER BY id ASC
            "#,
            &[],
        )
        .await
        .map_err(|error| pg_error(operation, error))?;
    rows.iter()
        .map(|row| RawConnectionRow::from_row(row)?.into_stored())
        .collect()
}

async fn load_record(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    operation: &'static str,
) -> Result<Option<StoredConnection>, ConnectionStoreError> {
    let row = client
        .query_opt(record_query("").as_str(), &[&id.as_str()])
        .await
        .map_err(|error| pg_error(operation, error))?;
    row.map(|row| RawConnectionRow::from_row(&row)?.into_stored())
        .transpose()
}

async fn load_record_for_update(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    operation: &'static str,
) -> Result<Option<StoredConnection>, ConnectionStoreError> {
    let row = client
        .query_opt(record_query(" FOR UPDATE").as_str(), &[&id.as_str()])
        .await
        .map_err(|error| pg_error(operation, error))?;
    row.map(|row| RawConnectionRow::from_row(&row)?.into_stored())
        .transpose()
}

fn record_query(lock: &str) -> String {
    format!(
        r#"
        SELECT id::text, schema_version, source, spec_json, connection_revision,
               credential_revision, tls_revision, discovery_revision,
               status_revision, created_at, updated_at
        FROM greengateway.connection_records
        WHERE id = $1::text::uuid{lock}
        "#
    )
}

/// The derived credential bindings must always match the stored document
/// exactly; a mismatch is corruption and fails closed rather than
/// serving a record whose secret wiring disagrees with its spec.
async fn validate_bindings(
    client: &deadpool_postgres::Object,
    record: &StoredConnection,
) -> Result<(), ConnectionStoreError> {
    let rows = client
        .query(
            r#"
            SELECT purpose, header_name, secret_id, binding_version
            FROM greengateway.connection_credential_bindings
            WHERE connection_id = $1::text::uuid
            ORDER BY purpose ASC, header_name ASC
            "#,
            &[&record.id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_GET, error))?;
    const REASON: &str = "credential binding column does not decode as its schema type";
    let mut actual: Vec<(String, String, String, i64)> = rows
        .iter()
        .map(|row| {
            Ok((
                column(row, 0, record.id.as_str(), REASON)?,
                column(row, 1, record.id.as_str(), REASON)?,
                column(row, 2, record.id.as_str(), REASON)?,
                column(row, 3, record.id.as_str(), REASON)?,
            ))
        })
        .collect::<Result<Vec<_>, ConnectionStoreError>>()?;
    let mut expected: Vec<(String, String, String, i64)> =
        expected_bindings(&record.write, &record.revisions)
            .into_iter()
            .map(|binding| {
                Ok((
                    binding.purpose.to_owned(),
                    binding.header_name.to_owned(),
                    binding.secret_id.to_owned(),
                    u64_to_i64(&record.id, binding.version.max(1))?,
                ))
            })
            .collect::<Result<Vec<_>, ConnectionStoreError>>()?;
    actual.sort();
    expected.sort();
    if actual != expected {
        return Err(ConnectionStoreError::CorruptRecord {
            id: record.id.to_string(),
            reason: "credential binding rows do not match the stored connection document",
        });
    }
    Ok(())
}

async fn replace_bindings(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    write: &ConnectionWrite,
    revisions: &ConnectionRevisions,
    now: &str,
) -> Result<(), ConnectionStoreError> {
    client
        .execute(
            "DELETE FROM greengateway.connection_credential_bindings WHERE connection_id = $1::text::uuid",
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    for binding in expected_bindings(write, revisions) {
        client
            .execute(
                r#"
                INSERT INTO greengateway.connection_credential_bindings (
                    connection_id, purpose, header_name, secret_id, binding_version, updated_at
                ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6)
                "#,
                &[
                    &id.as_str(),
                    &binding.purpose,
                    &binding.header_name,
                    &binding.secret_id,
                    &u64_to_i64(id, binding.version.max(1))?,
                    &now,
                ],
            )
            .await
            .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    }
    Ok(())
}

async fn ensure_binding_capacity(
    client: &deadpool_postgres::Object,
    replaced_id: Option<&ConnectionId>,
    replaced_binding_count: usize,
    candidate_binding_count: usize,
) -> Result<(), ConnectionStoreError> {
    let persisted_row = client
        .query_one(
            "SELECT COUNT(*) FROM greengateway.connection_credential_bindings",
            &[],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    let persisted: i64 = scalar(&persisted_row, 0, OPERATION_CREATE)?;
    let persisted =
        usize::try_from(persisted).map_err(|_| ConnectionStoreError::CorruptRecord {
            id: "<bindings>".to_owned(),
            reason: "negative or oversized binding count",
        })?;
    if let Some(id) = replaced_id {
        let record_bindings_row = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.connection_credential_bindings WHERE connection_id = $1::text::uuid",
                &[&id.as_str()],
            )
            .await
            .map_err(|error| pg_error(OPERATION_CREATE, error))?;
        let record_bindings: i64 = scalar(&record_bindings_row, 0, OPERATION_CREATE)?;
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

/// Append the immutable specification version for a committed write. The
/// document etag is the full connection etag of that version, so a
/// history read can verify a version exactly like the active record.
async fn append_version(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    version: u64,
    spec_json: &str,
    actor_user_id: &str,
) -> Result<(), ConnectionStoreError> {
    // The document etag hashes the spec document itself rather than
    // reusing the active row's etag derivation. The active-row etag
    // (`StoredConnection::etag`) is keyed by the five axis revisions, and a
    // version row does not have them: it is already addressable by
    // (id, version). What the etag is for here is guarding the stored body
    // against an out-of-band edit, which the spec bytes alone answer.
    let document_etag = version_document_etag(id, version, spec_json)?;
    client
        .execute(
            r#"
            INSERT INTO greengateway.connection_documents (
                connection_id, version, spec, document_etag, actor_user_id, diff_summary
            ) VALUES ($1::text::uuid, $2, $3, $4, $5, '{}'::text::jsonb)
            "#,
            &[
                &id.as_str(),
                &u64_to_i64(id, version)?,
                &spec_json,
                &document_etag,
                &actor_user_id,
            ],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    Ok(())
}

/// `connection_documents.document_etag` for one version: SHA-256 over the
/// id, the version and the stored spec bytes. Shared by the live write
/// path and the import so a version row an import wrote is verifiable by
/// exactly the derivation a version row a replica wrote is.
fn version_document_etag(
    id: &ConnectionId,
    version: u64,
    spec_json: &str,
) -> Result<String, ConnectionStoreError> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(id.as_str().as_bytes());
    hasher.update(u64_to_i64(id, version)?.to_be_bytes());
    hasher.update(spec_json.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// The outbox `resource_type` for a specification-version transition:
/// `from_version`/`to_version` are `connection_documents.version` values,
/// which is also `connection_records.connection_revision`. Reading every
/// `resource_type = 'connection'` row for one `resource_id` in revision
/// order therefore reconstructs that Connection's version chain exactly.
/// `to_version` 0 marks a deletion (specification versions start at 1).
const RESOURCE_CONNECTION: &str = "connection";

/// The outbox `resource_type` for a catalog replacement.
///
/// A catalog replacement advances the per-connection CATALOG revision --
/// `connection_mcp_catalogs.catalog_revision` or
/// `connection_openapi_catalogs.catalog_revision` -- and leaves the
/// specification version untouched. Emitting those numbers under
/// `'connection'` put two unrelated counters in one column, so a consumer
/// reconstructing a version chain from `outbox_after`
/// (storage/postgres_policy.rs, which returns `from_version`/`to_version`
/// verbatim) saw a non-monotonic interleaving of the two. Its own label
/// keeps both sequences readable without changing the outbox schema or
/// breaking `outbox_after`'s existing 'policy'/'tools'/'connection'
/// consumers: `resource_type` is unconstrained text and no consumer
/// filters on 'connection' today.
const RESOURCE_CONNECTION_CATALOG: &str = "connection_catalog";

/// Advance the shared security revision and the connections high-water
/// mark and append the outbox row, all inside the caller's transaction:
/// a connection mutation cannot succeed without its durable record.
/// `resource_type` says which counter `from_version`/`to_version` carry;
/// see the two constants above.
async fn bump_connection_state(
    client: &deadpool_postgres::Object,
    resource_type: &str,
    id: &ConnectionId,
    from_version: Option<u64>,
    to_version: u64,
) -> Result<(), ConnectionStoreError> {
    let from = match from_version {
        Some(version) => u64_to_i64(id, version)?,
        None => 0,
    };
    let to = u64_to_i64(id, to_version)?;
    let revision_row = client
        .query_one(
            r#"
            UPDATE greengateway.security_revision_state
            SET last_revision = last_revision + 1
            WHERE singleton
            RETURNING last_revision
            "#,
            &[],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    let security_revision: i64 = scalar(&revision_row, 0, OPERATION_CREATE)?;
    // The connections high-water mark is SET to the shared revision this
    // transaction just took, never incremented on its own.
    //
    // `ConnectionsResource::activation_revision` returns this value and the
    // gate compares it against `ClusterSecurityRuntime`'s compiled
    // watermark, which tracks the shared counter that policy and tools
    // commits also advance. A private per-resource counter would therefore
    // drift permanently below that watermark, `activation > compiled` would
    // stop being true, and connection commits would silently stop
    // triggering reconciliation on every replica -- the exact stale-allow
    // the gate exists to prevent. Policy and tools avoid this by recording
    // the shared revision on the document itself; connections record it
    // here.
    client
        .execute(
            r#"
            UPDATE greengateway.connection_state_revision
            SET last_revision = $1
            WHERE singleton
            "#,
            &[&security_revision],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    client
        .execute(
            r#"
            INSERT INTO greengateway.security_outbox (
                revision, resource_type, from_version, to_version, resource_id
            ) VALUES ($1, $2, $3, $4, $5::text)
            "#,
            &[&security_revision, &resource_type, &from, &to, &id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    Ok(())
}

/// Open a mutating transaction: `BEGIN`, then immediately take the one
/// lock that serializes connection mutations.
///
/// Every mutating path goes through this, so no capacity check can be
/// written that runs outside the lock.
async fn begin_mutation(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    client
        .batch_execute("BEGIN")
        .await
        .map_err(|error| pg_error(operation, error))?;
    if let Err(error) = lock_connection_state(client, operation).await {
        // The transaction is already open; close it before handing the
        // connection back to the pool.
        let _ = client.batch_execute("ROLLBACK").await;
        return Err(error);
    }
    Ok(())
}

/// The serializing lock every mutating connection transaction takes
/// FIRST, before its first global aggregate read.
///
/// PostgreSQL runs these transactions at READ COMMITTED, where a
/// `COUNT(*)` taken before an INSERT is only a hint: two transactions can
/// both read `maximum - 1` and both insert, and the bound is exceeded.
/// The SQLite reference store cannot do that -- every mutation opens with
/// `TransactionBehavior::Immediate`, which takes the database write lock
/// *before* the first count, so the count is authoritative
/// (store.rs `create`, `add_dependency`, `replace_dependencies_for_kind`,
/// the catalog replacements). `SELECT ... FOR UPDATE` on the record row
/// is not equivalent: it serializes writers on one connection, not
/// writers against the *global* aggregates (record count, binding count,
/// catalog entries and bytes, dependency count) that those checks read.
///
/// `connection_state_revision` is a single row, so locking it is exactly
/// SQLite's write lock: every mutating connection transaction is
/// serialized against every other one, counts included. It is the row
/// `bump_connection_state` already advances, so no mutating path pays for
/// a lock it did not already need.
///
/// Lock order -- identical in every mutating path, which is what makes a
/// deadlock between two of them impossible:
///
/// 1. `greengateway.connection_state_revision` (this singleton row),
/// 2. the `greengateway.connection_records` row, under the existing
///    `SELECT ... FOR UPDATE`,
/// 3. `greengateway.security_revision_state` (the singleton
///    `bump_connection_state` updates last).
///
/// Readers take none of these -- they use a `REPEATABLE READ` snapshot
/// instead (see `begin_snapshot`) -- and `remove_dependency` takes none
/// because deleting a row cannot exceed a bound; the SQLite store
/// likewise runs `remove_dependency` outside a transaction.
async fn lock_connection_state(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    let locked = client
        .query_opt(
            "SELECT last_revision FROM greengateway.connection_state_revision \
             WHERE singleton FOR UPDATE",
            &[],
        )
        .await
        .map_err(|error| pg_error(operation, error))?;
    if locked.is_none() {
        return Err(ConnectionStoreError::CorruptRecord {
            id: "<connection-state>".to_owned(),
            reason: "the connection state revision row is missing",
        });
    }
    Ok(())
}

/// Open a reader's transaction.
///
/// `REPEATABLE READ` gives every statement in the reader one snapshot,
/// which is what the SQLite store gets for free: `list` and `get` read
/// the record and validate its credential bindings inside a single
/// transaction (store.rs `list`/`get`, pinned by
/// `record_and_bindings_are_read_from_one_wal_snapshot`), and the catalog
/// and dependency readers hold the store's connection mutex across their
/// header and child queries. Issued separately under READ COMMITTED, a
/// concurrent commit landing between the two queries makes a healthy
/// record read as corrupt -- a spurious fail-closed on live data.
async fn begin_snapshot(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    client
        .batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .await
        .map_err(|error| pg_error(operation, error))
}

/// Close a reader's snapshot: commit on success, roll back on failure so
/// an aborted read never leaves an open transaction on a pooled
/// connection.
async fn finish_read<T>(
    client: &deadpool_postgres::Object,
    operation: &'static str,
    outcome: Result<T, ConnectionStoreError>,
) -> Result<T, ConnectionStoreError> {
    match outcome {
        Ok(value) => {
            commit(client, operation).await?;
            Ok(value)
        }
        Err(error) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}

async fn commit(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    client
        .batch_execute("COMMIT")
        .await
        .map_err(|error| pg_error(operation, error))
}

fn pg_unavailable(operation: &'static str) -> ConnectionStoreError {
    ConnectionStoreError::Postgres { operation }
}

/// Reserve a catalog lane's tool names at the authority inside the
/// caller's transaction, naming the holder on a conflict.
async fn reserve_catalog_tool_names(
    client: &tokio_postgres::Client,
    lane: &'static str,
    id: &ConnectionId,
    names: impl IntoIterator<Item = String>,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    postgres_tool_names::reserve_tool_names(client, lane, id.as_str(), names)
        .await
        .map_err(|error| match error {
            ToolNameReservationError::Taken {
                tool_name,
                lane,
                owner_id,
            } => ConnectionStoreError::ToolNameConflict {
                id: id.to_string(),
                tool_name,
                lane,
                owner_id,
            },
            ToolNameReservationError::Postgres(error) => pg_error(operation, error),
        })
}

fn pg_error(operation: &'static str, error: impl std::error::Error) -> ConnectionStoreError {
    tracing::error!(operation, error = %error, "connection PostgreSQL operation failed");
    ConnectionStoreError::Postgres { operation }
}

// ==== The standalone-to-cluster import (issue #241, PR 15, step 4) ====
//
// One Connection as a standalone deployment holds it, and the one write
// path that carries it across. It lives here, beside the store that owns
// these tables, for the reason `insert_imported_policy_versions_in` lives
// beside the policy store: an import writes the same rows a replica
// writes, and a second copy of that knowledge somewhere else would drift.
//
// What makes this path different from `create`/`replace`:
//
// - It NAMES the identifiers and the revisions. `create` mints a fresh
//   `ConnectionId` and starts every axis at its initial value; an import
//   must preserve both, because the `ConnectionEtag` an operator's
//   automation holds is derived from them and a Connection that changed
//   its ID is a different Connection.
// - Every insert is `ON CONFLICT DO NOTHING` on the natural key, so the
//   whole step is idempotent under `--resume`.
// - It takes ONE shared security revision for the whole step rather than
//   one per Connection, and writes NO outbox rows. The outbox is how a
//   RUNNING replica learns of a change; the import runs before any
//   replica serves this deployment, so there is nobody to notify, and a
//   stream of outbox rows describing an import would be replayed as a
//   change history the standalone deployment never had. The connections
//   high-water mark is still SET to the shared revision the step took --
//   the gate compares it against that same counter (see
//   `bump_connection_state`), and leaving it at zero while the counter had
//   moved would be a resource permanently behind its authority.
// - Credential bindings are derived from the record exactly as
//   `replace_bindings` derives them (`expected_bindings`): a purpose, a
//   SECRET ID and a version. The secret's VALUE is not in the standalone
//   database and is never read, moved or written by this path; the
//   operator's secret store keeps it, and a local-secret keyring stays
//   where it is (migration 0006 does not port `connection_local_secrets`,
//   and cluster mode refuses the configuration that would use one).

/// One standalone Connection and everything durable that hangs off it.
pub(crate) struct ImportedConnection {
    pub record: StoredConnection,
    pub activity: ConnectionActivityTimes,
    pub dependencies: Vec<ConnectionDependency>,
    pub current_status: Option<PersistedConnectionStatus>,
    /// Oldest first.
    pub status_history: Vec<PersistedConnectionStatus>,
    pub mcp_catalog: Option<StoredMcpCatalog>,
    pub openapi_catalog: Option<StoredOpenApiCatalog>,
    pub openapi_overlay: Option<StoredOpenApiOverlay>,
    pub enum_source_values: Vec<StoredEnumSourceValue>,
}

/// What one import step wrote, per table, for the section's report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ImportedConnectionCounts {
    pub records: i64,
    pub documents: i64,
    pub credential_bindings: i64,
    pub dependencies: i64,
    pub current_statuses: i64,
    pub status_history: i64,
    pub mcp_catalogs: i64,
    pub mcp_catalog_entries: i64,
    pub mcp_catalog_resources: i64,
    pub mcp_catalog_resource_templates: i64,
    pub openapi_catalogs: i64,
    pub openapi_catalog_entries: i64,
    pub openapi_overlays: i64,
    pub enum_source_values: i64,
    pub tool_name_reservations: i64,
    /// The one shared security revision the step took, or 0 when it had
    /// nothing to write.
    pub security_revision: i64,
}

/// Write `connections` into the caller's open transaction.
///
/// The caller owns the `BEGIN`/`COMMIT`: the import's Connections section
/// is one transaction, so a failure anywhere in it leaves the namespace
/// exactly as it was and `--resume` starts the section again.
pub(crate) async fn import_connections_in(
    client: &deadpool_postgres::Object,
    connections: &[ImportedConnection],
    actor_user_id: &str,
) -> Result<ImportedConnectionCounts, ConnectionStoreError> {
    const OPERATION: &str = "record_import";
    let mut counts = ImportedConnectionCounts::default();
    if connections.is_empty() {
        return Ok(counts);
    }
    // Lock order, identical to every other mutating path in this file:
    // the singleton first, then the record rows, then the shared security
    // counter (see `lock_connection_state`).
    lock_connection_state(client, OPERATION).await?;

    for connection in connections {
        let record = &connection.record;
        let id = &record.id;
        match (
            connection.openapi_catalog.as_ref(),
            connection.openapi_overlay.as_ref(),
        ) {
            (Some(catalog), Some(overlay))
                if catalog.overlay_revision == overlay.overlay_revision => {}
            (Some(catalog), None) if catalog.overlay_revision == 0 => {}
            (None, None) => {}
            _ => {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![format!(
                        "imported OpenAPI catalog and overlay revisions do not agree for '{id}'"
                    )],
                });
            }
        }
        let overlay_revision = connection
            .openapi_overlay
            .as_ref()
            .map_or(0, |overlay| overlay.overlay_revision);
        if connection.enum_source_values.len() > MAX_OPENAPI_ENUM_SOURCES {
            return Err(ConnectionStoreError::LimitExceeded {
                resource: "connection enum source values",
                maximum: MAX_OPENAPI_ENUM_SOURCES,
            });
        }
        let mut enum_source_ids = BTreeSet::new();
        for row in &connection.enum_source_values {
            if row.connection_id != *id
                || row.overlay_revision != overlay_revision
                || row.connection_revision > record.revisions.connection
                || row.credential_revision > record.revisions.credential
                || !enum_source_ids.insert(row.source_id.as_str())
            {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![format!(
                        "imported enum source values do not match Connection '{id}'"
                    )],
                });
            }
            encode_enum_source_values(&StoredEnumSourceValueWrite {
                connection_id: row.connection_id.clone(),
                source_id: row.source_id.clone(),
                overlay_revision: row.overlay_revision,
                source_digest: row.source_digest.clone(),
                expected_values_revision: row.values_revision,
                connection_revision: row.connection_revision,
                credential_revision: row.credential_revision,
                credential_generation_digest: row.credential_generation_digest.clone(),
                values: row.values.clone(),
                labels: row.labels.clone(),
                resolved_at: row.resolved_at.clone(),
            })?;
        }
        // The PostgreSQL key column is `uuid` and the managed store only
        // ever mints UUIDs (`ConnectionId::new_managed`). A source row
        // that carries anything else is refused by name here rather than
        // as an opaque cast failure three statements later.
        id_uuid(id)?;
        let spec_json =
            serde_json::to_string(&record.write).map_err(|source| ConnectionStoreError::Json {
                operation: "imported connection specification",
                source,
            })?;
        counts.records += i64::try_from(
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_records (
                        id, schema_version, source, spec_json, connection_revision,
                        credential_revision, tls_revision, discovery_revision,
                        status_revision, created_at, updated_at, last_test_at,
                        last_refresh_at
                    ) VALUES (
                        $1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
                    )
                    ON CONFLICT (id) DO NOTHING
                    "#,
                    &[
                        &id.as_str(),
                        &super::model::CONNECTION_SCHEMA_VERSION,
                        &SOURCE_MANAGED,
                        &spec_json,
                        &u64_to_i64(id, record.revisions.connection)?,
                        &u64_to_i64(id, record.revisions.credential)?,
                        &u64_to_i64(id, record.revisions.tls)?,
                        &u64_to_i64(id, record.revisions.discovery)?,
                        &u64_to_i64(id, record.revisions.status)?,
                        &record.created_at,
                        &record.updated_at,
                        &connection.activity.last_test_at,
                        &connection.activity.last_refresh_at,
                    ],
                )
                .await
                .map_err(|error| pg_error(OPERATION, error))?,
        )
        .unwrap_or(i64::MAX);

        // One immutable specification version, numbered by the record's
        // own connection revision, so the version chain a cluster reads
        // back is the one the standalone deployment had reached. The
        // versions BELOW it are not in the standalone database at all --
        // the SQLite store keeps only the active specification -- so the
        // chain begins where the source's history ends rather than being
        // invented.
        counts.documents += i64::try_from(
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_documents (
                        connection_id, version, spec, document_etag, actor_user_id, diff_summary
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6::text::jsonb)
                    ON CONFLICT (connection_id, version) DO NOTHING
                    "#,
                    &[
                        &id.as_str(),
                        &u64_to_i64(id, record.revisions.connection)?,
                        &spec_json,
                        &version_document_etag(id, record.revisions.connection, &spec_json)?,
                        &actor_user_id,
                        &IMPORT_DIFF_SUMMARY,
                    ],
                )
                .await
                .map_err(|error| pg_error(OPERATION, error))?,
        )
        .unwrap_or(i64::MAX);

        for binding in expected_bindings(&record.write, &record.revisions) {
            counts.credential_bindings += i64::try_from(
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_credential_bindings (
                            connection_id, purpose, header_name, secret_id, binding_version, updated_at
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6)
                        ON CONFLICT (connection_id, purpose, header_name) DO NOTHING
                        "#,
                        &[
                            &id.as_str(),
                            &binding.purpose,
                            &binding.header_name,
                            &binding.secret_id,
                            &u64_to_i64(id, binding.version.max(1))?,
                            &record.updated_at,
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION, error))?,
            )
            .unwrap_or(i64::MAX);
        }

        for dependency in &connection.dependencies {
            // `source_revision` 0, per the state model: a dependency set
            // carried across is not one this deployment's tools or policy
            // documents derived, so it claims no revision and the first
            // replica flush that does derive one supersedes it. The
            // `created_at` is the record's, because the source's own
            // reader (`SqliteConnectionStore::dependencies`) does not
            // expose the column and no reader anywhere reads it back.
            counts.dependencies += i64::try_from(
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_dependencies (
                            connection_id, consumer_kind, consumer_id, created_at, source_revision
                        ) VALUES ($1::text::uuid, $2, $3, $4, 0)
                        ON CONFLICT (connection_id, consumer_kind, consumer_id) DO NOTHING
                        "#,
                        &[
                            &id.as_str(),
                            &dependency.kind.as_str(),
                            &dependency.consumer_id,
                            &record.updated_at,
                        ],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION, error))?,
            )
            .unwrap_or(i64::MAX);
        }

        if let Some(status) = connection.current_status.as_ref() {
            counts.current_statuses += i64::try_from(
                insert_status_row(
                    client,
                    INSERT_IMPORTED_CURRENT_STATUS_SQL,
                    status,
                    OPERATION,
                )
                .await?,
            )
            .unwrap_or(i64::MAX);
        }

        for status in &connection.status_history {
            counts.status_history += i64::try_from(
                insert_status_row(
                    client,
                    INSERT_IMPORTED_STATUS_HISTORY_SQL,
                    status,
                    OPERATION,
                )
                .await?,
            )
            .unwrap_or(i64::MAX);
        }

        if let Some(catalog) = connection.mcp_catalog.as_ref() {
            import_mcp_catalog(client, id, catalog, actor_user_id, &mut counts, OPERATION).await?;
        }
        if let Some(overlay) = connection.openapi_overlay.as_ref() {
            import_openapi_overlay(client, id, overlay, actor_user_id, &mut counts, OPERATION)
                .await?;
        }
        if let Some(catalog) = connection.openapi_catalog.as_ref() {
            import_openapi_catalog(client, id, catalog, actor_user_id, &mut counts, OPERATION)
                .await?;
        }
        import_enum_source_values(
            client,
            id,
            &connection.enum_source_values,
            &mut counts,
            OPERATION,
        )
        .await?;
    }

    // The catalog lanes' names at the authority. `reserve_tool_names`
    // replaces the owner's own rows, so a resumed run re-reserves exactly
    // what it reserved before; a name another lane already holds refuses
    // the section rather than leaving a conflict no replica can install.
    for connection in connections {
        let id = &connection.record.id;
        if let Some(catalog) = connection.mcp_catalog.as_ref() {
            let names: Vec<String> = catalog
                .entries
                .iter()
                .map(|entry| format!("{}:{}", id.as_str(), entry.remote_tool_name))
                .collect();
            counts.tool_name_reservations += i64::try_from(names.len()).unwrap_or(i64::MAX);
            reserve_catalog_tool_names(client, postgres_tool_names::LANE_MCP, id, names, OPERATION)
                .await?;
        }
        if let Some(catalog) = connection.openapi_catalog.as_ref() {
            let names: Vec<String> = catalog
                .entries
                .iter()
                .map(|entry| entry.tool_name.clone())
                .collect();
            counts.tool_name_reservations += i64::try_from(names.len()).unwrap_or(i64::MAX);
            reserve_catalog_tool_names(
                client,
                postgres_tool_names::LANE_OPENAPI,
                id,
                names,
                OPERATION,
            )
            .await?;
        }
    }

    // One shared revision for the whole step; see the note above this
    // function for why it is one and why no outbox row accompanies it.
    let revision_row = client
        .query_one(
            r#"
            UPDATE greengateway.security_revision_state
            SET last_revision = last_revision + 1
            WHERE singleton
            RETURNING last_revision
            "#,
            &[],
        )
        .await
        .map_err(|error| pg_error(OPERATION, error))?;
    let security_revision: i64 = scalar(&revision_row, 0, OPERATION)?;
    client
        .execute(
            "UPDATE greengateway.connection_state_revision SET last_revision = $1 WHERE singleton",
            &[&security_revision],
        )
        .await
        .map_err(|error| pg_error(OPERATION, error))?;
    counts.security_revision = security_revision;
    Ok(counts)
}

/// The diff summary every imported specification version carries. A
/// history reader must be able to tell a version an import wrote from one
/// an administrator committed; the actor says who, this says why.
const IMPORT_DIFF_SUMMARY: &str = r#"{"action":"imported_from_standalone"}"#;

const INSERT_IMPORTED_CURRENT_STATUS_SQL: &str = r#"
INSERT INTO greengateway.connection_current_status (
    connection_id, status_revision, observed_connection_revision,
    observed_credential_revision, observed_tls_revision,
    observed_discovery_revision, state, reason, observed_at,
    latency_ms, catalog_age_secs, catalog_entry_count
) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (connection_id) DO NOTHING
"#;

/// `sequence` is generated, so a history row's natural key is
/// (connection_id, status_revision) -- the unique index migration 0006
/// creates for exactly that reason, and what makes a resumed import's
/// second pass write nothing.
const INSERT_IMPORTED_STATUS_HISTORY_SQL: &str = r#"
INSERT INTO greengateway.connection_status_history (
    connection_id, status_revision, observed_connection_revision,
    observed_credential_revision, observed_tls_revision,
    observed_discovery_revision, state, reason, observed_at,
    latency_ms, catalog_age_secs, catalog_entry_count
) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (connection_id, status_revision) DO NOTHING
"#;

/// Write one status row verbatim. Both tables take the same twelve
/// columns in the same order, so `sql` selects the table and nothing else.
/// The observation's own `catalog_age_secs` is bound as persisted, NOT as
/// the safe projection ages it (store.rs `RawStatus::into_safe_status`
/// adds the time since the observation to every read).
async fn insert_status_row(
    client: &deadpool_postgres::Object,
    sql: &'static str,
    status: &PersistedConnectionStatus,
    operation: &'static str,
) -> Result<u64, ConnectionStoreError> {
    let id = &status.connection_id;
    let status_revision = u64_to_i64(id, status.status_revision)?;
    let observed_connection = u64_to_i64(id, status.observed_connection_revision)?;
    let observed_credential = u64_to_i64(id, status.observed_credential_revision)?;
    let observed_tls = u64_to_i64(id, status.observed_tls_revision)?;
    let observed_discovery = u64_to_i64(id, status.observed_discovery_revision)?;
    let latency_ms = optional_u64_to_i64(status.latency_ms, "status latency")?;
    let catalog_age_secs = optional_u64_to_i64(status.catalog_age_secs, "status catalog age")?;
    let catalog_entry_count =
        optional_u64_to_i64(status.catalog_entry_count, "status catalog entry count")?;
    client
        .execute(
            sql,
            &[
                &id.as_str(),
                &status_revision,
                &observed_connection,
                &observed_credential,
                &observed_tls,
                &observed_discovery,
                &state_as_str(status.state),
                &reason_as_str(status.reason),
                &status.observed_at,
                &latency_ms,
                &catalog_age_secs,
                &catalog_entry_count,
            ],
        )
        .await
        .map_err(|error| pg_error(operation, error))
}

async fn import_mcp_catalog(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    catalog: &StoredMcpCatalog,
    actor_user_id: &str,
    counts: &mut ImportedConnectionCounts,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    // The catalog is re-validated on the way in, by the same validator the
    // live replacement path runs: a catalog this build cannot validate is
    // one no replica could serve, and it must refuse the import rather
    // than land in the authority.
    let validated = validate_mcp_catalog(
        id,
        &catalog.entries,
        &catalog.resources,
        &catalog.resource_templates,
    )?;
    counts.mcp_catalogs += i64::try_from(
        client
            .execute(
                r#"
                INSERT INTO greengateway.connection_mcp_catalogs (
                    connection_id, catalog_revision, observed_etag, refreshed_at, entry_count,
                    resource_count, resource_template_count, actor_user_id
                ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (connection_id) DO NOTHING
                "#,
                &[
                    &id.as_str(),
                    &u64_to_i64(id, catalog.catalog_revision)?,
                    &catalog.observed_etag.as_str(),
                    &catalog.refreshed_at,
                    &usize_to_i64(catalog.entries.len()),
                    &usize_to_i64(catalog.resources.len()),
                    &usize_to_i64(catalog.resource_templates.len()),
                    &actor_user_id,
                ],
            )
            .await
            .map_err(|error| pg_error(operation, error))?,
    )
    .unwrap_or(i64::MAX);
    for (ordinal, ((entry, input_schema_json), annotations_json)) in catalog
        .entries
        .iter()
        .zip(validated.encoded_tool_schemas.iter())
        .zip(validated.encoded_tool_annotations.iter())
        .enumerate()
    {
        counts.mcp_catalog_entries += i64::try_from(
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_mcp_catalog_entries (
                        connection_id, remote_tool_name, title, description,
                        input_schema_json, annotations_json, ordinal
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (connection_id, remote_tool_name) DO NOTHING
                    "#,
                    &[
                        &id.as_str(),
                        &entry.remote_tool_name,
                        &entry.title,
                        &entry.description,
                        input_schema_json,
                        annotations_json,
                        &usize_to_i64(ordinal),
                    ],
                )
                .await
                .map_err(|error| pg_error(operation, error))?,
        )
        .unwrap_or(i64::MAX);
    }
    for (ordinal, resource) in catalog.resources.iter().enumerate() {
        counts.mcp_catalog_resources += i64::try_from(
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_mcp_catalog_resources (
                        connection_id, uri, name, title, description, mime_type, size, ordinal
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (connection_id, uri) DO NOTHING
                    "#,
                    &[
                        &id.as_str(),
                        &resource.uri,
                        &resource.name,
                        &resource.title,
                        &resource.description,
                        &resource.mime_type,
                        &optional_u64_to_i64(resource.size, "MCP resource size")?,
                        &usize_to_i64(ordinal),
                    ],
                )
                .await
                .map_err(|error| pg_error(operation, error))?,
        )
        .unwrap_or(i64::MAX);
    }
    for (ordinal, template) in catalog.resource_templates.iter().enumerate() {
        counts.mcp_catalog_resource_templates += i64::try_from(
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_mcp_catalog_resource_templates (
                        connection_id, uri_template, name, title, description, mime_type, ordinal
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (connection_id, uri_template) DO NOTHING
                    "#,
                    &[
                        &id.as_str(),
                        &template.uri_template,
                        &template.name,
                        &template.title,
                        &template.description,
                        &template.mime_type,
                        &usize_to_i64(ordinal),
                    ],
                )
                .await
                .map_err(|error| pg_error(operation, error))?,
        )
        .unwrap_or(i64::MAX);
    }
    Ok(())
}

async fn import_openapi_catalog(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    catalog: &StoredOpenApiCatalog,
    actor_user_id: &str,
    counts: &mut ImportedConnectionCounts,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    validate_openapi_spec(&catalog.spec, &catalog.spec_digest)?;
    let encoded_entries = validate_openapi_catalog_entries(&catalog.entries)?;
    counts.openapi_catalogs += i64::try_from(
        client
            .execute(
                r#"
                INSERT INTO greengateway.connection_openapi_catalogs (
                    connection_id, spec_revision, catalog_revision, observed_etag,
                    spec_digest, spec, refreshed_at, entry_count, actor_user_id,
                    overlay_revision
                ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (connection_id) DO NOTHING
                "#,
                &[
                    &id.as_str(),
                    &u64_to_i64(id, catalog.spec_revision)?,
                    &u64_to_i64(id, catalog.catalog_revision)?,
                    &catalog.observed_etag.as_str(),
                    &catalog.spec_digest,
                    &catalog.spec,
                    &catalog.refreshed_at,
                    &usize_to_i64(catalog.entries.len()),
                    &actor_user_id,
                    &u64_to_i64(id, catalog.overlay_revision)?,
                ],
            )
            .await
            .map_err(|error| pg_error(operation, error))?,
    )
    .unwrap_or(i64::MAX);
    for (ordinal, encoded) in encoded_entries.iter().enumerate() {
        counts.openapi_catalog_entries += i64::try_from(
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_openapi_catalog_entries (
                        connection_id, tool_name, operation_id,
                        selected_scheme_names_json, definition_json, ordinal
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6)
                    ON CONFLICT (connection_id, tool_name) DO NOTHING
                    "#,
                    &[
                        &id.as_str(),
                        &encoded.entry.tool_name,
                        &encoded.entry.operation_id,
                        &encoded.selected_scheme_names_json,
                        &encoded.definition_json,
                        &usize_to_i64(ordinal),
                    ],
                )
                .await
                .map_err(|error| pg_error(operation, error))?,
        )
        .unwrap_or(i64::MAX);
    }
    Ok(())
}

async fn import_openapi_overlay(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    overlay: &StoredOpenApiOverlay,
    actor_user_id: &str,
    counts: &mut ImportedConnectionCounts,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    if overlay.connection_id != *id {
        return Err(ConnectionStoreError::Validation {
            problems: vec!["imported OpenAPI overlay belongs to another Connection".to_owned()],
        });
    }
    validate_openapi_overlay_write(&StoredOverlayWrite::Put {
        schema_version: overlay.schema_version.clone(),
        overlay_json: overlay.overlay_json.clone(),
        source_reports_json: overlay.source_reports_json.clone().unwrap_or_else(|| {
            StoredOpenApiSourceReports::empty()
                .canonical_json()
                .expect("the fixed empty source report snapshot serializes")
        }),
        expected_overlay_revision: 0,
    })?;
    counts.openapi_overlays += i64::try_from(
        client
            .execute(
                r#"
                INSERT INTO greengateway.connection_openapi_overlays (
                    connection_id, schema_version, overlay_revision, overlay_json,
                    source_reports_json, actor_user_id, updated_at
                ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (connection_id) DO NOTHING
                "#,
                &[
                    &id.as_str(),
                    &overlay.schema_version,
                    &u64_to_i64(id, overlay.overlay_revision)?,
                    &overlay.overlay_json,
                    &overlay.source_reports_json,
                    &actor_user_id,
                    &overlay.updated_at,
                ],
            )
            .await
            .map_err(|error| pg_error(operation, error))?,
    )
    .unwrap_or(i64::MAX);
    Ok(())
}

async fn import_enum_source_values(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    rows: &[StoredEnumSourceValue],
    counts: &mut ImportedConnectionCounts,
    operation: &'static str,
) -> Result<(), ConnectionStoreError> {
    for row in rows {
        let values_json = encode_enum_source_values(&StoredEnumSourceValueWrite {
            connection_id: row.connection_id.clone(),
            source_id: row.source_id.clone(),
            overlay_revision: row.overlay_revision,
            source_digest: row.source_digest.clone(),
            expected_values_revision: row.values_revision,
            connection_revision: row.connection_revision,
            credential_revision: row.credential_revision,
            credential_generation_digest: row.credential_generation_digest.clone(),
            values: row.values.clone(),
            labels: row.labels.clone(),
            resolved_at: row.resolved_at.clone(),
        })?;
        let overlay_revision = u64_to_i64(id, row.overlay_revision)?;
        let values_revision = u64_to_i64(id, row.values_revision)?;
        let connection_revision = u64_to_i64(id, row.connection_revision)?;
        let credential_revision = u64_to_i64(id, row.credential_revision)?;
        counts.enum_source_values += i64::try_from(
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_enum_source_values (
                        connection_id, source_id, overlay_revision, source_digest,
                        values_revision, connection_revision, credential_revision,
                        credential_generation_digest, values_json, resolved_at
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (connection_id, source_id) DO NOTHING
                    "#,
                    &[
                        &id.as_str(),
                        &row.source_id,
                        &overlay_revision,
                        &row.source_digest,
                        &values_revision,
                        &connection_revision,
                        &credential_revision,
                        &row.credential_generation_digest,
                        &values_json,
                        &row.resolved_at,
                    ],
                )
                .await
                .map_err(|error| pg_error(operation, error))?,
        )
        .unwrap_or(i64::MAX);
    }
    Ok(())
}

// Referenced types kept for the future snapshot reconciler.
#[allow(dead_code)]
type ConnectionSnapshot = BTreeMap<ConnectionId, StoredConnection>;

#[cfg(test)]
#[path = "pg_store_tests.rs"]
mod tests;
