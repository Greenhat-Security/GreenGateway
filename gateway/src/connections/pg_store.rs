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

use crate::storage::postgres_tool_names::{self, ToolNameReservationError};

use super::store::{
    binding_count, ensure_etag, expected_bindings, increment_revision, initial_revisions,
    managed_tool_dependency_id, optional_i64_to_u64, optional_u64_to_i64, parse_reason,
    parse_state, persisted_revision, reason_as_str, replacement_revisions, revision_from_i64,
    state_as_str, supports_managed_mcp_catalog, supports_managed_openapi_catalog, u64_to_i64,
    utc_timestamp, validate_activity_timestamp, validate_candidate, validate_dependency_id,
    validate_mcp_catalog, validate_openapi_catalog_entries, validate_openapi_spec,
    ConnectionActivityTimes, ConnectionDependency, ConnectionDependencyKind, ConnectionEtag,
    ConnectionStatusUpdate, ConnectionStoreError, ExportedConnectionStatuses,
    PersistedConnectionStatus, StoredConnection, StoredMcpCatalog, StoredMcpCatalogEntry,
    StoredMcpResource, StoredMcpResourceTemplate, StoredOpenApiCatalog, StoredOpenApiCatalogEntry,
    StoredOpenApiInventoryCatalog, MAX_CONNECTION_DEPENDENCIES, SOURCE_MANAGED,
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

            for (ordinal, (entry, input_schema_json)) in entries
                .iter()
                .zip(validated.encoded_tool_schemas.iter())
                .enumerate()
            {
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_mcp_catalog_entries (
                            connection_id, remote_tool_name, description, input_schema_json, ordinal
                        ) VALUES ($1::text::uuid, $2, $3, $4, $5)
                        "#,
                        &[
                            &id.as_str(),
                            &entry.remote_tool_name,
                            &entry.description,
                            &input_schema_json,
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
        validate_openapi_spec(spec, spec_digest)?;
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
            let current = load_record_for_update(&client, id, OPERATION_OPENAPI_CATALOG)
                .await?
                .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
            validate_bindings(&client, &current).await?;
            ensure_etag(id, expected_connection_etag, &current)?;
            if !supports_managed_openapi_catalog(&current.write) {
                return Err(ConnectionStoreError::Validation {
                    problems: vec![
                        "OpenAPI catalogs require a managed HTTP API OpenAPI Connection".to_owned(),
                    ],
                });
            }

            let previous = client
                .query_opt(
                    r#"
                    SELECT spec_revision, catalog_revision, spec_digest
                    FROM greengateway.connection_openapi_catalogs
                    WHERE connection_id = $1::text::uuid
                    "#,
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
            let (previous_spec_revision, previous_catalog_revision, previous_digest) =
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
                        )
                    }
                    None => (0, 0, None),
                };
            if expected_spec_revision != previous_spec_revision
                || expected_catalog_revision != previous_catalog_revision
            {
                return Err(ConnectionStoreError::Conflict {
                    id: id.to_string(),
                    current: current.etag(),
                });
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
                     FROM greengateway.connection_openapi_catalog_entries)
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
               + octet_length(description)
               + octet_length(input_schema_json)
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
                       spec_digest, spec, refreshed_at, entry_count
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
                       spec_digest, spec, refreshed_at, entry_count
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
            SELECT remote_tool_name, description, input_schema_json, ordinal
            FROM greengateway.connection_mcp_catalog_entries
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_MCP_READ, error))?;
    const REASON: &str = "MCP catalog entry column does not decode as its schema type";
    ensure_contiguous_ordinals(&rows, 3, id, "MCP catalog entries")?;
    rows.iter()
        .map(|row| {
            let input_schema: Value =
                serde_json::from_str(&column::<String>(row, 2, id.as_str(), REASON)?)
                    .map_err(|_| corrupt(id, "MCP catalog entry schema is not valid JSON"))?;
            Ok(StoredMcpCatalogEntry {
                remote_tool_name: column(row, 0, id.as_str(), REASON)?,
                description: column(row, 1, id.as_str(), REASON)?,
                input_schema,
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
        if let Some(catalog) = connection.openapi_catalog.as_ref() {
            import_openapi_catalog(client, id, catalog, actor_user_id, &mut counts, OPERATION)
                .await?;
        }
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
    for (ordinal, (entry, input_schema_json)) in catalog
        .entries
        .iter()
        .zip(validated.encoded_tool_schemas.iter())
        .enumerate()
    {
        counts.mcp_catalog_entries += i64::try_from(
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.connection_mcp_catalog_entries (
                        connection_id, remote_tool_name, description, input_schema_json, ordinal
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5)
                    ON CONFLICT (connection_id, remote_tool_name) DO NOTHING
                    "#,
                    &[
                        &id.as_str(),
                        &entry.remote_tool_name,
                        &entry.description,
                        input_schema_json,
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
                    spec_digest, spec, refreshed_at, entry_count, actor_user_id
                ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
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

// Referenced types kept for the future snapshot reconciler.
#[allow(dead_code)]
type ConnectionSnapshot = BTreeMap<ConnectionId, StoredConnection>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::status::ConnectionOperationalState;
    use crate::storage::postgres::PostgresFoundation;
    use serde_json::json;

    fn locator() -> Option<String> {
        let key = "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned();
        let file = std::env::var(&key).ok()?;
        if file.trim().is_empty() {
            return None;
        }
        let contents = std::fs::read_to_string(file).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    struct DsnFile {
        path: String,
        directory: std::path::PathBuf,
    }

    impl Drop for DsnFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn write_dsn_file(dsn: &str) -> DsnFile {
        let directory =
            std::env::temp_dir().join(format!("greengateway-conn-pg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("temp directory should create");
        let path = directory.join("database-url");
        std::fs::write(&path, format!("{dsn}\n")).expect("DSN file should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("DSN permissions should set");
        }
        DsnFile {
            path: path.display().to_string(),
            directory,
        }
    }

    struct TestDatabase {
        dsn: String,
        admin_dsn: String,
        name: String,
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let admin_dsn = self.admin_dsn.clone();
            let name = self.name.clone();
            std::thread::spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let Ok((client, connection)) =
                        tokio_postgres::connect(&admin_dsn, tokio_postgres::NoTls).await
                    else {
                        return;
                    };
                    let connection = tokio::spawn(connection);
                    let _ = client
                        .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                        .await;
                    let _ = connection.await;
                });
            });
        }
    }

    async fn create_test_database(admin_dsn: &str) -> TestDatabase {
        let name = format!("ggw_conn_test_{}", uuid::Uuid::new_v4().simple());
        let (client, connection) = tokio_postgres::connect(admin_dsn, tokio_postgres::NoTls)
            .await
            .expect("admin connection");
        let connection_task = tokio::spawn(connection);
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .expect("test database should create");
        drop(client);
        let _ = connection_task.await;
        let database_start = admin_dsn
            .rfind('/')
            .expect("locator DSN has a database path segment");
        let dsn = format!("{}/{}", &admin_dsn[..database_start], name);
        TestDatabase {
            dsn,
            admin_dsn: admin_dsn.to_owned(),
            name,
        }
    }

    async fn migrated_store(
        dsn: &str,
        maximum: usize,
    ) -> (PostgresConnectionStore, deadpool_postgres::Pool) {
        let dsn_file = write_dsn_file(dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-conn-pg".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("test database should establish");
        crate::storage::migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("schema should migrate");
        let pool = foundation.pool().clone();
        (
            PostgresConnectionStore::new(pool.clone(), maximum)
                .expect("the test maximum is within the hard ceiling"),
            pool,
        )
    }

    fn http_candidate(display_name: &str) -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": display_name,
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

    async fn count(pool: &deadpool_postgres::Pool, sql: &str) -> i64 {
        pool.get()
            .await
            .expect("count checkout")
            .query_one(sql, &[])
            .await
            .expect("count query")
            .get(0)
    }

    /// An etag that cannot match any live record: fabricated revisions no
    /// committed write could produce.
    fn fabricated_stale_etag(id: &ConnectionId) -> ConnectionEtag {
        ConnectionEtag::for_record(
            id,
            &ConnectionRevisions {
                connection: 999,
                credential: 999,
                tls: 999,
                discovery: 999,
                status: 999,
            },
        )
    }

    #[tokio::test]
    async fn records_create_replace_delete_with_cas_and_shared_state_bumps() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;

        let security_before = count(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
        )
        .await;
        let state_before = store.state_revision().await.expect("state revision");

        // Create: revision-1 record, one binding row (the bearer secret),
        // one immutable document version, one outbox row identifying the
        // connection, and both revision counters advanced.
        let created = store
            .create(http_candidate("Billing API"), "op-1", None)
            .await
            .expect("create should commit");
        assert_eq!(created.revisions.connection, 1);
        assert_eq!(created.revisions.credential, 1, "a secret is bound");
        let stored = store.get(&created.id).await.expect("get").expect("exists");
        assert_eq!(stored.write.display_name, "Billing API");
        assert_eq!(store.count().await.expect("count"), 1);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_credential_bindings"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_documents"
            )
            .await,
            1,
            "the create wrote the immutable version"
        );
        assert_eq!(
            count(
                &pool,
                &format!(
                    "SELECT COUNT(*) FROM greengateway.security_outbox \
                     WHERE resource_type = 'connection' AND resource_id = '{}'",
                    created.id.as_str()
                )
            )
            .await,
            1
        );
        let security_after = count(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
        )
        .await;
        assert!(
            security_after > security_before,
            "the security revision advanced"
        );
        assert!(
            store.state_revision().await.expect("state") > state_before,
            "the connections high-water mark advanced"
        );

        // Replace with the current etag wins; a fabricated stale etag
        // loses with Conflict and writes nothing.
        let stale_etag = fabricated_stale_etag(&created.id);
        // The etag of the CURRENT record is the precondition; use the
        // current one to win and a fabricated stale one to lose.
        let current_etag = store
            .get(&created.id)
            .await
            .expect("get")
            .expect("exists")
            .etag();
        let winner_candidate = http_candidate("Renamed API");
        let replaced = store
            .replace(&created.id, &current_etag, winner_candidate, "op-3")
            .await
            .expect("replace should win");
        assert_eq!(replaced.revisions.connection, 2);
        assert_eq!(
            replaced.revisions.credential, 1,
            "the authentication axis is unchanged"
        );

        // An identical candidate is a committed no-op.
        let identical_etag = replaced.etag();
        let no_op = store
            .replace(
                &created.id,
                &identical_etag,
                http_candidate("Renamed API"),
                "op-4",
            )
            .await
            .expect("identical replace is a no-op");
        assert_eq!(
            no_op.etag(),
            identical_etag,
            "the no-op returns the record unchanged"
        );

        // A stale etag loses with Conflict and writes nothing.
        let lost = store
            .replace(&created.id, &stale_etag, http_candidate("Loser"), "op-5")
            .await
            .expect_err("the stale etag must lose");
        assert!(
            matches!(lost, ConnectionStoreError::Conflict { .. }),
            "{lost}"
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_documents"
            )
            .await,
            2,
            "only the create and the winning replace wrote versions"
        );

        // Delete: a dependency row blocks it; without one it cascades.
        let etag = store
            .get(&created.id)
            .await
            .expect("get")
            .expect("exists")
            .etag();
        pool.get()
            .await
            .expect("dep checkout")
            .execute(
                "INSERT INTO greengateway.connection_dependencies \
                 (connection_id, consumer_kind, consumer_id, created_at) \
                 VALUES ($1::text::uuid, 'proxy_route', 'route-a', '2026-01-01T00:00:00Z')",
                &[&created.id.as_str()],
            )
            .await
            .expect("dependency insert");
        let blocked = store
            .delete(&created.id, &etag, "op-6")
            .await
            .expect_err("a referenced connection must not delete");
        assert!(
            matches!(blocked, ConnectionStoreError::DependencyConflict { .. }),
            "{blocked}"
        );
        pool.get()
            .await
            .expect("dep checkout")
            .execute("DELETE FROM greengateway.connection_dependencies", &[])
            .await
            .expect("dependency cleanup");
        store
            .delete(&created.id, &etag, "op-7")
            .await
            .expect("delete should commit");
        assert_eq!(store.count().await.expect("count"), 0);
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_documents"
            )
            .await,
            0,
            "the delete cascaded through the version history"
        );
    }

    #[tokio::test]
    async fn additional_header_bindings_round_trip_and_advance_the_credential_axis() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;

        let mut write = http_candidate("Access-fronted API");
        write.additional_headers = serde_json::from_value(json!([
            {"header_name": "CF-Access-Client-Id", "secret_id": "access-client-id"},
            {"header_name": "CF-Access-Client-Secret", "secret_id": "access-client-secret"}
        ]))
        .expect("additional headers should deserialize");
        let created = store
            .create(write, "additional-create", None)
            .await
            .expect("Connection with additional headers should create");
        assert_eq!(created.revisions.credential, 1);

        let client = pool.get().await.expect("binding checkout");
        let rows = client
            .query(
                r#"
                SELECT purpose, header_name, secret_id, binding_version
                FROM greengateway.connection_credential_bindings
                WHERE connection_id = $1::text::uuid
                ORDER BY purpose, header_name
                "#,
                &[&created.id.as_str()],
            )
            .await
            .expect("binding rows should query")
            .into_iter()
            .map(|row| {
                (
                    row.get::<_, String>(0),
                    row.get::<_, String>(1),
                    row.get::<_, String>(2),
                    row.get::<_, i64>(3),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![
                (
                    "additional_header".to_owned(),
                    "cf-access-client-id".to_owned(),
                    "access-client-id".to_owned(),
                    1,
                ),
                (
                    "additional_header".to_owned(),
                    "cf-access-client-secret".to_owned(),
                    "access-client-secret".to_owned(),
                    1,
                ),
                (
                    "http_authentication".to_owned(),
                    String::new(),
                    "billing-token".to_owned(),
                    1,
                ),
            ]
        );
        drop(client);

        let mut replacement = created.write.clone();
        replacement.additional_headers[0].secret_id = Some("rotated-client-id".to_owned());
        let replaced = store
            .replace(
                &created.id,
                &created.etag(),
                replacement,
                "additional-replace",
            )
            .await
            .expect("Connection with additional headers should replace");
        assert_eq!(replaced.revisions.connection, 2);
        assert_eq!(replaced.revisions.credential, 2);
        assert_ne!(replaced.etag(), created.etag());
        assert_eq!(
            store
                .get(&created.id)
                .await
                .expect("Connection should load")
                .expect("Connection should remain"),
            replaced
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_credential_bindings"
            )
            .await,
            3
        );
    }

    #[tokio::test]
    async fn concurrent_same_etag_replaces_produce_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(http_candidate("Race Base"), "op-1", None)
            .await
            .expect("create should commit");
        let etag = created.etag();

        let store_a = PostgresConnectionStore::new(pool.clone(), 64).expect("store a");
        let store_b = PostgresConnectionStore::new(pool.clone(), 64).expect("store b");
        let (a, b) = tokio::join!(
            store_a.replace(
                &created.id,
                &etag,
                http_candidate("Replica A Wins"),
                "replica-a"
            ),
            store_b.replace(
                &created.id,
                &etag,
                http_candidate("Replica B Wins"),
                "replica-b"
            )
        );
        let winners = usize::from(a.is_ok()) + usize::from(b.is_ok());
        assert_eq!(winners, 1, "exactly one racing writer commits");
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_documents"
            )
            .await,
            2,
            "create plus exactly one winning version"
        );
    }

    #[tokio::test]
    async fn capacity_and_binding_tamper_fail_closed() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 1).await;

        store
            .create(http_candidate("Only One"), "op-1", None)
            .await
            .expect("first create fits");
        let limited = store
            .create(http_candidate("Second"), "op-2", None)
            .await
            .expect_err("the capacity limit must hold");
        assert!(
            matches!(limited, ConnectionStoreError::LimitExceeded { .. }),
            "{limited}"
        );

        // Out-of-band binding edits are corruption: reads fail closed
        // instead of serving a record whose secret wiring disagrees.
        let created = store.list().await.expect("list").pop().expect("record");
        pool.get()
            .await
            .expect("tamper checkout")
            .execute(
                "UPDATE greengateway.connection_credential_bindings \
                 SET secret_id = 'tampered' WHERE connection_id = $1::text::uuid",
                &[&created.id.as_str()],
            )
            .await
            .expect("tamper should apply");
        let corrupt = store
            .get(&created.id)
            .await
            .expect_err("a tampered binding must fail closed");
        assert!(
            matches!(corrupt, ConnectionStoreError::CorruptRecord { .. }),
            "{corrupt}"
        );
    }

    /// The same shape as `http_candidate`, with the bearer secret under
    /// the caller's control: changing it moves the credential axis, so
    /// the derived binding row's `secret_id` *and* `binding_version` both
    /// change with the record.
    fn http_candidate_with_secret(display_name: &str, secret_id: &str) -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": display_name,
            "enabled": false,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {
                "type": "static_bearer",
                "secret_id": secret_id
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

    /// The capacity bound is global, so the lock that makes it hold has to
    /// be global too. Two replicas race the last free slot from separate
    /// pools: without the `connection_state_revision` lock taken before
    /// the count, both read `maximum - 1` under READ COMMITTED and both
    /// commit, and the store ends up over its configured maximum.
    #[tokio::test]
    async fn concurrent_creates_at_capacity_produce_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store_a, pool_a) = migrated_store(&database.dsn, 1).await;
        let (store_b, _pool_b) = migrated_store(&database.dsn, 1).await;

        let (a, b) = tokio::join!(
            store_a.create(http_candidate("Replica A"), "replica-a", None),
            store_b.create(http_candidate("Replica B"), "replica-b", None)
        );
        let winners = usize::from(a.is_ok()) + usize::from(b.is_ok());
        assert_eq!(winners, 1, "the last free slot is taken exactly once");
        let loser = match (a, b) {
            (Ok(_), Err(error)) | (Err(error), Ok(_)) => error,
            _ => unreachable!("exactly one winner was just asserted"),
        };
        assert!(
            matches!(
                loser,
                ConnectionStoreError::LimitExceeded {
                    resource: "managed connections",
                    maximum: 1,
                }
            ),
            "{loser}"
        );
        assert_eq!(
            count(
                &pool_a,
                "SELECT COUNT(*) FROM greengateway.connection_records"
            )
            .await,
            1,
            "the loser's transaction wrote nothing"
        );
        assert_eq!(
            count(
                &pool_a,
                "SELECT COUNT(*) FROM greengateway.connection_documents"
            )
            .await,
            1,
            "and appended no specification version"
        );
    }

    /// A record and the credential bindings it is validated against must
    /// come from one instant, or a replacement committing between the two
    /// reads makes a healthy record read as corrupt. The SQLite store gets
    /// this from its single transaction
    /// (`record_and_bindings_are_read_from_one_wal_snapshot`); here it is
    /// the reader's `REPEATABLE READ` snapshot.
    #[tokio::test]
    async fn record_and_bindings_are_read_from_one_snapshot() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (reader, reader_pool) = migrated_store(&database.dsn, 64).await;
        let (writer, _writer_pool) = migrated_store(&database.dsn, 64).await;

        let created = reader
            .create(
                http_candidate_with_secret("Snapshot", "billing-token"),
                "op-1",
                None,
            )
            .await
            .expect("create should commit");

        // The negative control, and the reason the snapshot is needed:
        // read the record and its bindings as two autocommit statements
        // and let a replacement land between them. The record is healthy
        // and the bindings are healthy, but they describe two different
        // instants, so the comparison reports corruption.
        let client = reader_pool.get().await.expect("reader checkout");
        let stale = load_record(&client, &created.id, OPERATION_GET)
            .await
            .expect("record read")
            .expect("record exists");
        let replaced = writer
            .replace(
                &created.id,
                &stale.etag(),
                http_candidate_with_secret("Snapshot", "billing-token-v2"),
                "op-2",
            )
            .await
            .expect("the concurrent replacement should commit");
        let spurious = validate_bindings(&client, &stale)
            .await
            .expect_err("two autocommit reads see two instants");
        assert!(
            matches!(spurious, ConnectionStoreError::CorruptRecord { .. }),
            "{spurious}"
        );
        drop(client);

        // The same interleaving inside the reader's snapshot: the bindings
        // are read from the instant the record was, so the commit in
        // between is invisible and the healthy record stays healthy.
        let client = reader_pool.get().await.expect("reader checkout");
        begin_snapshot(&client, OPERATION_GET)
            .await
            .expect("the reader's snapshot should begin");
        let snapshot = load_record(&client, &created.id, OPERATION_GET)
            .await
            .expect("record read")
            .expect("record exists");
        let replaced_again = writer
            .replace(
                &created.id,
                &replaced.etag(),
                http_candidate_with_secret("Snapshot", "billing-token-v3"),
                "op-3",
            )
            .await
            .expect("the second concurrent replacement should commit");
        validate_bindings(&client, &snapshot)
            .await
            .expect("binding validation must use the record's own snapshot");
        commit(&client, OPERATION_GET)
            .await
            .expect("the read transaction should commit");
        drop(client);

        // And the public readers serve the committed state afterwards.
        let after = reader
            .get(&created.id)
            .await
            .expect("get should succeed")
            .expect("the record remains");
        assert_eq!(after.etag(), replaced_again.etag());
        assert_eq!(reader.list().await.expect("list should succeed").len(), 1);
    }

    /// A persisted dependency count past the bound is refused, not served:
    /// the SQLite reader raises `LimitExceeded` for the same row
    /// (store.rs `dependency_counts`), where saturating the conversion
    /// would have skipped the bound entirely.
    #[tokio::test]
    async fn dependency_counts_fail_closed_above_the_dependency_bound() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(http_candidate("Counted"), "op-1", None)
            .await
            .expect("create should commit");

        let excess = i32::try_from(MAX_CONNECTION_DEPENDENCIES + 1)
            .expect("the dependency bound fits in an int4");
        pool.get()
            .await
            .expect("dependency checkout")
            .execute(
                r#"
                INSERT INTO greengateway.connection_dependencies (
                    connection_id, consumer_kind, consumer_id, created_at
                )
                SELECT $1::text::uuid, 'proxy_route', 'route-' || series.ordinal,
                       '2026-01-01T00:00:00Z'
                FROM generate_series(1, $2::int) AS series(ordinal)
                "#,
                &[&created.id.as_str(), &excess],
            )
            .await
            .expect("out-of-band dependency rows should insert");

        let error = store
            .dependency_counts()
            .await
            .expect_err("a count past the bound must fail closed");
        assert!(
            matches!(
                error,
                ConnectionStoreError::LimitExceeded {
                    resource: "connection dependencies",
                    ..
                }
            ),
            "{error}"
        );
    }

    fn mcp_candidate() -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": "Managed MCP",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": "https://mcp.example.test",
                "base_path": "/mcp"
            },
            "authentication": { "type": "none" },
            "tls": {},
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": false
            }
        }))
        .expect("MCP candidate should deserialize")
    }

    fn mcp_entry(name: &str) -> StoredMcpCatalogEntry {
        StoredMcpCatalogEntry {
            remote_tool_name: name.to_owned(),
            description: format!("{name} description"),
            input_schema: json!({ "type": "object", "properties": {} }),
        }
    }

    /// Changing a Connection's managed-catalog kind while a catalog is
    /// still published must be refused, not silently applied.
    ///
    /// The catalog's rows are attributed to the kind that produced them: an
    /// MCP catalog's entries each own a `managed_tool` dependency row, and
    /// the tool registry serves definitions derived from them. Letting the
    /// kind change out from under those rows would leave the registry
    /// advertising MCP tools for a Connection the authority now says is an
    /// OpenAPI one -- tools bound to an upstream contract nothing checks
    /// them against any more. The SQLite reference refuses it
    /// (`store.rs`, the `managed_catalog_kind_changed` branch of `replace`)
    /// and so must the authority.
    ///
    /// Withdraw the catalog first and the same replace is allowed, which is
    /// what makes this a guard rather than a permanent lock.
    #[tokio::test]
    async fn changing_the_catalog_kind_under_a_published_catalog_is_refused() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(mcp_candidate(), "op-1", None)
            .await
            .expect("MCP connection should create");
        store
            .replace_mcp_catalog(
                &created.id,
                &created.etag(),
                &[mcp_entry("alpha"), mcp_entry("beta")],
                &[],
                &[],
                0,
                "op-2",
            )
            .await
            .expect("catalog replace should win");
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_dependencies \
                 WHERE consumer_kind = 'managed_tool'",
            )
            .await,
            2,
            "the published catalog owns one managed-tool dependency per entry"
        );

        let current = store
            .get(&created.id)
            .await
            .expect("record read")
            .expect("record exists");
        let mut different_kind: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Now an OpenAPI connection",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://mcp.example.test",
                "base_path": "/mcp"
            },
            "authentication": { "type": "none" },
            "tls": {},
            "discovery": {
                "type": "managed_openapi",
                "use_connection_authentication": false
            }
        }))
        .expect("OpenAPI candidate should deserialize");

        let refused = store
            .replace(&created.id, &current.etag(), different_kind.clone(), "op-3")
            .await
            .expect_err("the kind change must be refused while a catalog is published");
        assert!(
            matches!(
                refused,
                ConnectionStoreError::DependencyConflict { count: 2, .. }
            ),
            "the refusal names the managed-tool rows that block it, got {refused:?}"
        );

        // Nothing partially applied: the record, its catalog, and its
        // dependency rows are exactly as they were.
        let unchanged = store
            .get(&created.id)
            .await
            .expect("record read")
            .expect("record exists");
        assert_eq!(
            unchanged, current,
            "a refused kind change leaves the record untouched"
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_mcp_catalogs",
            )
            .await,
            1,
            "the published catalog survives the refusal"
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_dependencies \
                 WHERE consumer_kind = 'managed_tool'",
            )
            .await,
            2,
            "the dependency rows survive the refusal"
        );

        // Withdraw the catalog, and the same replace is now allowed: the
        // guard tracks live rows, it does not pin the kind forever.
        store
            .replace_mcp_catalog(&created.id, &unchanged.etag(), &[], &[], &[], 1, "op-4")
            .await
            .expect("emptying the catalog should win");
        let after_withdrawal = store
            .get(&created.id)
            .await
            .expect("record read")
            .expect("record exists");
        different_kind.display_name = "Now an OpenAPI connection".to_owned();
        let replaced = store
            .replace(
                &created.id,
                &after_withdrawal.etag(),
                different_kind,
                "op-5",
            )
            .await
            .expect("the kind change is allowed once no managed-tool rows remain");
        assert_eq!(
            replaced.write.kind,
            crate::connections::model::ConnectionKind::HttpApi
        );
        assert_eq!(
            count(
                &pool,
                "SELECT COUNT(*) FROM greengateway.connection_mcp_catalogs",
            )
            .await,
            0,
            "the obsolete catalog is dropped with the kind change"
        );
    }

    #[tokio::test]
    async fn mcp_catalog_replaces_with_cas_revisions_dependencies_and_outbox() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(mcp_candidate(), "op-1", None)
            .await
            .expect("MCP connection should create");
        let etag = created.etag();

        // The first replace publishes revision 1 with the managed-tool
        // dependency per entry, and bumps the shared security revision and
        // the connections high-water mark with an outbox row naming the
        // connection.
        let security_before: i64 = count(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
        )
        .await;
        let catalog = store
            .replace_mcp_catalog(
                &created.id,
                &etag,
                &[mcp_entry("alpha"), mcp_entry("beta")],
                &[],
                &[],
                0,
                "op-2",
            )
            .await
            .expect("catalog replace should win");
        assert_eq!(catalog.catalog_revision, 1);
        assert_eq!(catalog.entries.len(), 2);
        let loaded = store
            .mcp_catalog(&created.id)
            .await
            .expect("catalog read")
            .expect("catalog exists");
        assert_eq!(loaded, catalog);
        assert_eq!(
            store.mcp_catalogs().await.expect("list").len(),
            1,
            "the listing loads every catalog"
        );
        let security_after: i64 = count(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
        )
        .await;
        assert!(
            security_after > security_before,
            "catalog replaces bump the shared revision"
        );
        assert!(
            store.state_revision().await.expect("state") > 0,
            "the connections high-water mark advanced"
        );
        let dependencies = store.dependencies(&created.id).await.expect("dependencies");
        assert_eq!(
            dependencies.len(),
            2,
            "one managed-tool dependency per entry"
        );
        assert!(dependencies
            .iter()
            .all(|dep| dep.kind == ConnectionDependencyKind::ManagedTool));

        // A stale CONNECTION etag loses with Conflict and leaves the
        // catalog untouched. Catalog replaces do not change the record's
        // etag (refresh loops rely on that), so staleness comes from a
        // record replacement: rename the connection, then present the
        // pre-rename etag.
        let mut renamed = mcp_candidate();
        renamed.display_name = "Renamed MCP".to_owned();
        let fresh_record_etag = store
            .replace(&created.id, &etag, renamed, "op-3")
            .await
            .expect("record replace should win")
            .etag();
        let stale = store
            .replace_mcp_catalog(
                &created.id,
                &etag,
                &[mcp_entry("gamma")],
                &[],
                &[],
                1,
                "op-4",
            )
            .await
            .expect_err("the stale connection etag must lose");
        assert!(
            matches!(stale, ConnectionStoreError::Conflict { .. }),
            "{stale}"
        );
        assert_eq!(
            store
                .mcp_catalog(&created.id)
                .await
                .expect("catalog read")
                .expect("exists")
                .entries
                .len(),
            2
        );

        // The record's new etag wins; the managed-tool dependencies are
        // REPLACED (not accumulated) and the catalog revision increments.
        let second = store
            .replace_mcp_catalog(
                &created.id,
                &fresh_record_etag,
                &[mcp_entry("alpha"), mcp_entry("beta"), mcp_entry("delta")],
                &[],
                &[],
                1,
                "op-5",
            )
            .await
            .expect("the fresh etag should win");
        assert_eq!(second.catalog_revision, 2);
        let dependencies = store.dependencies(&created.id).await.expect("dependencies");
        assert_eq!(dependencies.len(), 3, "dependencies follow the new catalog");
    }

    /// The retained half of the MCP catalog byte budget must measure the
    /// same three tables the candidate half does (`validate_mcp_catalog`'s
    /// `stored_bytes`). Summing entries alone made every stored resource
    /// and resource template free, so the two halves of the comparison
    /// described different quantities.
    /// Two replicas refresh from the same prior catalog. The connection
    /// ETag does not move on a catalog replacement, so only the catalog's
    /// own revision can tell the second, older discovery result from a
    /// legitimate follow-on refresh. Without this CAS the slower, older
    /// result would commit last and replace the newer catalog.
    #[tokio::test]
    async fn a_stale_catalog_revision_is_refused_even_under_a_fresh_connection_etag() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(mcp_candidate(), "op-1", None)
            .await
            .expect("MCP connection should create");

        // Both replicas observed "no catalog yet" (revision 0).
        let first = store
            .replace_mcp_catalog(
                &created.id,
                &created.etag(),
                &[mcp_entry("alpha")],
                &[],
                &[],
                0,
                "replica-a",
            )
            .await
            .expect("the first discovery commits");
        assert_eq!(first.catalog_revision, 1);

        // The second replica's discovery was slower. Its connection ETag is
        // still current (catalog replacements do not move it), so only the
        // catalog revision it observed can stop it.
        let stale = store
            .replace_mcp_catalog(
                &created.id,
                &created.etag(),
                &[mcp_entry("older-view")],
                &[],
                &[],
                0,
                "replica-b",
            )
            .await
            .expect_err("a discovery from a superseded catalog must be refused");
        assert!(
            matches!(stale, ConnectionStoreError::Conflict { .. }),
            "the refusal is a conflict, got {stale}"
        );
        let live = store
            .mcp_catalog(&created.id)
            .await
            .expect("catalog read")
            .expect("catalog exists");
        assert_eq!(live.catalog_revision, 1);
        assert_eq!(
            live.entries[0].remote_tool_name, "alpha",
            "the newer catalog stays live"
        );

        // A refresh that observed revision 1 is the legitimate follow-on.
        let next = store
            .replace_mcp_catalog(
                &created.id,
                &created.etag(),
                &[mcp_entry("beta")],
                &[],
                &[],
                1,
                "replica-b",
            )
            .await
            .expect("a refresh from the live catalog commits");
        assert_eq!(next.catalog_revision, 2);
    }

    /// Two replicas create under the same collection `If-Match`. Each passed
    /// its own process-local check (both snapshots were empty), so only the
    /// authority can decide: under the singleton lock it re-derives the
    /// collection ETag from its records and refuses the second create.
    /// Without this, both inserts succeed and the caller's precondition is
    /// decoration.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_creates_under_one_collection_etag_produce_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (replica_a, _pool_a) = migrated_store(&database.dsn, 64).await;
        let (replica_b, _pool_b) = migrated_store(&database.dsn, 64).await;
        let replica_a = std::sync::Arc::new(replica_a);
        let replica_b = std::sync::Arc::new(replica_b);

        // The derivation the control plane would supply: here, the sorted
        // ids joined, which is enough to change the moment a row lands.
        fn derive(records: &BTreeMap<ConnectionId, StoredConnection>) -> String {
            if records.is_empty() {
                "empty".to_owned()
            } else {
                records
                    .keys()
                    .map(ConnectionId::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            }
        }
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let create_on = |store: std::sync::Arc<PostgresConnectionStore>, name: &'static str| {
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .create(
                        http_candidate(name),
                        "op",
                        Some(super::super::store::CollectionCheck {
                            expected_etag: "empty",
                            compute: &derive,
                        }),
                    )
                    .await
            })
        };
        let (first, second) = tokio::join!(
            create_on(replica_a.clone(), "Replica A"),
            create_on(replica_b.clone(), "Replica B")
        );
        let outcomes = [first.expect("task"), second.expect("task")];
        let winners = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
        assert_eq!(
            winners, 1,
            "exactly one create wins the collection precondition"
        );
        let loser = outcomes
            .iter()
            .find_map(|outcome| outcome.as_ref().err())
            .expect("one create loses");
        assert!(
            matches!(loser, ConnectionStoreError::CollectionConflict { current } if current != "empty"),
            "the loser is told the collection moved, got {loser}"
        );
        assert_eq!(
            replica_a.count().await.expect("count"),
            1,
            "the loser wrote nothing"
        );
    }

    #[tokio::test]
    async fn retained_mcp_catalog_bytes_charge_entries_resources_and_templates() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(mcp_candidate(), "op-1", None)
            .await
            .expect("MCP connection should create");

        let entry = mcp_entry("alpha");
        let resource = StoredMcpResource {
            uri: "res://alpha".to_owned(),
            name: "alpha".to_owned(),
            title: Some("Alpha".to_owned()),
            description: None,
            mime_type: Some("text/plain".to_owned()),
            size: Some(12),
        };
        let template = StoredMcpResourceTemplate {
            uri_template: "res://alpha/{id}".to_owned(),
            name: "alpha-template".to_owned(),
            title: None,
            description: Some("templated alpha".to_owned()),
            mime_type: None,
        };
        store
            .replace_mcp_catalog(
                &created.id,
                &created.etag(),
                std::slice::from_ref(&entry),
                std::slice::from_ref(&resource),
                std::slice::from_ref(&template),
                0,
                "op-2",
            )
            .await
            .expect("catalog replace should win");

        fn optional_len(value: &Option<String>) -> usize {
            value.as_ref().map_or(0, String::len)
        }
        let encoded_schema =
            serde_json::to_string(&entry.input_schema).expect("entry schema should encode");
        let entry_bytes =
            entry.remote_tool_name.len() + entry.description.len() + encoded_schema.len();
        let resource_bytes = resource.uri.len()
            + resource.name.len()
            + optional_len(&resource.title)
            + optional_len(&resource.description)
            + optional_len(&resource.mime_type)
            + 8;
        let template_bytes = template.uri_template.len()
            + template.name.len()
            + optional_len(&template.title)
            + optional_len(&template.description)
            + optional_len(&template.mime_type);

        let client = pool.get().await.expect("pooled client");
        let retained = mcp_catalog_bytes(&client, None, "test retained bytes")
            .await
            .expect("retained byte count should read");
        assert_eq!(
            retained,
            entry_bytes + resource_bytes + template_bytes,
            "the retained sum charges entries, resources AND resource templates,              exactly as store.rs mcp_catalog_bytes does"
        );
        assert!(
            retained > entry_bytes,
            "resources and templates are not free: summing entries alone under-counts by {}",
            resource_bytes + template_bytes
        );

        // The bytes are the ones serde_json wrote, not a jsonb rendering:
        // the schema column is text, so this is byte-identical to SQLite.
        let stored_schema_bytes: i64 = client
            .query_one(
                // octet_length is int4; the sum above is int8 because SUM
                // widens. Cast so both read back as the same Rust type.
                "SELECT octet_length(input_schema_json)::bigint                  FROM greengateway.connection_mcp_catalog_entries",
                &[],
            )
            .await
            .expect("stored schema length should read")
            .get(0);
        assert_eq!(
            usize::try_from(stored_schema_bytes).expect("length fits"),
            encoded_schema.len(),
            "the persisted schema is verbatim, so both stores count the same bytes"
        );

        // The replacement preflight excludes the connection it is about to
        // rewrite, so the only stored catalog contributes nothing.
        let excluded = mcp_catalog_bytes(&client, Some(&created.id), "test retained bytes")
            .await
            .expect("excluding byte count should read");
        assert_eq!(
            excluded, 0,
            "the connection being replaced is excluded from all three tables"
        );
    }

    fn openapi_entry(tool_name: &str) -> StoredOpenApiCatalogEntry {
        StoredOpenApiCatalogEntry {
            tool_name: tool_name.to_owned(),
            operation_id: Some("listInvoices".to_owned()),
            selected_scheme_names: vec![],
            definition: json!({
                "name": tool_name,
                "description": "Lists invoices.",
                "input_json_schema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                },
                "upstream": {
                    "method": "GET",
                    "path_template": "/v1/invoices",
                    "body": { "mode": "whole_args_json" }
                }
            }),
        }
    }

    fn local_tools_document(tool_names: &[&str]) -> Value {
        json!({
            "schema_version": "0.1.0",
            "tools": tool_names.iter().map(|name| json!({
                "name": name,
                "description": "Echoes the provided message.",
                "input_json_schema": {
                    "type": "object",
                    "required": ["message"],
                    "properties": { "message": { "type": "string" } },
                    "additionalProperties": false
                },
                "upstream": {
                    "method": "POST",
                    "path_template": "/v1/echo",
                    "body": { "mode": "whole_args_json" }
                }
            })).collect::<Vec<_>>()
        })
    }

    const RESERVATION_SPEC: &str = "{\"openapi\":\"3.1.0\"}";

    fn reservation_spec_digest() -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(RESERVATION_SPEC.as_bytes()))
    }

    fn mcp_resource(uri: &str) -> StoredMcpResource {
        StoredMcpResource {
            uri: uri.to_owned(),
            name: format!("resource {uri}"),
            title: None,
            description: None,
            mime_type: Some("text/plain".to_owned()),
            size: None,
        }
    }

    async fn published_mcp_catalog(store: &PostgresConnectionStore) -> StoredConnection {
        let mcp = store
            .create(mcp_candidate(), "op-1", None)
            .await
            .expect("create");
        store
            .replace_mcp_catalog(
                &mcp.id,
                &mcp.etag(),
                &[mcp_entry("alpha"), mcp_entry("beta")],
                &[mcp_resource("file:///a"), mcp_resource("file:///b")],
                &[],
                0,
                "op-2",
            )
            .await
            .expect("MCP catalog publishes");
        assert_eq!(store.mcp_catalogs().await.expect("loads").len(), 1);
        mcp
    }

    /// Persisted catalog rows carry ordinals 0..n; a gap left by an
    /// out-of-band edit (the schema allows it) is corruption when loaded.
    #[tokio::test]
    async fn persisted_mcp_ordinals_shifted_out_of_band_load_as_corruption() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let mcp = published_mcp_catalog(&store).await;
        pool.get()
            .await
            .expect("client")
            .execute(
                "UPDATE greengateway.connection_mcp_catalog_entries SET ordinal = ordinal + 7 \
                 WHERE connection_id = $1::text::uuid",
                &[&mcp.id.as_str()],
            )
            .await
            .expect("tamper");
        let error = store
            .mcp_catalogs()
            .await
            .expect_err("non-contiguous persisted ordinals are corruption");
        assert!(
            matches!(error, ConnectionStoreError::CorruptRecord { .. }),
            "{error}"
        );
    }

    /// A persisted catalog is re-validated when loaded, as the standalone
    /// loader does: a resource locator carrying a query component (nothing
    /// in the schema forbids it) is a validator verdict, surfaced as
    /// corruption.
    #[tokio::test]
    async fn persisted_mcp_resources_duplicated_out_of_band_load_as_corruption() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let mcp = published_mcp_catalog(&store).await;
        pool.get()
            .await
            .expect("client")
            .execute(
                "UPDATE greengateway.connection_mcp_catalog_resources SET uri = 'file:///b?leak=1' \
                 WHERE connection_id = $1::text::uuid AND ordinal = 1",
                &[&mcp.id.as_str()],
            )
            .await
            .expect("tamper");
        let error = store
            .mcp_catalogs()
            .await
            .expect_err("a persisted catalog the validator rejects is corruption");
        assert!(
            matches!(error, ConnectionStoreError::CorruptRecord { .. }),
            "{error}"
        );
    }

    /// A persisted OpenAPI entry whose stored JSON is not what this binary
    /// would write for it -- here the same definition with a trailing space,
    /// which still parses and still validates -- was edited out of band:
    /// corruption, never a definition to activate.
    #[tokio::test]
    async fn persisted_openapi_entry_edited_out_of_band_loads_as_corruption() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let api = store
            .create(http_candidate("Billing API"), "op-3", None)
            .await
            .expect("create");
        store
            .replace_openapi_catalog(
                &api.id,
                &api.etag(),
                0,
                0,
                RESERVATION_SPEC,
                &reservation_spec_digest(),
                &[openapi_entry("billing.list"), openapi_entry("billing.get")],
                "op-4",
            )
            .await
            .expect("OpenAPI catalog publishes");
        assert_eq!(store.openapi_catalogs().await.expect("loads").len(), 1);
        pool.get()
            .await
            .expect("client")
            .execute(
                "UPDATE greengateway.connection_openapi_catalog_entries \
                 SET definition_json = definition_json || ' ' \
                 WHERE connection_id = $1::text::uuid AND ordinal = 0",
                &[&api.id.as_str()],
            )
            .await
            .expect("tamper");
        let error = store
            .openapi_catalogs()
            .await
            .expect_err("a definition that is not what this binary would write is corruption");
        assert!(
            matches!(error, ConnectionStoreError::CorruptRecord { .. }),
            "{error}"
        );
    }

    /// A delete waits for a dependency batch the background flusher has
    /// already taken but not yet written: flushes and mutations share one
    /// lock, so the batch lands before the delete is judged -- and refuses
    /// it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn a_delete_waits_for_an_in_flight_dependency_flush() {
        use crate::connections::control_plane::{
            ClusterConnectionStoreSeed, ConnectionControlPlane, ConnectionMutationError,
        };
        use crate::connections::managed_store::{ClusterConnectionsBoot, ManagedConnectionStore};
        use crate::connections::store::ConnectionDependencyKind;
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_store(&database.dsn, 64).await;
        let config = crate::config::Config::test_defaults();
        let control_plane = ConnectionControlPlane::from_config_with_cluster_seed(
            &config,
            Some(ClusterConnectionStoreSeed {
                store: ManagedConnectionStore::Postgres {
                    store: std::sync::Arc::new(store),
                    boot: std::sync::Arc::new(ClusterConnectionsBoot {
                        mcp_catalogs: Vec::new(),
                        openapi_catalogs: Vec::new(),
                        openapi_inventory_catalogs: Vec::new(),
                    }),
                },
                records: Vec::new(),
            }),
        )
        .expect("cluster control plane should build");
        let snapshot = control_plane.runtime_snapshot();
        let record = control_plane
            .create_managed(
                snapshot.collection_etag(),
                http_candidate("Referenced API"),
                "op-1",
            )
            .await
            .expect("create");
        control_plane
            .replace_runtime_dependencies(
                ConnectionDependencyKind::ProxyRoute,
                &[(record.id.clone(), "route-1".to_owned())],
            )
            .expect("the dependency set queues");

        // The background flush takes the batch and stalls before writing.
        let (release, released) = std::sync::mpsc::channel::<()>();
        let released = std::sync::Mutex::new(released);
        control_plane.set_flush_hook_for_test(std::sync::Arc::new(move || {
            let _ = released
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .recv();
        }));
        let flusher = {
            let control_plane = control_plane.clone();
            tokio::spawn(async move { control_plane.flush_pending_dependencies().await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let mut deleter = {
            let control_plane = control_plane.clone();
            let (id, etag) = (record.id.clone(), record.etag());
            tokio::spawn(async move { control_plane.delete_managed(&id, &etag, "op-2").await })
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut deleter)
                .await
                .is_err(),
            "the delete waits for the in-flight flush"
        );
        release.send(()).expect("the flush is waiting");
        flusher
            .await
            .expect("task")
            .expect("the flush writes its batch");
        let refused = deleter
            .await
            .expect("task")
            .expect_err("the flushed guard refuses the delete");
        assert!(
            matches!(
                refused,
                ConnectionMutationError::Store(ConnectionStoreError::DependencyConflict { .. })
            ),
            "{refused}"
        );
    }

    /// Cluster mode queues dependency guard rows for a background flush.
    /// An admin delete flushes them first, so a Connection a live route
    /// references is refused even before the background task has run --
    /// and a delete after the reference is gone succeeds.
    #[tokio::test]
    async fn delete_flushes_queued_dependency_guards_before_it_is_judged() {
        use crate::connections::control_plane::{
            ClusterConnectionStoreSeed, ConnectionControlPlane, ConnectionMutationError,
        };
        use crate::connections::managed_store::{ClusterConnectionsBoot, ManagedConnectionStore};
        use crate::connections::store::ConnectionDependencyKind;
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let config = crate::config::Config::test_defaults();
        let control_plane = ConnectionControlPlane::from_config_with_cluster_seed(
            &config,
            Some(ClusterConnectionStoreSeed {
                store: ManagedConnectionStore::Postgres {
                    store: std::sync::Arc::new(store),
                    boot: std::sync::Arc::new(ClusterConnectionsBoot {
                        mcp_catalogs: Vec::new(),
                        openapi_catalogs: Vec::new(),
                        openapi_inventory_catalogs: Vec::new(),
                    }),
                },
                records: Vec::new(),
            }),
        )
        .expect("cluster control plane should build");
        let snapshot = control_plane.runtime_snapshot();
        let record = control_plane
            .create_managed(
                snapshot.collection_etag(),
                http_candidate("Referenced API"),
                "op-1",
            )
            .await
            .expect("create");

        // A route references the Connection; in cluster mode the guard row
        // is only queued.
        control_plane
            .replace_runtime_dependencies(
                ConnectionDependencyKind::ProxyRoute,
                &[(record.id.clone(), "route-1".to_owned())],
            )
            .expect("the dependency set queues");
        let client = pool.get().await.expect("client");
        let queued_only: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.connection_dependencies WHERE connection_id = $1::text::uuid",
                &[&record.id.as_str()],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(queued_only, 0, "nothing is written until a flush");

        let refused = control_plane
            .delete_managed(&record.id, &record.etag(), "op-2")
            .await
            .expect_err("a referenced Connection must not be deleted");
        assert!(
            matches!(
                refused,
                ConnectionMutationError::Store(ConnectionStoreError::DependencyConflict { .. })
            ),
            "{refused}"
        );
        let flushed: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.connection_dependencies WHERE connection_id = $1::text::uuid",
                &[&record.id.as_str()],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(
            flushed, 1,
            "the delete flushed the guard before judging itself"
        );

        // The reference goes away; the next delete flushes that too and
        // succeeds.
        control_plane
            .replace_runtime_dependencies(ConnectionDependencyKind::ProxyRoute, &[])
            .expect("the empty set queues");
        control_plane
            .delete_managed(&record.id, &record.etag(), "op-3")
            .await
            .expect("an unreferenced Connection deletes");
    }

    /// The authority itself refuses a tool name another lane holds, so two
    /// lanes can never both commit a name that only one replica-side
    /// registry could install (the review of PR 8). Replacing the holder's
    /// catalog without the name frees it.
    #[tokio::test]
    async fn tool_names_are_reserved_across_lanes_at_the_authority() {
        use crate::storage::{PolicyCommitError, PolicyCommitPrecondition, ToolControlPlane};
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let tools = crate::storage::PostgresToolStore::new(pool.clone());
        tools.seed_empty_document().await.expect("seed");
        let digest = reservation_spec_digest();
        let api = store
            .create(http_candidate("Billing API"), "op-1", None)
            .await
            .expect("create");
        store
            .replace_openapi_catalog(
                &api.id,
                &api.etag(),
                0,
                0,
                RESERVATION_SPEC,
                &digest,
                &[openapi_entry("shared_tool")],
                "op-2",
            )
            .await
            .expect("the OpenAPI lane publishes first");

        // The local lane cannot take the name; nothing is written.
        let active = tools.active_tools().await.expect("active").expect("seeded");
        let refused = tools
            .commit_tools(
                PolicyCommitPrecondition::Expected {
                    etag: active.etag.clone(),
                },
                &local_tools_document(&["shared_tool"]),
                "op-3",
                &json!({"action": "test"}),
            )
            .await
            .expect_err("the name is held by the OpenAPI lane");
        assert!(
            matches!(
                &refused,
                PolicyCommitError::ToolNameTaken { tool_name, lane, owner_id }
                    if tool_name == "shared_tool" && lane == "openapi" && owner_id == api.id.as_str()
            ),
            "{refused}"
        );
        let unchanged = tools.active_tools().await.expect("active").expect("seeded");
        assert_eq!(
            unchanged.version, active.version,
            "a refused commit writes nothing"
        );

        // Nor can a second Connection.
        let other = store
            .create(http_candidate("Other API"), "op-4", None)
            .await
            .expect("create");
        let refused = store
            .replace_openapi_catalog(
                &other.id,
                &other.etag(),
                0,
                0,
                RESERVATION_SPEC,
                &digest,
                &[openapi_entry("shared_tool")],
                "op-5",
            )
            .await
            .expect_err("the name is held by another Connection");
        assert!(
            matches!(
                &refused,
                ConnectionStoreError::ToolNameConflict { tool_name, lane, owner_id, .. }
                    if tool_name == "shared_tool" && lane == "openapi" && owner_id == api.id.as_str()
            ),
            "{refused}"
        );

        // Replacing the holder's catalog without the name frees it for the
        // local lane -- and then the OpenAPI lane cannot take it back.
        let api_now = store
            .get(&api.id)
            .await
            .expect("get")
            .expect("the Connection exists");
        store
            .replace_openapi_catalog(
                &api.id,
                &api_now.etag(),
                1,
                1,
                RESERVATION_SPEC,
                &digest,
                &[openapi_entry("renamed_tool")],
                "op-6",
            )
            .await
            .expect("republish without the name");
        let committed = tools
            .commit_tools(
                PolicyCommitPrecondition::Expected {
                    etag: unchanged.etag.clone(),
                },
                &local_tools_document(&["shared_tool"]),
                "op-7",
                &json!({"action": "test"}),
            )
            .await
            .expect("the local lane takes the freed name");
        assert!(committed.version > unchanged.version);
        let api_now = store
            .get(&api.id)
            .await
            .expect("get")
            .expect("the Connection exists");
        let refused = store
            .replace_openapi_catalog(
                &api.id,
                &api_now.etag(),
                // The spec is unchanged, so its revision stays at 1; only
                // the catalog revision advanced.
                1,
                2,
                RESERVATION_SPEC,
                &digest,
                &[openapi_entry("shared_tool"), openapi_entry("renamed_tool")],
                "op-8",
            )
            .await
            .expect_err("the local lane holds it now");
        assert!(
            matches!(
                &refused,
                ConnectionStoreError::ToolNameConflict { tool_name, lane, owner_id, .. }
                    if tool_name == "shared_tool" && lane == "local" && owner_id == "tools"
            ),
            "{refused}"
        );
        // A refused catalog publish wrote nothing: the previous catalog
        // and its reservation stand.
        let client = pool.get().await.expect("client");
        let held: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.tool_name_reservations WHERE tool_name = 'renamed_tool' AND lane = 'openapi'",
                &[],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(held, 1);
    }

    /// Two lanes racing to publish one name: exactly one wins, on the
    /// authority's own guarantee rather than any replica's registry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_cross_lane_publishes_of_one_tool_name_produce_exactly_one_winner() {
        use crate::storage::{PolicyCommitPrecondition, ToolControlPlane};
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let store = std::sync::Arc::new(store);
        let tools = std::sync::Arc::new(crate::storage::PostgresToolStore::new(pool.clone()));
        tools.seed_empty_document().await.expect("seed");
        let digest = reservation_spec_digest();
        // The local lane must be able to win on its own terms, or a parse
        // failure would masquerade as losing every race.
        let seeded = tools.active_tools().await.expect("active").expect("seeded");
        tools
            .commit_tools(
                PolicyCommitPrecondition::Expected {
                    etag: seeded.etag.clone(),
                },
                &local_tools_document(&["warmup_tool"]),
                "op-w",
                &json!({"action": "warmup"}),
            )
            .await
            .expect("the local lane commits an uncontested name");
        for round in 0..4 {
            let name = format!("raced_{round}");
            let api = store
                .create(http_candidate(&format!("API {round}")), "op-c", None)
                .await
                .expect("create");
            let active = tools.active_tools().await.expect("active").expect("seeded");
            let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
            let local = {
                let (tools, barrier, name) = (tools.clone(), barrier.clone(), name.clone());
                let etag = active.etag.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    tools
                        .commit_tools(
                            PolicyCommitPrecondition::Expected { etag },
                            &local_tools_document(&[name.as_str()]),
                            "op-l",
                            &json!({"action": "race"}),
                        )
                        .await
                        .is_ok()
                })
            };
            let openapi = {
                let (store, barrier, name, digest) =
                    (store.clone(), barrier.clone(), name.clone(), digest.clone());
                let (id, etag) = (api.id.clone(), api.etag());
                tokio::spawn(async move {
                    barrier.wait().await;
                    store
                        .replace_openapi_catalog(
                            &id,
                            &etag,
                            0,
                            0,
                            RESERVATION_SPEC,
                            &digest,
                            &[openapi_entry(&name)],
                            "op-o",
                        )
                        .await
                        .is_ok()
                })
            };
            let (local_won, openapi_won) = tokio::join!(local, openapi);
            let winners =
                usize::from(local_won.expect("task")) + usize::from(openapi_won.expect("task"));
            assert_eq!(
                winners, 1,
                "round {round}: exactly one lane publishes '{name}'"
            );
            let client = pool.get().await.expect("client");
            let holders: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.tool_name_reservations WHERE tool_name = $1",
                    &[&name],
                )
                .await
                .expect("count")
                .get(0);
            assert_eq!(holders, 1, "round {round}: one reservation for '{name}'");
        }
    }

    #[tokio::test]
    async fn openapi_catalog_triple_cas_and_status_append() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(http_candidate("Billing API"), "op-1", None)
            .await
            .expect("OpenAPI connection should create");

        let entry = StoredOpenApiCatalogEntry {
            tool_name: "billing.list".to_owned(),
            operation_id: Some("listInvoices".to_owned()),
            selected_scheme_names: vec![],
            definition: json!({
                "name": "billing.list",
                "description": "Lists invoices.",
                "input_json_schema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                },
                "upstream": {
                    "method": "GET",
                    "path_template": "/v1/invoices",
                    "body": { "mode": "whole_args_json" }
                }
            }),
        };
        // Wrong digest shape is rejected before any transaction runs.
        let bad_digest = store
            .replace_openapi_catalog(
                &created.id,
                &created.etag(),
                0,
                0,
                "{\"openapi\":\"3.1.0\"}",
                "not-a-sha256",
                std::slice::from_ref(&entry),
                "op-2",
            )
            .await
            .expect_err("an invalid digest must be rejected");
        assert!(
            matches!(bad_digest, ConnectionStoreError::Validation { .. }),
            "{bad_digest}"
        );

        let digest = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(b"{\"openapi\":\"3.1.0\"}"))
        };
        let catalog = store
            .replace_openapi_catalog(
                &created.id,
                &created.etag(),
                0,
                0,
                "{\"openapi\":\"3.1.0\"}",
                &digest,
                std::slice::from_ref(&entry),
                "op-3",
            )
            .await
            .expect("the initial triple CAS (0,0) should win");
        assert_eq!(
            catalog.spec_revision, 1,
            "a new digest bumps the spec revision"
        );
        assert_eq!(catalog.catalog_revision, 1);
        assert_eq!(store.openapi_catalogs().await.expect("list").len(), 1);
        let inventory = store.openapi_inventory_catalogs().await.expect("inventory");
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].entries.len(), 1);

        // A stale catalog revision loses the triple CAS.
        let stale = store
            .replace_openapi_catalog(
                &created.id,
                &created.etag(),
                1,
                0,
                "{\"openapi\":\"3.1.0\"}",
                &digest,
                std::slice::from_ref(&entry),
                "op-4",
            )
            .await
            .expect_err("the stale catalog revision must lose");
        assert!(
            matches!(stale, ConnectionStoreError::Conflict { .. }),
            "{stale}"
        );

        // Status appends: etag CAS, latest reads, history, and no
        // security-revision bump (status is observational state).
        let security_before: i64 = count(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
        )
        .await;
        let etag = store
            .get(&created.id)
            .await
            .expect("get")
            .expect("exists")
            .etag();
        let status = store
            .append_status(
                &created.id,
                &etag,
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: Some(42),
                    catalog_age_secs: None,
                    catalog_entry_count: Some(1),
                },
            )
            .await
            .expect("status should append");
        assert_eq!(status.state, ConnectionOperationalState::Healthy);
        let latest = store
            .latest_status(&created.id)
            .await
            .expect("latest")
            .expect("status exists");
        assert_eq!(latest.state, ConnectionOperationalState::Healthy);
        assert_eq!(latest.latency_ms, Some(42));
        let history = store
            .status_history(&created.id, 10)
            .await
            .expect("history");
        assert_eq!(history.len(), 1);
        let security_after: i64 = count(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
        )
        .await;
        assert_eq!(
            security_after, security_before,
            "status appends must not bump the security revision"
        );

        // Dependency replacement: kind-scoped, owner-checked.
        store
            .add_dependency(
                &created.id,
                ConnectionDependencyKind::ProxyRoute,
                "route-payments",
            )
            .await
            .expect("dependency should add");
        store
            .add_dependency(
                &created.id,
                ConnectionDependencyKind::ProxyRoute,
                "route-payments",
            )
            .await
            .expect("duplicate add is an idempotent no-op");
        store
            .replace_dependencies_for_kind(
                ConnectionDependencyKind::ManualTool,
                &[(created.id.clone(), "manual.echo".to_owned())],
                0,
            )
            .await
            .expect("manual-tool dependencies should replace");
        let deps = store.dependencies(&created.id).await.expect("dependencies");
        assert_eq!(
            deps.len(),
            3,
            "managed_tool from the catalog + proxy_route + manual_tool"
        );
        let missing = store
            .replace_dependencies_for_kind(
                ConnectionDependencyKind::ControlPlane,
                &[(
                    ConnectionId::parse("11111111-1111-1111-1111-111111111111").expect("id"),
                    "ghost".to_owned(),
                )],
                0,
            )
            .await
            .expect_err("an unknown owner must be refused");
        assert!(
            matches!(missing, ConnectionStoreError::NotFound { .. }),
            "{missing}"
        );
    }

    /// Replicas flush derived dependency sets independently: a set from an
    /// older tools document never replaces the guards a newer document
    /// derived; a re-flush of the same document and a newer document do,
    /// and unfenced kinds (revision 0) keep replacing as before.
    #[tokio::test]
    async fn a_stale_dependency_flush_never_replaces_a_newer_documents_guards() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(http_candidate("Billing API"), "op-1", None)
            .await
            .expect("connection should create");
        let manual_tools = |deps: Vec<ConnectionDependency>| {
            let mut names = deps
                .into_iter()
                .filter(|dep| dep.kind == ConnectionDependencyKind::ManualTool)
                .map(|dep| dep.consumer_id)
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        let dep = |name: &str| (created.id.clone(), name.to_owned());
        store
            .replace_dependencies_for_kind(
                ConnectionDependencyKind::ManualTool,
                &[dep("tool-at-11")],
                11,
            )
            .await
            .expect("flush at 11");
        assert_eq!(
            manual_tools(store.dependencies(&created.id).await.expect("deps")),
            vec!["tool-at-11".to_owned()]
        );
        store
            .replace_dependencies_for_kind(ConnectionDependencyKind::ManualTool, &[], 10)
            .await
            .expect("a stale flush is accepted and ignored");
        assert_eq!(
            manual_tools(store.dependencies(&created.id).await.expect("deps")),
            vec!["tool-at-11".to_owned()],
            "the older document's empty set did not erase the guard"
        );
        store
            .replace_dependencies_for_kind(
                ConnectionDependencyKind::ManualTool,
                &[dep("tool-at-11"), dep("tool-at-11-b")],
                11,
            )
            .await
            .expect("a re-flush of the same document replaces");
        assert_eq!(
            manual_tools(store.dependencies(&created.id).await.expect("deps")),
            vec!["tool-at-11".to_owned(), "tool-at-11-b".to_owned()]
        );
        store
            .replace_dependencies_for_kind(
                ConnectionDependencyKind::ManualTool,
                &[dep("tool-at-12")],
                12,
            )
            .await
            .expect("flush at 12");
        assert_eq!(
            manual_tools(store.dependencies(&created.id).await.expect("deps")),
            vec!["tool-at-12".to_owned()]
        );
        store
            .replace_dependencies_for_kind(
                ConnectionDependencyKind::ProxyRoute,
                &[dep("route-a")],
                0,
            )
            .await
            .expect("unfenced flush");
        store
            .replace_dependencies_for_kind(ConnectionDependencyKind::ProxyRoute, &[], 0)
            .await
            .expect("unfenced flush replaces");
        let routes = store
            .dependencies(&created.id)
            .await
            .expect("deps")
            .into_iter()
            .filter(|dep| dep.kind == ConnectionDependencyKind::ProxyRoute)
            .count();
        assert_eq!(
            routes, 0,
            "revision 0 sets replace unconditionally, as before"
        );
    }

    /// The durable bound on an operation ID counts characters, as the
    /// validator and the SQLite backend do: 100 non-ASCII characters (400
    /// bytes) publish in cluster mode too.
    #[tokio::test]
    async fn operation_ids_are_bounded_by_characters_not_bytes() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_store(&database.dsn, 64).await;
        let api = store
            .create(http_candidate("Billing API"), "op-1", None)
            .await
            .expect("connection should create");
        let mut entry = openapi_entry("billing.list");
        entry.operation_id = Some("\u{1F600}".repeat(100));
        store
            .replace_openapi_catalog(
                &api.id,
                &api.etag(),
                0,
                0,
                RESERVATION_SPEC,
                &reservation_spec_digest(),
                &[entry],
                "op-2",
            )
            .await
            .expect("a 100-character non-ASCII operation id publishes");
    }

    /// A status write moves the authority's status revision and no security
    /// revision, so another replica's runtime record keeps its old one; the
    /// views read the revision from the authority instead.
    #[tokio::test]
    async fn status_revisions_are_read_from_the_authority() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(http_candidate("Billing API"), "op-1", None)
            .await
            .expect("connection should create");
        let before = store
            .status_revisions(std::slice::from_ref(&created.id))
            .await
            .expect("revisions");
        assert_eq!(
            before.get(&created.id).copied(),
            Some(created.revisions.status)
        );
        let etag = store
            .get(&created.id)
            .await
            .expect("get")
            .expect("exists")
            .etag();
        store
            .append_status(
                &created.id,
                &etag,
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: Some(42),
                    catalog_age_secs: None,
                    catalog_entry_count: Some(1),
                },
            )
            .await
            .expect("status should append");
        let after = store
            .status_revisions(std::slice::from_ref(&created.id))
            .await
            .expect("revisions");
        assert_eq!(
            after.get(&created.id).copied(),
            Some(created.revisions.status + 1),
            "the authority's status revision moved with the write"
        );
        let unknown = ConnectionId::parse("11111111-1111-1111-1111-111111111111").expect("id");
        assert!(!after.contains_key(&unknown));
        assert!(store.status_revisions(&[]).await.expect("empty").is_empty());
    }

    /// The global status-history bound covers every persisted status row,
    /// and a connection's current-status row is never pruned -- so the
    /// prune has to reserve one history slot per live connection. Without
    /// the reservation the store over-retains by exactly the number of
    /// connections and `current + history <= MAX_STATUS_HISTORY_ROWS` --
    /// the bound the restart preflight asserts -- stops holding. Same
    /// shape as the SQLite store's
    /// `global_history_pruning_preserves_every_connections_current_status`.
    #[tokio::test]
    async fn global_history_pruning_preserves_every_connections_current_status() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let maximum = crate::connections::model::MAX_STATUS_HISTORY_ROWS;
        let seed_limit = i64::try_from(maximum).expect("history limit should fit PostgreSQL");

        let quiet = store
            .create(http_candidate("Quiet API"), "op-1", None)
            .await
            .expect("quiet connection should create");
        let noisy = store
            .create(http_candidate("Noisy API"), "op-2", None)
            .await
            .expect("noisy connection should create");

        // Quiet writes the two OLDEST history rows in the database and then
        // never speaks again: it is the connection a global prune would
        // otherwise evict entirely.
        let quiet_test = store
            .append_status(
                &quiet.id,
                &quiet.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: Some(3),
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                },
            )
            .await
            .expect("quiet status should append");
        let quiet_test_at = quiet_test
            .observed_at
            .expect("quiet test should carry an observation time");
        let quiet_after_test = store
            .get(&quiet.id)
            .await
            .expect("quiet Connection should load")
            .expect("quiet Connection should remain");
        let quiet_refresh = store
            .append_status(
                &quiet.id,
                &quiet_after_test.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::CatalogRefreshed,
                    latency_ms: Some(4),
                    catalog_age_secs: Some(0),
                    catalog_entry_count: Some(1),
                },
            )
            .await
            .expect("quiet refresh should append");
        let quiet_refresh_at = quiet_refresh
            .observed_at
            .expect("quiet refresh should carry an observation time");
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
            .await
            .expect("initial noisy status should append");

        // Seed the noisy connection's history out of band, exactly as the
        // SQLite fixture does, so the very next append has to prune.
        let client = pool.get().await.expect("seed checkout");
        client
            .execute(
                r#"
                INSERT INTO greengateway.connection_status_history (
                    connection_id, status_revision, observed_connection_revision,
                    observed_credential_revision, observed_tls_revision,
                    observed_discovery_revision, state, reason, observed_at
                )
                SELECT $1::text::uuid, revision, 1, 1, 0, 1,
                       'degraded', 'request_failed', $2
                FROM generate_series(2, $3::bigint) AS revision
                "#,
                &[
                    &noisy.id.as_str(),
                    &utc_timestamp().expect("timestamp should format"),
                    &seed_limit,
                ],
            )
            .await
            .expect("noisy history rows should seed");
        client
            .execute(
                "UPDATE greengateway.connection_records SET status_revision = $1 \
                 WHERE id = $2::text::uuid",
                &[&seed_limit, &noisy.id.as_str()],
            )
            .await
            .expect("noisy record revision should update");
        client
            .execute(
                "UPDATE greengateway.connection_current_status SET status_revision = $1 \
                 WHERE connection_id = $2::text::uuid",
                &[&seed_limit, &noisy.id.as_str()],
            )
            .await
            .expect("noisy current revision should update");
        drop(client);

        let noisy_current = store
            .get(&noisy.id)
            .await
            .expect("noisy Connection should load")
            .expect("noisy Connection should remain");
        store
            .append_status(
                &noisy.id,
                &noisy_current.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: Some(4),
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                },
            )
            .await
            .expect("bounded noisy append should succeed");

        // Every connection keeps its current-status row, and the prune
        // reserved a slot for each of them: the total is exactly the bound,
        // not the bound plus one row per live connection.
        let current_rows = count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_current_status",
        )
        .await;
        assert_eq!(current_rows, 2, "both connections keep a current status");
        let history_rows = count(
            &pool,
            "SELECT COUNT(*) FROM greengateway.connection_status_history",
        )
        .await;
        assert_eq!(
            history_rows,
            seed_limit - current_rows,
            "history is trimmed to the budget MINUS the retained current-status rows"
        );
        let total_status_rows = count(
            &pool,
            r#"
            SELECT
                (SELECT COUNT(*) FROM greengateway.connection_current_status)
                + (SELECT COUNT(*) FROM greengateway.connection_status_history)
            "#,
        )
        .await;
        assert_eq!(
            total_status_rows, seed_limit,
            "the persisted status-row bound the restart preflight asserts must hold"
        );

        // The quiet connection lost its history to the global prune but
        // kept the state that is never pruned.
        let quiet_latest = store
            .latest_status(&quiet.id)
            .await
            .expect("quiet latest query should succeed")
            .expect("quiet current status must be retained");
        assert_eq!(quiet_latest.state, ConnectionOperationalState::Healthy);
        assert_eq!(
            quiet_latest.reason,
            ConnectionStatusReason::CatalogRefreshed
        );
        assert!(
            store
                .status_history(&quiet.id, maximum)
                .await
                .expect("quiet history query should succeed")
                .is_empty(),
            "the global prune fixture removes both quiet history rows"
        );
        let quiet_activity = store
            .activity_times()
            .await
            .expect("quiet activity should load")
            .remove(&quiet.id)
            .expect("quiet activity metadata must be retained");
        assert_eq!(
            quiet_activity,
            ConnectionActivityTimes {
                last_test_at: Some(quiet_test_at),
                last_refresh_at: Some(quiet_refresh_at),
            },
            "durable activity timestamps must survive global history pruning"
        );
    }
}
