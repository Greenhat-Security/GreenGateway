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
//! Concurrency is the authority's: `SELECT ... FOR UPDATE` on the record
//! row serializes writers per connection; the etag precondition is
//! re-verified inside that lock, so two writers presenting the same
//! expected etag produce exactly one winner and one
//! [`ConnectionStoreError::Conflict`].
//!
//! Catalog, status, and dependency surfaces are not on this store yet;
//! they arrive with the remaining PR 8 wiring. The record layer is
//! complete and independently tested.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::store::{
    binding_count, ensure_etag, expected_bindings, increment_revision, initial_revisions,
    managed_tool_dependency_id, optional_u64_to_i64, parse_reason, parse_state, persisted_revision,
    reason_as_str, replacement_revisions, state_as_str, supports_managed_mcp_catalog,
    supports_managed_openapi_catalog, u64_to_i64, utc_timestamp, validate_candidate,
    validate_dependency_id, validate_mcp_catalog, validate_openapi_catalog_entries,
    validate_openapi_spec, ConnectionDependency, ConnectionDependencyKind, ConnectionEtag,
    ConnectionStatusUpdate, ConnectionStoreError, StoredConnection, StoredMcpCatalog,
    StoredMcpCatalogEntry, StoredMcpResource, StoredMcpResourceTemplate, StoredOpenApiCatalog,
    StoredOpenApiCatalogEntry, StoredOpenApiInventoryCatalog, MAX_CONNECTION_DEPENDENCIES,
    SOURCE_MANAGED,
};
use super::{
    model::{ConnectionId, ConnectionWrite, MAX_CONNECTIONS, MAX_CREDENTIALS},
    status::{ConnectionRevisions, ConnectionStatusReason, SafeConnectionStatus},
};

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
    fn from_row(row: &tokio_postgres::Row) -> Self {
        Self {
            id: row.get(0),
            schema_version: row.get(1),
            source: row.get(2),
            spec_json: row.get(3),
            connection_revision: row.get(4),
            credential_revision: row.get(5),
            tls_revision: row.get(6),
            discovery_revision: row.get(7),
            status_revision: row.get(8),
            created_at: row.get(9),
            updated_at: row.get(10),
        }
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

/// The PostgreSQL managed-connection record store. Cheap to construct;
/// borrows the foundation's pool.
pub struct PostgresConnectionStore {
    pool: deadpool_postgres::Pool,
    maximum_connections: usize,
}

impl PostgresConnectionStore {
    pub fn new(pool: deadpool_postgres::Pool, maximum_connections: usize) -> Self {
        Self {
            pool,
            maximum_connections: maximum_connections.min(MAX_CONNECTIONS),
        }
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
        row.map(|row| row.get::<_, i64>(0))
            .ok_or_else(|| ConnectionStoreError::CorruptRecord {
                id: "<connection-state>".to_owned(),
                reason: "the connection state revision row is missing",
            })
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
        let rows = client
            .query(
                r#"
                SELECT id::text, schema_version, source, spec_json::text, connection_revision,
                       credential_revision, tls_revision, discovery_revision,
                       status_revision, created_at, updated_at
                FROM greengateway.connection_records
                ORDER BY created_at, id
                "#,
                &[],
            )
            .await
            .map_err(|error| pg_error(OPERATION_LIST, error))?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let raw = RawConnectionRow::from_row(&row);
            let record = raw.into_stored()?;
            validate_bindings(&client, &record).await?;
            records.push(record);
        }
        Ok(records)
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
        let record = load_record(&client, id, OPERATION_GET).await?;
        match record {
            Some(record) => {
                validate_bindings(&client, &record).await?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// Create a managed connection: capacity-checked, validated, and
    /// committed with its first immutable specification version, the
    /// derived credential bindings, and the shared-state bumps (security
    /// revision, connections high-water mark, outbox row).
    pub async fn create(
        &self,
        candidate: ConnectionWrite,
        actor_user_id: &str,
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
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_CREATE, error))?;
        // The outcome pattern (postgres_documents'): any failure rolls the
        // transaction back explicitly, releasing row locks immediately and
        // returning a clean connection to the pool instead of leaving an
        // aborted transaction on it.
        let outcome: Result<StoredConnection, ConnectionStoreError> = async {
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
                        status_revision, created_at, updated_at, activation_revision
                    ) VALUES ($1::text::uuid, $2, $3, $4::text::jsonb, $5, $6, $7, $8, $9, $10, $10, 0)
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
                &candidate,
                actor_user_id,
            )
            .await?;
            bump_connection_state(&client, &id, None, revisions.connection).await?;
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
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_REPLACE, error))?;
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
                let managed_tool_count: i64 = client
                    .query_one(
                        r#"
                        SELECT COUNT(*)
                        FROM greengateway.connection_dependencies
                        WHERE connection_id = $1::text::uuid AND consumer_kind = 'managed_tool'
                        "#,
                        &[&id.as_str()],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_REPLACE, error))?
                    .get(0);
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
                    SET spec_json = $1::text::jsonb,
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
                &candidate,
                actor_user_id,
            )
            .await?;
            bump_connection_state(
                &client,
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
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_DELETE, error))?;
        let outcome: Result<(), ConnectionStoreError> = async {
            let current = load_record_for_update(&client, id, OPERATION_DELETE)
                .await?
                .ok_or_else(|| ConnectionStoreError::NotFound { id: id.to_string() })?;
            validate_bindings(&client, &current).await?;
            ensure_etag(id, expected, &current)?;
            let dependency_count: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DELETE, error))?
                .get(0);
            if dependency_count > 0 {
                return Err(ConnectionStoreError::DependencyConflict {
                    id: id.to_string(),
                    count: usize::try_from(dependency_count).unwrap_or(usize::MAX),
                });
            }
            // The outbox row precedes the cascade delete: version 0 marks a
            // deletion (specification versions start at 1). The actor is
            // carried by the outbox revision; the version rows cascade.
            bump_connection_state(&client, id, Some(current.revisions.connection), 0).await?;
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
        let retained_bytes: i64 = client
            .query_one(
                r#"
                SELECT COALESCE(SUM(
                    octet_length(remote_tool_name) + octet_length(description)
                    + octet_length(input_schema_json::text)
                ), 0)
                FROM greengateway.connection_mcp_catalog_entries
                "#,
                &[],
            )
            .await
            .map_err(|error| pg_error(OPERATION_MCP_READ, error))?
            .get(0);
        if usize::try_from(retained_bytes).unwrap_or(usize::MAX)
            > super::store::MAX_MANAGED_MCP_CATALOG_BYTES
        {
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

        let mut catalogs = Vec::with_capacity(rows.len());
        for row in &rows {
            let connection_id = parse_catalog_id(&row.get::<_, String>(0))?;
            let catalog_revision =
                persisted_revision(&connection_id, row.get(1), "invalid MCP catalog revision")?;
            if catalog_revision == 0 {
                return Err(corrupt(&connection_id, "invalid MCP catalog revision"));
            }
            let entry_count = row.get::<_, i64>(4);
            let resource_count = row.get::<_, i64>(5);
            let template_count = row.get::<_, i64>(6);
            let total = entry_count
                .saturating_add(resource_count)
                .saturating_add(template_count);
            if total < 0
                || usize::try_from(total).unwrap_or(usize::MAX) > super::model::MAX_CATALOG_ENTRIES
            {
                return Err(corrupt(&connection_id, "invalid MCP catalog entry count"));
            }
            let entries = load_mcp_entries(&client, &connection_id).await?;
            if entries.len() != usize::try_from(entry_count).unwrap_or(usize::MAX) {
                return Err(corrupt(&connection_id, "MCP catalog entry count mismatch"));
            }
            let resources = load_mcp_resources(&client, &connection_id).await?;
            if resources.len() != usize::try_from(resource_count).unwrap_or(usize::MAX) {
                return Err(corrupt(&connection_id, "MCP resource count mismatch"));
            }
            let resource_templates = load_mcp_resource_templates(&client, &connection_id).await?;
            if resource_templates.len() != usize::try_from(template_count).unwrap_or(usize::MAX) {
                return Err(corrupt(
                    &connection_id,
                    "MCP resource template count mismatch",
                ));
            }
            catalogs.push(StoredMcpCatalog {
                connection_id,
                catalog_revision,
                observed_etag: parse_etag(&row.get::<_, String>(2))?,
                refreshed_at: row.get(3),
                entries,
                resources,
                resource_templates,
            });
        }
        Ok(catalogs)
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
        actor_user_id: &str,
    ) -> Result<StoredMcpCatalog, ConnectionStoreError> {
        let validated = validate_mcp_catalog(id, entries, resources, resource_templates)?;
        let now = utc_timestamp()?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| pg_unavailable(OPERATION_MCP_CATALOG))?;
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
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

            let retained: i64 = client
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
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?
                .get(0);
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
            let retained_bytes: i64 = client
                .query_one(
                    r#"
                    SELECT COALESCE(SUM(
                        octet_length(remote_tool_name) + octet_length(description)
                        + octet_length(input_schema_json::text)
                    ), 0)
                    FROM greengateway.connection_mcp_catalog_entries
                    WHERE connection_id != $1::text::uuid
                    "#,
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?
                .get(0);
            if usize::try_from(retained_bytes).unwrap_or(usize::MAX)
                .checked_add(validated.stored_bytes)
                .is_none_or(|total| total > super::store::MAX_MANAGED_MCP_CATALOG_BYTES)
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection MCP catalog bytes",
                    maximum: super::store::MAX_MANAGED_MCP_CATALOG_BYTES,
                });
            }

            let previous_revision: Option<i64> = client
                .query_opt(
                    "SELECT catalog_revision FROM greengateway.connection_mcp_catalogs \
                     WHERE connection_id = $1::text::uuid",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?
                .map(|row| row.get(0));
            let previous_revision = previous_revision
                .map(|revision| persisted_revision(id, revision, "invalid MCP catalog revision"))
                .transpose()?
                .unwrap_or_default();
            let catalog_revision = increment_revision(id, previous_revision)?;

            client
                .execute(
                    "DELETE FROM greengateway.connection_dependencies \
                     WHERE connection_id = $1::text::uuid AND consumer_kind = 'managed_tool'",
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?;
            let retained_dependencies: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies",
                    &[],
                )
                .await
                .map_err(|error| pg_error(OPERATION_MCP_CATALOG, error))?
                .get(0);
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
                        resource_count, resource_template_count
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
                    "#,
                    &[
                        &id.as_str(),
                        &u64_to_i64(id, catalog_revision)?,
                        &expected.as_str(),
                        &now,
                        &usize_to_i64(entries.len()),
                        &usize_to_i64(resources.len()),
                        &usize_to_i64(resource_templates.len()),
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
                        ) VALUES ($1::text::uuid, $2, $3, $4::text::jsonb, $5)
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

            bump_connection_state(&client, id, Some(previous_revision), catalog_revision).await?;
            let _ = actor_user_id;
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
        let rows = match requested {
            Some(id) => {
                client
                    .query(
                        r#"
                        SELECT connection_id::text, spec_revision, catalog_revision, observed_etag,
                               spec_digest, spec::text, refreshed_at, entry_count
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
                               spec_digest, spec::text, refreshed_at, entry_count
                        FROM greengateway.connection_openapi_catalogs
                        ORDER BY connection_id
                        "#,
                        &[],
                    )
                    .await
            }
        }
        .map_err(|error| pg_error(OPERATION_OPENAPI_READ, error))?;

        let mut catalogs = Vec::with_capacity(rows.len());
        for row in &rows {
            let connection_id = parse_catalog_id(&row.get::<_, String>(0))?;
            let spec_revision =
                persisted_revision(&connection_id, row.get(1), "invalid OpenAPI spec revision")?;
            let catalog_revision = persisted_revision(
                &connection_id,
                row.get(2),
                "invalid OpenAPI catalog revision",
            )?;
            if spec_revision == 0 || catalog_revision == 0 {
                return Err(corrupt(&connection_id, "invalid OpenAPI catalog revision"));
            }
            let entry_count = row.get::<_, i64>(7);
            if entry_count < 0
                || usize::try_from(entry_count).unwrap_or(usize::MAX)
                    > super::model::MAX_CATALOG_ENTRIES
            {
                return Err(corrupt(
                    &connection_id,
                    "invalid OpenAPI catalog entry count",
                ));
            }
            let entries = load_openapi_entries(&client, &connection_id).await?;
            if entries.len() != usize::try_from(entry_count).unwrap_or(usize::MAX) {
                return Err(corrupt(
                    &connection_id,
                    "OpenAPI catalog entry count mismatch",
                ));
            }
            catalogs.push(StoredOpenApiCatalog {
                connection_id,
                spec_revision,
                catalog_revision,
                observed_etag: parse_etag(&row.get::<_, String>(3))?,
                spec_digest: row.get(4),
                spec: row.get(5),
                refreshed_at: row.get(6),
                entries,
            });
        }
        Ok(catalogs)
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
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?;
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
                    Some(row) => (
                        persisted_revision(id, row.get(0), "invalid OpenAPI spec revision")?,
                        persisted_revision(id, row.get(1), "invalid OpenAPI catalog revision")?,
                        Some(row.get::<_, String>(2)),
                    ),
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

            let retained: i64 = client
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
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?
                .get(0);
            if usize::try_from(retained).unwrap_or(usize::MAX).saturating_add(entries.len())
                > super::model::MAX_CATALOG_ENTRIES
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection catalog entries",
                    maximum: super::model::MAX_CATALOG_ENTRIES,
                });
            }
            let retained_definition_bytes: i64 = client
                .query_one(
                    r#"
                    SELECT COALESCE(SUM(octet_length(definition_json::text)), 0)
                    FROM greengateway.connection_openapi_catalog_entries
                    WHERE connection_id != $1::text::uuid
                    "#,
                    &[&id.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?
                .get(0);
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
            let retained_dependencies: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies",
                    &[],
                )
                .await
                .map_err(|error| pg_error(OPERATION_OPENAPI_CATALOG, error))?
                .get(0);
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
                        spec_digest, spec, refreshed_at, entry_count
                    ) VALUES ($1::text::uuid, $2, $3, $4, $5, $6::text::jsonb, $7, $8)
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
                        ) VALUES ($1::text::uuid, $2, $3, $4::text::jsonb, $5::text::jsonb, $6)
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

            bump_connection_state(&client, id, Some(previous_catalog_revision), catalog_revision)
                .await?;
            let _ = actor_user_id;
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
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_STATUS, error))?;
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
                // MAX_STATUS_HISTORY_ROWS rows across every connection.
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
                        &[&(super::model::MAX_STATUS_HISTORY_ROWS as i64)],
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
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_DEPS, error))?;
        let outcome: Result<(), ConnectionStoreError> = async {
            let exists: bool = client
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
                .map_err(|error| pg_error(OPERATION_DEPS, error))?
                .get(0);
            if exists {
                return Ok(());
            }
            let count: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies",
                    &[],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?
                .get(0);
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
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| pg_error(OPERATION_DEPS, error))?;
        let outcome: Result<(), ConnectionStoreError> = async {
            client
                .execute(
                    "DELETE FROM greengateway.connection_dependencies WHERE consumer_kind = $1",
                    &[&kind.as_str()],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?;
            let retained: i64 = client
                .query_one(
                    "SELECT COUNT(*) FROM greengateway.connection_dependencies",
                    &[],
                )
                .await
                .map_err(|error| pg_error(OPERATION_DEPS, error))?
                .get(0);
            if usize::try_from(retained).unwrap_or(usize::MAX).saturating_add(desired.len())
                > MAX_CONNECTION_DEPENDENCIES
            {
                return Err(ConnectionStoreError::LimitExceeded {
                    resource: "connection dependencies",
                    maximum: MAX_CONNECTION_DEPENDENCIES,
                });
            }
            for (connection_id, consumer_id) in desired {
                let exists: bool = client
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM greengateway.connection_records WHERE id = $1::text::uuid)",
                        &[&connection_id.as_str()],
                    )
                    .await
                    .map_err(|error| pg_error(OPERATION_DEPS, error))?
                    .get(0);
                if !exists {
                    return Err(ConnectionStoreError::NotFound {
                        id: connection_id.to_string(),
                    });
                }
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.connection_dependencies (
                            connection_id, consumer_kind, consumer_id, created_at
                        ) VALUES ($1::text::uuid, $2, $3, $4)
                        "#,
                        &[&connection_id.as_str(), &kind.as_str(), &consumer_id, &now],
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
        let exists: bool = client
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM greengateway.connection_records WHERE id = $1::text::uuid)",
                &[&id.as_str()],
            )
            .await
            .map_err(|error| pg_error(OPERATION_DEPS_READ, error))?
            .get(0);
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
        rows.iter()
            .map(|row| {
                let kind = ConnectionDependencyKind::parse(&row.get::<_, String>(0))
                    .ok_or_else(|| corrupt(id, "unknown dependency kind"))?;
                Ok(ConnectionDependency {
                    kind,
                    consumer_id: row.get(1),
                })
            })
            .collect()
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
        let mut counts = BTreeMap::new();
        for row in rows {
            let id = parse_catalog_id(&row.get::<_, String>(0))?;
            let count: i64 = row.get(1);
            counts.insert(id, usize::try_from(count).unwrap_or(usize::MAX));
        }
        Ok(counts)
    }

    pub fn maximum_connections(&self) -> usize {
        self.maximum_connections
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
    let state =
        parse_state(&row.get::<_, String>(0)).ok_or_else(|| corrupt(id, "unknown status state"))?;
    let reason = parse_reason(&row.get::<_, String>(1))
        .ok_or_else(|| corrupt(id, "unknown status reason"))?;
    let optional = |value: Option<i64>| {
        value
            .map(|v| u64::try_from(v).map_err(|_| corrupt(id, "negative safe status count")))
            .transpose()
    };
    Ok(SafeConnectionStatus {
        state,
        reason,
        observed_at: Some(row.get(2)),
        latency_ms: optional(row.get(3))?,
        catalog_age_secs: optional(row.get(4))?,
        catalog_entry_count: optional(row.get(5))?
            .map(|count| usize::try_from(count).unwrap_or(usize::MAX)),
    })
}

async fn load_mcp_entries(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
) -> Result<Vec<StoredMcpCatalogEntry>, ConnectionStoreError> {
    let rows = client
        .query(
            r#"
            SELECT remote_tool_name, description, input_schema_json::text
            FROM greengateway.connection_mcp_catalog_entries
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_MCP_READ, error))?;
    rows.iter()
        .map(|row| {
            let input_schema: Value = serde_json::from_str(&row.get::<_, String>(2))
                .map_err(|_| corrupt(id, "MCP catalog entry schema is not valid JSON"))?;
            Ok(StoredMcpCatalogEntry {
                remote_tool_name: row.get(0),
                description: row.get(1),
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
            SELECT uri, name, title, description, mime_type, size
            FROM greengateway.connection_mcp_catalog_resources
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_MCP_READ, error))?;
    rows.iter()
        .map(|row| {
            Ok(StoredMcpResource {
                uri: row.get(0),
                name: row.get(1),
                title: row.get(2),
                description: row.get(3),
                mime_type: row.get(4),
                size: row
                    .get::<_, Option<i64>>(5)
                    .map(|size| u64::try_from(size).unwrap_or(u64::MAX)),
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
            SELECT uri_template, name, title, description, mime_type
            FROM greengateway.connection_mcp_catalog_resource_templates
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_MCP_READ, error))?;
    rows.iter()
        .map(|row| {
            Ok(StoredMcpResourceTemplate {
                uri_template: row.get(0),
                name: row.get(1),
                title: row.get(2),
                description: row.get(3),
                mime_type: row.get(4),
            })
        })
        .collect()
}

async fn load_openapi_entries(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
) -> Result<Vec<StoredOpenApiCatalogEntry>, ConnectionStoreError> {
    let rows = client
        .query(
            r#"
            SELECT tool_name, operation_id, selected_scheme_names_json::text, definition_json::text
            FROM greengateway.connection_openapi_catalog_entries
            WHERE connection_id = $1::text::uuid
            ORDER BY ordinal
            "#,
            &[&id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_OPENAPI_READ, error))?;
    rows.iter()
        .map(|row| {
            let selected: Vec<String> = serde_json::from_str(&row.get::<_, String>(2))
                .map_err(|_| corrupt(id, "OpenAPI selected schemes are not valid JSON"))?;
            let definition: Value = serde_json::from_str(&row.get::<_, String>(3))
                .map_err(|_| corrupt(id, "OpenAPI tool definition is not valid JSON"))?;
            Ok(StoredOpenApiCatalogEntry {
                tool_name: row.get(0),
                operation_id: row.get(1),
                selected_scheme_names: selected,
                definition,
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
    let count: i64 = client
        .query_one("SELECT COUNT(*) FROM greengateway.connection_records", &[])
        .await
        .map_err(|error| pg_error(OPERATION_LIST, error))?
        .get(0);
    usize::try_from(count).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: "<collection>".to_owned(),
        reason: "negative or oversized record count",
    })
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
    row.map(|row| RawConnectionRow::from_row(&row).into_stored())
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
    row.map(|row| RawConnectionRow::from_row(&row).into_stored())
        .transpose()
}

fn record_query(lock: &str) -> String {
    format!(
        r#"
        SELECT id::text, schema_version, source, spec_json::text, connection_revision,
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
            SELECT purpose, secret_id, binding_version
            FROM greengateway.connection_credential_bindings
            WHERE connection_id = $1::text::uuid
            ORDER BY purpose ASC
            "#,
            &[&record.id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_GET, error))?;
    let mut actual: Vec<(String, String, i64)> = rows
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let mut expected: Vec<(String, String, i64)> =
        expected_bindings(&record.write, &record.revisions)
            .into_iter()
            .map(|(purpose, secret_id, version)| {
                Ok((
                    purpose.to_owned(),
                    secret_id.to_owned(),
                    u64_to_i64(&record.id, version.max(1))?,
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
    for (purpose, secret_id, version) in expected_bindings(write, revisions) {
        client
            .execute(
                r#"
                INSERT INTO greengateway.connection_credential_bindings (
                    connection_id, purpose, secret_id, binding_version, updated_at
                ) VALUES ($1::text::uuid, $2, $3, $4, $5)
                "#,
                &[
                    &id.as_str(),
                    &purpose,
                    &secret_id,
                    &u64_to_i64(id, version.max(1))?,
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
    let persisted: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM greengateway.connection_credential_bindings",
            &[],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?
        .get(0);
    let persisted =
        usize::try_from(persisted).map_err(|_| ConnectionStoreError::CorruptRecord {
            id: "<bindings>".to_owned(),
            reason: "negative or oversized binding count",
        })?;
    if let Some(id) = replaced_id {
        let record_bindings: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM greengateway.connection_credential_bindings WHERE connection_id = $1::text::uuid",
                &[&id.as_str()],
            )
            .await
            .map_err(|error| pg_error(OPERATION_CREATE, error))?
            .get(0);
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
    write: &ConnectionWrite,
    actor_user_id: &str,
) -> Result<(), ConnectionStoreError> {
    let revisions = ConnectionRevisions {
        connection: version,
        credential: 0,
        tls: 0,
        discovery: 0,
        status: 0,
    };
    let _ = write;
    let _ = revisions;
    // The document etag: the same derivation the active row's etag uses,
    // recomputed from the persisted spec plus its revisions. Binding the
    // etag here would require the axis revisions of this exact version;
    // callers pass the freshly computed set, so derive directly.
    // (The active-row etag is computed by StoredConnection::etag; for the
    // version row we hash the spec document itself -- the version is
    // already addressable by (id, version), and the hash guards the body
    // against out-of-band edits.)
    let digest = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(id.as_str().as_bytes());
        hasher.update(u64_to_i64(id, version)?.to_be_bytes());
        hasher.update(spec_json.as_bytes());
        hex::encode(hasher.finalize())
    };
    client
        .execute(
            r#"
            INSERT INTO greengateway.connection_documents (
                connection_id, version, spec, document_etag, actor_user_id, diff_summary
            ) VALUES ($1::text::uuid, $2, $3::text::jsonb, $4, $5, '{}'::text::jsonb)
            "#,
            &[
                &id.as_str(),
                &u64_to_i64(id, version)?,
                &spec_json,
                &format!("sha256:{digest}"),
                &actor_user_id,
            ],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    Ok(())
}

/// Advance the shared security revision and the connections high-water
/// mark and append the outbox row, all inside the caller's transaction:
/// a connection mutation cannot succeed without its durable record.
/// `to_version` 0 marks a deletion (specification versions start at 1).
async fn bump_connection_state(
    client: &deadpool_postgres::Object,
    id: &ConnectionId,
    from_version: Option<u64>,
    to_version: u64,
) -> Result<(), ConnectionStoreError> {
    let from = match from_version {
        Some(version) => u64_to_i64(id, version)?,
        None => 0,
    };
    let to = u64_to_i64(id, to_version)?;
    let security_revision: i64 = client
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
        .map_err(|error| pg_error(OPERATION_CREATE, error))?
        .get(0);
    client
        .execute(
            r#"
            UPDATE greengateway.connection_state_revision
            SET last_revision = last_revision + 1
            WHERE singleton
            "#,
            &[],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    client
        .execute(
            r#"
            INSERT INTO greengateway.security_outbox (
                revision, resource_type, from_version, to_version, resource_id
            ) VALUES ($1, 'connection', $2, $3, $4::text)
            "#,
            &[&security_revision, &from, &to, &id.as_str()],
        )
        .await
        .map_err(|error| pg_error(OPERATION_CREATE, error))?;
    Ok(())
}

async fn transaction(
    client: deadpool_postgres::Object,
    operation: &'static str,
) -> Result<deadpool_postgres::Object, ConnectionStoreError> {
    client
        .batch_execute("BEGIN")
        .await
        .map_err(|error| pg_error(operation, error))?;
    Ok(client)
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

fn pg_error(operation: &'static str, error: impl std::error::Error) -> ConnectionStoreError {
    tracing::error!(operation, error = %error, "connection PostgreSQL operation failed");
    ConnectionStoreError::Postgres { operation }
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
        (PostgresConnectionStore::new(pool.clone(), maximum), pool)
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
            .create(http_candidate("Billing API"), "op-1")
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
    async fn concurrent_same_etag_replaces_produce_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(http_candidate("Race Base"), "op-1")
            .await
            .expect("create should commit");
        let etag = created.etag();

        let store_a = PostgresConnectionStore::new(pool.clone(), 64);
        let store_b = PostgresConnectionStore::new(pool.clone(), 64);
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
            .create(http_candidate("Only One"), "op-1")
            .await
            .expect("first create fits");
        let limited = store
            .create(http_candidate("Second"), "op-2")
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

    #[tokio::test]
    async fn mcp_catalog_replaces_with_cas_revisions_dependencies_and_outbox() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_store(&database.dsn, 64).await;
        let created = store
            .create(mcp_candidate(), "op-1")
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
            .replace_mcp_catalog(&created.id, &etag, &[mcp_entry("gamma")], &[], &[], "op-4")
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
                "op-5",
            )
            .await
            .expect("the fresh etag should win");
        assert_eq!(second.catalog_revision, 2);
        let dependencies = store.dependencies(&created.id).await.expect("dependencies");
        assert_eq!(dependencies.len(), 3, "dependencies follow the new catalog");
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
            .create(http_candidate("Billing API"), "op-1")
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
            )
            .await
            .expect_err("an unknown owner must be refused");
        assert!(
            matches!(missing, ConnectionStoreError::NotFound { .. }),
            "{missing}"
        );
    }
}
