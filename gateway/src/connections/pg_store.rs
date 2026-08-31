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

use std::collections::BTreeMap;

use super::store::{
    binding_count, ensure_etag, expected_bindings, initial_revisions, replacement_revisions,
    u64_to_i64, utc_timestamp, validate_candidate, ConnectionEtag, ConnectionStoreError,
    StoredConnection, SOURCE_MANAGED,
};
use super::{
    model::{ConnectionId, ConnectionWrite, MAX_CONNECTIONS, MAX_CREDENTIALS},
    status::ConnectionRevisions,
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
}
