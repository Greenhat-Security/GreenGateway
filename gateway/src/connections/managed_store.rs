//! The managed-connection store dispatch (issue #241, PR 8).
//!
//! Standalone mode serves from the SQLite store exactly as before; cluster
//! mode serves from the PostgreSQL authority with the same method surface
//! and semantics (compare-and-swap etags, per-axis revisions, catalog
//! revisions, capacity bounds).
//!
//! Every method here is `async`, and the two arms reach that contract from
//! opposite directions:
//!
//! - The **SQLite** arm runs its synchronous `rusqlite` body on Tokio's
//!   blocking pool (`spawn_blocking`), never on a request executor. That is
//!   the rule `crate::storage` states for every standalone adapter, and it
//!   is what the catalog services were already doing by hand at each call
//!   site; moving it in here makes it impossible to forget and lets one
//!   call site serve both modes.
//! - The **PostgreSQL** arm awaits the authority.
//!
//! Callers must therefore be async contexts with a Tokio runtime. The one
//! exception is startup: the app builder is synchronous, so the `boot_*`
//! readers below serve the app builder from state `run()` already fetched
//! (cluster mode) or read SQLite directly (standalone mode).

use std::collections::BTreeMap;
#[cfg(feature = "postgres")]
use std::sync::{Arc, Mutex};

use super::model::ConnectionId;
use super::model::ConnectionWrite;
#[cfg(feature = "postgres")]
use super::pg_store::PostgresConnectionStore;
use super::status::SafeConnectionStatus;
use super::store::{
    CollectionCheck, ConnectionDependency, ConnectionDependencyKind, ConnectionEtag,
    ConnectionStatusUpdate, ConnectionStore, ConnectionStoreError, SqliteConnectionStore,
    StoredConnection, StoredEnumSourceRevision, StoredEnumSourceValue, StoredEnumSourceValueWrite,
    StoredMcpCatalog, StoredMcpCatalogEntry, StoredMcpResource, StoredMcpResourceTemplate,
    StoredOpenApiCatalog, StoredOpenApiCatalogEntry, StoredOpenApiInventoryCatalog,
    StoredOpenApiOverlay, StoredOverlayWrite,
};

/// What the authority held when this replica started, fetched by `run()`
/// while it still had an async context and handed to the synchronous app
/// builder. Only the `boot_*` readers consult it; every read after startup
/// goes through the async surface, and the reconciler owns freshness from
/// that point on.
#[cfg(feature = "postgres")]
pub struct ClusterConnectionsBoot {
    pub mcp_catalogs: Vec<StoredMcpCatalog>,
    pub openapi_catalogs: Vec<StoredOpenApiCatalog>,
    pub openapi_inventory_catalogs: Vec<StoredOpenApiInventoryCatalog>,
    pub openapi_overlays: Vec<StoredOpenApiOverlay>,
    /// Full enum payloads may be large and have exactly one startup consumer.
    /// Taking them prevents the cluster boot snapshot from retaining a second
    /// copy for the lifetime of every ManagedConnectionStore clone.
    pub enum_source_values: Mutex<Option<Vec<StoredEnumSourceValue>>>,
}

/// Which authority owns the managed-connection store for this process.
#[derive(Clone)]
pub enum ManagedConnectionStore {
    Sqlite(SqliteConnectionStore),
    #[cfg(feature = "postgres")]
    Postgres {
        store: Arc<PostgresConnectionStore>,
        boot: Arc<ClusterConnectionsBoot>,
    },
}

/// Run a synchronous SQLite body on the blocking pool. A join failure means
/// the runtime is shutting down or the body panicked; either way the store
/// could not be consulted, which is
/// [`ConnectionStoreError::Unavailable`] -- the fail-closed classification,
/// never a "not found" or a success.
async fn blocking<T, F>(operation: &'static str, body: F) -> Result<T, ConnectionStoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ConnectionStoreError> + Send + 'static,
{
    match tokio::task::spawn_blocking(body).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(
                operation,
                panicked = error.is_panic(),
                "the managed Connection store's blocking worker did not complete"
            );
            Err(ConnectionStoreError::Unavailable { operation })
        }
    }
}

impl ManagedConnectionStore {
    pub fn maximum_connections(&self) -> usize {
        match self {
            Self::Sqlite(store) => store.maximum_connections(),
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.maximum_connections(),
        }
    }

    /// The SQLite store behind a standalone-mode dispatch, if this is one.
    /// The local secret provider is SQLite-only by design (cluster mode
    /// requires an external secret provider, see
    /// `docs/deployment/postgres.md`), so it asks for the concrete store
    /// rather than going through this surface.
    pub fn sqlite(&self) -> Option<&SqliteConnectionStore> {
        match self {
            Self::Sqlite(store) => Some(store),
            #[cfg(feature = "postgres")]
            Self::Postgres { .. } => None,
        }
    }

    /// The security revision at which this resource's authoritative state
    /// last changed, for the cluster security gate. Standalone mode has no
    /// shared revision: its authority is this process.
    #[cfg(feature = "postgres")]
    pub async fn state_revision(&self) -> Option<Result<i64, ConnectionStoreError>> {
        match self {
            Self::Sqlite(_) => None,
            Self::Postgres { store, .. } => Some(store.state_revision().await),
        }
    }

    // -- Boot-path readers -------------------------------------------------
    //
    // The app builder is synchronous, so these must not await. Standalone
    // mode reads SQLite inline exactly as it did before cluster mode
    // existed (startup, before any listener binds, is the one place a
    // blocking SQLite read is not on a request executor); cluster mode
    // serves the snapshot `run()` fetched from the authority.

    pub fn boot_mcp_catalogs(&self) -> Result<Vec<StoredMcpCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.mcp_catalogs(),
            #[cfg(feature = "postgres")]
            Self::Postgres { boot, .. } => Ok(boot.mcp_catalogs.clone()),
        }
    }

    pub fn boot_openapi_catalogs(&self) -> Result<Vec<StoredOpenApiCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.openapi_catalogs(),
            #[cfg(feature = "postgres")]
            Self::Postgres { boot, .. } => Ok(boot.openapi_catalogs.clone()),
        }
    }

    pub fn boot_openapi_catalogs_with_overlays(
        &self,
    ) -> Result<(Vec<StoredOpenApiCatalog>, Vec<StoredOpenApiOverlay>), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.openapi_catalogs_with_overlays(),
            #[cfg(feature = "postgres")]
            Self::Postgres { boot, .. } => {
                Ok((boot.openapi_catalogs.clone(), boot.openapi_overlays.clone()))
            }
        }
    }

    pub fn boot_openapi_overlays(&self) -> Result<Vec<StoredOpenApiOverlay>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.openapi_overlays(),
            #[cfg(feature = "postgres")]
            Self::Postgres { boot, .. } => Ok(boot.openapi_overlays.clone()),
        }
    }

    pub fn boot_enum_source_values(
        &self,
    ) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.enum_source_values(),
            #[cfg(feature = "postgres")]
            Self::Postgres { boot, .. } => Ok(boot
                .enum_source_values
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
                .unwrap_or_default()),
        }
    }

    pub fn boot_openapi_inventory_catalogs(
        &self,
    ) -> Result<Vec<StoredOpenApiInventoryCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.openapi_inventory_catalogs(),
            #[cfg(feature = "postgres")]
            Self::Postgres { boot, .. } => Ok(boot.openapi_inventory_catalogs.clone()),
        }
    }

    // -- Records -----------------------------------------------------------

    pub async fn count(&self) -> Result<usize, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("connection count", move || ConnectionStore::count(&store)).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.count().await,
        }
    }

    pub async fn list(&self) -> Result<Vec<StoredConnection>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("connection list", move || ConnectionStore::list(&store)).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.list().await,
        }
    }

    pub async fn get(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredConnection>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("connection read", move || ConnectionStore::get(&store, &id)).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.get(id).await,
        }
    }

    /// `collection` is the cross-replica half of the caller's `If-Match`
    /// (see [`CollectionCheck`]). The SQLite arm does not consult it: a
    /// standalone process's runtime snapshot is the only writer's view, so
    /// the control plane's local check against it is already
    /// authoritative. The PostgreSQL arm re-checks under the authority's
    /// lock, where the local check can be stale.
    pub async fn create(
        &self,
        candidate: ConnectionWrite,
        actor: &str,
        collection: Option<CollectionCheck<'_>>,
    ) -> Result<StoredConnection, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let _ = (actor, collection);
                let store = store.clone();
                blocking("connection create", move || {
                    ConnectionStore::create(&store, candidate)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.create(candidate, actor, collection).await,
        }
    }

    pub async fn replace(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        candidate: ConnectionWrite,
        actor: &str,
    ) -> Result<StoredConnection, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let _ = actor;
                let store = store.clone();
                let id = id.clone();
                let expected = expected.clone();
                blocking("connection replace", move || {
                    ConnectionStore::replace(&store, &id, &expected, candidate)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.replace(id, expected, candidate, actor).await,
        }
    }

    pub async fn delete(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        actor: &str,
    ) -> Result<(), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let _ = actor;
                let store = store.clone();
                let id = id.clone();
                let expected = expected.clone();
                blocking("connection delete", move || {
                    ConnectionStore::delete(&store, &id, &expected)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.delete(id, expected, actor).await,
        }
    }

    // -- Status ------------------------------------------------------------

    pub async fn append_status(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
    ) -> Result<SafeConnectionStatus, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                let expected = expected.clone();
                blocking("connection status append", move || {
                    store.append_status(&id, &expected, update)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.append_status(id, expected, update).await,
        }
    }

    pub async fn append_status_before(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
        deadline: std::time::Instant,
    ) -> Result<(SafeConnectionStatus, StoredConnection), ConnectionStoreError> {
        // The deadline is checked here as well as inside the body: the
        // blocking pool can queue, and a caller that has already run out of
        // time must get `DeadlineExceeded` rather than start work.
        super::store::remaining_before(deadline, "connection status persistence")?;
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                let expected = expected.clone();
                blocking("connection status persistence", move || {
                    store.append_status_before(&id, &expected, update, deadline)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => {
                // The session `lock_timeout` bounds the authority by a
                // global setting, not by THIS caller's deadline: a probe
                // with a few milliseconds left must not wait out a pool
                // checkout and a lock wait measured in seconds. The whole
                // operation runs inside the remaining budget and reports
                // `DeadlineExceeded` when it runs out -- the classification
                // the connection test maps to its own timeout response.
                let remaining =
                    super::store::remaining_before(deadline, "connection status persistence")?;
                match tokio::time::timeout(
                    remaining,
                    store.append_status_before(id, expected, update),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_elapsed) => Err(ConnectionStoreError::DeadlineExceeded {
                        operation: "connection status persistence",
                    }),
                }
            }
        }
    }

    pub async fn latest_status(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<SafeConnectionStatus>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("connection status read", move || store.latest_status(&id)).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.latest_status(id).await,
        }
    }

    /// Every listed Connection's latest safe status in one pass (one lock
    /// on SQLite, one round trip on PostgreSQL).
    pub async fn latest_statuses(
        &self,
        ids: &[ConnectionId],
    ) -> Result<BTreeMap<ConnectionId, SafeConnectionStatus>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let ids = ids.to_vec();
                blocking("connection status read", move || {
                    store.latest_statuses(&ids)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.latest_statuses(ids).await,
        }
    }

    /// The authority's status revision per Connection (cluster mode); empty
    /// in standalone mode, where the runtime record is the authority.
    pub async fn status_revisions(
        &self,
        ids: &[ConnectionId],
    ) -> Result<BTreeMap<ConnectionId, u64>, ConnectionStoreError> {
        match self {
            Self::Sqlite(_) => {
                let _ = ids;
                Ok(BTreeMap::new())
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.status_revisions(ids).await,
        }
    }

    pub async fn status_history(
        &self,
        id: &ConnectionId,
        limit: usize,
    ) -> Result<Vec<SafeConnectionStatus>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("connection status history", move || {
                    store.status_history(&id, limit)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.status_history(id, limit).await,
        }
    }

    /// The last-test and last-refresh times the admin listing reports.
    /// Derived state: the status path writes both columns, and this only
    /// reads them back.
    pub async fn activity_times(
        &self,
    ) -> Result<BTreeMap<ConnectionId, super::store::ConnectionActivityTimes>, ConnectionStoreError>
    {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("connection activity times", move || store.activity_times()).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.activity_times().await,
        }
    }

    // -- Dependencies ------------------------------------------------------

    pub async fn add_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                let consumer_id = consumer_id.to_owned();
                blocking("connection dependency add", move || {
                    store.add_dependency(&id, kind, &consumer_id)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.add_dependency(id, kind, consumer_id).await,
        }
    }

    pub async fn remove_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                let consumer_id = consumer_id.to_owned();
                blocking("connection dependency remove", move || {
                    store.remove_dependency(&id, kind, &consumer_id)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.remove_dependency(id, kind, consumer_id).await,
        }
    }

    pub async fn replace_dependencies_for_kind(
        &self,
        kind: ConnectionDependencyKind,
        desired: &[(ConnectionId, String)],
        source_revision: i64,
    ) -> Result<(), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                // Standalone mode has one process deriving the set: nothing
                // can flush a stale one, so the fence is not needed there.
                let _ = source_revision;
                let store = store.clone();
                let desired = desired.to_vec();
                blocking("connection dependency replace", move || {
                    store.replace_dependencies_for_kind(kind, &desired)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => {
                store
                    .replace_dependencies_for_kind(kind, desired, source_revision)
                    .await
            }
        }
    }

    pub async fn dependencies(
        &self,
        id: &ConnectionId,
    ) -> Result<Vec<ConnectionDependency>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("connection dependency list", move || {
                    store.dependencies(&id)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.dependencies(id).await,
        }
    }

    pub async fn dependency_counts(
        &self,
    ) -> Result<BTreeMap<ConnectionId, usize>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("connection dependency counts", move || {
                    store.dependency_counts()
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.dependency_counts().await,
        }
    }

    // -- MCP catalogs ------------------------------------------------------

    pub async fn mcp_catalogs(&self) -> Result<Vec<StoredMcpCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("mcp catalog list", move || store.mcp_catalogs()).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.mcp_catalogs().await,
        }
    }

    pub async fn mcp_catalog(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredMcpCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("mcp catalog read", move || store.mcp_catalog(&id)).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.mcp_catalog(id).await,
        }
    }

    #[allow(clippy::too_many_arguments)] // The store's own signature, one per axis.
    pub async fn replace_mcp_catalog(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        entries: &[StoredMcpCatalogEntry],
        resources: &[StoredMcpResource],
        resource_templates: &[StoredMcpResourceTemplate],
        expected_catalog_revision: u64,
        actor: &str,
    ) -> Result<StoredMcpCatalog, ConnectionStoreError> {
        // `expected_catalog_revision` is the catalog's own compare-and-swap
        // (`0` = no catalog yet). The connection ETag does not move on a
        // catalog replacement and the per-process refresh guard does not
        // reach other replicas, so without it two replicas discovering
        // from the same prior catalog would let the slower, older result
        // commit last. Both arms enforce it.
        match self {
            Self::Sqlite(store) => {
                let _ = actor;
                let store = store.clone();
                let id = id.clone();
                let expected = expected.clone();
                let entries = entries.to_vec();
                let resources = resources.to_vec();
                let resource_templates = resource_templates.to_vec();
                blocking("mcp catalog replace", move || {
                    store.replace_mcp_catalog_expecting(
                        &id,
                        &expected,
                        &entries,
                        &resources,
                        &resource_templates,
                        Some(expected_catalog_revision),
                    )
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => {
                store
                    .replace_mcp_catalog(
                        id,
                        expected,
                        entries,
                        resources,
                        resource_templates,
                        expected_catalog_revision,
                        actor,
                    )
                    .await
            }
        }
    }

    // -- OpenAPI catalogs --------------------------------------------------

    pub async fn openapi_catalogs(
        &self,
    ) -> Result<Vec<StoredOpenApiCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("openapi catalog list", move || store.openapi_catalogs()).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.openapi_catalogs().await,
        }
    }

    pub async fn openapi_inventory_catalogs(
        &self,
    ) -> Result<Vec<StoredOpenApiInventoryCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("openapi inventory catalog list", move || {
                    store.openapi_inventory_catalogs()
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.openapi_inventory_catalogs().await,
        }
    }

    pub async fn openapi_catalog(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredOpenApiCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("openapi catalog read", move || store.openapi_catalog(&id)).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.openapi_catalog(id).await,
        }
    }

    pub async fn openapi_catalogs_with_overlays(
        &self,
    ) -> Result<(Vec<StoredOpenApiCatalog>, Vec<StoredOpenApiOverlay>), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("OpenAPI catalog/overlay snapshot", move || {
                    store.openapi_catalogs_with_overlays()
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.openapi_catalogs_with_overlays().await,
        }
    }

    pub async fn openapi_catalog_with_overlay(
        &self,
        id: &ConnectionId,
    ) -> Result<(Option<StoredOpenApiCatalog>, Option<StoredOpenApiOverlay>), ConnectionStoreError>
    {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("OpenAPI catalog/overlay read", move || {
                    store.openapi_catalog_with_overlay(&id)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.openapi_catalog_with_overlay(id).await,
        }
    }

    pub async fn openapi_overlays(
        &self,
    ) -> Result<Vec<StoredOpenApiOverlay>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("OpenAPI overlays read", move || store.openapi_overlays()).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.openapi_overlays().await,
        }
    }

    pub async fn openapi_overlay(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredOpenApiOverlay>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("OpenAPI overlay read", move || store.openapi_overlay(&id)).await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.openapi_overlay(id).await,
        }
    }

    pub async fn enum_source_values(
        &self,
    ) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("enum source values read", move || {
                    store.enum_source_values()
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.enum_source_values().await,
        }
    }

    pub async fn enum_source_values_for_connection(
        &self,
        id: &ConnectionId,
    ) -> Result<Vec<StoredEnumSourceValue>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                blocking("enum source values read", move || {
                    store.enum_source_values_for_connection(&id)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.enum_source_values_for_connection(id).await,
        }
    }

    pub async fn enum_source_revisions(
        &self,
    ) -> Result<Vec<StoredEnumSourceRevision>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                blocking("enum source revisions read", move || {
                    store.enum_source_revisions()
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.enum_source_revisions().await,
        }
    }

    pub async fn enum_source_value(
        &self,
        id: &ConnectionId,
        source_id: &str,
    ) -> Result<Option<StoredEnumSourceValue>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let id = id.clone();
                let source_id = source_id.to_owned();
                blocking("enum source value read", move || {
                    store.enum_source_value(&id, &source_id)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => store.enum_source_value(id, source_id).await,
        }
    }

    pub async fn replace_enum_source_value(
        &self,
        write: &StoredEnumSourceValueWrite,
        expected_values_revision: u64,
    ) -> Result<StoredEnumSourceValue, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let store = store.clone();
                let write = write.clone();
                blocking("enum source value replace", move || {
                    store.replace_enum_source_value(&write, expected_values_revision)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => {
                store
                    .replace_enum_source_value(write, expected_values_revision)
                    .await
            }
        }
    }

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
        actor: &str,
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
            actor,
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
        actor: &str,
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
            actor,
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
        actor: &str,
        policy_protected_names: &[String],
        enum_values: &[StoredEnumSourceValueWrite],
    ) -> Result<StoredOpenApiCatalog, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let _ = actor;
                let store = store.clone();
                let id = id.clone();
                let expected_connection_etag = expected_connection_etag.clone();
                let spec = spec.to_owned();
                let spec_digest = spec_digest.to_owned();
                let entries = entries.to_vec();
                let overlay = overlay.cloned();
                let actor = actor.to_owned();
                let policy_protected_names = policy_protected_names.to_vec();
                let enum_values = enum_values.to_vec();
                blocking("openapi catalog replace", move || {
                    store.replace_openapi_catalog_with_overlay_and_enum_values(
                        &id,
                        &expected_connection_etag,
                        expected_spec_revision,
                        expected_catalog_revision,
                        &spec,
                        &spec_digest,
                        &entries,
                        overlay.as_ref(),
                        compiled_overlay_revision,
                        &actor,
                        &policy_protected_names,
                        &enum_values,
                    )
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres { store, .. } => {
                store
                    .replace_openapi_catalog_with_overlay_and_enum_values(
                        id,
                        expected_connection_etag,
                        expected_spec_revision,
                        expected_catalog_revision,
                        spec,
                        spec_digest,
                        entries,
                        overlay,
                        compiled_overlay_revision,
                        actor,
                        policy_protected_names,
                        enum_values,
                    )
                    .await
            }
        }
    }
}
