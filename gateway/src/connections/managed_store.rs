//! The managed-connection store dispatch (issue #241, PR 8).
//!
//! Standalone mode serves from the SQLite store exactly as before; cluster
//! mode serves from the PostgreSQL authority with the same method surface
//! and semantics (compare-and-swap etags, per-axis revisions, catalog
//! revisions, capacity bounds). Every method is `async`: the SQLite arms
//! keep their synchronous bodies (the blocking SQLite call runs on the
//! caller's context exactly as the pre-cluster code did), and the
//! PostgreSQL arms await the authority. Callers must be async contexts --
//! the control plane and catalog services provide them.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::model::ConnectionId;
use super::model::ConnectionWrite;
use super::pg_store::PostgresConnectionStore;
use super::status::SafeConnectionStatus;
use super::store::{
    ConnectionDependency, ConnectionDependencyKind, ConnectionEtag, ConnectionStatusUpdate,
    ConnectionStore, ConnectionStoreError, SqliteConnectionStore, StoredConnection,
    StoredMcpCatalog, StoredMcpCatalogEntry, StoredMcpResource, StoredMcpResourceTemplate,
    StoredOpenApiCatalog, StoredOpenApiCatalogEntry, StoredOpenApiInventoryCatalog,
};

/// Which authority owns the managed-connection store for this process.
pub enum ManagedConnectionStore {
    Sqlite(SqliteConnectionStore),
    #[cfg(feature = "postgres")]
    Postgres(Arc<PostgresConnectionStore>),
}

impl ManagedConnectionStore {
    pub fn maximum_connections(&self) -> usize {
        match self {
            Self::Sqlite(store) => store.maximum_connections(),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.maximum_connections(),
        }
    }

    pub async fn count(&self) -> Result<usize, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => ConnectionStore::count(store),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.count().await,
        }
    }

    pub async fn list(&self) -> Result<Vec<StoredConnection>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => ConnectionStore::list(store),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.list().await,
        }
    }

    pub async fn get(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredConnection>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => ConnectionStore::get(store, id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.get(id).await,
        }
    }

    pub async fn create(
        &self,
        candidate: ConnectionWrite,
        actor: &str,
    ) -> Result<StoredConnection, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let _ = actor;
                ConnectionStore::create(store, candidate)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.create(candidate, actor).await,
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
                ConnectionStore::replace(store, id, expected, candidate)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.replace(id, expected, candidate, actor).await,
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
                ConnectionStore::delete(store, id, expected)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.delete(id, expected, actor).await,
        }
    }

    pub async fn append_status(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
    ) -> Result<SafeConnectionStatus, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.append_status(id, expected, update),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.append_status(id, expected, update).await,
        }
    }

    pub async fn append_status_before(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        update: ConnectionStatusUpdate,
        deadline: std::time::Instant,
    ) -> Result<(SafeConnectionStatus, StoredConnection), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.append_status_before(id, expected, update, deadline),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => {
                // The deadline bounds the SQLite busy-wait; the PostgreSQL
                // authority bounds itself with the session lock_timeout.
                // The remaining-deadline entry check preserves the "bounded
                // wait, then Busy/DeadlineExceeded" contract callers rely on.
                super::store::remaining_before(deadline, "connection status persistence")?;
                store.append_status_before(id, expected, update).await
            }
        }
    }

    pub async fn latest_status(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<SafeConnectionStatus>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.latest_status(id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.latest_status(id).await,
        }
    }

    pub async fn status_history(
        &self,
        id: &ConnectionId,
        limit: usize,
    ) -> Result<Vec<SafeConnectionStatus>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.status_history(id, limit),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.status_history(id, limit).await,
        }
    }

    pub async fn add_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.add_dependency(id, kind, consumer_id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.add_dependency(id, kind, consumer_id).await,
        }
    }

    pub async fn remove_dependency(
        &self,
        id: &ConnectionId,
        kind: ConnectionDependencyKind,
        consumer_id: &str,
    ) -> Result<(), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.remove_dependency(id, kind, consumer_id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.remove_dependency(id, kind, consumer_id).await,
        }
    }

    pub async fn replace_dependencies_for_kind(
        &self,
        kind: ConnectionDependencyKind,
        desired: &[(ConnectionId, String)],
    ) -> Result<(), ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.replace_dependencies_for_kind(kind, desired),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.replace_dependencies_for_kind(kind, desired).await,
        }
    }

    pub async fn dependencies(
        &self,
        id: &ConnectionId,
    ) -> Result<Vec<ConnectionDependency>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.dependencies(id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.dependencies(id).await,
        }
    }

    pub async fn dependency_counts(
        &self,
    ) -> Result<BTreeMap<ConnectionId, usize>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.dependency_counts(),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.dependency_counts().await,
        }
    }

    pub async fn mcp_catalogs(&self) -> Result<Vec<StoredMcpCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.mcp_catalogs(),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.mcp_catalogs().await,
        }
    }

    pub async fn mcp_catalog(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredMcpCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.mcp_catalog(id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.mcp_catalog(id).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn replace_mcp_catalog(
        &self,
        id: &ConnectionId,
        expected: &ConnectionEtag,
        entries: &[StoredMcpCatalogEntry],
        resources: &[StoredMcpResource],
        resource_templates: &[StoredMcpResourceTemplate],
        actor: &str,
    ) -> Result<StoredMcpCatalog, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => {
                let _ = actor;
                store.replace_mcp_catalog(id, expected, entries, resources, resource_templates)
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => {
                store
                    .replace_mcp_catalog(
                        id,
                        expected,
                        entries,
                        resources,
                        resource_templates,
                        actor,
                    )
                    .await
            }
        }
    }

    pub async fn openapi_catalogs(
        &self,
    ) -> Result<Vec<StoredOpenApiCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.openapi_catalogs(),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.openapi_catalogs().await,
        }
    }

    pub async fn openapi_inventory_catalogs(
        &self,
    ) -> Result<Vec<StoredOpenApiInventoryCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.openapi_inventory_catalogs(),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.openapi_inventory_catalogs().await,
        }
    }

    pub async fn openapi_catalog(
        &self,
        id: &ConnectionId,
    ) -> Result<Option<StoredOpenApiCatalog>, ConnectionStoreError> {
        match self {
            Self::Sqlite(store) => store.openapi_catalog(id),
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => store.openapi_catalog(id).await,
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
        match self {
            Self::Sqlite(store) => {
                let _ = actor;
                store.replace_openapi_catalog(
                    id,
                    expected_connection_etag,
                    expected_spec_revision,
                    expected_catalog_revision,
                    spec,
                    spec_digest,
                    entries,
                )
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => {
                store
                    .replace_openapi_catalog(
                        id,
                        expected_connection_etag,
                        expected_spec_revision,
                        expected_catalog_revision,
                        spec,
                        spec_digest,
                        entries,
                        actor,
                    )
                    .await
            }
        }
    }
}
