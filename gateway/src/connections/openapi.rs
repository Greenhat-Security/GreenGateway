use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use futures_util::StreamExt;
use http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    egress::{EgressError, EgressRequestBody},
    tools::{
        definitions::{
            McpCatalogPublishError, ToolDefinition, ToolRegistry, ToolRegistryError, ToolSource,
            ToolTarget,
        },
        openapi::{self, OpenApiToolBinding, OpenApiToolGeneration, OpenApiToolSecuritySelection},
    },
};

use super::{
    control_plane::{CatalogLifecycleError, CatalogMutationGuard, ConnectionControlPlane},
    http::{ConnectionHttpError, ConnectionHttpRuntime},
    model::{
        normalize_origin_relative_path, ConnectionId, ConnectionKind, DiscoveryConfig,
        MAX_CATALOG_ENTRIES, MAX_MANAGED_OPENAPI_CATALOG_BYTES, MAX_MANAGED_SPEC_BYTES,
    },
    status::{ConnectionOperationalState, ConnectionStatusReason, SafeConnectionStatus},
    store::{
        ConnectionEtag, ConnectionStatusUpdate, ConnectionStoreError, StoredConnection,
        StoredOpenApiCatalog, StoredOpenApiCatalogEntry,
    },
};

#[derive(Clone)]
pub struct OpenApiConnectionCatalogRuntime {
    state: Arc<ArcSwap<BTreeMap<ConnectionId, ActiveOpenApiCatalog>>>,
}

#[derive(Clone, Debug)]
struct ActiveOpenApiCatalog {
    observed_etag: String,
    catalog_revision: u64,
    refreshed_at: String,
    definition_digests: BTreeMap<String, [u8; 32]>,
}

#[derive(Clone)]
pub struct OpenApiConnectionCatalogService {
    control_plane: ConnectionControlPlane,
    http: ConnectionHttpRuntime,
    registry: ToolRegistry,
    runtime: OpenApiConnectionCatalogRuntime,
    /// Test seam: runs between the authority commit and the registry
    /// install, where another lane can move underneath a publish.
    #[cfg(test)]
    install_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

struct OpenApiPublishCandidate<'a> {
    record: &'a StoredConnection,
    expected_spec_revision: u64,
    expected_catalog_revision: u64,
    spec: &'a str,
    digest: &'a str,
    binding: OpenApiToolBinding,
    started: Instant,
    /// Who is publishing. The authority records it on the immutable
    /// specification version; standalone mode has no version table and
    /// ignores it.
    actor: &'a str,
}

#[derive(Debug)]
pub struct OpenApiCatalogPreview {
    pub connection_id: ConnectionId,
    pub connection_etag: ConnectionEtag,
    pub spec_digest: String,
    pub spec_revision: u64,
    pub catalog_revision: u64,
    pub generation: OpenApiToolGeneration,
    pub binding: OpenApiToolBinding,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenApiCatalogPublishResult {
    pub connection_id: ConnectionId,
    pub spec_digest: String,
    pub spec_revision: u64,
    pub catalog_revision: u64,
    pub status: SafeConnectionStatus,
    pub registered_tool_names: Vec<String>,
    pub total_count: usize,
    pub added_count: usize,
    pub changed_count: usize,
    pub removed_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenApiCatalogError {
    StoreUnavailable,
    InvalidConnectionId,
    ConnectionNotFound,
    ConnectionDisabled,
    ConnectionKindMismatch,
    DiscoveryNotConfigured,
    PreconditionFailed,
    StalePreview,
    CatalogNotRegistered,
    OperationInProgress,
    SpecTooLarge,
    InvalidSpec,
    InvalidSelection,
    AuthenticationMismatch,
    ToolConflict,
    EgressDenied,
    SecretUnavailable,
    AuthenticationFailed,
    RequestFailed,
    InvalidResponse,
    StorageUnavailable,
}

impl OpenApiCatalogError {
    pub const fn safe_reason(self) -> &'static str {
        match self {
            Self::StoreUnavailable => "connection_store_not_configured",
            Self::InvalidConnectionId => "invalid_connection_id",
            Self::ConnectionNotFound => "connection_not_found",
            Self::ConnectionDisabled => "connection_disabled",
            Self::ConnectionKindMismatch => "connection_kind_mismatch",
            Self::DiscoveryNotConfigured => "discovery_not_configured",
            Self::PreconditionFailed => "connection_changed",
            Self::StalePreview => "stale_preview",
            Self::CatalogNotRegistered => "catalog_not_registered",
            Self::OperationInProgress => "catalog_operation_in_progress",
            Self::SpecTooLarge => "spec_too_large",
            Self::InvalidSpec => "invalid_spec",
            Self::InvalidSelection => "invalid_selection",
            Self::AuthenticationMismatch => "authentication_mismatch",
            Self::ToolConflict => "tool_name_conflict",
            Self::EgressDenied => "egress_denied",
            Self::SecretUnavailable => "secret_unavailable",
            Self::AuthenticationFailed => "auth_failed",
            Self::RequestFailed => "request_failed",
            Self::InvalidResponse => "invalid_response",
            Self::StorageUnavailable => "storage_unavailable",
        }
    }
}

impl fmt::Display for OpenApiCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed OpenAPI catalog operation failed: {}",
            self.safe_reason()
        )
    }
}

impl std::error::Error for OpenApiCatalogError {}

impl OpenApiConnectionCatalogRuntime {
    fn new(catalogs: &[StoredOpenApiCatalog]) -> Result<Self, ConnectionStoreError> {
        let state = catalogs
            .iter()
            .map(|catalog| {
                active_catalog(catalog).map(|active| (catalog.connection_id.clone(), active))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(Self {
            state: Arc::new(ArcSwap::from_pointee(state)),
        })
    }

    fn publish(&self, catalog: &StoredOpenApiCatalog) -> Result<(), ConnectionStoreError> {
        let active = active_catalog(catalog)?;
        self.publish_active(catalog.connection_id.clone(), active);
        Ok(())
    }

    fn publish_prevalidated(
        &self,
        catalog: &StoredOpenApiCatalog,
        definition_digests: BTreeMap<String, [u8; 32]>,
    ) {
        self.publish_active(
            catalog.connection_id.clone(),
            ActiveOpenApiCatalog {
                observed_etag: catalog.observed_etag.to_string(),
                catalog_revision: catalog.catalog_revision,
                refreshed_at: catalog.refreshed_at.clone(),
                definition_digests,
            },
        );
    }

    fn publish_active(&self, connection_id: ConnectionId, active: ActiveOpenApiCatalog) {
        self.state.rcu(|current| {
            let mut next = current.as_ref().clone();
            next.insert(connection_id.clone(), active.clone());
            Arc::new(next)
        });
    }

    #[cfg(test)]
    pub(crate) fn from_catalogs_for_test(
        catalogs: &[StoredOpenApiCatalog],
    ) -> Result<Self, ConnectionStoreError> {
        Self::new(catalogs)
    }

    #[cfg(test)]
    pub(crate) fn publish_for_test(
        &self,
        catalog: &StoredOpenApiCatalog,
    ) -> Result<(), ConnectionStoreError> {
        self.publish(catalog)
    }

    /// The Connections whose catalogs this replica is currently serving.
    fn connection_ids(&self) -> Vec<ConnectionId> {
        self.state.load().keys().cloned().collect()
    }

    /// The catalog revision this replica currently serves for a Connection.
    fn current_revision(&self, connection_id: &ConnectionId) -> Option<u64> {
        self.state
            .load()
            .get(connection_id)
            .map(|catalog| catalog.catalog_revision)
    }

    fn remove(&self, connection_id: &ConnectionId) {
        self.state.rcu(|current| {
            if !current.contains_key(connection_id) {
                return Arc::clone(current);
            }
            let mut next = current.as_ref().clone();
            next.remove(connection_id);
            Arc::new(next)
        });
    }

    pub fn definition_is_current(
        &self,
        definition: &ToolDefinition,
        current_connection_etag: &str,
    ) -> bool {
        let (
            ToolSource::OpenApi {
                connection_id: source_connection_id,
                catalog_revision: Some(source_catalog_revision),
                ..
            },
            Some(ToolTarget::Http {
                connection_id: target_connection_id,
                ..
            }),
        ) = (&definition.source, &definition.target)
        else {
            return false;
        };
        if source_connection_id != target_connection_id {
            return false;
        }
        let Ok(connection_id) = ConnectionId::parse(source_connection_id.clone()) else {
            return false;
        };
        let state = self.state.load();
        let Some(catalog) = state.get(&connection_id) else {
            return false;
        };
        catalog.observed_etag == current_connection_etag
            && catalog.catalog_revision == *source_catalog_revision
            && catalog
                .definition_digests
                .get(&definition.name)
                .is_some_and(|digest| {
                    definition_digest(definition)
                        .is_ok_and(|definition_digest| *digest == definition_digest)
                })
    }

    pub fn catalog_status(
        &self,
        connection_id: &ConnectionId,
        current_etag: &ConnectionEtag,
    ) -> Option<SafeConnectionStatus> {
        let state = self.state.load();
        let catalog = state.get(connection_id)?;
        let current = catalog.observed_etag == current_etag.as_str();
        Some(SafeConnectionStatus {
            state: if current {
                ConnectionOperationalState::Healthy
            } else {
                ConnectionOperationalState::Degraded
            },
            reason: if current {
                ConnectionStatusReason::CatalogRefreshed
            } else {
                ConnectionStatusReason::CatalogStale
            },
            observed_at: Some(catalog.refreshed_at.clone()),
            latency_ms: None,
            catalog_age_secs: Some(timestamp_age_seconds(&catalog.refreshed_at)),
            catalog_entry_count: Some(catalog.definition_digests.len()),
        })
    }
}

impl OpenApiConnectionCatalogService {
    pub fn load(
        control_plane: ConnectionControlPlane,
        http: ConnectionHttpRuntime,
        registry: ToolRegistry,
    ) -> Result<Self, ConnectionStoreError> {
        Self::load_with(
            control_plane,
            http,
            registry,
            crate::tools::definitions::LaneConflicts::Refuse,
        )
    }

    /// `load` with the boot merge's conflict policy: cluster mode passes
    /// [`crate::tools::definitions::LaneConflicts::EvictStale`], because its
    /// boot seeds are read one resource at a time and the gate's first pass
    /// reconciles them before a request is served.
    pub fn load_with(
        control_plane: ConnectionControlPlane,
        http: ConnectionHttpRuntime,
        registry: ToolRegistry,
        conflicts: crate::tools::definitions::LaneConflicts,
    ) -> Result<Self, ConnectionStoreError> {
        let catalogs = if control_plane.is_managed_store_configured() {
            control_plane
                .managed_store()
                .map_err(|_| ConnectionStoreError::Validation {
                    problems: vec!["managed Connection store is unavailable".to_owned()],
                })?
                .boot_openapi_catalogs()?
        } else {
            Vec::new()
        };
        let snapshot = control_plane.runtime_snapshot();
        let active_catalogs = catalogs
            .into_iter()
            .filter(|catalog| {
                snapshot
                    .managed()
                    .get(&catalog.connection_id)
                    .is_some_and(|record| {
                        record.write.enabled && supports_managed_openapi_catalog(record)
                    })
            })
            .collect::<Vec<_>>();
        let definitions = active_catalogs
            .iter()
            .map(catalog_definitions)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        registry
            .merge_definitions_with(definitions, conflicts)
            .map_err(tool_registry_store_error)?;
        let runtime = OpenApiConnectionCatalogRuntime::new(&active_catalogs)?;
        Ok(Self {
            control_plane,
            http,
            registry,
            runtime,
            #[cfg(test)]
            install_hook: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_install_hook_for_test(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.install_hook = Some(hook);
        self
    }

    pub fn runtime(&self) -> OpenApiConnectionCatalogRuntime {
        self.runtime.clone()
    }

    /// Rebuild the managed-OpenAPI lane from the authority (issue #241,
    /// PR 8).
    ///
    /// The Connections reconciler calls this after the records have been
    /// republished, so the "is this catalog still active" filter sees the
    /// records the authority does -- filtering against the previous
    /// snapshot would keep serving a catalog whose Connection was disabled
    /// on another replica. It is the computation
    /// [`OpenApiConnectionCatalogService::load`] performs at startup, done
    /// against the authority, and it installs through the registry's
    /// re-validating install so a catalog this binary cannot enforce fails
    /// closed instead of becoming live.
    pub async fn reconcile_from_authority(&self) -> Result<(), ConnectionStoreError> {
        let catalogs = self
            .control_plane
            .managed_store()
            .map_err(|_| ConnectionStoreError::Validation {
                problems: vec!["managed Connection store is unavailable".to_owned()],
            })?
            .openapi_catalogs()
            .await?;
        let snapshot = self.control_plane.runtime_snapshot();
        let active = catalogs
            .into_iter()
            .filter(|catalog| {
                snapshot
                    .managed()
                    .get(&catalog.connection_id)
                    .is_some_and(|record| {
                        record.write.enabled && supports_managed_openapi_catalog(record)
                    })
            })
            .collect::<Vec<_>>();
        let active_ids = active
            .iter()
            .map(|catalog| catalog.connection_id.clone())
            .collect::<BTreeSet<_>>();
        for catalog in &active {
            // See the MCP reconciler: the per-Connection guard a publish
            // holds, and a monotonic revision check under it.
            let _guard = self
                .control_plane
                .begin_catalog_mutation(&catalog.connection_id)
                .map_err(|_| ConnectionStoreError::Busy {
                    resource: "connection catalog lifecycle",
                })?;
            if self
                .runtime
                .current_revision(&catalog.connection_id)
                .is_some_and(|live| live >= catalog.catalog_revision)
            {
                continue;
            }
            let definitions = catalog_definitions(catalog)?;
            // Authoritative content: a conflicting holder is stale by the
            // authority's reservation, and evicting it is what lets a name
            // that moved between catalogs converge in any order.
            self.registry
                .install_openapi_connection_catalog_with(
                    catalog.connection_id.as_str(),
                    definitions,
                    crate::tools::definitions::LaneConflicts::EvictStale,
                )
                .map_err(tool_registry_store_error)?;
            // `publish` recomputes the definition digests from the stored
            // entries and rejects a catalog whose entries do not agree with
            // them, which is what the boot path does too.
            self.runtime.publish(catalog)?;
        }
        // A catalog the authority no longer holds as active must stop
        // being served here too. Withdrawing is the fail-closed direction.
        for connection_id in self.runtime.connection_ids() {
            if !active_ids.contains(&connection_id) {
                self.discard_runtime_catalog(&connection_id);
            }
        }
        Ok(())
    }

    pub(crate) fn begin_connection_mutation(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<CatalogMutationGuard, OpenApiCatalogError> {
        self.control_plane
            .begin_catalog_mutation(connection_id)
            .map_err(catalog_lifecycle_error)
    }

    pub fn reconcile_connection(&self, record: &StoredConnection) {
        if !record.write.enabled || !supports_managed_openapi_catalog(record) {
            self.discard_runtime_catalog(&record.id);
        }
    }

    pub fn remove_connection(&self, connection_id: &ConnectionId) {
        self.discard_runtime_catalog(connection_id);
    }

    pub fn status_fallback(
        &self,
        connection_id: &ConnectionId,
        current_etag: &ConnectionEtag,
        stored: Option<SafeConnectionStatus>,
    ) -> Option<SafeConnectionStatus> {
        stored.or_else(|| self.runtime.catalog_status(connection_id, current_etag))
    }

    pub async fn preview(
        &self,
        raw_connection_id: &str,
        spec: &str,
    ) -> Result<OpenApiCatalogPreview, OpenApiCatalogError> {
        validate_spec_size(spec)?;
        let (connection_id, record) = self.managed_openapi_record(raw_connection_id, None)?;
        let prior = self
            .control_plane
            .managed_store()
            .map_err(|_| OpenApiCatalogError::StoreUnavailable)?
            .openapi_catalog(&connection_id)
            .await
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let generation = openapi::generate_tools_from_openapi_str("managed-openapi-preview", spec)
            .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        let binding = openapi::bind_generated_openapi_tools(
            &generation,
            &connection_id,
            &record.write.authentication,
        )
        .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        validate_binding_budget(&binding)?;
        Ok(OpenApiCatalogPreview {
            connection_id,
            connection_etag: record.etag(),
            spec_digest: spec_digest(spec),
            spec_revision: prior.as_ref().map_or(0, |catalog| catalog.spec_revision),
            catalog_revision: prior.as_ref().map_or(0, |catalog| catalog.catalog_revision),
            generation,
            binding,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register(
        &self,
        raw_connection_id: &str,
        expected_connection_etag: &str,
        expected_spec_revision: u64,
        expected_catalog_revision: u64,
        expected_spec_digest: &str,
        spec: &str,
        selected_tool_names: &[String],
        confirmations: &[OpenApiToolSecuritySelection],
        actor: &str,
    ) -> Result<OpenApiCatalogPublishResult, OpenApiCatalogError> {
        validate_spec_size(spec)?;
        if spec_digest(spec) != expected_spec_digest {
            return Err(OpenApiCatalogError::StalePreview);
        }
        let connection_id = ConnectionId::parse(raw_connection_id.to_owned())
            .map_err(|_| OpenApiCatalogError::InvalidConnectionId)?;
        let _active = self
            .control_plane
            .begin_catalog_mutation(&connection_id)
            .map_err(catalog_lifecycle_error)?;
        let (_, record) = if selected_tool_names.is_empty() {
            self.managed_openapi_record_identity(raw_connection_id, Some(expected_connection_etag))?
        } else {
            self.managed_openapi_record(raw_connection_id, Some(expected_connection_etag))?
        };
        let generation = openapi::generate_tools_from_openapi_str("managed-openapi-register", spec)
            .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        let binding = bind_selected_tools(
            &generation,
            &connection_id,
            &record,
            selected_tool_names,
            confirmations,
        )?;
        self.publish_candidate(OpenApiPublishCandidate {
            record: &record,
            expected_spec_revision,
            expected_catalog_revision,
            spec,
            digest: expected_spec_digest,
            binding,
            started: Instant::now(),
            actor,
        })
        .await
    }

    pub async fn refresh(
        &self,
        raw_connection_id: &str,
        expected_connection_etag: &str,
        actor: &str,
    ) -> Result<OpenApiCatalogPublishResult, OpenApiCatalogError> {
        let connection_id = ConnectionId::parse(raw_connection_id.to_owned())
            .map_err(|_| OpenApiCatalogError::InvalidConnectionId)?;
        let _active = self
            .control_plane
            .begin_catalog_refresh(&connection_id)
            .map_err(catalog_lifecycle_error)?;
        let (_, record) =
            self.managed_openapi_record(raw_connection_id, Some(expected_connection_etag))?;
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| OpenApiCatalogError::StoreUnavailable)?
            .clone();
        // The store dispatch keeps standalone mode's SQLite query on the
        // blocking pool and awaits the authority in cluster mode; either
        // way the request executor stays free.
        let prior = match store.openapi_catalog(&connection_id).await {
            Ok(Some(prior)) => prior,
            Ok(None) => return Err(OpenApiCatalogError::CatalogNotRegistered),
            Err(_) => return Err(OpenApiCatalogError::StorageUnavailable),
        };
        let started = Instant::now();
        let spec = match &record.write.discovery {
            Some(DiscoveryConfig::ManagedOpenapi { path: Some(_), .. }) => {
                match self.fetch_stored_spec(&record).await {
                    Ok(spec) => spec,
                    Err(error) => {
                        self.record_failed_status(
                            &connection_id,
                            &record.etag(),
                            Some(&prior),
                            error,
                            started.elapsed(),
                        )
                        .await;
                        return Err(error);
                    }
                }
            }
            Some(DiscoveryConfig::ManagedOpenapi { path: None, .. }) => prior.spec.clone(),
            _ => return Err(OpenApiCatalogError::DiscoveryNotConfigured),
        };
        let generation =
            match openapi::generate_tools_from_openapi_str("managed-openapi-refresh", &spec) {
                Ok(generation) => generation,
                Err(_) => {
                    self.record_failed_status(
                        &connection_id,
                        &record.etag(),
                        Some(&prior),
                        OpenApiCatalogError::InvalidSpec,
                        started.elapsed(),
                    )
                    .await;
                    return Err(OpenApiCatalogError::InvalidSpec);
                }
            };
        let (selected_tool_names, confirmations) =
            match surviving_refresh_selection(&prior, &generation) {
                Ok(selection) => selection,
                Err(error) => {
                    self.record_failed_status(
                        &connection_id,
                        &record.etag(),
                        Some(&prior),
                        error,
                        started.elapsed(),
                    )
                    .await;
                    return Err(error);
                }
            };
        let binding = match bind_selected_tools(
            &generation,
            &connection_id,
            &record,
            &selected_tool_names,
            &confirmations,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                self.record_failed_status(
                    &connection_id,
                    &record.etag(),
                    Some(&prior),
                    error,
                    started.elapsed(),
                )
                .await;
                return Err(error);
            }
        };
        let digest = spec_digest(&spec);
        let published = self
            .publish_candidate(OpenApiPublishCandidate {
                record: &record,
                expected_spec_revision: prior.spec_revision,
                expected_catalog_revision: prior.catalog_revision,
                spec: &spec,
                digest: &digest,
                binding,
                started,
                actor,
            })
            .await;
        match published {
            Ok(result) => Ok(result),
            Err(error) => {
                self.record_failed_status(
                    &connection_id,
                    &record.etag(),
                    Some(&prior),
                    error,
                    started.elapsed(),
                )
                .await;
                Err(error)
            }
        }
    }

    fn managed_openapi_record(
        &self,
        raw_connection_id: &str,
        expected_etag: Option<&str>,
    ) -> Result<(ConnectionId, StoredConnection), OpenApiCatalogError> {
        let (connection_id, record) =
            self.managed_openapi_record_identity(raw_connection_id, expected_etag)?;
        if !record.write.enabled {
            return Err(OpenApiCatalogError::ConnectionDisabled);
        }
        self.http
            .validate_binding(connection_id.as_str())
            .map_err(connection_http_error)?;
        Ok((connection_id, record))
    }

    fn managed_openapi_record_identity(
        &self,
        raw_connection_id: &str,
        expected_etag: Option<&str>,
    ) -> Result<(ConnectionId, StoredConnection), OpenApiCatalogError> {
        if !self.control_plane.is_managed_store_configured() {
            return Err(OpenApiCatalogError::StoreUnavailable);
        }
        let connection_id = ConnectionId::parse(raw_connection_id.to_owned())
            .map_err(|_| OpenApiCatalogError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .cloned()
            .ok_or(OpenApiCatalogError::ConnectionNotFound)?;
        if expected_etag.is_some_and(|expected| record.etag().as_str() != expected) {
            return Err(OpenApiCatalogError::PreconditionFailed);
        }
        if record.write.kind != ConnectionKind::HttpApi {
            return Err(OpenApiCatalogError::ConnectionKindMismatch);
        }
        if !matches!(
            &record.write.discovery,
            Some(DiscoveryConfig::ManagedOpenapi { .. })
        ) {
            return Err(OpenApiCatalogError::DiscoveryNotConfigured);
        }
        Ok((connection_id, record))
    }

    fn discard_runtime_catalog(&self, connection_id: &ConnectionId) {
        if let Err(error) = self.registry.replace_openapi_connection_catalog(
            connection_id.as_str(),
            Vec::new(),
            || Ok::<(), Infallible>(()),
        ) {
            match error {
                McpCatalogPublishError::Registry(error) => tracing::error!(
                    connection_id = %connection_id,
                    error = %error,
                    "failed to remove an inactive OpenAPI catalog from the tool registry"
                ),
                McpCatalogPublishError::Persist(error) => match error {},
            }
        }
        self.runtime.remove(connection_id);
    }

    async fn publish_candidate(
        &self,
        candidate: OpenApiPublishCandidate<'_>,
    ) -> Result<OpenApiCatalogPublishResult, OpenApiCatalogError> {
        let OpenApiPublishCandidate {
            record,
            expected_spec_revision,
            expected_catalog_revision,
            spec,
            digest,
            mut binding,
            started,
            actor,
        } = candidate;
        if !binding.incompatibilities.is_empty() {
            return Err(OpenApiCatalogError::AuthenticationMismatch);
        }
        let next_catalog_revision = expected_catalog_revision
            .checked_add(1)
            .ok_or(OpenApiCatalogError::StorageUnavailable)?;
        for definition in &mut binding.definitions {
            let ToolSource::OpenApi {
                catalog_revision, ..
            } = &mut definition.source
            else {
                return Err(OpenApiCatalogError::InvalidSpec);
            };
            *catalog_revision = Some(next_catalog_revision);
        }
        let definition_digests = binding
            .definitions
            .iter()
            .map(|definition| {
                definition_digest(definition).map(|digest| (definition.name.clone(), digest))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        let entries = stored_entries(&binding)?;
        let binding_definitions = binding.definitions;
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| OpenApiCatalogError::StoreUnavailable)?
            .clone();
        let expected_connection_etag = record.etag();
        let (published_state, published_reason) = if record.write.enabled {
            (
                ConnectionOperationalState::Healthy,
                ConnectionStatusReason::CatalogRefreshed,
            )
        } else {
            (
                ConnectionOperationalState::Disabled,
                ConnectionStatusReason::Disabled,
            )
        };
        // Validate, commit, install -- the same split the MCP catalog and
        // the tools document use, for the same reason: the commit awaits
        // the store, and the registry write lock is a `std` mutex that
        // cannot be held across an await. The install re-validates against
        // the lanes current at install time and fails closed.
        let registry = self.registry.clone();
        let prior = store
            .openapi_catalog(&record.id)
            .await
            .map_err(|error| openapi_store_error(&error))?;
        let counts = catalog_change_counts(prior.as_ref(), &entries);
        registry
            .validate_openapi_connection_catalog(record.id.as_str(), &binding_definitions)
            .map_err(|_| OpenApiCatalogError::ToolConflict)?;
        let catalog = store
            .replace_openapi_catalog(
                &record.id,
                &expected_connection_etag,
                expected_spec_revision,
                expected_catalog_revision,
                spec,
                digest,
                &entries,
                actor,
            )
            .await
            .map_err(|error| openapi_store_error(&error))?;
        // Publication is revision-monotonic: this publish holds the
        // per-Connection lifecycle guard, but reconciliation may already
        // have published a NEWER catalog another replica committed while
        // this one was between its commit and here. Installing over it
        // would roll the live lane back with no revision left to repair
        // it; the committed catalog is durable at the authority.
        if self
            .runtime
            .current_revision(&record.id)
            .is_some_and(|live| live > catalog.catalog_revision)
        {
            tracing::info!(
                connection_id = %record.id,
                committed = catalog.catalog_revision,
                "a newer OpenAPI catalog is already live on this replica; the committed one is durable and not installed"
            );
            return Err(OpenApiCatalogError::ToolConflict);
        }
        // Registry first, runtime marker second. The marker is what
        // `reconcile_from_authority` compares against: publishing it before
        // a registry install that then fails would leave this replica
        // treating the catalog as live while the registry lacks its tools,
        // and nothing would ever retry. With the registry installed first a
        // failed install publishes nothing locally, and the reconciler
        // installs the durable catalog on its next pass -- the same order
        // the reconciler itself uses.
        #[cfg(test)]
        if let Some(hook) = self.install_hook.as_ref() {
            hook();
        }
        if let Err(error) =
            registry.install_openapi_connection_catalog(record.id.as_str(), binding_definitions)
        {
            tracing::error!(
                connection_id = %record.id,
                error = %error,
                "OpenAPI catalog is durable but could not be installed into the tool registry; reconciliation will retry"
            );
            return Err(OpenApiCatalogError::ToolConflict);
        }
        self.runtime
            .publish_prevalidated(&catalog, definition_digests);
        let status = {
            let latency = duration_millis(started.elapsed());
            match self
                .control_plane
                .append_status(
                    &record.id,
                    &expected_connection_etag,
                    ConnectionStatusUpdate {
                        state: published_state,
                        reason: published_reason,
                        latency_ms: Some(latency),
                        catalog_age_secs: Some(0),
                        catalog_entry_count: Some(catalog.entries.len()),
                    },
                )
                .await
            {
                Ok(status) => status,
                Err(error) => {
                    tracing::error!(
                        connection_id = %record.id,
                        error = %error,
                        "OpenAPI catalog was published but its safe status could not be recorded"
                    );
                    SafeConnectionStatus {
                        state: published_state,
                        reason: published_reason,
                        observed_at: Some(catalog.refreshed_at.clone()),
                        latency_ms: Some(duration_millis(started.elapsed())),
                        catalog_age_secs: Some(0),
                        catalog_entry_count: Some(catalog.entries.len()),
                    }
                }
            }
        };
        let registered_tool_names = catalog
            .entries
            .iter()
            .map(|entry| entry.tool_name.clone())
            .collect::<Vec<_>>();
        Ok(OpenApiCatalogPublishResult {
            connection_id: record.id.clone(),
            spec_digest: catalog.spec_digest.clone(),
            spec_revision: catalog.spec_revision,
            catalog_revision: catalog.catalog_revision,
            status,
            total_count: catalog.entries.len(),
            registered_tool_names,
            added_count: counts.0,
            changed_count: counts.1,
            removed_count: counts.2,
        })
    }

    async fn fetch_stored_spec(
        &self,
        record: &StoredConnection,
    ) -> Result<String, OpenApiCatalogError> {
        let target = self
            .http
            .openapi_discovery_target(record.id.as_str())
            .map_err(connection_http_error)?;
        if target.connection_etag() != record.etag().as_str() {
            return Err(OpenApiCatalogError::PreconditionFailed);
        }
        let destination = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .map_err(egress_error)?;
        let prepared = self
            .http
            .prepare_transport(&target, &destination)
            .await
            .map_err(connection_http_error)?;
        let credential = self
            .http
            .resolve_credential(&target)
            .await
            .map_err(connection_http_error)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "application/json, application/yaml, application/vnd.oai.openapi, text/yaml, text/plain",
            ),
        );
        if let Some(credential) = credential.as_ref() {
            credential
                .inject(&mut headers)
                .map_err(connection_http_error)?;
        }
        let response = prepared
            .client()
            .stream_request_with_body_at_checked_destination(
                prepared.destination(),
                Method::GET,
                target.url(),
                headers,
                EgressRequestBody::Empty,
            )
            .await
            .map_err(egress_error)?;
        if matches!(
            response.status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) && target.is_credentialed()
        {
            if response.status == StatusCode::UNAUTHORIZED {
                if let Some(credential) = credential
                    .as_ref()
                    .filter(|credential| credential.is_oauth())
                {
                    credential.invalidate_after_unauthorized().await;
                }
            }
            return Err(OpenApiCatalogError::AuthenticationFailed);
        }
        if !response.status.is_success() {
            return Err(OpenApiCatalogError::RequestFailed);
        }
        let mut body = Vec::new();
        let mut response_body = response.body;
        while let Some(chunk) = response_body.next().await {
            let chunk = chunk.map_err(egress_error)?;
            if body.len().saturating_add(chunk.len()) > MAX_MANAGED_SPEC_BYTES {
                return Err(OpenApiCatalogError::SpecTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        String::from_utf8(body).map_err(|_| OpenApiCatalogError::InvalidResponse)
    }

    async fn record_failed_status(
        &self,
        connection_id: &ConnectionId,
        expected: &ConnectionEtag,
        prior: Option<&StoredOpenApiCatalog>,
        failure: OpenApiCatalogError,
        elapsed: Duration,
    ) {
        let (state, reason, age, count) = if let Some(prior) = prior {
            (
                ConnectionOperationalState::Degraded,
                ConnectionStatusReason::CatalogStale,
                Some(timestamp_age_seconds(&prior.refreshed_at)),
                Some(prior.entries.len()),
            )
        } else {
            let reason = match failure {
                OpenApiCatalogError::EgressDenied => ConnectionStatusReason::EgressDenied,
                OpenApiCatalogError::SecretUnavailable => ConnectionStatusReason::SecretUnavailable,
                OpenApiCatalogError::InvalidSpec
                | OpenApiCatalogError::InvalidResponse
                | OpenApiCatalogError::AuthenticationFailed
                | OpenApiCatalogError::AuthenticationMismatch => {
                    ConnectionStatusReason::InvalidResponse
                }
                _ => ConnectionStatusReason::RequestFailed,
            };
            (
                ConnectionOperationalState::Unavailable,
                reason,
                None,
                Some(0),
            )
        };
        // A failed status write only logs, exactly as before: the publish
        // failure it describes is already being returned to the caller, and
        // losing the breadcrumb must not turn one failure into two.
        let latency = duration_millis(elapsed);
        if let Err(error) = self
            .control_plane
            .append_status(
                connection_id,
                expected,
                ConnectionStatusUpdate {
                    state,
                    reason,
                    latency_ms: Some(latency),
                    catalog_age_secs: age,
                    catalog_entry_count: count,
                },
            )
            .await
        {
            tracing::error!(
                connection_id = %connection_id,
                error = %error,
                "failed to persist bounded OpenAPI refresh failure status"
            );
        }
    }
}

fn bind_selected_tools(
    generation: &OpenApiToolGeneration,
    connection_id: &ConnectionId,
    record: &StoredConnection,
    selected_tool_names: &[String],
    confirmations: &[OpenApiToolSecuritySelection],
) -> Result<OpenApiToolBinding, OpenApiCatalogError> {
    let selected = selected_tool_names.iter().collect::<BTreeSet<_>>();
    if selected.len() != selected_tool_names.len() {
        return Err(OpenApiCatalogError::InvalidSelection);
    }
    let generated = generation
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();
    if selected
        .iter()
        .any(|name| !generated.contains(name.as_str()))
    {
        return Err(OpenApiCatalogError::InvalidSelection);
    }
    let confirmation_names = confirmations
        .iter()
        .map(|confirmation| confirmation.tool_name.as_str())
        .collect::<BTreeSet<_>>();
    if confirmation_names.len() != confirmations.len()
        || confirmation_names
            != selected
                .iter()
                .map(|name| name.as_str())
                .collect::<BTreeSet<_>>()
    {
        return Err(OpenApiCatalogError::InvalidSelection);
    }
    let binding = openapi::bind_generated_openapi_tools_with_confirmations(
        generation,
        connection_id,
        &record.write.authentication,
        confirmations,
    )
    .map_err(|_| OpenApiCatalogError::AuthenticationMismatch)?;
    if binding.definitions.len() != selected.len() || !binding.incompatibilities.is_empty() {
        return Err(OpenApiCatalogError::AuthenticationMismatch);
    }
    validate_binding_budget(&binding)?;
    Ok(binding)
}

fn surviving_refresh_selection(
    prior: &StoredOpenApiCatalog,
    generation: &OpenApiToolGeneration,
) -> Result<(Vec<String>, Vec<OpenApiToolSecuritySelection>), OpenApiCatalogError> {
    let generated_definitions = generation
        .definitions
        .iter()
        .map(|definition| (definition.name.as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    let generated_security = generation
        .security_requirements
        .iter()
        .map(|security| (security.tool_name.as_str(), security))
        .collect::<BTreeMap<_, _>>();
    let prior_definitions = catalog_definitions(prior)
        .map_err(|_| OpenApiCatalogError::InvalidSpec)?
        .into_iter()
        .map(|definition| (definition.name.clone(), definition))
        .collect::<BTreeMap<_, _>>();
    let mut selected_tool_names = Vec::new();
    let mut confirmations = Vec::new();

    for entry in &prior.entries {
        let Some(candidate) = generated_definitions.get(entry.tool_name.as_str()) else {
            continue;
        };
        let security = generated_security
            .get(entry.tool_name.as_str())
            .ok_or(OpenApiCatalogError::InvalidSpec)?;
        let previous = prior_definitions
            .get(entry.tool_name.as_str())
            .ok_or(OpenApiCatalogError::InvalidSpec)?;
        let candidate_path = normalize_origin_relative_path(
            "openapi.path_template",
            &candidate.upstream.path_template,
        )
        .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        if entry.operation_id != security.operation_id
            || previous.upstream.method != candidate.upstream.method
            || previous.upstream.path_template != candidate_path
        {
            return Err(OpenApiCatalogError::InvalidSelection);
        }
        selected_tool_names.push(entry.tool_name.clone());
        confirmations.push(OpenApiToolSecuritySelection {
            tool_name: entry.tool_name.clone(),
            selected_scheme_names: entry.selected_scheme_names.clone(),
        });
    }

    Ok((selected_tool_names, confirmations))
}

fn validate_binding_budget(binding: &OpenApiToolBinding) -> Result<(), OpenApiCatalogError> {
    if binding.definitions.len() > MAX_CATALOG_ENTRIES {
        return Err(OpenApiCatalogError::InvalidSpec);
    }
    let mut total_bytes = 0_usize;
    for definition in &binding.definitions {
        let definition_bytes =
            serde_json::to_vec(definition).map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        total_bytes = total_bytes
            .checked_add(definition_bytes.len())
            .ok_or(OpenApiCatalogError::InvalidSpec)?;
        if total_bytes > MAX_MANAGED_OPENAPI_CATALOG_BYTES {
            return Err(OpenApiCatalogError::InvalidSpec);
        }
    }
    Ok(())
}

fn stored_entries(
    binding: &OpenApiToolBinding,
) -> Result<Vec<StoredOpenApiCatalogEntry>, OpenApiCatalogError> {
    let selections = binding
        .security_selections
        .iter()
        .map(|selection| (selection.tool_name.as_str(), selection))
        .collect::<BTreeMap<_, _>>();
    binding
        .definitions
        .iter()
        .map(|definition| {
            let ToolSource::OpenApi {
                operation_id,
                catalog_revision: Some(_),
                ..
            } = &definition.source
            else {
                return Err(OpenApiCatalogError::InvalidSpec);
            };
            let selection = selections
                .get(definition.name.as_str())
                .ok_or(OpenApiCatalogError::InvalidSelection)?;
            let definition_value =
                serde_json::to_value(definition).map_err(|_| OpenApiCatalogError::InvalidSpec)?;
            Ok(StoredOpenApiCatalogEntry {
                tool_name: definition.name.clone(),
                operation_id: operation_id.clone(),
                selected_scheme_names: selection.selected_scheme_names.clone(),
                definition: definition_value,
            })
        })
        .collect()
}

fn catalog_definitions(
    catalog: &StoredOpenApiCatalog,
) -> Result<Vec<ToolDefinition>, ConnectionStoreError> {
    catalog
        .entries
        .iter()
        .map(|entry| {
            let definition = serde_json::from_value::<ToolDefinition>(entry.definition.clone())
                .map_err(|source| ConnectionStoreError::Json {
                    operation: "stored OpenAPI catalog definition",
                    source,
                })?;
            let valid = definition.name == entry.tool_name
                && matches!(
                    &definition.source,
                    ToolSource::OpenApi {
                        connection_id,
                        operation_id,
                        catalog_revision: Some(catalog_revision),
                    } if connection_id == catalog.connection_id.as_str()
                        && operation_id == &entry.operation_id
                        && *catalog_revision == catalog.catalog_revision
                )
                && matches!(
                    &definition.target,
                    Some(ToolTarget::Http { connection_id, .. })
                        if connection_id == catalog.connection_id.as_str()
                );
            if !valid {
                return Err(ConnectionStoreError::CorruptRecord {
                    id: catalog.connection_id.to_string(),
                    reason: "stored OpenAPI definition binding is inconsistent",
                });
            }
            Ok(definition)
        })
        .collect()
}

fn active_catalog(
    catalog: &StoredOpenApiCatalog,
) -> Result<ActiveOpenApiCatalog, ConnectionStoreError> {
    let definitions = catalog_definitions(catalog)?;
    Ok(ActiveOpenApiCatalog {
        observed_etag: catalog.observed_etag.to_string(),
        catalog_revision: catalog.catalog_revision,
        refreshed_at: catalog.refreshed_at.clone(),
        definition_digests: definitions
            .iter()
            .map(|definition| {
                definition_digest(definition).map(|digest| (definition.name.clone(), digest))
            })
            .collect::<Result<_, _>>()?,
    })
}

fn definition_digest(definition: &ToolDefinition) -> Result<[u8; 32], ConnectionStoreError> {
    let encoded = serde_json::to_vec(definition).map_err(|source| ConnectionStoreError::Json {
        operation: "OpenAPI definition digest",
        source,
    })?;
    Ok(Sha256::digest(encoded).into())
}

fn spec_digest(spec: &str) -> String {
    format!("{:x}", Sha256::digest(spec.as_bytes()))
}

fn validate_spec_size(spec: &str) -> Result<(), OpenApiCatalogError> {
    if spec.is_empty() {
        return Err(OpenApiCatalogError::InvalidSpec);
    }
    if spec.len() > MAX_MANAGED_SPEC_BYTES {
        return Err(OpenApiCatalogError::SpecTooLarge);
    }
    Ok(())
}

fn supports_managed_openapi_catalog(record: &StoredConnection) -> bool {
    record.write.kind == ConnectionKind::HttpApi
        && matches!(
            &record.write.discovery,
            Some(DiscoveryConfig::ManagedOpenapi { .. })
        )
}

fn catalog_change_counts(
    prior: Option<&StoredOpenApiCatalog>,
    candidate: &[StoredOpenApiCatalogEntry],
) -> (usize, usize, usize) {
    let prior = prior
        .into_iter()
        .flat_map(|catalog| catalog.entries.iter())
        .map(|entry| (entry.tool_name.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|entry| (entry.tool_name.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let added = candidate
        .keys()
        .filter(|name| !prior.contains_key(**name))
        .count();
    let changed = candidate
        .iter()
        .filter(|(name, entry)| {
            prior
                .get(**name)
                .is_some_and(|old| !catalog_entries_semantically_equal(old, entry))
        })
        .count();
    let removed = prior
        .keys()
        .filter(|name| !candidate.contains_key(**name))
        .count();
    (added, changed, removed)
}

fn catalog_entries_semantically_equal(
    left: &StoredOpenApiCatalogEntry,
    right: &StoredOpenApiCatalogEntry,
) -> bool {
    left.tool_name == right.tool_name
        && left.operation_id == right.operation_id
        && left.selected_scheme_names == right.selected_scheme_names
        && definition_without_catalog_revision(&left.definition)
            == definition_without_catalog_revision(&right.definition)
}

fn definition_without_catalog_revision(definition: &Value) -> Value {
    let mut normalized = definition.clone();
    if let Some(source) = normalized.get_mut("source").and_then(Value::as_object_mut) {
        source.remove("catalog_revision");
    }
    normalized
}

fn catalog_lifecycle_error(error: CatalogLifecycleError) -> OpenApiCatalogError {
    match error {
        CatalogLifecycleError::Busy => OpenApiCatalogError::OperationInProgress,
    }
}

fn connection_http_error(error: ConnectionHttpError) -> OpenApiCatalogError {
    match error {
        ConnectionHttpError::InvalidConnectionId => OpenApiCatalogError::InvalidConnectionId,
        ConnectionHttpError::ConnectionNotFound => OpenApiCatalogError::ConnectionNotFound,
        ConnectionHttpError::ConnectionDisabled => OpenApiCatalogError::ConnectionDisabled,
        ConnectionHttpError::WrongConnectionKind => OpenApiCatalogError::ConnectionKindMismatch,
        ConnectionHttpError::InvalidTargetPath => OpenApiCatalogError::DiscoveryNotConfigured,
        ConnectionHttpError::CredentialInvalid
        | ConnectionHttpError::CredentialUnavailable
        | ConnectionHttpError::TlsInvalid
        | ConnectionHttpError::TlsUnavailable
        | ConnectionHttpError::OAuthTokenUnavailable
        | ConnectionHttpError::OAuthTokenRejected
        | ConnectionHttpError::OAuthTokenInvalidResponse => OpenApiCatalogError::SecretUnavailable,
        ConnectionHttpError::OAuthTokenEgressDenied => OpenApiCatalogError::EgressDenied,
        ConnectionHttpError::UpstreamAuthenticationRejected => {
            OpenApiCatalogError::AuthenticationFailed
        }
        ConnectionHttpError::UnsupportedAuthentication
        | ConnectionHttpError::CredentialHeaderConflict => {
            OpenApiCatalogError::AuthenticationMismatch
        }
        ConnectionHttpError::TransportUnavailable => OpenApiCatalogError::RequestFailed,
    }
}

fn egress_error(error: EgressError) -> OpenApiCatalogError {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::SchemeNotAllowed(_) => OpenApiCatalogError::EgressDenied,
        EgressError::ResponseTooLarge { .. } => OpenApiCatalogError::SpecTooLarge,
        EgressError::RequestBodyTooLarge { .. }
        | EgressError::RequestBodyReadFailed
        | EgressError::UnexpectedStatus(_) => OpenApiCatalogError::InvalidResponse,
        EgressError::DnsResolutionFailed(_)
        | EgressError::ResponseIdleTimeout { .. }
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity
        | EgressError::Http(_) => OpenApiCatalogError::RequestFailed,
        // Unreachable: catalog fetches use the pinned HTTP/1.1 transport only.
        EgressError::Grpc(_) => OpenApiCatalogError::RequestFailed,
    }
}

fn openapi_store_error(error: &ConnectionStoreError) -> OpenApiCatalogError {
    match error {
        ConnectionStoreError::ToolNameConflict { .. } => OpenApiCatalogError::ToolConflict,
        ConnectionStoreError::Conflict { .. } => OpenApiCatalogError::StalePreview,
        ConnectionStoreError::Validation { .. } | ConnectionStoreError::LimitExceeded { .. } => {
            OpenApiCatalogError::InvalidSpec
        }
        _ => OpenApiCatalogError::StorageUnavailable,
    }
}

fn tool_registry_store_error(error: ToolRegistryError) -> ConnectionStoreError {
    drop(error);
    ConnectionStoreError::Validation {
        problems: vec!["stored OpenAPI catalog failed safe validation".to_owned()],
    }
}

fn timestamp_age_seconds(value: &str) -> u64 {
    let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) else {
        return 0;
    };
    let elapsed = OffsetDateTime::now_utc() - timestamp;
    u64::try_from(elapsed.whole_seconds().max(0)).unwrap_or(u64::MAX)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{fs, net::Ipv4Addr, path::PathBuf};

    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use uuid::Uuid;

    use super::*;
    use crate::{
        config::Config,
        connections::model::ConnectionWrite,
        egress::{EgressClient, EgressConfig},
        tools::definitions::{HttpToolMapping, ToolSource, ToolTarget},
    };

    struct TemporaryDatabase(PathBuf);

    impl TemporaryDatabase {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "greengateway-managed-openapi-{}.sqlite",
                Uuid::new_v4()
            )))
        }
    }

    impl Drop for TemporaryDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(format!("{}-wal", self.0.display()));
            let _ = fs::remove_file(format!("{}-shm", self.0.display()));
        }
    }

    #[test]
    fn oauth_token_egress_denial_keeps_egress_status_reason() {
        assert_eq!(
            connection_http_error(ConnectionHttpError::OAuthTokenEgressDenied),
            OpenApiCatalogError::EgressDenied
        );
    }

    #[test]
    fn tls_transport_material_failures_are_safe_secret_failures() {
        assert_eq!(
            connection_http_error(ConnectionHttpError::TlsInvalid),
            OpenApiCatalogError::SecretUnavailable
        );
        assert_eq!(
            connection_http_error(ConnectionHttpError::TlsUnavailable),
            OpenApiCatalogError::SecretUnavailable
        );
    }

    fn managed_definition(connection_id: &ConnectionId, catalog_revision: u64) -> ToolDefinition {
        let mapping = HttpToolMapping {
            method: "GET".to_owned(),
            path_template: "/invoices/{invoice_id}".to_owned(),
            query_params: Vec::new(),
            body: None,
        };
        ToolDefinition {
            name: "get_invoice".to_owned(),
            description: "Read one invoice".to_owned(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "invoice_id": {"type": "string"}
                },
                "required": ["invoice_id"],
                "additionalProperties": false
            }),
            target: Some(ToolTarget::Http {
                connection_id: connection_id.as_str().to_owned(),
                mapping: mapping.clone(),
            }),
            source: ToolSource::OpenApi {
                connection_id: connection_id.as_str().to_owned(),
                operation_id: Some("getInvoice".to_owned()),
                catalog_revision: Some(catalog_revision),
            },
            upstream: mapping,
        }
    }

    #[test]
    fn active_runtime_requires_exact_etag_revision_and_definition_digest() {
        let connection_id =
            ConnectionId::parse("billing-api").expect("test Connection ID should be valid");
        let definition = managed_definition(&connection_id, 7);
        let digest = definition_digest(&definition).expect("definition should serialize");
        let runtime = OpenApiConnectionCatalogRuntime {
            state: Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
                connection_id.clone(),
                ActiveOpenApiCatalog {
                    observed_etag: "\"connection:billing-api:c1:k1:t1:d1\"".to_owned(),
                    catalog_revision: 7,
                    refreshed_at: "2026-07-28T00:00:00Z".to_owned(),
                    definition_digests: BTreeMap::from([(definition.name.clone(), digest)]),
                },
            )]))),
        };

        assert!(
            runtime.definition_is_current(&definition, "\"connection:billing-api:c1:k1:t1:d1\"")
        );
        assert!(
            !runtime.definition_is_current(&definition, "\"connection:billing-api:c2:k1:t1:d1\"")
        );

        let mut stale_revision = definition.clone();
        let ToolSource::OpenApi {
            catalog_revision, ..
        } = &mut stale_revision.source
        else {
            panic!("test definition should retain OpenAPI provenance");
        };
        *catalog_revision = Some(6);
        assert!(!runtime
            .definition_is_current(&stale_revision, "\"connection:billing-api:c1:k1:t1:d1\""));

        let mut tampered = definition;
        tampered.upstream.path_template = "/admin/invoices/{invoice_id}".to_owned();
        assert!(!runtime.definition_is_current(&tampered, "\"connection:billing-api:c1:k1:t1:d1\""));
    }

    #[test]
    fn managed_spec_size_is_enforced_in_bytes() {
        assert_eq!(
            validate_spec_size(""),
            Err(OpenApiCatalogError::InvalidSpec)
        );
        assert!(validate_spec_size(&"x".repeat(MAX_MANAGED_SPEC_BYTES)).is_ok());
        assert_eq!(
            validate_spec_size(&"x".repeat(MAX_MANAGED_SPEC_BYTES + 1)),
            Err(OpenApiCatalogError::SpecTooLarge)
        );
    }

    #[test]
    fn additional_headers_do_not_participate_in_openapi_security_matching() {
        let generation = openapi::generate_tools_from_openapi_str(
            "additional-header-security.yaml",
            r#"
openapi: 3.0.3
info: { title: Additional header security, version: 1.0.0 }
components:
  securitySchemes:
    UpstreamKey: { type: apiKey, in: header, name: X-Upstream-Key }
    AccessKey: { type: apiKey, in: header, name: CF-Access-Client-Id }
    BearerAuth: { type: http, scheme: bearer }
paths:
  /widgets:
    get:
      operationId: list_widgets
      security:
        - UpstreamKey: []
        - AccessKey: []
        - BearerAuth: []
"#,
        )
        .expect("security alternatives should parse");
        let connection_id =
            ConnectionId::parse("widgets-api").expect("test Connection ID should parse");
        let selection = |scheme: &str| OpenApiToolSecuritySelection {
            tool_name: "list_widgets".to_owned(),
            selected_scheme_names: vec![scheme.to_owned()],
        };
        let record = |authentication: serde_json::Value, additional_name: &str| {
            let write = serde_json::from_value(json!({
                "display_name": "Widgets API",
                "enabled": true,
                "kind": "http_api",
                "endpoint": {
                    "base_url": "https://widgets.example.test",
                    "base_path": "/v1"
                },
                "authentication": authentication,
                "additional_headers": [{
                    "header_name": additional_name,
                    "secret_id": "additional-secret"
                }],
                "tls": {},
                "discovery": {
                    "type": "managed_openapi",
                    "use_connection_authentication": true
                }
            }))
            .expect("test Connection should deserialize");
            StoredConnection {
                id: connection_id.clone(),
                write,
                revisions: crate::connections::status::ConnectionRevisions {
                    connection: 1,
                    credential: 1,
                    tls: 0,
                    discovery: 1,
                    status: 0,
                },
                created_at: "2026-09-03T00:00:00Z".to_owned(),
                updated_at: "2026-09-03T00:00:00Z".to_owned(),
            }
        };

        let bearer_with_upstream_key_as_extra = record(
            json!({"type": "static_bearer", "secret_id": "bearer-secret"}),
            "x-upstream-key",
        );
        assert_eq!(
            bind_selected_tools(
                &generation,
                &connection_id,
                &bearer_with_upstream_key_as_extra,
                &["list_widgets".to_owned()],
                &[selection("UpstreamKey")],
            ),
            Err(OpenApiCatalogError::AuthenticationMismatch),
            "an additional header must not satisfy an OpenAPI apiKey scheme"
        );
        assert!(bind_selected_tools(
            &generation,
            &connection_id,
            &bearer_with_upstream_key_as_extra,
            &["list_widgets".to_owned()],
            &[selection("BearerAuth")],
        )
        .is_ok());

        let upstream_key_with_access_key_as_extra = record(
            json!({
                "type": "header_api_key",
                "header_name": "x-upstream-key",
                "secret_id": "upstream-secret"
            }),
            "cf-access-client-id",
        );
        assert!(bind_selected_tools(
            &generation,
            &connection_id,
            &upstream_key_with_access_key_as_extra,
            &["list_widgets".to_owned()],
            &[selection("UpstreamKey")],
        )
        .is_ok());
        assert_eq!(
            bind_selected_tools(
                &generation,
                &connection_id,
                &upstream_key_with_access_key_as_extra,
                &["list_widgets".to_owned()],
                &[selection("AccessKey")],
            ),
            Err(OpenApiCatalogError::AuthenticationMismatch),
            "a matching additional proxy header must not replace the primary OpenAPI scheme"
        );
    }

    #[test]
    fn catalog_change_comparison_ignores_only_the_generation_revision() {
        let connection_id =
            ConnectionId::parse("billing-api").expect("test Connection ID should be valid");
        let revision_one = managed_definition(&connection_id, 1);
        let revision_two = managed_definition(&connection_id, 2);
        let entry = |definition: ToolDefinition| StoredOpenApiCatalogEntry {
            tool_name: definition.name.clone(),
            operation_id: Some("getInvoice".to_owned()),
            selected_scheme_names: Vec::new(),
            definition: serde_json::to_value(definition).expect("test definition should serialize"),
        };
        let first = entry(revision_one);
        let second = entry(revision_two.clone());
        assert!(catalog_entries_semantically_equal(&first, &second));

        let mut changed_mapping = revision_two;
        changed_mapping.upstream.path_template = "/admin/invoices/{invoice_id}".to_owned();
        assert!(!catalog_entries_semantically_equal(
            &first,
            &entry(changed_mapping)
        ));
    }

    /// A request admitted by the gate dispatches under the Connection
    /// snapshot pinned at admission, not under whatever a later reconcile
    /// installed while it was in flight: the runtime resolves targets from
    /// the pinned snapshot, and only from the live one outside a request.
    #[tokio::test]
    async fn targets_resolve_from_the_pinned_snapshot_inside_a_request() {
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let snapshot = control_plane.runtime_snapshot();
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Pinned API",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://pinned.example.test",
                "base_path": "/v1"
            },
            "authentication": {"type": "none"},
            "tls": {},
            "timeouts": {
                "connect_timeout_ms": 1000,
                "request_timeout_ms": 3000,
                "response_idle_timeout_ms": 1000
            }
        }))
        .expect("HTTP Connection should deserialize");
        let record = control_plane
            .create_managed(snapshot.collection_etag(), candidate, "test-admin")
            .await
            .expect("HTTP Connection should create");
        let egress_config = EgressConfig::from_config(&config);
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress should build"));
        let http = ConnectionHttpRuntime::new(control_plane.clone(), egress_config, egress_client);
        let pinned = control_plane.runtime_snapshot();

        // The Connection disappears from the live state after admission.
        control_plane
            .delete_managed(&record.id, &record.etag(), "test-admin")
            .await
            .expect("delete");
        assert!(
            http.target(record.id.as_str(), "/invoices").is_err(),
            "outside a request the live snapshot no longer has it"
        );
        let target = crate::connections::http::with_pinned_connections(pinned, async {
            http.target(record.id.as_str(), "/invoices")
        })
        .await
        .expect("inside the admitted request the pinned snapshot still has it");
        assert_eq!(target.connection_id(), &record.id);
    }

    /// A registry install that fails after the authority commit -- another
    /// lane moved underneath the publish -- publishes no runtime marker,
    /// so `reconcile_from_authority` still sees the durable catalog as
    /// newer than what is live and installs it on its next pass. Publishing
    /// the marker first would have left this replica believing the catalog
    /// was live with its tools absent from the registry, forever.
    #[tokio::test]
    async fn a_failed_registry_install_publishes_no_runtime_marker() {
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let snapshot = control_plane.runtime_snapshot();
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Managed Billing OpenAPI",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {"type": "none"},
            "tls": {},
            "timeouts": {
                "connect_timeout_ms": 1000,
                "request_timeout_ms": 3000,
                "response_idle_timeout_ms": 1000
            },
            "discovery": {
                "type": "managed_openapi",
                "use_connection_authentication": false
            }
        }))
        .expect("managed OpenAPI Connection should deserialize");
        let record = control_plane
            .create_managed(snapshot.collection_etag(), candidate, "test-admin")
            .await
            .expect("managed OpenAPI Connection should create");
        let egress_config = EgressConfig::from_config(&config);
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress should build"));
        let http = ConnectionHttpRuntime::new(control_plane.clone(), egress_config, egress_client);
        let registry = ToolRegistry::disabled();
        // Between the commit and the install, the local lane takes the
        // name the catalog is about to publish.
        let racing_registry = registry.clone();
        let service = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            http.clone(),
            registry.clone(),
        )
        .expect("managed OpenAPI service should load")
        .with_install_hook_for_test(Arc::new(move || {
            let local = crate::tools::definitions::definitions_from_json_value(
                json!({
                    "schema_version": "0.1.0",
                    "tools": [{
                        "name": "get_invoice",
                        "description": "A local tool that takes the name first.",
                        "input_json_schema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": false
                        },
                        "upstream": {
                            "method": "POST",
                            "path_template": "/v1/echo",
                            "body": { "mode": "whole_args_json" }
                        }
                    }]
                }),
                None,
            )
            .expect("local definitions should parse");
            racing_registry
                .install_local_definitions(local)
                .expect("the local lane installs against the old registry");
        }));
        let spec = r#"
openapi: 3.0.3
info:
  title: Billing
  version: 1.0.0
paths:
  /invoices/{invoice_id}:
    get:
      operationId: get_invoice
      summary: Read one invoice
      parameters:
        - in: path
          name: invoice_id
          required: true
          schema:
            type: string
"#;
        let preview = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("bounded managed spec should preview");
        let selected_tool_names = preview
            .binding
            .definitions
            .iter()
            .map(|definition| definition.name.clone())
            .collect::<Vec<_>>();
        let confirmations = preview.binding.security_selections.clone();

        let refused = service
            .register(
                record.id.as_str(),
                record.etag().as_str(),
                preview.spec_revision,
                preview.catalog_revision,
                &preview.spec_digest,
                spec,
                &selected_tool_names,
                &confirmations,
                "test-admin",
            )
            .await
            .expect_err("the registry install must be refused");
        assert_eq!(refused, OpenApiCatalogError::ToolConflict);
        assert_eq!(
            service.runtime().current_revision(&record.id),
            None,
            "no runtime marker is published for a catalog the registry does not serve"
        );
        // The catalog is durable at the authority: the next preview sees
        // its revision, which is what reconciliation will install once the
        // conflict is resolved.
        let next = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("the durable catalog previews");
        assert_eq!(next.catalog_revision, 1);
        assert!(
            registry.get("get_invoice").is_some_and(|definition| {
                !matches!(
                    definition.source,
                    crate::tools::definitions::ToolSource::OpenApi { .. }
                        | crate::tools::definitions::ToolSource::Mcp { .. }
                )
            }),
            "the local lane keeps the name it took"
        );
    }

    #[tokio::test]
    async fn register_is_revision_bound_and_restart_reconstructs_last_known_good_catalog() {
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let snapshot = control_plane.runtime_snapshot();
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Managed Billing OpenAPI",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {"type": "none"},
            "tls": {},
            "timeouts": {
                "connect_timeout_ms": 1000,
                "request_timeout_ms": 3000,
                "response_idle_timeout_ms": 1000
            },
            "discovery": {
                "type": "managed_openapi",
                "use_connection_authentication": false
            }
        }))
        .expect("managed OpenAPI Connection should deserialize");
        let record = control_plane
            .create_managed(snapshot.collection_etag(), candidate, "test-admin")
            .await
            .expect("managed OpenAPI Connection should create");
        let egress_config = EgressConfig::from_config(&config);
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress should build"));
        let http = ConnectionHttpRuntime::new(control_plane.clone(), egress_config, egress_client);
        let registry = ToolRegistry::disabled();
        let service = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            http.clone(),
            registry.clone(),
        )
        .expect("managed OpenAPI service should load");
        let spec = r#"
openapi: 3.0.3
info:
  title: Billing
  version: 1.0.0
paths:
  /invoices/{invoice_id}:
    get:
      operationId: get_invoice
      summary: Read one invoice
      parameters:
        - in: path
          name: invoice_id
          required: true
          schema:
            type: string
"#;

        let preview = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("bounded managed spec should preview");
        assert_eq!(preview.connection_etag, record.etag());
        assert_eq!(preview.spec_revision, 0);
        assert_eq!(preview.catalog_revision, 0);
        assert_eq!(preview.spec_digest, spec_digest(spec));
        let selected_tool_names = preview
            .binding
            .definitions
            .iter()
            .map(|definition| definition.name.clone())
            .collect::<Vec<_>>();
        let confirmations = preview.binding.security_selections.clone();

        let published = service
            .register(
                record.id.as_str(),
                record.etag().as_str(),
                preview.spec_revision,
                preview.catalog_revision,
                &preview.spec_digest,
                spec,
                &selected_tool_names,
                &confirmations,
                "test-admin",
            )
            .await
            .expect("exact preview should publish");
        assert_eq!(published.spec_revision, 1);
        assert_eq!(published.catalog_revision, 1);
        assert_eq!(published.added_count, 1);
        let definition = registry
            .get("get_invoice")
            .expect("published definition should be visible");
        assert!(service
            .runtime()
            .definition_is_current(&definition, record.etag().as_str()));

        assert_eq!(
            service
                .register(
                    record.id.as_str(),
                    record.etag().as_str(),
                    preview.spec_revision,
                    preview.catalog_revision,
                    &preview.spec_digest,
                    spec,
                    &selected_tool_names,
                    &confirmations,
                    "test-admin",
                )
                .await
                .err(),
            Some(OpenApiCatalogError::StalePreview),
            "the consumed preview revisions must not replace the current catalog"
        );
        let active_guard = service
            .begin_connection_mutation(&record.id)
            .expect("test should acquire the shared catalog mutation guard");
        assert_eq!(
            service
                .register(
                    record.id.as_str(),
                    record.etag().as_str(),
                    published.spec_revision,
                    published.catalog_revision,
                    &preview.spec_digest,
                    spec,
                    &selected_tool_names,
                    &confirmations,
                    "test-admin",
                )
                .await
                .err(),
            Some(OpenApiCatalogError::OperationInProgress)
        );
        drop(active_guard);

        let retained = control_plane
            .managed_store()
            .expect("managed store should exist")
            .openapi_catalog(&record.id)
            .await
            .expect("catalog should load")
            .expect("last-known-good catalog should remain");
        assert_eq!(retained.spec_revision, 1);
        assert_eq!(retained.catalog_revision, 1);
        assert_eq!(retained.spec_digest, preview.spec_digest);
        assert!(service
            .runtime()
            .definition_is_current(&definition, record.etag().as_str()));

        let restarted_registry = ToolRegistry::disabled();
        let restarted = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            http.clone(),
            restarted_registry.clone(),
        )
        .expect("stored OpenAPI catalog should reconstruct at restart");
        let restarted_definition = restarted_registry
            .get("get_invoice")
            .expect("restart should republish the stored definition");
        assert!(restarted
            .runtime()
            .definition_is_current(&restarted_definition, record.etag().as_str()));

        let mut disabled_write = record.write.clone();
        disabled_write.enabled = false;
        let disabled = control_plane
            .replace_managed(&record.id, &record.etag(), disabled_write, "test-admin")
            .await
            .expect("registered Connection should be disableable");
        let disabled_registry = ToolRegistry::disabled();
        let disabled_service = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            http,
            disabled_registry.clone(),
        )
        .expect("restart should retain but not expose a disabled Connection catalog");
        assert!(
            disabled_registry.get("get_invoice").is_none(),
            "disabled persisted catalog tools must not be republished at restart"
        );
        let disabled_status = disabled
            .safe_summary(disabled_service.status_fallback(&disabled.id, &disabled.etag(), None))
            .status;
        assert_eq!(
            disabled_status.state,
            ConnectionOperationalState::Disabled,
            "a disabled persisted catalog must not become stale after restart"
        );
        assert_eq!(
            disabled_status.reason,
            ConnectionStatusReason::Disabled,
            "a disabled persisted catalog must retain its disabled reason after restart"
        );
        let cleared = service
            .register(
                disabled.id.as_str(),
                disabled.etag().as_str(),
                published.spec_revision,
                published.catalog_revision,
                &preview.spec_digest,
                spec,
                &[],
                &[],
                "test-admin",
            )
            .await
            .expect("an exact empty registration should clear a disabled catalog");
        assert_eq!(cleared.total_count, 0);
        assert_eq!(cleared.removed_count, 1);
        assert_eq!(cleared.status.state, ConnectionOperationalState::Disabled);
        assert_eq!(cleared.status.reason, ConnectionStatusReason::Disabled);
        assert!(registry.get("get_invoice").is_none());
        assert!(!service
            .runtime()
            .definition_is_current(&definition, disabled.etag().as_str()));
        assert!(control_plane
            .managed_store()
            .expect("managed store should exist")
            .dependencies(&disabled.id)
            .await
            .expect("dependencies should load")
            .is_empty());
        control_plane
            .delete_managed(&disabled.id, &disabled.etag(), "test-admin")
            .await
            .expect("cleared disabled Connection should be deleteable");
    }

    #[tokio::test]
    async fn successful_refresh_prunes_removed_tools_and_dependencies() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("OpenAPI test listener should bind");
        let address = listener
            .local_addr()
            .expect("OpenAPI test address should be available");
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        config.egress_allowed_hosts = vec![Ipv4Addr::LOCALHOST.to_string()];
        config.egress_deny_private_ips = false;
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let snapshot = control_plane.runtime_snapshot();
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Refreshable OpenAPI",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": format!("http://{address}"),
                "base_path": "/v1"
            },
            "authentication": {"type": "none"},
            "tls": {},
            "timeouts": {
                "connect_timeout_ms": 1000,
                "request_timeout_ms": 3000,
                "response_idle_timeout_ms": 1000
            },
            "discovery": {
                "type": "managed_openapi",
                "path": "/openapi.yaml",
                "use_connection_authentication": false
            }
        }))
        .expect("refreshable OpenAPI Connection should deserialize");
        let record = control_plane
            .create_managed(snapshot.collection_etag(), candidate, "test-admin")
            .await
            .expect("refreshable OpenAPI Connection should create");
        let egress_config = EgressConfig::from_config(&config);
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress should build"));
        let registry = ToolRegistry::disabled();
        let service = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            ConnectionHttpRuntime::new(control_plane.clone(), egress_config, egress_client),
            registry.clone(),
        )
        .expect("managed OpenAPI service should load");
        let initial_spec = r#"
openapi: 3.0.3
info: {title: Refreshable, version: 1.0.0}
paths:
  /a/:
    get:
      operationId: operation_a
  /b:
    get:
      operationId: operation_b
"#;
        let refreshed_spec = r#"
openapi: 3.0.3
info: {title: Refreshable, version: 2.0.0}
paths:
  /a/:
    get:
      operationId: operation_a
"#;
        let preview = service
            .preview(record.id.as_str(), initial_spec)
            .await
            .expect("initial spec should preview");
        let selected = preview
            .binding
            .definitions
            .iter()
            .map(|definition| definition.name.clone())
            .collect::<Vec<_>>();
        service
            .register(
                record.id.as_str(),
                record.etag().as_str(),
                preview.spec_revision,
                preview.catalog_revision,
                &preview.spec_digest,
                initial_spec,
                &selected,
                &preview.binding.security_selections,
                "test-admin",
            )
            .await
            .expect("initial A+B catalog should publish");
        let initial_catalog = control_plane
            .managed_store()
            .expect("managed store should exist")
            .openapi_catalog(&record.id)
            .await
            .expect("initial catalog should load")
            .expect("initial catalog should exist");
        let reassigned_name = openapi::generate_tools_from_openapi_str(
            "reassigned-operation.yaml",
            r#"
openapi: 3.0.3
info: {title: Reassigned, version: 2.0.0}
paths:
  /replacement:
    get:
      operationId: operation_a
"#,
        )
        .expect("reassigned-name spec should parse");
        assert_eq!(
            surviving_refresh_selection(&initial_catalog, &reassigned_name).err(),
            Some(OpenApiCatalogError::InvalidSelection),
            "a surviving public name must not silently move to another operation path"
        );
        let held_removed_definition = registry
            .get("operation_b")
            .expect("operation B should initially exist");
        let server = tokio::spawn(serve_openapi_once(listener, refreshed_spec.to_owned()));

        let refreshed = service
            .refresh(record.id.as_str(), record.etag().as_str(), "test-admin")
            .await
            .expect("refresh should successfully prune a deleted operation");
        server
            .await
            .expect("one-shot OpenAPI server should complete");
        assert_eq!(refreshed.total_count, 1);
        assert_eq!(refreshed.removed_count, 1);
        assert!(registry.get("operation_a").is_some());
        assert!(registry.get("operation_b").is_none());
        assert!(!service
            .runtime()
            .definition_is_current(&held_removed_definition, record.etag().as_str()));
        let stored = control_plane
            .managed_store()
            .expect("managed store should exist")
            .openapi_catalog(&record.id)
            .await
            .expect("catalog should load")
            .expect("refreshed catalog should remain");
        assert_eq!(
            stored
                .entries
                .iter()
                .map(|entry| entry.tool_name.as_str())
                .collect::<Vec<_>>(),
            vec!["operation_a"]
        );
        let dependencies = control_plane
            .managed_store()
            .expect("managed store should exist")
            .dependencies(&record.id)
            .await
            .expect("dependencies should load");
        assert_eq!(dependencies.len(), 1);
        assert_eq!(
            dependencies[0].kind,
            super::super::store::ConnectionDependencyKind::ManagedTool
        );
        assert_eq!(dependencies[0].consumer_id, "operation_a");
    }

    async fn serve_openapi_once(listener: TcpListener, spec: String) {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("OpenAPI refresh request should connect");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1_024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("OpenAPI refresh request should read");
            assert!(read > 0, "OpenAPI request closed before its headers");
            request.extend_from_slice(&chunk[..read]);
            assert!(request.len() <= 16_384, "OpenAPI request headers too large");
        }
        assert!(
            String::from_utf8_lossy(&request).starts_with("GET /v1/openapi.yaml HTTP/1.1\r\n"),
            "refresh must use the stored same-authority discovery path"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/yaml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            spec.len(),
            spec
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("OpenAPI response should write");
        stream
            .shutdown()
            .await
            .expect("OpenAPI response should close");
    }
}
