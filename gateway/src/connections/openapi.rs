use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    fmt,
    sync::{Arc, OnceLock},
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
    middleware::rbac::RbacState,
    tools::{
        definitions::{
            McpCatalogPublishError, ToolDefinition, ToolRegistry, ToolRegistryError, ToolSource,
            ToolTarget,
        },
        enum_source::{EnumSourceRuntime, EnumSourceState, ResolvedPlan, SourceAuthorizer},
        openapi::{self, OpenApiToolBinding, OpenApiToolGeneration, OpenApiToolSecuritySelection},
        overlay::{
            self, CompiledCatalog, OverlayCompileContext, OverlayCompositeReport, OverlayDocument,
            OverlayError, OverlayProblem, OverlaySourcePlan, OverlayToolReport, OverlayWarning,
            ResolvedOverlaySources, OVERLAY_SCHEMA_VERSION,
        },
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
        decode_openapi_source_reports, ConnectionEtag, ConnectionStatusUpdate,
        ConnectionStoreError, OverlayEtag, StoredConnection, StoredEnumSourceValueWrite,
        StoredOpenApiCatalog, StoredOpenApiCatalogEntry, StoredOpenApiOverlay,
        StoredOpenApiSourceKind, StoredOpenApiSourceReport, StoredOpenApiSourceReports,
        StoredOverlayWrite,
    },
};

#[derive(Clone)]
pub struct OpenApiConnectionCatalogRuntime {
    state: Arc<ArcSwap<BTreeMap<ConnectionId, ActiveOpenApiCatalog>>>,
}

#[derive(Clone, Debug)]
struct ActiveOpenApiCatalog {
    connection_revision: u64,
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
    enum_source_runtime: Option<EnumSourceRuntime>,
    source_authorizer: Arc<OnceLock<Arc<dyn SourceAuthorizer>>>,
    rbac: Option<RbacState>,
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
    /// `None` preserves the durable overlay; `Some` stores or deletes it in
    /// the same transaction as this compiled catalog.
    overlay: Option<StoredOverlayWrite>,
    /// Overlay revision the binding was compiled against. A preserve write
    /// must compare this under the store transaction lock.
    compiled_overlay_revision: u64,
    /// Rename targets that were not owned by this generated operation in
    /// the prior stored overlay. PostgreSQL rechecks these against the
    /// authoritative policy under the shared policy/catalog advisory lock.
    policy_protected_names: Vec<String>,
    /// The exact enum refresh plan published with this catalog. `None`
    /// removes any prior plan after the authority commit.
    source_plan: Option<OverlaySourcePlan>,
    enum_values: Vec<StoredEnumSourceValueWrite>,
    started: Instant,
    /// Who is publishing. The authority records it on the immutable
    /// specification version; standalone mode has no version table and
    /// ignores it.
    actor: &'a str,
}

struct OpenApiPublishedCatalog {
    result: OpenApiCatalogPublishResult,
    catalog: StoredOpenApiCatalog,
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
    /// Always keyed by generated names, even when the previewed binding was
    /// renamed for serving. Registration confirmations use this copy.
    pub registration_security_selections: Vec<OpenApiToolSecuritySelection>,
    pub overlay_report: Option<OpenApiOverlayCompileReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OpenApiOverlayCompileReport {
    pub tools: Vec<OverlayToolReport>,
    pub composites: Vec<OverlayCompositeReport>,
    pub warnings: Vec<OverlayWarning>,
    pub sources: Vec<StoredOpenApiSourceReport>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OpenApiOverlayMutationResult {
    pub stored: Option<StoredOpenApiOverlay>,
    /// The strong ETag of the catalog/overlay pair committed by this
    /// mutation. Including the monotonically increasing catalog revision
    /// prevents a deleted and recreated overlay from reusing an old tag.
    pub etag: OverlayEtag,
    pub report: Option<OpenApiOverlayCompileReport>,
    pub catalog: OpenApiCatalogPublishResult,
}

#[derive(Debug)]
pub enum OpenApiOverlayOperationError {
    Catalog(OpenApiCatalogError),
    Rejected(OverlayError),
    PreconditionFailed(OverlayEtag),
    SecretsWriteRequired,
}

impl fmt::Display for OpenApiOverlayOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => error.fmt(formatter),
            Self::Rejected(error) => error.fmt(formatter),
            Self::PreconditionFailed(current) => write!(
                formatter,
                "connection overlay changed; current ETag is {current}"
            ),
            Self::SecretsWriteRequired => write!(
                formatter,
                "raw OpenAPI overlay source paths require secrets-write authority"
            ),
        }
    }
}

impl std::error::Error for OpenApiOverlayOperationError {}

impl From<OpenApiCatalogError> for OpenApiOverlayOperationError {
    fn from(error: OpenApiCatalogError) -> Self {
        Self::Catalog(error)
    }
}

impl From<OverlayError> for OpenApiOverlayOperationError {
    fn from(error: OverlayError) -> Self {
        Self::Rejected(error)
    }
}

#[derive(Debug)]
enum OpenApiPublishError {
    Catalog(OpenApiCatalogError),
    OverlayPreconditionFailed(OverlayEtag),
}

impl From<OpenApiCatalogError> for OpenApiPublishError {
    fn from(error: OpenApiCatalogError) -> Self {
        Self::Catalog(error)
    }
}

impl OpenApiPublishError {
    fn into_catalog(self) -> OpenApiCatalogError {
        match self {
            Self::Catalog(error) => error,
            // Register and refresh preserve the overlay and never expose an
            // overlay precondition. If another replica changed it after the
            // compile, fail closed and make the caller retry from a preview.
            Self::OverlayPreconditionFailed(_) => OpenApiCatalogError::StalePreview,
        }
    }

    fn into_overlay_operation(self) -> OpenApiOverlayOperationError {
        match self {
            Self::Catalog(error) => OpenApiOverlayOperationError::Catalog(error),
            Self::OverlayPreconditionFailed(current) => {
                OpenApiOverlayOperationError::PreconditionFailed(current)
            }
        }
    }
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
        connection_revision: u64,
        definition_digests: BTreeMap<String, [u8; 32]>,
    ) {
        self.publish_active(
            catalog.connection_id.clone(),
            ActiveOpenApiCatalog {
                connection_revision,
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

    fn current_generation(&self, connection_id: &ConnectionId) -> Option<(u64, String, u64)> {
        self.state.load().get(connection_id).map(|catalog| {
            (
                catalog.connection_revision,
                catalog.observed_etag.clone(),
                catalog.catalog_revision,
            )
        })
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
            })
            | Some(ToolTarget::Composite {
                connection_id: target_connection_id,
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
        Self::load_with_enum_sources(control_plane, http, registry, conflicts, None)
    }

    pub fn load_with_enum_sources(
        control_plane: ConnectionControlPlane,
        http: ConnectionHttpRuntime,
        registry: ToolRegistry,
        conflicts: crate::tools::definitions::LaneConflicts,
        enum_source_runtime: Option<EnumSourceRuntime>,
    ) -> Result<Self, ConnectionStoreError> {
        let (catalogs, overlays) = if control_plane.is_managed_store_configured() {
            control_plane
                .managed_store()
                .map_err(|_| ConnectionStoreError::Validation {
                    problems: vec!["managed Connection store is unavailable".to_owned()],
                })?
                .boot_openapi_catalogs_with_overlays()?
        } else {
            (Vec::new(), Vec::new())
        };
        validate_catalog_overlay_pairs(&catalogs, &overlays)?;
        let snapshot = control_plane.runtime_snapshot();
        let active_catalogs = catalogs
            .into_iter()
            .filter(|catalog| {
                snapshot
                    .managed()
                    .get(&catalog.connection_id)
                    .is_some_and(|record| {
                        record.write.enabled
                            && supports_managed_openapi_catalog(record)
                            && catalog.observed_etag == record.etag()
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
        let service = Self {
            control_plane,
            http,
            registry,
            runtime,
            enum_source_runtime,
            source_authorizer: Arc::new(OnceLock::new()),
            rbac: None,
            #[cfg(test)]
            install_hook: None,
        };
        service.install_boot_source_plans(&active_catalogs, &overlays)?;
        if let Some(runtime) = &service.enum_source_runtime {
            runtime.discard_unclaimed_boot_rows();
        }
        Ok(service)
    }

    pub fn with_rbac_state(mut self, rbac: Option<RbacState>) -> Self {
        self.rbac = rbac;
        self
    }

    pub fn set_source_authorizer(&self, authorizer: Arc<dyn SourceAuthorizer>) {
        let _ = self.source_authorizer.set(authorizer);
    }

    pub fn enum_source_runtime(&self) -> Option<EnumSourceRuntime> {
        self.enum_source_runtime.clone()
    }

    #[cfg(test)]
    pub(crate) fn with_install_hook_for_test(mut self, hook: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.install_hook = Some(hook);
        self
    }

    pub fn runtime(&self) -> OpenApiConnectionCatalogRuntime {
        self.runtime.clone()
    }

    fn install_boot_source_plans(
        &self,
        catalogs: &[StoredOpenApiCatalog],
        overlays: &[StoredOpenApiOverlay],
    ) -> Result<(), ConnectionStoreError> {
        let Some(runtime) = self.enum_source_runtime.as_ref() else {
            return Ok(());
        };
        let overlays = overlays
            .iter()
            .map(|overlay| (&overlay.connection_id, overlay))
            .collect::<BTreeMap<_, _>>();
        for catalog in catalogs {
            let Some(stored_overlay) = overlays.get(&catalog.connection_id).copied() else {
                runtime.remove_plan(&catalog.connection_id);
                continue;
            };
            let plan = stored_source_plan(catalog, stored_overlay)?;
            runtime.install_plan(
                &catalog.connection_id,
                stored_overlay.overlay_revision,
                &plan,
            );
        }
        Ok(())
    }

    async fn resolve_source_plan(
        &self,
        connection_id: &ConnectionId,
        overlay_revision: u64,
        plan: &OverlaySourcePlan,
        allow_unresolved_enum_sources: bool,
    ) -> Result<ResolvedPlan, OverlayError> {
        if plan.enum_sources.is_empty() && plan.label_sources.is_empty() {
            return Ok(ResolvedPlan {
                sources: ResolvedOverlaySources::default(),
                enum_values: Vec::new(),
                reports: StoredOpenApiSourceReports::empty(),
                warnings: Vec::new(),
            });
        }
        let runtime = self
            .enum_source_runtime
            .as_ref()
            .ok_or_else(|| OverlayError {
                problems: vec![OverlayProblem {
                    path: "/".to_owned(),
                    message: "dynamic source runtime is unavailable".to_owned(),
                }],
            })?;
        let authorizer = self.source_authorizer.get().ok_or_else(|| OverlayError {
            problems: vec![OverlayProblem {
                path: "/".to_owned(),
                message: "dynamic source authorization is unavailable".to_owned(),
            }],
        })?;
        runtime
            .resolve_plan(
                connection_id,
                overlay_revision,
                plan,
                allow_unresolved_enum_sources,
                authorizer.as_ref(),
            )
            .await
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
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| ConnectionStoreError::Validation {
                problems: vec!["managed Connection store is unavailable".to_owned()],
            })?
            .clone();
        let (catalogs, overlays) = store.openapi_catalogs_with_overlays().await?;
        if let Err(error) = validate_catalog_overlay_pairs(&catalogs, &overlays) {
            // The catalog and overlay are one logical authority resource.
            // The store returns them from one snapshot, so a mismatch is
            // durable corruption rather than a concurrent publication.
            // Keeping an older compiled lane live could retain a name or
            // visibility decision that no longer has an authoring document
            // behind it, so withdraw every affected Connection.
            let affected = catalogs
                .iter()
                .map(|catalog| catalog.connection_id.clone())
                .chain(overlays.iter().map(|overlay| overlay.connection_id.clone()))
                .collect::<BTreeSet<_>>();
            for connection_id in affected {
                self.discard_runtime_catalog(&connection_id);
            }
            return Err(error);
        }
        let snapshot = self.control_plane.runtime_snapshot();
        let overlays_by_id = overlays
            .iter()
            .map(|overlay| (&overlay.connection_id, overlay))
            .collect::<BTreeMap<_, _>>();
        let active = catalogs
            .into_iter()
            .filter(|catalog| {
                snapshot
                    .managed()
                    .get(&catalog.connection_id)
                    .is_some_and(|record| {
                        record.write.enabled
                            && supports_managed_openapi_catalog(record)
                            && catalog.observed_etag == record.etag()
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
            // A Connection mutation can race the snapshot collected above.
            // Re-read it while holding the same lifecycle guard used by
            // publishers and refuse to install a catalog from an older
            // endpoint/authentication generation.
            let current_record = self
                .control_plane
                .runtime_snapshot()
                .managed()
                .get(&catalog.connection_id)
                .cloned();
            let Some(current_record) = current_record.filter(|record| {
                record.write.enabled
                    && supports_managed_openapi_catalog(record)
                    && catalog.observed_etag == record.etag()
            }) else {
                self.discard_runtime_catalog(&catalog.connection_id);
                continue;
            };
            let candidate_generation = (
                current_record.revisions.connection,
                catalog.observed_etag.as_str(),
                catalog.catalog_revision,
            );
            if self
                .runtime
                .current_generation(&catalog.connection_id)
                .is_some_and(
                    |(live_connection_revision, live_etag, live_catalog_revision)| {
                        live_connection_revision > candidate_generation.0
                            || (live_connection_revision == candidate_generation.0
                                && live_etag == candidate_generation.1
                                && live_catalog_revision >= candidate_generation.2)
                    },
                )
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
            if let Some(enum_runtime) = self.enum_source_runtime.as_ref() {
                if let Some(stored_overlay) = overlays_by_id.get(&catalog.connection_id).copied() {
                    let plan = stored_source_plan(catalog, stored_overlay)?;
                    // Reconciliation may observe a volatile row written by
                    // another replica. Register the plan empty first, then
                    // let the safe authority reader adopt only rows backed
                    // by a stable credential generation.
                    enum_runtime.remove_plan(&catalog.connection_id);
                    enum_runtime.install_plan(
                        &catalog.connection_id,
                        stored_overlay.overlay_revision,
                        &plan,
                    );
                    enum_runtime
                        .install_plan_from_store(
                            &catalog.connection_id,
                            stored_overlay.overlay_revision,
                            &plan,
                        )
                        .await?;
                } else {
                    enum_runtime.remove_plan(&catalog.connection_id);
                }
            }
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

    /// Read the authoring overlay independently of the compiled catalog.
    ///
    /// The returned ETag is present even when the document is absent (`o0`).
    /// It includes both the catalog revision and the overlay document
    /// revision, with `r0:o0` representing a Connection that has no catalog.
    /// The third tuple item is the catalog revision that currently contains
    /// the compiled document, or `None` when the Connection has not registered
    /// an OpenAPI catalog yet. A corrupt revision/document pair fails closed.
    pub async fn openapi_overlay(
        &self,
        raw_connection_id: &str,
    ) -> Result<(Option<StoredOpenApiOverlay>, OverlayEtag, Option<u64>), OpenApiCatalogError> {
        let (connection_id, record) =
            self.managed_openapi_record_identity(raw_connection_id, None)?;
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| OpenApiCatalogError::StoreUnavailable)?;
        let (catalog, mut stored) = store
            .openapi_catalog_with_overlay(&connection_id)
            .await
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        validate_catalog_overlay_pair(catalog.as_ref(), stored.as_ref())
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let overlay_revision = stored
            .as_ref()
            .map_or(0, |overlay| overlay.overlay_revision);
        let catalog_revision = catalog
            .as_ref()
            .map_or(0, |catalog| catalog.catalog_revision);
        let applied_catalog_revision = catalog.as_ref().map(|catalog| catalog.catalog_revision);
        if let (Some(enum_runtime), Some(catalog), Some(stored_overlay)) = (
            self.enum_source_runtime.as_ref(),
            catalog.as_ref(),
            stored.as_mut(),
        ) {
            project_enum_source_reports(enum_runtime, catalog, stored_overlay)
                .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        }
        Ok((
            stored,
            OverlayEtag::for_revisions(
                connection_id.as_str(),
                record.revisions.connection,
                catalog_revision,
                overlay_revision,
            ),
            applied_catalog_revision,
        ))
    }

    /// Validate, compile, persist, and publish an overlay as one catalog
    /// mutation. The document is canonicalised through its typed model before
    /// storage; a failed validation, compile, CAS, or authority write leaves
    /// both the overlay and the live registry lane unchanged.
    pub async fn put_overlay(
        &self,
        raw_connection_id: &str,
        expected_overlay_etag: &str,
        document: &Value,
        actor: &str,
    ) -> Result<OpenApiOverlayMutationResult, OpenApiOverlayOperationError> {
        self.put_overlay_with_options(
            raw_connection_id,
            expected_overlay_etag,
            document,
            false,
            actor,
        )
        .await
    }

    pub async fn put_overlay_with_options(
        &self,
        raw_connection_id: &str,
        expected_overlay_etag: &str,
        document: &Value,
        allow_unresolved_enum_sources: bool,
        actor: &str,
    ) -> Result<OpenApiOverlayMutationResult, OpenApiOverlayOperationError> {
        self.put_overlay_with_authorization(
            raw_connection_id,
            expected_overlay_etag,
            document,
            allow_unresolved_enum_sources,
            true,
            actor,
        )
        .await
    }

    pub async fn put_overlay_with_authorization(
        &self,
        raw_connection_id: &str,
        expected_overlay_etag: &str,
        document: &Value,
        allow_unresolved_enum_sources: bool,
        secrets_write_authorized: bool,
        actor: &str,
    ) -> Result<OpenApiOverlayMutationResult, OpenApiOverlayOperationError> {
        let connection_id = ConnectionId::parse(raw_connection_id.to_owned())
            .map_err(|_| OpenApiCatalogError::InvalidConnectionId)?;
        let _active = self
            .control_plane
            .begin_catalog_mutation(&connection_id)
            .map_err(catalog_lifecycle_error)?;
        let document = overlay::validate(document)?;
        if document.has_raw_path_sources() && !secrets_write_authorized {
            return Err(OpenApiOverlayOperationError::SecretsWriteRequired);
        }
        // A rename is checked against the live policy map. Serialize this
        // local mutation with policy writes so a grant cannot appear between
        // the ownership check and catalog publication.
        let _policy_write_guard = match self.rbac.as_ref() {
            Some(rbac) => Some(rbac.policy_write_guard().await),
            None => None,
        };
        let (_, record) = self.managed_openapi_record(raw_connection_id, None)?;
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| OpenApiCatalogError::StoreUnavailable)?
            .clone();
        let (prior, stored_overlay) = store
            .openapi_catalog_with_overlay(&connection_id)
            .await
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let prior = prior.ok_or(OpenApiCatalogError::CatalogNotRegistered)?;
        validate_catalog_overlay_pair(Some(&prior), stored_overlay.as_ref())
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let current_overlay_revision = require_overlay_precondition(
            &connection_id,
            record.revisions.connection,
            prior.catalog_revision,
            stored_overlay.as_ref(),
            expected_overlay_etag,
        )?;
        if prior.observed_etag != record.etag() {
            return Err(OpenApiCatalogError::StalePreview.into());
        }
        let encoded_document = serde_json::to_string(&document)
            .map_err(|_| OpenApiOverlayOperationError::Catalog(OpenApiCatalogError::InvalidSpec))?;
        let prior_document = decode_stored_overlay(stored_overlay.as_ref())?;
        let generation =
            openapi::generate_tools_from_openapi_str("managed-openapi-overlay-put", &prior.spec)
                .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        let (selected_tool_names, confirmations) =
            surviving_refresh_selection(&prior, &generation, prior_document.as_ref())?;
        let binding = bind_selected_tools(
            &generation,
            &connection_id,
            &record,
            &selected_tool_names,
            &confirmations,
        )?;
        let compile_context =
            self.overlay_compile_context(&connection_id, Some(&prior), prior_document.as_ref());
        let next_overlay_revision = current_overlay_revision
            .checked_add(1)
            .ok_or(OpenApiCatalogError::StorageUnavailable)?;
        let source_plan = overlay::plan_sources(&generation, &document)?;
        let resolved = self
            .resolve_source_plan(
                &connection_id,
                next_overlay_revision,
                &source_plan,
                allow_unresolved_enum_sources,
            )
            .await?;
        let mut compiled = overlay::compile_with_resolved_sources(
            &generation,
            binding,
            &document,
            &compile_context,
            &resolved.sources,
        )?;
        compiled.warnings.extend(resolved.warnings.iter().cloned());
        validate_binding_budget(&compiled.binding)?;
        let report = compiled_report(&compiled, &resolved.reports);
        let policy_protected_names = compiled
            .renames
            .iter()
            .filter(|(generated_name, served_name)| {
                compile_context
                    .prior_overlay_name_owners
                    .get(served_name.as_str())
                    != Some(*generated_name)
            })
            .map(|(_, served_name)| served_name.clone())
            .chain(
                document
                    .composites
                    .keys()
                    .filter(|composite_name| {
                        compile_context
                            .prior_overlay_name_owners
                            .get(composite_name.as_str())
                            != Some(*composite_name)
                    })
                    .cloned(),
            )
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let digest = prior.spec_digest.clone();
        let source_reports_json = resolved
            .reports
            .canonical_json()
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let published = self
            .publish_candidate(OpenApiPublishCandidate {
                record: &record,
                expected_spec_revision: prior.spec_revision,
                expected_catalog_revision: prior.catalog_revision,
                spec: &prior.spec,
                digest: &digest,
                binding: compiled.binding,
                overlay: Some(StoredOverlayWrite::Put {
                    schema_version: document.schema_version.clone(),
                    overlay_json: encoded_document.clone(),
                    source_reports_json: source_reports_json.clone(),
                    expected_overlay_revision: current_overlay_revision,
                }),
                compiled_overlay_revision: next_overlay_revision,
                policy_protected_names,
                source_plan: Some(compiled.source_plan.clone()),
                enum_values: resolved.enum_values,
                started: Instant::now(),
                actor,
            })
            .await
            .map_err(OpenApiPublishError::into_overlay_operation)?;
        if published.catalog.overlay_revision != next_overlay_revision {
            return Err(OpenApiCatalogError::StorageUnavailable.into());
        }
        let stored = StoredOpenApiOverlay {
            connection_id,
            schema_version: document.schema_version,
            overlay_revision: next_overlay_revision,
            overlay_json: encoded_document,
            source_reports_json: Some(source_reports_json),
            updated_at: published.catalog.refreshed_at.clone(),
        };
        let etag = OverlayEtag::for_revisions(
            stored.connection_id.as_str(),
            record.revisions.connection,
            published.catalog.catalog_revision,
            stored.overlay_revision,
        );
        Ok(OpenApiOverlayMutationResult {
            stored: Some(stored),
            etag,
            report: Some(report),
            catalog: published.result,
        })
    }

    /// Recompile the registered catalog without an overlay and delete the
    /// authoring document in the same authority transaction.
    pub async fn delete_overlay(
        &self,
        raw_connection_id: &str,
        expected_overlay_etag: &str,
        actor: &str,
    ) -> Result<OpenApiOverlayMutationResult, OpenApiOverlayOperationError> {
        let connection_id = ConnectionId::parse(raw_connection_id.to_owned())
            .map_err(|_| OpenApiCatalogError::InvalidConnectionId)?;
        let _active = self
            .control_plane
            .begin_catalog_mutation(&connection_id)
            .map_err(catalog_lifecycle_error)?;
        let _policy_write_guard = match self.rbac.as_ref() {
            Some(rbac) => Some(rbac.policy_write_guard().await),
            None => None,
        };
        let (_, record) = self.managed_openapi_record(raw_connection_id, None)?;
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| OpenApiCatalogError::StoreUnavailable)?
            .clone();
        let (prior, stored_overlay) = store
            .openapi_catalog_with_overlay(&connection_id)
            .await
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let prior = prior.ok_or(OpenApiCatalogError::CatalogNotRegistered)?;
        validate_catalog_overlay_pair(Some(&prior), stored_overlay.as_ref())
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let current_overlay_revision = require_overlay_precondition(
            &connection_id,
            record.revisions.connection,
            prior.catalog_revision,
            stored_overlay.as_ref(),
            expected_overlay_etag,
        )?;
        if prior.observed_etag != record.etag() {
            return Err(OpenApiCatalogError::StalePreview.into());
        }
        let prior_document = decode_stored_overlay(stored_overlay.as_ref())?;
        let generation =
            openapi::generate_tools_from_openapi_str("managed-openapi-overlay-delete", &prior.spec)
                .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        let (selected_tool_names, confirmations) =
            surviving_refresh_selection(&prior, &generation, prior_document.as_ref())?;
        let binding = bind_selected_tools(
            &generation,
            &connection_id,
            &record,
            &selected_tool_names,
            &confirmations,
        )?;
        validate_binding_budget(&binding)?;
        let digest = prior.spec_digest.clone();
        let published = self
            .publish_candidate(OpenApiPublishCandidate {
                record: &record,
                expected_spec_revision: prior.spec_revision,
                expected_catalog_revision: prior.catalog_revision,
                spec: &prior.spec,
                digest: &digest,
                binding,
                overlay: Some(StoredOverlayWrite::Delete {
                    expected_overlay_revision: current_overlay_revision,
                }),
                compiled_overlay_revision: 0,
                policy_protected_names: Vec::new(),
                source_plan: None,
                enum_values: Vec::new(),
                started: Instant::now(),
                actor,
            })
            .await
            .map_err(OpenApiPublishError::into_overlay_operation)?;
        if published.catalog.overlay_revision != 0 {
            return Err(OpenApiCatalogError::StorageUnavailable.into());
        }
        let etag = OverlayEtag::for_revisions(
            connection_id.as_str(),
            record.revisions.connection,
            published.catalog.catalog_revision,
            0,
        );
        Ok(OpenApiOverlayMutationResult {
            stored: None,
            etag,
            report: None,
            catalog: published.result,
        })
    }

    pub async fn preview(
        &self,
        raw_connection_id: &str,
        spec: &str,
    ) -> Result<OpenApiCatalogPreview, OpenApiCatalogError> {
        match self
            .preview_with_overlay(raw_connection_id, spec, None)
            .await
        {
            Ok(preview) => Ok(preview),
            Err(OpenApiOverlayOperationError::Catalog(error)) => Err(error),
            Err(OpenApiOverlayOperationError::Rejected(_)) => Err(OpenApiCatalogError::InvalidSpec),
            Err(OpenApiOverlayOperationError::PreconditionFailed(_)) => {
                Err(OpenApiCatalogError::StorageUnavailable)
            }
            Err(OpenApiOverlayOperationError::SecretsWriteRequired) => {
                Err(OpenApiCatalogError::InvalidSpec)
            }
        }
    }

    pub async fn preview_with_overlay(
        &self,
        raw_connection_id: &str,
        spec: &str,
        candidate_overlay: Option<&Value>,
    ) -> Result<OpenApiCatalogPreview, OpenApiOverlayOperationError> {
        self.preview_with_overlay_authorization(raw_connection_id, spec, candidate_overlay, true)
            .await
    }

    pub async fn preview_with_overlay_authorization(
        &self,
        raw_connection_id: &str,
        spec: &str,
        candidate_overlay: Option<&Value>,
        secrets_write_authorized: bool,
    ) -> Result<OpenApiCatalogPreview, OpenApiOverlayOperationError> {
        validate_spec_size(spec)?;
        let (connection_id, record) = self.managed_openapi_record(raw_connection_id, None)?;
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| OpenApiCatalogError::StoreUnavailable)?;
        let (prior, stored_overlay) = store
            .openapi_catalog_with_overlay(&connection_id)
            .await
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        validate_catalog_overlay_pair(prior.as_ref(), stored_overlay.as_ref())
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let generation = openapi::generate_tools_from_openapi_str("managed-openapi-preview", spec)
            .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        let mut binding = openapi::bind_generated_openapi_tools(
            &generation,
            &connection_id,
            &record.write.authentication,
        )
        .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
        let registration_security_selections = binding.security_selections.clone();
        let prior_document = decode_stored_overlay(stored_overlay.as_ref())?;
        let candidate_document = match candidate_overlay {
            Some(document) => Some(overlay::validate(document)?),
            None => prior_document.clone(),
        };
        if candidate_document
            .as_ref()
            .is_some_and(|document| document.has_raw_path_sources())
            && !secrets_write_authorized
        {
            return Err(OpenApiOverlayOperationError::SecretsWriteRequired);
        }
        let overlay_report = if let Some(document) = candidate_document.as_ref() {
            let source_plan = overlay::plan_sources(&generation, document)?;
            let overlay_revision = if candidate_overlay.is_some() {
                stored_overlay
                    .as_ref()
                    .map_or(0, |stored| stored.overlay_revision)
                    .checked_add(1)
                    .ok_or(OpenApiCatalogError::StorageUnavailable)?
            } else {
                stored_overlay
                    .as_ref()
                    .map_or(0, |stored| stored.overlay_revision)
            };
            let resolved = self
                .resolve_source_plan(&connection_id, overlay_revision, &source_plan, false)
                .await?;
            let mut compiled = overlay::compile_with_resolved_sources(
                &generation,
                binding,
                document,
                &self.overlay_compile_context(
                    &connection_id,
                    prior.as_ref(),
                    prior_document.as_ref(),
                ),
                &resolved.sources,
            )
            .map_err(OpenApiOverlayOperationError::Rejected)?;
            compiled.warnings.extend(resolved.warnings.iter().cloned());
            let report = compiled_report(&compiled, &resolved.reports);
            binding = compiled.binding;
            inject_preview_enum_values(&mut binding, &resolved.sources)?;
            Some(report)
        } else {
            None
        };
        validate_binding_budget(&binding)?;
        Ok(OpenApiCatalogPreview {
            connection_id,
            connection_etag: record.etag(),
            spec_digest: spec_digest(spec),
            spec_revision: prior.as_ref().map_or(0, |catalog| catalog.spec_revision),
            catalog_revision: prior.as_ref().map_or(0, |catalog| catalog.catalog_revision),
            generation,
            binding,
            registration_security_selections,
            overlay_report,
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
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| OpenApiCatalogError::StoreUnavailable)?;
        let (prior, stored_overlay) = store
            .openapi_catalog_with_overlay(&connection_id)
            .await
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        validate_catalog_overlay_pair(prior.as_ref(), stored_overlay.as_ref())
            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
        let overlay_document = decode_stored_overlay(stored_overlay.as_ref())?;
        let selected_tool_names = normalize_registration_selection(
            &generation,
            selected_tool_names,
            overlay_document.as_ref(),
        )?;
        let mut binding = bind_selected_tools(
            &generation,
            &connection_id,
            &record,
            &selected_tool_names,
            confirmations,
        )?;
        let (source_plan, enum_values, overlay_write) =
            if let Some(document) = overlay_document.as_ref() {
                let source_plan = overlay::plan_sources(&generation, document)
                    .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
                let overlay_revision = stored_overlay
                    .as_ref()
                    .map_or(0, |stored| stored.overlay_revision);
                let resolved = self
                    .resolve_source_plan(&connection_id, overlay_revision, &source_plan, false)
                    .await
                    .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
                let compiled = overlay::compile_with_resolved_sources(
                    &generation,
                    binding,
                    document,
                    &self.overlay_compile_context(
                        &connection_id,
                        prior.as_ref(),
                        overlay_document.as_ref(),
                    ),
                    &resolved.sources,
                )
                .map_err(|_| OpenApiCatalogError::InvalidSpec)?;
                binding = compiled.binding;
                let source_reports_json = resolved
                    .reports
                    .canonical_json()
                    .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
                (
                    Some(compiled.source_plan),
                    resolved.enum_values,
                    Some(StoredOverlayWrite::Reports {
                        source_reports_json,
                        expected_overlay_revision: overlay_revision,
                    }),
                )
            } else {
                (None, Vec::new(), None)
            };
        self.publish_candidate(OpenApiPublishCandidate {
            record: &record,
            expected_spec_revision,
            expected_catalog_revision,
            spec,
            digest: expected_spec_digest,
            binding,
            overlay: overlay_write,
            compiled_overlay_revision: stored_overlay
                .as_ref()
                .map_or(0, |stored| stored.overlay_revision),
            policy_protected_names: Vec::new(),
            source_plan,
            enum_values,
            started: Instant::now(),
            actor,
        })
        .await
        .map(|published| published.result)
        .map_err(OpenApiPublishError::into_catalog)
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
        let (prior, stored_overlay) = match store.openapi_catalog_with_overlay(&connection_id).await
        {
            Ok(pair) => pair,
            Err(_) => return Err(OpenApiCatalogError::StorageUnavailable),
        };
        let prior = match prior {
            Some(prior) => prior,
            None => return Err(OpenApiCatalogError::CatalogNotRegistered),
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
        if validate_catalog_overlay_pair(Some(&prior), stored_overlay.as_ref()).is_err() {
            let error = OpenApiCatalogError::StorageUnavailable;
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
        let overlay_document = match decode_stored_overlay(stored_overlay.as_ref()) {
            Ok(document) => document,
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
        let (selected_tool_names, confirmations) =
            match surviving_refresh_selection(&prior, &generation, overlay_document.as_ref()) {
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
        let mut binding = match bind_selected_tools(
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
        let (source_plan, enum_values, overlay_write) =
            if let Some(document) = overlay_document.as_ref() {
                let source_plan = match overlay::plan_sources(&generation, document) {
                    Ok(plan) => plan,
                    Err(_) => {
                        let error = OpenApiCatalogError::InvalidSpec;
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
                let overlay_revision = stored_overlay
                    .as_ref()
                    .map_or(0, |stored| stored.overlay_revision);
                let resolved = match self
                    .resolve_source_plan(&connection_id, overlay_revision, &source_plan, false)
                    .await
                {
                    Ok(resolved) => resolved,
                    Err(_) => {
                        let error = OpenApiCatalogError::InvalidSpec;
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
                match overlay::compile_with_resolved_sources(
                    &generation,
                    binding,
                    document,
                    &self.overlay_compile_context(
                        &connection_id,
                        Some(&prior),
                        overlay_document.as_ref(),
                    ),
                    &resolved.sources,
                ) {
                    Ok(compiled) => {
                        binding = compiled.binding;
                        let source_reports_json = resolved
                            .reports
                            .canonical_json()
                            .map_err(|_| OpenApiCatalogError::StorageUnavailable)?;
                        (
                            Some(compiled.source_plan),
                            resolved.enum_values,
                            Some(StoredOverlayWrite::Reports {
                                source_reports_json,
                                expected_overlay_revision: overlay_revision,
                            }),
                        )
                    }
                    Err(_) => {
                        let error = OpenApiCatalogError::InvalidSpec;
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
            } else {
                (None, Vec::new(), None)
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
                overlay: overlay_write,
                compiled_overlay_revision: stored_overlay
                    .as_ref()
                    .map_or(0, |stored| stored.overlay_revision),
                policy_protected_names: Vec::new(),
                source_plan,
                enum_values,
                started,
                actor,
            })
            .await;
        match published {
            Ok(published) => Ok(published.result),
            Err(error) => {
                let error = error.into_catalog();
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

    fn overlay_compile_context(
        &self,
        connection_id: &ConnectionId,
        _stored_catalog: Option<&StoredOpenApiCatalog>,
        stored_overlay: Option<&OverlayDocument>,
    ) -> OverlayCompileContext {
        let policy_tool_names = self
            .rbac
            .as_ref()
            .map(|rbac| rbac.current_policy().tools.into_keys().collect())
            .unwrap_or_default();
        let other_lane_tool_names = self
            .registry
            .list()
            .into_iter()
            .filter(|definition| {
                !matches!(
                    &definition.source,
                    ToolSource::OpenApi {
                        connection_id: owner,
                        ..
                    } if owner == connection_id.as_str()
                )
            })
            .map(|definition| definition.name.clone())
            .collect();
        let prior_overlay_name_owners = stored_overlay
            .into_iter()
            .flat_map(|overlay| {
                let mut owners = overlay
                    .tools
                    .iter()
                    .filter_map(|(generated_name, tool)| {
                        tool.rename
                            .as_ref()
                            .map(|served_name| (served_name.clone(), generated_name.clone()))
                    })
                    .collect::<Vec<_>>();
                owners.extend(
                    overlay
                        .composites
                        .keys()
                        .cloned()
                        .map(|name| (name.clone(), name)),
                );
                owners
            })
            .collect();
        OverlayCompileContext {
            policy_tool_names,
            other_lane_tool_names,
            prior_overlay_name_owners,
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
        if let Some(enum_runtime) = self.enum_source_runtime.as_ref() {
            enum_runtime.remove_plan(connection_id);
        }
    }

    async fn publish_candidate(
        &self,
        candidate: OpenApiPublishCandidate<'_>,
    ) -> Result<OpenApiPublishedCatalog, OpenApiPublishError> {
        let OpenApiPublishCandidate {
            record,
            expected_spec_revision,
            expected_catalog_revision,
            spec,
            digest,
            mut binding,
            overlay,
            compiled_overlay_revision,
            policy_protected_names,
            source_plan,
            enum_values,
            started,
            actor,
        } = candidate;
        if !binding.incompatibilities.is_empty() {
            return Err(OpenApiCatalogError::AuthenticationMismatch.into());
        }
        let next_catalog_revision = expected_catalog_revision
            .checked_add(1)
            .ok_or(OpenApiCatalogError::StorageUnavailable)?;
        for definition in &mut binding.definitions {
            let ToolSource::OpenApi {
                catalog_revision, ..
            } = &mut definition.source
            else {
                return Err(OpenApiCatalogError::InvalidSpec.into());
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
            .replace_openapi_catalog_with_overlay_and_enum_values(
                &record.id,
                &expected_connection_etag,
                expected_spec_revision,
                expected_catalog_revision,
                spec,
                digest,
                &entries,
                overlay.as_ref(),
                compiled_overlay_revision,
                actor,
                &policy_protected_names,
                &enum_values,
            )
            .await
            .map_err(|error| publish_store_error(&record.id, &error))?;
        // Catalog revisions reset when a Connection leaves and later
        // re-enters managed OpenAPI. Order first by the monotonically
        // increasing Connection generation, then by the exact observed
        // ETag and catalog revision within that generation. Otherwise an
        // old c1/r99 publisher can overwrite a current c3/r1 catalog on a
        // replica that missed the intermediate removal callbacks.
        let candidate_generation = (
            record.revisions.connection,
            catalog.observed_etag.as_str(),
            catalog.catalog_revision,
        );
        if self.runtime.current_generation(&record.id).is_some_and(
            |(live_connection_revision, live_etag, live_catalog_revision)| {
                live_connection_revision > candidate_generation.0
                    || (live_connection_revision == candidate_generation.0
                        && live_etag == candidate_generation.1
                        && live_catalog_revision > candidate_generation.2)
            },
        ) {
            tracing::info!(
                connection_id = %record.id,
                connection_revision = record.revisions.connection,
                catalog_revision = catalog.catalog_revision,
                "a newer OpenAPI catalog generation is already live on this replica; the committed one is durable and not installed"
            );
            return Err(OpenApiCatalogError::ToolConflict.into());
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
            return Err(OpenApiCatalogError::ToolConflict.into());
        }
        self.runtime.publish_prevalidated(
            &catalog,
            record.revisions.connection,
            definition_digests,
        );
        if let Some(enum_runtime) = self.enum_source_runtime.as_ref() {
            match source_plan.as_ref() {
                Some(plan) => {
                    // Clear the prior registration only after both the
                    // authority commit and monotonic local catalog install.
                    // An empty registration keeps a failed post-commit read
                    // fail-closed without reviving a pruned boot row.
                    enum_runtime.remove_plan(&record.id);
                    enum_runtime.install_plan(&record.id, compiled_overlay_revision, plan);
                    if let Err(error) = enum_runtime
                        .install_published_plan_from_store(
                            &record.id,
                            compiled_overlay_revision,
                            plan,
                            &enum_values,
                        )
                        .await
                    {
                        tracing::error!(
                            connection_id = %record.id,
                            error = %error,
                            "OpenAPI enum values are durable but could not be installed; calls remain fail-closed until refresh"
                        );
                    }
                }
                None => enum_runtime.remove_plan(&record.id),
            }
        }
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
        Ok(OpenApiPublishedCatalog {
            result: OpenApiCatalogPublishResult {
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
            },
            catalog,
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

fn validate_catalog_overlay_pairs(
    catalogs: &[StoredOpenApiCatalog],
    overlays: &[StoredOpenApiOverlay],
) -> Result<(), ConnectionStoreError> {
    let mut catalogs_by_id = BTreeMap::new();
    for catalog in catalogs {
        if catalogs_by_id
            .insert(&catalog.connection_id, catalog)
            .is_some()
        {
            return Err(ConnectionStoreError::CorruptRecord {
                id: catalog.connection_id.to_string(),
                reason: "duplicate stored OpenAPI catalog",
            });
        }
    }
    let mut overlays_by_id = BTreeMap::new();
    for overlay in overlays {
        if overlays_by_id
            .insert(&overlay.connection_id, overlay)
            .is_some()
        {
            return Err(ConnectionStoreError::CorruptRecord {
                id: overlay.connection_id.to_string(),
                reason: "duplicate stored OpenAPI overlay",
            });
        }
    }
    for (connection_id, catalog) in &catalogs_by_id {
        validate_catalog_overlay_pair(Some(catalog), overlays_by_id.get(connection_id).copied())?;
    }
    for (connection_id, overlay) in overlays_by_id {
        if !catalogs_by_id.contains_key(connection_id) {
            validate_catalog_overlay_pair(None, Some(overlay))?;
        }
    }
    Ok(())
}

fn validate_catalog_overlay_pair(
    catalog: Option<&StoredOpenApiCatalog>,
    overlay: Option<&StoredOpenApiOverlay>,
) -> Result<(), ConnectionStoreError> {
    if let Some(overlay) = overlay {
        parse_stored_overlay(overlay)?;
    }
    match (catalog, overlay) {
        (None, None) => Ok(()),
        (None, Some(overlay)) => Err(ConnectionStoreError::CorruptRecord {
            id: overlay.connection_id.to_string(),
            reason: "stored OpenAPI overlay has no catalog",
        }),
        (Some(catalog), None) if catalog.overlay_revision == 0 => Ok(()),
        (Some(catalog), None) => Err(ConnectionStoreError::CorruptRecord {
            id: catalog.connection_id.to_string(),
            reason: "OpenAPI catalog names a missing overlay revision",
        }),
        (Some(catalog), Some(overlay))
            if catalog.connection_id == overlay.connection_id
                && catalog.overlay_revision == overlay.overlay_revision =>
        {
            Ok(())
        }
        (Some(catalog), Some(_)) => Err(ConnectionStoreError::CorruptRecord {
            id: catalog.connection_id.to_string(),
            reason: "OpenAPI catalog and overlay revisions are inconsistent",
        }),
    }
}

fn parse_stored_overlay(
    stored: &StoredOpenApiOverlay,
) -> Result<OverlayDocument, ConnectionStoreError> {
    if stored.schema_version != OVERLAY_SCHEMA_VERSION {
        return Err(ConnectionStoreError::CorruptRecord {
            id: stored.connection_id.to_string(),
            reason: "stored OpenAPI overlay schema version is unsupported",
        });
    }
    let value = serde_json::from_str::<Value>(&stored.overlay_json).map_err(|_| {
        ConnectionStoreError::CorruptRecord {
            id: stored.connection_id.to_string(),
            reason: "stored OpenAPI overlay is not valid JSON",
        }
    })?;
    let document = overlay::validate(&value).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: stored.connection_id.to_string(),
        reason: "stored OpenAPI overlay fails validation",
    })?;
    if document.schema_version != stored.schema_version {
        return Err(ConnectionStoreError::CorruptRecord {
            id: stored.connection_id.to_string(),
            reason: "stored OpenAPI overlay schema version is inconsistent",
        });
    }
    Ok(document)
}

fn stored_source_plan(
    catalog: &StoredOpenApiCatalog,
    stored_overlay: &StoredOpenApiOverlay,
) -> Result<OverlaySourcePlan, ConnectionStoreError> {
    let document = parse_stored_overlay(stored_overlay)?;
    let generation = openapi::generate_tools_from_openapi_str(
        "managed-openapi-source-plan-replay",
        &catalog.spec,
    )
    .map_err(|_| ConnectionStoreError::CorruptRecord {
        id: catalog.connection_id.to_string(),
        reason: "stored OpenAPI catalog spec cannot rebuild its source plan",
    })?;
    overlay::plan_sources(&generation, &document).map_err(|_| ConnectionStoreError::CorruptRecord {
        id: catalog.connection_id.to_string(),
        reason: "stored OpenAPI overlay cannot rebuild its source plan",
    })
}

/// Replace durable enum report entries with the exact in-memory state this
/// replica currently serves. Label reports remain compile-time facts. This
/// keeps the admin read path free of upstream/store side effects while making
/// its enum status agree with `tools/list`, `tools/call`, and inventory after
/// a timer refresh.
fn project_enum_source_reports(
    runtime: &EnumSourceRuntime,
    catalog: &StoredOpenApiCatalog,
    stored_overlay: &mut StoredOpenApiOverlay,
) -> Result<(), ConnectionStoreError> {
    let plan = stored_source_plan(catalog, stored_overlay)?;
    let durable = match stored_overlay.source_reports_json.as_deref() {
        Some(encoded) => decode_openapi_source_reports(encoded).map_err(|()| {
            ConnectionStoreError::CorruptRecord {
                id: stored_overlay.connection_id.to_string(),
                reason: "stored OpenAPI overlay source reports are invalid",
            }
        })?,
        None if plan.enum_sources.is_empty() && plan.label_sources.is_empty() => {
            // PR1 overlays predate source reports. They remain valid when the
            // rebuilt document has no PR2 sources; project a canonical empty
            // report for this read rather than turning an upgrade into 503.
            StoredOpenApiSourceReports::empty()
        }
        None => {
            return Err(ConnectionStoreError::CorruptRecord {
                id: stored_overlay.connection_id.to_string(),
                reason: "stored OpenAPI overlay is missing source reports",
            });
        }
    };
    let durable_labels = durable
        .sources
        .iter()
        .filter(|report| report.kind == StoredOpenApiSourceKind::Label)
        .map(|report| (report.id.as_str(), report))
        .collect::<BTreeMap<_, _>>();
    let mut projected = Vec::with_capacity(
        plan.enum_sources
            .len()
            .saturating_add(plan.label_sources.len()),
    );
    for (source_id, source) in &plan.enum_sources {
        let snapshot = runtime.snapshot(
            &stored_overlay.connection_id,
            source_id,
            &source.source_digest,
        );
        let state = match snapshot.state {
            EnumSourceState::Fresh => "fresh",
            EnumSourceState::Stale => "stale",
            EnumSourceState::Missing => "missing",
        };
        projected.push(StoredOpenApiSourceReport {
            id: source_id.clone(),
            kind: StoredOpenApiSourceKind::Enum,
            state: state.to_owned(),
            item_count: u64::try_from(snapshot.item_count()).unwrap_or(u64::MAX),
            resolved_at: snapshot.resolved_at,
        });
    }
    for source_id in plan.label_sources.keys() {
        let report = durable_labels.get(source_id.as_str()).ok_or_else(|| {
            ConnectionStoreError::CorruptRecord {
                id: stored_overlay.connection_id.to_string(),
                reason: "stored OpenAPI overlay is missing a label source report",
            }
        })?;
        projected.push((*report).clone());
    }
    stored_overlay.source_reports_json = Some(
        StoredOpenApiSourceReports {
            schema_version: durable.schema_version,
            sources: projected,
        }
        .canonical_json()
        .map_err(|_| ConnectionStoreError::CorruptRecord {
            id: stored_overlay.connection_id.to_string(),
            reason: "stored OpenAPI overlay source reports cannot be serialized",
        })?,
    );
    Ok(())
}

fn decode_stored_overlay(
    stored: Option<&StoredOpenApiOverlay>,
) -> Result<Option<OverlayDocument>, OpenApiCatalogError> {
    stored
        .map(parse_stored_overlay)
        .transpose()
        .map_err(|_| OpenApiCatalogError::StorageUnavailable)
}

fn require_overlay_precondition(
    connection_id: &ConnectionId,
    connection_revision: u64,
    catalog_revision: u64,
    stored: Option<&StoredOpenApiOverlay>,
    expected: &str,
) -> Result<u64, OpenApiOverlayOperationError> {
    let revision = stored.map_or(0, |overlay| overlay.overlay_revision);
    let current = OverlayEtag::for_revisions(
        connection_id.as_str(),
        connection_revision,
        catalog_revision,
        revision,
    );
    if expected != current.as_str() {
        return Err(OpenApiOverlayOperationError::PreconditionFailed(current));
    }
    Ok(revision)
}

fn compiled_report(
    compiled: &CompiledCatalog,
    reports: &StoredOpenApiSourceReports,
) -> OpenApiOverlayCompileReport {
    OpenApiOverlayCompileReport {
        tools: compiled.tools.clone(),
        composites: compiled.composites.clone(),
        warnings: compiled.warnings.clone(),
        sources: reports.sources.clone(),
    }
}

fn inject_preview_enum_values(
    binding: &mut OpenApiToolBinding,
    resolved: &ResolvedOverlaySources,
) -> Result<(), OverlayError> {
    for definition in &mut binding.definitions {
        for enum_binding in definition.enum_bindings.clone() {
            let Some(source) = resolved.enum_sources.get(&enum_binding.source_id) else {
                continue;
            };
            overlay::apply_enum_to_served_clone(
                definition,
                &enum_binding,
                &source.values,
                source.labels.as_deref(),
            )
            .map_err(|message| OverlayError {
                problems: vec![OverlayProblem {
                    path: format!(
                        "/tools/{}/parameters/{}/enum_source",
                        definition.name, enum_binding.property
                    ),
                    message,
                }],
            })?;
        }
    }
    Ok(())
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

/// Preview exposes compiled (served) names, while OpenAPI binding and its
/// security confirmations remain keyed by generated names. Accept either
/// spelling at registration and collapse it to one generated identity. The
/// stored overlay has already passed document validation, but keep the
/// inverse construction defensive so corrupt or ambiguous aliases fail
/// closed instead of selecting an arbitrary operation.
fn normalize_registration_selection(
    generation: &OpenApiToolGeneration,
    selected_tool_names: &[String],
    stored_overlay: Option<&OverlayDocument>,
) -> Result<Vec<String>, OpenApiCatalogError> {
    let generated_names = generation
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut served_to_generated = BTreeMap::new();
    for (generated_name, tool) in stored_overlay
        .into_iter()
        .flat_map(|document| document.tools.iter())
    {
        let Some(served_name) = tool.rename.as_deref() else {
            continue;
        };
        if served_to_generated
            .insert(served_name, generated_name.as_str())
            .is_some()
        {
            return Err(OpenApiCatalogError::InvalidSelection);
        }
    }

    let mut normalized = Vec::with_capacity(selected_tool_names.len());
    let mut seen = BTreeSet::new();
    for selected_name in selected_tool_names {
        let generated = generated_names.contains(selected_name.as_str());
        let renamed_owner = served_to_generated.get(selected_name.as_str()).copied();
        if generated && renamed_owner.is_some() {
            return Err(OpenApiCatalogError::InvalidSelection);
        }
        let normalized_name = renamed_owner.unwrap_or(selected_name.as_str()).to_owned();
        if !seen.insert(normalized_name.clone()) {
            return Err(OpenApiCatalogError::InvalidSelection);
        }
        normalized.push(normalized_name);
    }
    Ok(normalized)
}

fn surviving_refresh_selection(
    prior: &StoredOpenApiCatalog,
    generation: &OpenApiToolGeneration,
    stored_overlay: Option<&OverlayDocument>,
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
    let rename_inverse = stored_overlay
        .into_iter()
        .flat_map(|overlay| overlay.tools.iter())
        .filter_map(|(generated, tool)| {
            tool.rename
                .as_deref()
                .map(|served| (served, generated.as_str()))
        })
        .collect::<BTreeMap<_, _>>();

    for entry in &prior.entries {
        let served_name = entry.tool_name.as_str();
        if prior_definitions
            .get(served_name)
            .is_some_and(|definition| {
                matches!(&definition.target, Some(ToolTarget::Composite { .. }))
            })
        {
            // Synthetic composites are rederived from the stored overlay after
            // their selected leaf operations are rebound to the new document.
            continue;
        }
        let generated_name = rename_inverse
            .get(served_name)
            .copied()
            .unwrap_or(served_name);
        if stored_overlay
            .and_then(|overlay| overlay.tools.get(generated_name))
            .and_then(|tool| tool.rename.as_deref())
            .is_some_and(|expected_served| expected_served != served_name)
        {
            return Err(OpenApiCatalogError::InvalidSpec);
        }
        let Some(candidate) = generated_definitions.get(generated_name) else {
            continue;
        };
        let security = generated_security
            .get(generated_name)
            .ok_or(OpenApiCatalogError::InvalidSpec)?;
        let previous = prior_definitions
            .get(served_name)
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
        selected_tool_names.push(generated_name.to_owned());
        confirmations.push(OpenApiToolSecuritySelection {
            tool_name: generated_name.to_owned(),
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
                        | Some(ToolTarget::Composite { connection_id })
                        if connection_id == catalog.connection_id.as_str()
                )
                && (!matches!(&definition.target, Some(ToolTarget::Composite { .. }))
                    || entry.selected_scheme_names.is_empty());
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
        connection_revision: connection_revision_from_etag(
            &catalog.connection_id,
            &catalog.observed_etag,
        )?,
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

fn connection_revision_from_etag(
    id: &ConnectionId,
    etag: &ConnectionEtag,
) -> Result<u64, ConnectionStoreError> {
    let prefix = format!("\"connection:{}:c", id.as_str());
    let invalid = || ConnectionStoreError::CorruptRecord {
        id: id.to_string(),
        reason: "stored OpenAPI catalog has a non-canonical Connection ETag",
    };
    let encoded = etag.as_str().strip_prefix(&prefix).ok_or_else(invalid)?;
    let (connection, encoded) = encoded.split_once(":k").ok_or_else(invalid)?;
    let (credential, encoded) = encoded.split_once(":t").ok_or_else(invalid)?;
    let (tls, discovery) = encoded.split_once(":d").ok_or_else(invalid)?;
    let discovery = discovery.strip_suffix('"').ok_or_else(invalid)?;
    let connection = connection.parse::<u64>().map_err(|_| invalid())?;
    let credential = credential.parse::<u64>().map_err(|_| invalid())?;
    let tls = tls.parse::<u64>().map_err(|_| invalid())?;
    let discovery = discovery.parse::<u64>().map_err(|_| invalid())?;
    if etag.as_str()
        != format!(
            "\"connection:{}:c{connection}:k{credential}:t{tls}:d{discovery}\"",
            id.as_str()
        )
    {
        return Err(invalid());
    }
    Ok(connection)
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

fn publish_store_error(
    connection_id: &ConnectionId,
    error: &ConnectionStoreError,
) -> OpenApiPublishError {
    match error {
        ConnectionStoreError::OverlayConflict {
            current_connection_revision,
            current_catalog_revision,
            current_overlay_revision,
            ..
        } => OpenApiPublishError::OverlayPreconditionFailed(OverlayEtag::for_revisions(
            connection_id.as_str(),
            *current_connection_revision,
            *current_catalog_revision,
            *current_overlay_revision,
        )),
        _ => OpenApiPublishError::Catalog(openapi_store_error(error)),
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
        audit::{sink::tests::CaptureSink, AuditLog, AuditSink},
        config::Config,
        connections::model::ConnectionWrite,
        egress::{EgressClient, EgressConfig},
        rbac::policy::Policy,
        tools::definitions::{HttpToolMapping, ToolSource, ToolTarget, ToolVisibility},
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
            title: None,
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
            composite: None,
            enum_bindings: Vec::new(),
            visibility: ToolVisibility::Listed,
            transform: None,
            annotations: None,
        }
    }

    #[test]
    fn active_runtime_requires_exact_etag_revision_and_definition_digest() {
        let connection_id =
            ConnectionId::parse("billing-api").expect("test Connection ID should be valid");
        let definition = managed_definition(&connection_id, 7);
        let digest = definition_digest(&definition).expect("definition should serialize");
        let composite_definition = ToolDefinition {
            name: "read_invoice_composite".to_owned(),
            title: None,
            description: "Read an invoice through a composite".to_owned(),
            input_schema: definition.input_schema.clone(),
            target: Some(ToolTarget::Composite {
                connection_id: connection_id.to_string(),
            }),
            source: ToolSource::OpenApi {
                connection_id: connection_id.to_string(),
                operation_id: None,
                catalog_revision: Some(7),
            },
            upstream: HttpToolMapping::composite_sentinel(),
            annotations: None,
            composite: Some(crate::tools::composite::CompositeMapping {
                steps: vec![crate::tools::composite::CompositeStep {
                    id: "read".to_owned(),
                    tool: "get_invoice".to_owned(),
                    arguments: BTreeMap::from([(
                        "invoice_id".to_owned(),
                        crate::tools::composite::CompositeBinding::Input {
                            input: "invoice_id".to_owned(),
                            pointer: None,
                        },
                    )]),
                    for_each: None,
                    success_statuses: None,
                    ambiguous_statuses: None,
                    compensate: None,
                }],
                result: None,
                limits: crate::tools::composite::CompositeLimits::default(),
            }),
            enum_bindings: Vec::new(),
            visibility: ToolVisibility::Listed,
            transform: None,
        };
        let composite_digest =
            definition_digest(&composite_definition).expect("composite should serialize");
        let runtime = OpenApiConnectionCatalogRuntime {
            state: Arc::new(ArcSwap::from_pointee(BTreeMap::from([(
                connection_id.clone(),
                ActiveOpenApiCatalog {
                    connection_revision: 1,
                    observed_etag: "\"connection:billing-api:c1:k1:t1:d1\"".to_owned(),
                    catalog_revision: 7,
                    refreshed_at: "2026-07-28T00:00:00Z".to_owned(),
                    definition_digests: BTreeMap::from([
                        (definition.name.clone(), digest),
                        (composite_definition.name.clone(), composite_digest),
                    ]),
                },
            )]))),
        };

        assert!(
            runtime.definition_is_current(&definition, "\"connection:billing-api:c1:k1:t1:d1\"")
        );
        assert!(runtime.definition_is_current(
            &composite_definition,
            "\"connection:billing-api:c1:k1:t1:d1\""
        ));
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
    fn refresh_selection_skips_synthetic_composites_and_rederives_them() {
        let connection_id =
            ConnectionId::parse("billing-api").expect("test Connection ID should be valid");
        let mut leaf = managed_definition(&connection_id, 7);
        let ToolSource::OpenApi { operation_id, .. } = &mut leaf.source else {
            panic!("managed definition");
        };
        *operation_id = Some("get_invoice".to_owned());
        let composite = ToolDefinition {
            name: "read_invoice_composite".to_owned(),
            title: None,
            description: "Read an invoice through a composite".to_owned(),
            input_schema: leaf.input_schema.clone(),
            target: Some(ToolTarget::Composite {
                connection_id: connection_id.to_string(),
            }),
            source: ToolSource::OpenApi {
                connection_id: connection_id.to_string(),
                operation_id: None,
                catalog_revision: Some(7),
            },
            upstream: HttpToolMapping::composite_sentinel(),
            annotations: None,
            composite: Some(crate::tools::composite::CompositeMapping {
                steps: vec![crate::tools::composite::CompositeStep {
                    id: "read".to_owned(),
                    tool: "get_invoice".to_owned(),
                    arguments: BTreeMap::from([(
                        "invoice_id".to_owned(),
                        crate::tools::composite::CompositeBinding::Input {
                            input: "invoice_id".to_owned(),
                            pointer: None,
                        },
                    )]),
                    for_each: None,
                    success_statuses: None,
                    ambiguous_statuses: None,
                    compensate: None,
                }],
                result: None,
                limits: crate::tools::composite::CompositeLimits::default(),
            }),
            enum_bindings: Vec::new(),
            visibility: ToolVisibility::Listed,
            transform: None,
        };
        let binding = OpenApiToolBinding {
            definitions: vec![leaf, composite],
            security_selections: vec![
                OpenApiToolSecuritySelection {
                    tool_name: "get_invoice".to_owned(),
                    selected_scheme_names: Vec::new(),
                },
                OpenApiToolSecuritySelection {
                    tool_name: "read_invoice_composite".to_owned(),
                    selected_scheme_names: Vec::new(),
                },
            ],
            incompatibilities: Vec::new(),
        };
        let entries = stored_entries(&binding).expect("synthetic selection stores");
        let prior = StoredOpenApiCatalog {
            connection_id: connection_id.clone(),
            spec_revision: 1,
            catalog_revision: 7,
            observed_etag: ConnectionEtag::from_stored(
                "\"connection:billing-api:c1:k1:t1:d1\"".to_owned(),
            ),
            spec_digest: "digest".to_owned(),
            spec: "spec".to_owned(),
            refreshed_at: "2026-09-03T00:00:00Z".to_owned(),
            entries,
            overlay_revision: 1,
        };
        let generation = openapi::generate_tools_from_openapi_str(
            "refresh-composite.yaml",
            r#"
openapi: 3.0.3
info: {title: Billing, version: 1.0.0}
paths:
  /invoices/{invoice_id}:
    get:
      operationId: get_invoice
      parameters:
        - in: path
          name: invoice_id
          required: true
          schema: {type: string}
"#,
        )
        .expect("refresh generation");

        let (selected, confirmations) =
            surviving_refresh_selection(&prior, &generation, None).expect("selection survives");
        assert_eq!(selected, vec!["get_invoice"]);
        assert_eq!(confirmations.len(), 1);
        assert_eq!(confirmations[0].tool_name, "get_invoice");
    }

    #[test]
    fn inactive_overlay_rename_retains_its_policy_ownership() {
        let config = Config::test_defaults();
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let egress_config = EgressConfig::from_config(&config);
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress should build"));
        let policy = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "tools": {"read_invoice": {}}
        }))
        .expect("policy should validate");
        let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
        let service = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            ConnectionHttpRuntime::new(control_plane, egress_config, egress_client),
            ToolRegistry::disabled(),
        )
        .expect("service should load")
        .with_rbac_state(Some(RbacState::new(policy, Vec::new(), false, audit)));
        let connection_id =
            ConnectionId::parse("inactive-api").expect("fixture Connection ID should validate");
        let document = overlay::validate(&json!({
            "schema_version": "0.1.0",
            "tools": {"get_invoice": {"rename": "read_invoice"}}
        }))
        .expect("stored overlay should validate");

        let context = service.overlay_compile_context(&connection_id, None, Some(&document));
        assert_eq!(
            context.prior_overlay_name_owners,
            BTreeMap::from([("read_invoice".to_owned(), "get_invoice".to_owned())]),
            "ownership comes from the durable overlay even while its tool is deselected"
        );
        assert!(context.policy_tool_names.contains("read_invoice"));
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
        service
            .reconcile_from_authority()
            .await
            .expect("the atomic authority snapshot should repair the failed local install");
        assert_eq!(service.runtime().current_revision(&record.id), Some(1));
        assert!(
            registry
                .get("get_invoice")
                .is_some_and(|definition| matches!(
                    &definition.source,
                    crate::tools::definitions::ToolSource::OpenApi {
                        connection_id,
                        catalog_revision: Some(1),
                        ..
                    } if connection_id == record.id.as_str()
                )),
            "reconciliation installs the durable authoritative catalog"
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
        let (absent_document, unregistered_etag, applied_catalog_revision) = service
            .openapi_overlay(record.id.as_str())
            .await
            .expect("overlay GET should represent an unregistered catalog");
        assert!(absent_document.is_none());
        assert_eq!(
            unregistered_etag,
            OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 0, 0,)
        );
        assert_eq!(applied_catalog_revision, None);
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
    async fn overlay_put_delete_and_restart_keep_document_and_compiled_catalog_paired() {
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Overlaid Billing OpenAPI",
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
            .create_managed(
                control_plane.runtime_snapshot().collection_etag(),
                candidate,
                "test-admin",
            )
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
info: {title: Billing, version: 1.0.0}
paths:
  /invoices/{invoice_id}:
    post:
      operationId: get_invoice
      summary: Read one invoice
      parameters:
        - in: path
          name: invoice_id
          required: true
          schema: {type: string}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [total]
              properties:
                total:
                  type: object
                  required: [amountMicros, currencyCode]
                  properties:
                    amountMicros: {type: string}
                    currencyCode: {type: string}
      responses:
        '200':
          description: Invoice
          content:
            application/json:
              schema:
                type: object
                properties:
                  invoice:
                    type: object
                    properties:
                      total:
                        type: object
                        properties:
                          amountMicros: {type: string}
                          currencyCode: {type: string}
"#;
        let preview = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("initial spec should preview");
        let selected = preview
            .generation
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
                spec,
                &selected,
                &preview.registration_security_selections,
                "test-admin",
            )
            .await
            .expect("initial catalog should publish");

        let raw_source_document = json!({
            "schema_version": "0.1.0",
            "enum_sources": {
                "statuses": {
                    "request": {"path": "/metadata/statuses"},
                    "select": {"items": "/items/*", "value": "/value"}
                }
            }
        });
        let unauthorized_preview = service
            .preview_with_overlay_authorization(
                record.id.as_str(),
                spec,
                Some(&raw_source_document),
                false,
            )
            .await
            .expect_err("raw source preview must require secrets-write authority");
        assert!(matches!(
            unauthorized_preview,
            OpenApiOverlayOperationError::SecretsWriteRequired
        ));
        let unauthorized_put = service
            .put_overlay_with_authorization(
                record.id.as_str(),
                "\"deliberately-stale\"",
                &raw_source_document,
                true,
                false,
                "test-admin",
            )
            .await
            .expect_err("raw source PUT must require secrets-write authority");
        assert!(matches!(
            unauthorized_put,
            OpenApiOverlayOperationError::SecretsWriteRequired
        ));

        let document = json!({
            "schema_version": "0.1.0",
            "shapes": {
                "money": {
                    "agent": {
                        "amount": {"type": "number"},
                        "currency": {"type": "string"}
                    },
                    "required": ["amount", "currency"],
                    "wire": {
                        "/amountMicros": {
                            "from": "amount",
                            "codec": {
                                "kind": "decimal_scale",
                                "scale": 6,
                                "wire_encoding": "integer_string"
                            }
                        },
                        "/currencyCode": {"from": "currency"}
                    }
                }
            },
            "tools": {
                "get_invoice": {
                    "rename": "read_invoice",
                    "description": "Read a billing invoice safely",
                    "parameters": {
                        "total": {
                            "shape": {"$use": "money", "prefix": "invoice"}
                        }
                    },
                    "response": {"root": "/invoice"}
                }
            }
        });
        let initial_store = control_plane
            .managed_store()
            .expect("managed store should exist");
        let (initial_catalog, initial_overlay) = initial_store
            .openapi_catalog_with_overlay(&record.id)
            .await
            .expect("catalog/overlay pair should read atomically");
        let initial_catalog = initial_catalog.expect("registered catalog should exist");
        assert_eq!(initial_catalog.overlay_revision, 0);
        assert!(initial_overlay.is_none());
        validate_catalog_overlay_pair(Some(&initial_catalog), initial_overlay.as_ref())
            .expect("initial bare catalog should be a valid o0 pair");
        let candidate_preview = service
            .preview_with_overlay(record.id.as_str(), spec, Some(&document))
            .await
            .expect("candidate overlay should compile without being stored");
        assert_eq!(
            candidate_preview.binding.definitions[0].name,
            "read_invoice"
        );
        assert!(candidate_preview.binding.definitions[0].transform.is_some());
        assert!(
            candidate_preview.binding.definitions[0].input_schema["properties"]
                .get("invoice_amount")
                .is_some()
        );
        assert!(
            candidate_preview.binding.definitions[0].input_schema["properties"]
                .get("total")
                .is_none()
        );
        assert_eq!(
            candidate_preview.registration_security_selections[0].tool_name,
            "get_invoice"
        );
        assert!(control_plane
            .managed_store()
            .expect("managed store should exist")
            .openapi_overlay(&record.id)
            .await
            .expect("overlay read should succeed")
            .is_none());
        let stale = service
            .put_overlay(
                record.id.as_str(),
                &format!(
                    "\"overlay:{}:c{}:r1:o9\"",
                    record.id, record.revisions.connection
                ),
                &document,
                "test-admin",
            )
            .await
            .expect_err("a stale overlay ETag must be refused");
        match stale {
            OpenApiOverlayOperationError::PreconditionFailed(current) => {
                assert_eq!(
                    current,
                    OverlayEtag::for_revisions(
                        record.id.as_str(),
                        record.revisions.connection,
                        1,
                        0,
                    )
                )
            }
            other => panic!("unexpected stale overlay error: {other:?}"),
        }

        let put = service
            .put_overlay(
                record.id.as_str(),
                &OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 1, 0)
                    .to_string(),
                &document,
                "test-admin",
            )
            .await
            .expect("valid overlay should atomically publish");
        assert_eq!(put.catalog.catalog_revision, 2);
        let first_put_etag = put.etag.clone();
        assert_eq!(
            first_put_etag,
            OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 2, 1,)
        );
        let stored_overlay = put.stored.expect("PUT should return the stored document");
        assert_eq!(stored_overlay.overlay_revision, 1);
        assert_eq!(
            put.report
                .expect("PUT should report its compile")
                .tools
                .len(),
            1
        );
        assert!(registry.get("get_invoice").is_none());
        let served = registry
            .get("read_invoice")
            .expect("renamed definition should be live");
        assert_eq!(served.description, "Read a billing invoice safely");
        assert_eq!(
            served
                .transform
                .as_ref()
                .and_then(|transform| transform.response_root.as_ref())
                .map(ToString::to_string),
            Some("/invoice".to_owned())
        );

        let store = control_plane
            .managed_store()
            .expect("managed store should exist");
        let (durable_catalog, durable_overlay) = store
            .openapi_catalog_with_overlay(&record.id)
            .await
            .expect("durable catalog/overlay pair should read atomically");
        let durable_catalog = durable_catalog.expect("catalog should exist");
        let durable_overlay = durable_overlay.expect("overlay should exist");
        assert_eq!(durable_catalog.overlay_revision, 1);
        assert_eq!(durable_overlay.overlay_revision, 1);
        let mut pre_source_reports_overlay = durable_overlay.clone();
        pre_source_reports_overlay.source_reports_json = None;
        let empty_enum_runtime = EnumSourceRuntime::new(
            control_plane.clone(),
            http.clone(),
            AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>),
            Vec::new(),
        );
        project_enum_source_reports(
            &empty_enum_runtime,
            &durable_catalog,
            &mut pre_source_reports_overlay,
        )
        .expect("a pre-PR2 overlay without sources should project an empty report");
        assert!(decode_openapi_source_reports(
            pre_source_reports_overlay
                .source_reports_json
                .as_deref()
                .expect("empty reports should be canonicalized")
        )
        .expect("projected empty reports should decode")
        .sources
        .is_empty());
        let (read_overlay, read_etag, applied_catalog_revision) = service
            .openapi_overlay(record.id.as_str())
            .await
            .expect("overlay GET service should read the paired state");
        assert_eq!(read_overlay, Some(durable_overlay.clone()));
        assert_eq!(read_etag, first_put_etag);
        assert_eq!(applied_catalog_revision, Some(2));

        let overlaid_preview = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("stored overlay should compile in preview");
        assert_eq!(overlaid_preview.binding.definitions[0].name, "read_invoice");
        assert_eq!(
            overlaid_preview.registration_security_selections[0].tool_name, "get_invoice",
            "registration confirmations remain keyed by generated name"
        );

        let restarted_registry = ToolRegistry::disabled();
        let restarted = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            http,
            restarted_registry.clone(),
        )
        .expect("paired overlay catalog should replay after restart");
        let restarted_definition = restarted_registry
            .get("read_invoice")
            .expect("compiled transform should replay after restart");
        assert_eq!(restarted_definition.transform, served.transform);
        assert_eq!(restarted_definition.input_schema, served.input_schema);
        assert!(restarted
            .runtime()
            .definition_is_current(&served, record.etag().as_str()));

        let deleted = service
            .delete_overlay(record.id.as_str(), first_put_etag.as_str(), "test-admin")
            .await
            .expect("overlay DELETE should atomically publish the bare catalog");
        let delete_etag = deleted.etag.clone();
        assert!(deleted.stored.is_none());
        assert_eq!(deleted.catalog.catalog_revision, 3);
        assert_eq!(
            delete_etag,
            OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 3, 0,)
        );
        assert!(registry.get("read_invoice").is_none());
        assert!(registry.get("get_invoice").is_some());
        let (bare_catalog, absent_overlay) = store
            .openapi_catalog_with_overlay(&record.id)
            .await
            .expect("bare catalog/overlay pair should read atomically");
        assert!(absent_overlay.is_none());
        assert_eq!(
            bare_catalog.expect("catalog should exist").overlay_revision,
            0
        );
        let (read_overlay, read_etag, applied_catalog_revision) = service
            .openapi_overlay(record.id.as_str())
            .await
            .expect("overlay GET should expose the compiled bare catalog");
        assert!(read_overlay.is_none());
        assert_eq!(read_etag, delete_etag);
        assert_eq!(applied_catalog_revision, Some(3));

        let recreated = service
            .put_overlay(
                record.id.as_str(),
                delete_etag.as_str(),
                &document,
                "test-admin",
            )
            .await
            .expect("overlay should recreate after deletion");
        let recreated_etag = recreated.etag.clone();
        assert_eq!(recreated.catalog.catalog_revision, 4);
        assert_eq!(
            recreated_etag,
            OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 4, 1,)
        );
        assert_eq!(
            recreated
                .stored
                .as_ref()
                .expect("recreated document should be returned")
                .overlay_revision,
            1,
            "the document revision may repeat after deletion"
        );

        let aba_rejected = service
            .put_overlay(
                record.id.as_str(),
                first_put_etag.as_str(),
                &document,
                "test-admin",
            )
            .await
            .expect_err("a pre-delete ETag must not match the recreated overlay");
        assert!(matches!(
            aba_rejected,
            OpenApiOverlayOperationError::PreconditionFailed(ref current)
                if current == &recreated_etag
        ));

        let registration_preview = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("the recreated overlay should preview for registration");
        let served_selection = registration_preview
            .binding
            .definitions
            .iter()
            .map(|definition| definition.name.clone())
            .collect::<Vec<_>>();
        assert_eq!(served_selection, vec!["read_invoice"]);
        assert_eq!(
            registration_preview.registration_security_selections[0].tool_name,
            "get_invoice"
        );
        let alias_mix = service
            .register(
                record.id.as_str(),
                record.etag().as_str(),
                registration_preview.spec_revision,
                registration_preview.catalog_revision,
                &registration_preview.spec_digest,
                spec,
                &["get_invoice".to_owned(), "read_invoice".to_owned()],
                &registration_preview.registration_security_selections,
                "test-admin",
            )
            .await;
        assert_eq!(
            alias_mix,
            Err(OpenApiCatalogError::InvalidSelection),
            "generated and served aliases must not select one operation twice"
        );
        let reregistered = service
            .register(
                record.id.as_str(),
                record.etag().as_str(),
                registration_preview.spec_revision,
                registration_preview.catalog_revision,
                &registration_preview.spec_digest,
                spec,
                &served_selection,
                &registration_preview.registration_security_selections,
                "test-admin",
            )
            .await
            .expect("served preview names should round-trip through registration");
        assert_eq!(reregistered.catalog_revision, 5);
        assert_eq!(reregistered.registered_tool_names, vec!["read_invoice"]);
    }

    #[tokio::test]
    async fn current_overlay_etag_cannot_mutate_a_catalog_from_an_older_connection_generation() {
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Generation-stale overlay",
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
            .create_managed(
                control_plane.runtime_snapshot().collection_etag(),
                candidate,
                "test-admin",
            )
            .await
            .expect("managed OpenAPI Connection should create");
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
        let spec = r#"
openapi: 3.0.3
info: {title: Billing, version: 1.0.0}
paths:
  /invoices/{invoice_id}:
    get:
      operationId: get_invoice
      parameters:
        - in: path
          name: invoice_id
          required: true
          schema: {type: string}
"#;
        let preview = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("spec should preview");
        service
            .register(
                record.id.as_str(),
                record.etag().as_str(),
                preview.spec_revision,
                preview.catalog_revision,
                &preview.spec_digest,
                spec,
                &["get_invoice".to_owned()],
                &preview.registration_security_selections,
                "test-admin",
            )
            .await
            .expect("nonempty catalog should register");
        let document = json!({
            "schema_version": "0.1.0",
            "tools": {
                "get_invoice": {
                    "rename": "read_invoice",
                    "description": "Read an invoice from the generation that compiled this tool"
                }
            }
        });
        let put = service
            .put_overlay(
                record.id.as_str(),
                OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 1, 0)
                    .as_str(),
                &document,
                "test-admin",
            )
            .await
            .expect("overlay should publish against the current catalog");
        let held_definition = registry
            .get("read_invoice")
            .expect("the overlaid definition should be live");
        assert!(service
            .runtime()
            .definition_is_current(&held_definition, record.etag().as_str()));
        let durable_before = control_plane
            .managed_store()
            .expect("managed store should exist")
            .openapi_catalog_with_overlay(&record.id)
            .await
            .expect("catalog/overlay pair should read atomically");
        assert!(durable_before.0.is_some());
        assert!(durable_before.1.is_some());

        let mut endpoint_edit = record.write.clone();
        endpoint_edit.endpoint.base_url = "https://replacement.example.test".to_owned();
        let updated = control_plane
            .replace_managed(&record.id, &record.etag(), endpoint_edit, "test-admin")
            .await
            .expect("a compatible endpoint edit should preserve the durable catalog");
        assert!(updated.revisions.connection > record.revisions.connection);
        assert!(!service
            .runtime()
            .definition_is_current(&held_definition, updated.etag().as_str()));

        let (stored, current_etag, applied_catalog_revision) = service
            .openapi_overlay(updated.id.as_str())
            .await
            .expect("overlay GET should expose the current Connection generation");
        assert_eq!(stored, durable_before.1);
        assert_eq!(applied_catalog_revision, Some(put.catalog.catalog_revision));
        assert_eq!(
            current_etag,
            OverlayEtag::for_revisions(
                updated.id.as_str(),
                updated.revisions.connection,
                put.catalog.catalog_revision,
                1,
            ),
            "the read token must carry the current cN even though the catalog observed the prior one"
        );

        let rejected_put = service
            .put_overlay(
                updated.id.as_str(),
                current_etag.as_str(),
                &document,
                "test-admin",
            )
            .await
            .expect_err("PUT must not compile an old catalog under a current-generation token");
        assert!(matches!(
            rejected_put,
            OpenApiOverlayOperationError::Catalog(OpenApiCatalogError::StalePreview)
        ));
        let rejected_delete = service
            .delete_overlay(updated.id.as_str(), current_etag.as_str(), "test-admin")
            .await
            .expect_err("DELETE must not compile an old catalog under a current-generation token");
        assert!(matches!(
            rejected_delete,
            OpenApiOverlayOperationError::Catalog(OpenApiCatalogError::StalePreview)
        ));

        let durable_after = control_plane
            .managed_store()
            .expect("managed store should exist")
            .openapi_catalog_with_overlay(&record.id)
            .await
            .expect("catalog/overlay pair should remain readable");
        assert_eq!(
            durable_after, durable_before,
            "rejected mutations must leave every durable catalog and overlay byte unchanged"
        );

        let restarted_registry = ToolRegistry::disabled();
        let restarted_egress = EgressConfig::from_config(&config);
        let restarted_client = Arc::new(
            EgressClient::new(restarted_egress.clone()).expect("restart egress should build"),
        );
        let restarted = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            ConnectionHttpRuntime::new(control_plane, restarted_egress, restarted_client),
            restarted_registry.clone(),
        )
        .expect("a stale durable pair is filtered rather than replayed");
        assert_eq!(restarted.runtime().current_revision(&updated.id), None);
        assert!(restarted_registry.get("read_invoice").is_none());
    }

    #[tokio::test]
    async fn overlay_etag_rejects_a_previous_connection_generation_after_kind_round_trip() {
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let openapi_write: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Generation-bound OpenAPI",
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
            .create_managed(
                control_plane.runtime_snapshot().collection_etag(),
                openapi_write.clone(),
                "test-admin",
            )
            .await
            .expect("managed OpenAPI Connection should create");
        let egress_config = EgressConfig::from_config(&config);
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress should build"));
        let service = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            ConnectionHttpRuntime::new(control_plane.clone(), egress_config, egress_client),
            ToolRegistry::disabled(),
        )
        .expect("managed OpenAPI service should load");
        let spec = r#"
openapi: 3.0.3
info: {title: Billing, version: 1.0.0}
paths:
  /invoices:
    get: {operationId: get_invoice}
"#;
        let document = json!({
            "schema_version": "0.1.0",
            "tools": {"get_invoice": {"rename": "read_invoice"}}
        });

        let preview = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("initial spec should preview");
        service
            .register(
                record.id.as_str(),
                record.etag().as_str(),
                preview.spec_revision,
                preview.catalog_revision,
                &preview.spec_digest,
                spec,
                &[],
                &[],
                "test-admin",
            )
            .await
            .expect("empty catalog should register");
        let first = service
            .put_overlay(
                record.id.as_str(),
                OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 1, 0)
                    .as_str(),
                &document,
                "test-admin",
            )
            .await
            .expect("first-generation overlay should publish");
        let old_etag = first.etag;
        assert_eq!(
            old_etag,
            OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 2, 1,)
        );

        let mcp_write: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Generation-bound OpenAPI",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/mcp"
            },
            "authentication": {"type": "none"},
            "tls": {},
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": false
            }
        }))
        .expect("managed MCP replacement should deserialize");
        let converted = control_plane
            .replace_managed(&record.id, &record.etag(), mcp_write, "test-admin")
            .await
            .expect("an empty catalog should permit a supported cross-kind replacement");
        service.reconcile_connection(&converted);
        assert_eq!(service.runtime().current_revision(&record.id), None);
        let (removed_catalog, removed_overlay) = control_plane
            .managed_store()
            .expect("managed store should exist")
            .openapi_catalog_with_overlay(&record.id)
            .await
            .expect("removed catalog/overlay pair should read atomically");
        assert!(removed_catalog.is_none());
        assert!(removed_overlay.is_none());

        let restored = control_plane
            .replace_managed(&record.id, &converted.etag(), openapi_write, "test-admin")
            .await
            .expect("Connection should convert back to managed OpenAPI");
        assert!(restored.revisions.connection > record.revisions.connection);
        let preview = service
            .preview(restored.id.as_str(), spec)
            .await
            .expect("restored OpenAPI Connection should preview");
        service
            .register(
                restored.id.as_str(),
                restored.etag().as_str(),
                preview.spec_revision,
                preview.catalog_revision,
                &preview.spec_digest,
                spec,
                &[],
                &[],
                "test-admin",
            )
            .await
            .expect("restored empty catalog should register from revision zero");
        let recreated = service
            .put_overlay(
                restored.id.as_str(),
                OverlayEtag::for_revisions(
                    restored.id.as_str(),
                    restored.revisions.connection,
                    1,
                    0,
                )
                .as_str(),
                &document,
                "test-admin",
            )
            .await
            .expect("restored overlay should reuse catalog/document revisions safely");
        let current_etag = recreated.etag;
        assert_eq!(
            current_etag,
            OverlayEtag::for_revisions(restored.id.as_str(), restored.revisions.connection, 2, 1,)
        );
        assert_ne!(old_etag, current_etag);

        let stale = service
            .put_overlay(
                restored.id.as_str(),
                old_etag.as_str(),
                &document,
                "test-admin",
            )
            .await
            .expect_err("an ETag from the previous Connection generation must be refused");
        assert!(matches!(
            stale,
            OpenApiOverlayOperationError::PreconditionFailed(ref current)
                if current == &current_etag
        ));
    }

    #[tokio::test]
    async fn reconciliation_replaces_an_equal_catalog_revision_from_an_older_connection_generation()
    {
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        let replica_a =
            ConnectionControlPlane::from_config(&config).expect("replica A should build");
        let openapi_write: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Replica generation ordering",
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
        let original = replica_a
            .create_managed(
                replica_a.runtime_snapshot().collection_etag(),
                openapi_write.clone(),
                "replica-a",
            )
            .await
            .expect("managed OpenAPI Connection should create");
        let egress_config_a = EgressConfig::from_config(&config);
        let egress_client_a = Arc::new(
            EgressClient::new(egress_config_a.clone()).expect("replica A egress should build"),
        );
        let registry_a = ToolRegistry::disabled();
        let service_a = OpenApiConnectionCatalogService::load(
            replica_a.clone(),
            ConnectionHttpRuntime::new(replica_a.clone(), egress_config_a, egress_client_a),
            registry_a.clone(),
        )
        .expect("replica A OpenAPI service should load");
        let spec = r#"
openapi: 3.0.3
info: {title: Billing, version: 1.0.0}
paths:
  /invoices:
    get: {operationId: get_invoice}
"#;
        let original_preview = service_a
            .preview(original.id.as_str(), spec)
            .await
            .expect("original catalog should preview");
        service_a
            .register(
                original.id.as_str(),
                original.etag().as_str(),
                original_preview.spec_revision,
                original_preview.catalog_revision,
                &original_preview.spec_digest,
                spec,
                &[],
                &[],
                "replica-a",
            )
            .await
            .expect("replica A should publish an empty c1/r1 catalog");
        assert_eq!(
            service_a.runtime().current_generation(&original.id),
            Some((
                original.revisions.connection,
                original.etag().to_string(),
                1,
            ))
        );
        assert!(registry_a.get("get_invoice").is_none());

        // Replica B shares the authority but has independent Connection and
        // catalog runtimes. Replica A deliberately receives neither kind
        // transition callback below.
        let replica_b =
            ConnectionControlPlane::from_config(&config).expect("replica B should build");
        let mcp_write: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Replica generation ordering",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/mcp"
            },
            "authentication": {"type": "none"},
            "tls": {},
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": false
            }
        }))
        .expect("managed MCP replacement should deserialize");
        let converted = replica_b
            .replace_managed(&original.id, &original.etag(), mcp_write, "replica-b")
            .await
            .expect("an empty OpenAPI catalog should allow conversion to MCP");
        let restored = replica_b
            .replace_managed(&original.id, &converted.etag(), openapi_write, "replica-b")
            .await
            .expect("the Connection should convert back to OpenAPI");
        assert!(restored.revisions.connection > original.revisions.connection);

        let egress_config_b = EgressConfig::from_config(&config);
        let egress_client_b = Arc::new(
            EgressClient::new(egress_config_b.clone()).expect("replica B egress should build"),
        );
        let service_b = OpenApiConnectionCatalogService::load(
            replica_b.clone(),
            ConnectionHttpRuntime::new(replica_b.clone(), egress_config_b, egress_client_b),
            ToolRegistry::disabled(),
        )
        .expect("replica B OpenAPI service should load after restoration");
        let restored_preview = service_b
            .preview(restored.id.as_str(), spec)
            .await
            .expect("restored catalog should preview from revision zero");
        assert_eq!(restored_preview.catalog_revision, 0);
        service_b
            .register(
                restored.id.as_str(),
                restored.etag().as_str(),
                restored_preview.spec_revision,
                restored_preview.catalog_revision,
                &restored_preview.spec_digest,
                spec,
                &["get_invoice".to_owned()],
                &restored_preview.registration_security_selections,
                "replica-b",
            )
            .await
            .expect("replica B should publish a nonempty c3/r1 catalog");
        let authoritative_catalog = replica_b
            .managed_store()
            .expect("managed store should exist")
            .openapi_catalog(&restored.id)
            .await
            .expect("authoritative catalog should read")
            .expect("authoritative catalog should exist");
        assert_eq!(authoritative_catalog.catalog_revision, 1);
        assert_eq!(authoritative_catalog.observed_etag, restored.etag());

        assert_eq!(
            service_a.runtime().current_generation(&original.id),
            Some((
                original.revisions.connection,
                original.etag().to_string(),
                1,
            )),
            "replica A intentionally missed both removal callbacks"
        );
        let authoritative_records = replica_a
            .managed_store()
            .expect("managed store should exist")
            .list()
            .await
            .expect("replica A should read the shared authority");
        replica_a
            .publish_authoritative_records(authoritative_records)
            .await
            .expect("replica A should publish the c3 Connection snapshot");
        assert_eq!(
            service_a.runtime().current_generation(&original.id),
            Some((
                original.revisions.connection,
                original.etag().to_string(),
                1,
            )),
            "publishing Connection records alone must not forge a catalog callback"
        );

        service_a
            .reconcile_from_authority()
            .await
            .expect("catalog reconciliation should prefer c3/r1 over c1/r1");
        assert_eq!(
            service_a.runtime().current_generation(&restored.id),
            Some((
                restored.revisions.connection,
                restored.etag().to_string(),
                1,
            ))
        );
        let reconciled_definition = registry_a
            .get("get_invoice")
            .expect("replica A should serve the c3/r1 definition");
        assert!(service_a
            .runtime()
            .definition_is_current(&reconciled_definition, restored.etag().as_str()));
    }

    #[tokio::test]
    async fn rejected_overlay_put_keeps_the_live_and_durable_catalog_unchanged() {
        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Overlay rejection OpenAPI",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {"base_url": "https://billing.example.test", "base_path": "/"},
            "authentication": {"type": "none"},
            "tls": {},
            "timeouts": {
                "connect_timeout_ms": 1000,
                "request_timeout_ms": 3000,
                "response_idle_timeout_ms": 1000
            },
            "discovery": {"type": "managed_openapi", "use_connection_authentication": false}
        }))
        .expect("managed OpenAPI Connection should deserialize");
        let record = control_plane
            .create_managed(
                control_plane.runtime_snapshot().collection_etag(),
                candidate,
                "test-admin",
            )
            .await
            .expect("managed OpenAPI Connection should create");
        let egress_config = EgressConfig::from_config(&config);
        let egress_client =
            Arc::new(EgressClient::new(egress_config.clone()).expect("egress should build"));
        let registry = ToolRegistry::disabled();
        let policy = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {"admin": {"permissions": []}},
            "routes": [],
            "tools": {
                "unsafe_adoption": {
                    "allowed_roles": ["admin"],
                    "timeout_ms": 5000,
                    "max_concurrent": 1
                }
            }
        }))
        .expect("test policy should validate");
        let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
        let rbac = RbacState::new(policy, Vec::new(), false, audit);
        let service = OpenApiConnectionCatalogService::load(
            control_plane.clone(),
            ConnectionHttpRuntime::new(control_plane.clone(), egress_config, egress_client),
            registry.clone(),
        )
        .expect("managed OpenAPI service should load")
        .with_rbac_state(Some(rbac));
        let spec = r#"
openapi: 3.0.3
info: {title: Billing, version: 1.0.0}
paths:
  /invoices:
    post:
      operationId: get_invoice
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                payload: {type: string}
"#;
        let preview = service
            .preview(record.id.as_str(), spec)
            .await
            .expect("spec should preview");
        service
            .register(
                record.id.as_str(),
                record.etag().as_str(),
                0,
                0,
                &preview.spec_digest,
                spec,
                &["get_invoice".to_owned()],
                &preview.registration_security_selections,
                "test-admin",
            )
            .await
            .expect("catalog should publish");
        let absent_overlay_etag =
            OverlayEtag::for_revisions(record.id.as_str(), record.revisions.connection, 1, 0);
        let adoption_rejected = service
            .put_overlay(
                record.id.as_str(),
                absent_overlay_etag.as_str(),
                &json!({
                    "schema_version": "0.1.0",
                    "tools": {"get_invoice": {"rename": "unsafe_adoption"}}
                }),
                "test-admin",
            )
            .await
            .expect_err("an unowned policy grant must not be adopted by rename");
        assert!(matches!(
            adoption_rejected,
            OpenApiOverlayOperationError::Rejected(ref error)
                if error.problems.iter().any(|problem| {
                    problem.path == "/tools/get_invoice/rename"
                        && problem.message.contains("existing policy entry")
                })
        ));
        let invalid_document = json!({
            "schema_version": "0.1.0",
            "tools": {"unknown_operation": {"rename": "unsafe_adoption"}}
        });
        let rejected = service
            .put_overlay(
                record.id.as_str(),
                absent_overlay_etag.as_str(),
                &invalid_document,
                "test-admin",
            )
            .await
            .expect_err("unknown generated tool should reject the overlay");
        assert!(matches!(
            rejected,
            OpenApiOverlayOperationError::Rejected(_)
        ));
        let preview_rejected = service
            .preview_with_overlay(record.id.as_str(), spec, Some(&invalid_document))
            .await
            .expect_err("preview should preserve structured overlay problems");
        assert!(matches!(
            preview_rejected,
            OpenApiOverlayOperationError::Rejected(ref error)
                if error.problems.iter().any(|problem| problem.path == "/tools/unknown_operation")
        ));
        let invalid_transform = json!({
            "schema_version": "0.1.0",
            "tools": {
                "get_invoice": {
                    "parameters": {
                        "payload": {
                            "shape": {
                                "agent": {"value": {"type": "string"}},
                                "wire": {"/value": {"from": "value"}}
                            }
                        }
                    }
                }
            }
        });
        let transform_rejected = service
            .put_overlay(
                record.id.as_str(),
                absent_overlay_etag.as_str(),
                &invalid_transform,
                "test-admin",
            )
            .await
            .expect_err("a shape over a scalar body property must reject atomically");
        assert!(matches!(
            transform_rejected,
            OpenApiOverlayOperationError::Rejected(ref error)
                if error.problems.iter().any(|problem| {
                    problem.path == "/tools/get_invoice/parameters/payload/shape"
                        && problem.message.contains("must have type object")
                })
        ));
        let catalog = control_plane
            .managed_store()
            .expect("managed store should exist")
            .openapi_catalog(&record.id)
            .await
            .expect("catalog read should succeed")
            .expect("catalog should remain");
        assert_eq!(catalog.catalog_revision, 1);
        assert_eq!(catalog.overlay_revision, 0);
        assert!(registry.get("get_invoice").is_some());
        assert!(registry.get("unsafe_adoption").is_none());
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
            surviving_refresh_selection(&initial_catalog, &reassigned_name, None).err(),
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
