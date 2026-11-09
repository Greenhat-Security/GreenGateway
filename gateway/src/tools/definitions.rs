//! The gateway's tool registry: loading and watching the tools file,
//! merging it with the managed OpenAPI and MCP catalogs, and publishing the
//! result for the executor.
//!
//! The tool definition model and the tools document's validating parse are
//! `gateway_config::tools::definitions` (issue #242), shared with `ggctl` and
//! re-exported here so call sites keep their paths. Every registry update is
//! held to the same semantic checks.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use arc_swap::ArcSwap;
use notify::{RecursiveMode, Watcher};
use rmcp::model::ToolAnnotations as McpToolAnnotations;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    audit::{self, AuditEvent, AuditLog},
    authority_events::required::{AuthorityOperation, BackgroundEvidenceGate},
    config::Config,
};

pub use gateway_config::tools::definitions::*;

const TOOL_REGISTRY_RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);
const MAX_TOOLS_FILE_BYTES: u64 = 1_048_576;

/// The gateway's tool annotations from an MCP upstream's. The two types
/// carry the same five hints; the definition model is `gateway-config`'s,
/// which does not link the MCP SDK, so the conversion lives here.
pub(crate) fn tool_annotations_from_mcp(value: McpToolAnnotations) -> ToolAnnotations {
    ToolAnnotations {
        title: value.title,
        read_only_hint: value.read_only_hint,
        destructive_hint: value.destructive_hint,
        idempotent_hint: value.idempotent_hint,
        open_world_hint: value.open_world_hint,
    }
}

/// The MCP SDK's tool annotations for a definition's, as `tools/list`
/// serves them.
pub(crate) fn mcp_tool_annotations(value: ToolAnnotations) -> McpToolAnnotations {
    let mut annotations = McpToolAnnotations::default();
    annotations.title = value.title;
    annotations.read_only_hint = value.read_only_hint;
    annotations.destructive_hint = value.destructive_hint;
    annotations.idempotent_hint = value.idempotent_hint;
    annotations.open_world_hint = value.open_world_hint;
    annotations
}

#[derive(Debug)]
pub enum McpCatalogPublishError<E> {
    Registry(ToolRegistryError),
    Persist(E),
}

pub type OpenApiCatalogPublishError<E> = McpCatalogPublishError<E>;
pub type LocalDefinitionsPublishError<E> = McpCatalogPublishError<E>;

#[derive(Clone)]
pub struct ToolRegistry {
    state: Arc<ArcSwap<ToolRegistryState>>,
    write_lock: Arc<Mutex<()>>,
    definition_validator: Arc<Mutex<Option<ToolDefinitionsValidator>>>,
    audit: Option<AuditLog>,
}

pub type McpProxyDefinitionsProvider =
    Arc<dyn Fn() -> Option<Vec<ToolDefinition>> + Send + Sync + 'static>;
pub type ToolDefinitionsValidator =
    Arc<dyn Fn(&[ToolDefinition]) -> Result<(), Vec<String>> + Send + Sync + 'static>;

impl fmt::Debug for ToolRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolRegistry")
            .field("tool_count", &self.state.load().tools.len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "postgres")]
tokio::task_local! {
    /// The registry state pinned for the request being served, set when
    /// the gate admits it, so every tool lookup inside the request sees
    /// the lane the request was admitted with.
    static PINNED_TOOLS: Arc<ToolRegistryState>;
}

/// Run `future` with `state` pinned as the request's registry state.
#[cfg(feature = "postgres")]
pub(crate) async fn with_pinned_tools<F: std::future::Future>(
    state: Arc<ToolRegistryState>,
    future: F,
) -> F::Output {
    PINNED_TOOLS.scope(state, future).await
}

#[allow(dead_code)] // Future MCP executor and admin surfaces will query this registry state.
pub(crate) struct ToolRegistryState {
    tools: BTreeMap<String, Arc<ToolDefinition>>,
    local_definitions: Vec<ToolDefinition>,
    managed_openapi_definitions: Vec<ToolDefinition>,
    mcp_proxy_definitions: Vec<ToolDefinition>,
}

/// How an install treats a tool name another lane already holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneConflicts {
    /// Refuse the install: the request-path installs, which run before
    /// the authority has accepted anything.
    Refuse,
    /// Evict the holder: the reconciliation installs of content the
    /// authority has already committed. The authority reserves every tool
    /// name across the local lane and the managed catalogs, and legacy
    /// projections carry no catalogs, so a holder that conflicts with
    /// authoritative content is provably stale -- its own authoritative
    /// content, which no longer carries the name, follows in the same
    /// pass. Refusing instead would make convergence depend on the order
    /// lanes are reconciled in: a name that moved between lanes, or two
    /// names swapped, would never install on a lagging replica.
    EvictStale,
}

impl ToolRegistry {
    #[allow(dead_code)] // Exposed for callers that intentionally run without TOOLS_FILE.
    pub fn disabled() -> Self {
        Self::from_definitions_with_audit(Vec::new(), None)
    }

    #[allow(dead_code)] // Future callers without audit wiring can construct the registry from Config.
    pub fn from_config(config: &Config) -> Result<Self, ToolRegistryError> {
        match config.tools_file.as_deref() {
            Some(path) => Self::from_file(path),
            None => Ok(Self::disabled()),
        }
    }

    pub fn from_config_with_audit(
        config: &Config,
        audit: AuditLog,
    ) -> Result<Self, ToolRegistryError> {
        match config.tools_file.as_deref() {
            Some(path) => Self::from_file_with_audit(path, audit),
            None => Ok(Self::from_definitions_with_audit(Vec::new(), Some(audit))),
        }
    }

    #[allow(dead_code)] // Tests and future startup variants load registries directly from files.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ToolRegistryError> {
        let definitions = definitions_from_file(path.as_ref())?;
        Ok(Self::from_definitions_with_audit(definitions, None))
    }

    pub fn from_file_with_audit(
        path: impl AsRef<Path>,
        audit: AuditLog,
    ) -> Result<Self, ToolRegistryError> {
        let path = path.as_ref();
        match definitions_from_file(path) {
            Ok(definitions) => {
                let count = definitions.len();
                let registry = Self::from_definitions_with_audit(definitions, Some(audit));
                registry.emit_loaded(path, count);
                Ok(registry)
            }
            Err(err) => {
                emit_registry_failure(Some(&audit), path, &err);
                Err(err)
            }
        }
    }

    #[allow(dead_code)] // Useful for API-side validation without a temporary file.
    pub fn from_json_value(value: Value) -> Result<Self, ToolRegistryError> {
        let definitions = definitions_from_json_value(value, None)?;
        Ok(Self::from_definitions_with_audit(definitions, None))
    }

    /// The registry state this request reads: the one the gate pinned at
    /// admission (cluster mode), else the live lane. Dispatch reads go
    /// through it; install paths read the live lane directly.
    fn effective_state(&self) -> Arc<ToolRegistryState> {
        #[cfg(feature = "postgres")]
        if let Ok(pinned) = PINNED_TOOLS.try_with(Arc::clone) {
            return pinned;
        }
        self.state.load_full()
    }

    /// The live registry lane, for the security runtime to capture
    /// bundles from.
    #[cfg(feature = "postgres")]
    pub(crate) fn state_handle(&self) -> Arc<ArcSwap<ToolRegistryState>> {
        Arc::clone(&self.state)
    }

    #[allow(dead_code)] // Future MCP call handling will query by tool name.
    pub fn get(&self, name: &str) -> Option<Arc<ToolDefinition>> {
        self.effective_state().tools.get(name).cloned()
    }

    #[allow(dead_code)] // Future MCP list-tools handling will expose registry contents.
    pub fn list(&self) -> Vec<Arc<ToolDefinition>> {
        self.effective_state().tools.values().cloned().collect()
    }

    pub fn has_legacy_http_tools(&self) -> bool {
        self.effective_state()
            .tools
            .values()
            .any(|definition| definition.target.is_none() && !definition.upstream.is_mcp_proxy())
    }

    pub fn merge_definitions(
        &self,
        definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        self.merge_definitions_with(definitions, LaneConflicts::Refuse)
    }

    /// `merge_definitions` with a conflict policy. Cluster-mode boot merges
    /// authoritative catalogs with [`LaneConflicts::EvictStale`]: the boot
    /// seeds are read one resource at a time and a commit can land between
    /// the reads, so a name may appear in two seeds that never coexisted at
    /// the authority; the gate's first pass reconciles every resource to
    /// the current revision before a request is served, so the boot merge
    /// only needs to install *something* consistent rather than refuse.
    pub fn merge_definitions_with(
        &self,
        definitions: Vec<ToolDefinition>,
        conflicts: LaneConflicts,
    ) -> Result<(), ToolRegistryError> {
        if definitions.is_empty() {
            return Ok(());
        }

        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let state = self.state.load();
        let mut local_definitions = state.local_definitions.clone();
        let mut managed_openapi_definitions = state.managed_openapi_definitions.clone();
        let mut mcp_proxy_definitions = state.mcp_proxy_definitions.clone();
        drop(state);
        if conflicts == LaneConflicts::EvictStale {
            let incoming = definitions
                .iter()
                .map(|definition| definition.name.clone())
                .collect::<BTreeSet<_>>();
            evict_stale_holders(
                "boot",
                "authority",
                &incoming,
                [
                    &mut local_definitions,
                    &mut managed_openapi_definitions,
                    &mut mcp_proxy_definitions,
                ],
                |_| false,
            );
        }

        let (new_local_definitions, new_managed_openapi_definitions, new_mcp_proxy_definitions) =
            split_definitions_by_source(definitions);
        local_definitions.extend(new_local_definitions);
        managed_openapi_definitions.extend(new_managed_openapi_definitions);
        mcp_proxy_definitions.extend(new_mcp_proxy_definitions);

        let merged = combined_definitions(
            &local_definitions,
            &managed_openapi_definitions,
            &mcp_proxy_definitions,
        );
        let semantic_problems = tool_definition_problems(&merged);
        if !semantic_problems.is_empty() {
            return Err(ToolRegistryError::invalid(semantic_problems));
        }
        self.validate_definitions(&merged)?;

        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local_definitions,
                managed_openapi_definitions,
                mcp_proxy_definitions,
            )));
        Ok(())
    }

    /// Replace `connection_id`'s managed-MCP lane, persisting inside the
    /// registry's write lock so validation, durability, and the swap are
    /// one atomic step. Standalone mode uses this; the asynchronous
    /// cluster path uses the validate/commit/install split above, which
    /// cannot hold this lock across its await.
    pub fn replace_mcp_connection_catalog<E>(
        &self,
        connection_id: &str,
        definitions: Vec<ToolDefinition>,
        persist: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), McpCatalogPublishError<E>> {
        let provenance = mcp_catalog_provenance_problems(connection_id, &definitions);
        if !provenance.is_empty() {
            return Err(McpCatalogPublishError::Registry(
                ToolRegistryError::invalid(provenance),
            ));
        }

        let _guard = self.write_guard();
        let (local_definitions, managed_openapi_definitions, mcp_proxy_definitions) =
            self.mcp_lanes_after(connection_id, definitions);
        self.validate_merged_lanes(
            &local_definitions,
            &managed_openapi_definitions,
            &mcp_proxy_definitions,
        )
        .map_err(McpCatalogPublishError::Registry)?;
        persist().map_err(McpCatalogPublishError::Persist)?;
        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local_definitions,
                managed_openapi_definitions,
                mcp_proxy_definitions,
            )));
        Ok(())
    }

    /// The managed-OpenAPI counterpart of
    /// [`ToolRegistry::replace_mcp_connection_catalog`].
    pub fn replace_openapi_connection_catalog<E>(
        &self,
        connection_id: &str,
        definitions: Vec<ToolDefinition>,
        persist: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), OpenApiCatalogPublishError<E>> {
        let provenance = openapi_catalog_provenance_problems(connection_id, &definitions);
        if !provenance.is_empty() {
            return Err(McpCatalogPublishError::Registry(
                ToolRegistryError::invalid(provenance),
            ));
        }

        let _guard = self.write_guard();
        let (local_definitions, managed_openapi_definitions, mcp_proxy_definitions) =
            self.openapi_lanes_after(connection_id, definitions);
        self.validate_merged_lanes(
            &local_definitions,
            &managed_openapi_definitions,
            &mcp_proxy_definitions,
        )
        .map_err(McpCatalogPublishError::Registry)?;
        persist().map_err(McpCatalogPublishError::Persist)?;
        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local_definitions,
                managed_openapi_definitions,
                mcp_proxy_definitions,
            )));
        Ok(())
    }

    /// Validate a candidate managed-MCP lane for `connection_id` exactly
    /// the way [`ToolRegistry::replace_mcp_connection_catalog`] would
    /// (provenance, semantic checks, and the registered validator hook
    /// over the merged set) without installing anything.
    ///
    /// This is the read half of the validate/commit/install split the
    /// catalog services use once the persist step is asynchronous: a
    /// `persist` closure cannot await, and the registry's write lock is a
    /// `std` mutex that must not be held across one. The commit happens
    /// between this call and
    /// [`ToolRegistry::install_mcp_connection_catalog`], which re-validates
    /// against the lanes current at install time. It is the same shape
    /// [`ToolRegistry::validate_local_definitions`] and
    /// [`ToolRegistry::install_local_definitions`] already use for the
    /// document-owned lane.
    pub fn validate_mcp_connection_catalog(
        &self,
        connection_id: &str,
        definitions: &[ToolDefinition],
    ) -> Result<(), ToolRegistryError> {
        let provenance = mcp_catalog_provenance_problems(connection_id, definitions);
        if !provenance.is_empty() {
            return Err(ToolRegistryError::invalid(provenance));
        }
        let (local, managed_openapi, mcp_proxy) =
            self.mcp_lanes_after(connection_id, definitions.to_vec());
        self.validate_merged_lanes(&local, &managed_openapi, &mcp_proxy)
    }

    /// Install a managed-MCP lane that was validated and committed to the
    /// authority. Re-validates against the lanes current at install time
    /// (another lane may have moved since validation) and swaps. A
    /// rejected install keeps the existing registry active -- fail closed,
    /// exactly like a rejected file reload.
    pub fn install_mcp_connection_catalog(
        &self,
        connection_id: &str,
        definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        self.install_mcp_connection_catalog_with(connection_id, definitions, LaneConflicts::Refuse)
    }

    pub fn install_mcp_connection_catalog_with(
        &self,
        connection_id: &str,
        definitions: Vec<ToolDefinition>,
        conflicts: LaneConflicts,
    ) -> Result<(), ToolRegistryError> {
        let provenance = mcp_catalog_provenance_problems(connection_id, &definitions);
        if !provenance.is_empty() {
            return Err(ToolRegistryError::invalid(provenance));
        }
        let _guard = self.write_guard();
        let (mut local, mut managed_openapi, mut mcp_proxy) =
            self.mcp_lanes_after(connection_id, definitions);
        if conflicts == LaneConflicts::EvictStale {
            let is_incoming =
                |definition: &ToolDefinition| mcp_source_is(definition, connection_id);
            let incoming = incoming_names(&mcp_proxy, is_incoming);
            evict_stale_holders(
                "mcp",
                connection_id,
                &incoming,
                [&mut local, &mut managed_openapi, &mut mcp_proxy],
                is_incoming,
            );
        }
        self.validate_merged_lanes(&local, &managed_openapi, &mcp_proxy)?;
        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local,
                managed_openapi,
                mcp_proxy,
            )));
        Ok(())
    }

    /// The managed-OpenAPI counterpart of
    /// [`ToolRegistry::validate_mcp_connection_catalog`].
    pub fn validate_openapi_connection_catalog(
        &self,
        connection_id: &str,
        definitions: &[ToolDefinition],
    ) -> Result<(), ToolRegistryError> {
        let provenance = openapi_catalog_provenance_problems(connection_id, definitions);
        if !provenance.is_empty() {
            return Err(ToolRegistryError::invalid(provenance));
        }
        let (local, managed_openapi, mcp_proxy) =
            self.openapi_lanes_after(connection_id, definitions.to_vec());
        self.validate_merged_lanes(&local, &managed_openapi, &mcp_proxy)
    }

    /// The managed-OpenAPI counterpart of
    /// [`ToolRegistry::install_mcp_connection_catalog`].
    pub fn install_openapi_connection_catalog(
        &self,
        connection_id: &str,
        definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        self.install_openapi_connection_catalog_with(
            connection_id,
            definitions,
            LaneConflicts::Refuse,
        )
    }

    pub fn install_openapi_connection_catalog_with(
        &self,
        connection_id: &str,
        definitions: Vec<ToolDefinition>,
        conflicts: LaneConflicts,
    ) -> Result<(), ToolRegistryError> {
        let provenance = openapi_catalog_provenance_problems(connection_id, &definitions);
        if !provenance.is_empty() {
            return Err(ToolRegistryError::invalid(provenance));
        }
        let _guard = self.write_guard();
        let (mut local, mut managed_openapi, mut mcp_proxy) =
            self.openapi_lanes_after(connection_id, definitions);
        if conflicts == LaneConflicts::EvictStale {
            let is_incoming =
                |definition: &ToolDefinition| openapi_source_is(definition, connection_id);
            let incoming = incoming_names(&managed_openapi, is_incoming);
            evict_stale_holders(
                "openapi",
                connection_id,
                &incoming,
                [&mut local, &mut managed_openapi, &mut mcp_proxy],
                is_incoming,
            );
        }
        self.validate_merged_lanes(&local, &managed_openapi, &mcp_proxy)?;
        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local,
                managed_openapi,
                mcp_proxy,
            )));
        Ok(())
    }

    /// The three lanes as they would stand after `connection_id`'s
    /// managed-MCP lane is replaced by `definitions`, in
    /// (local, managed OpenAPI, MCP proxy) order.
    fn mcp_lanes_after(
        &self,
        connection_id: &str,
        definitions: Vec<ToolDefinition>,
    ) -> (
        Vec<ToolDefinition>,
        Vec<ToolDefinition>,
        Vec<ToolDefinition>,
    ) {
        let state = self.state.load();
        let local_definitions = state.local_definitions.clone();
        let managed_openapi_definitions = state.managed_openapi_definitions.clone();
        let mut mcp_proxy_definitions = state
            .mcp_proxy_definitions
            .iter()
            .filter(|definition| {
                !matches!(
                    &definition.source,
                    ToolSource::Mcp {
                        connection_id: source_connection_id,
                        ..
                    } if source_connection_id == connection_id
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        drop(state);
        mcp_proxy_definitions.extend(definitions);
        (
            local_definitions,
            managed_openapi_definitions,
            mcp_proxy_definitions,
        )
    }

    /// The managed-OpenAPI counterpart of [`ToolRegistry::mcp_lanes_after`].
    fn openapi_lanes_after(
        &self,
        connection_id: &str,
        definitions: Vec<ToolDefinition>,
    ) -> (
        Vec<ToolDefinition>,
        Vec<ToolDefinition>,
        Vec<ToolDefinition>,
    ) {
        let state = self.state.load();
        let local_definitions = state.local_definitions.clone();
        let mut managed_openapi_definitions = state
            .managed_openapi_definitions
            .iter()
            .filter(|definition| {
                !matches!(
                    &definition.source,
                    ToolSource::OpenApi {
                        connection_id: source_connection_id,
                        ..
                    } if source_connection_id == connection_id
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        let mcp_proxy_definitions = state.mcp_proxy_definitions.clone();
        drop(state);
        managed_openapi_definitions.extend(definitions);
        (
            local_definitions,
            managed_openapi_definitions,
            mcp_proxy_definitions,
        )
    }

    /// The semantic checks plus the registered validator hook over the
    /// merged set of three lanes.
    fn validate_merged_lanes(
        &self,
        local: &[ToolDefinition],
        managed_openapi: &[ToolDefinition],
        mcp_proxy: &[ToolDefinition],
    ) -> Result<(), ToolRegistryError> {
        let merged = combined_definitions(local, managed_openapi, mcp_proxy);
        let semantic_problems = tool_definition_problems(&merged);
        if !semantic_problems.is_empty() {
            return Err(ToolRegistryError::invalid(semantic_problems));
        }
        self.validate_definitions(&merged)
    }

    /// The registry write lock, recovering a poisoned guard: poisoning
    /// means a writer panicked mid-swap, which leaves the `ArcSwap`
    /// structurally valid (it is swapped, never mutated in place).
    fn write_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn replace_local_definitions_with_persist<E>(
        &self,
        local_definitions: Vec<ToolDefinition>,
        persist: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), LocalDefinitionsPublishError<E>> {
        let provenance_problems = local_definition_provenance_problems(&local_definitions);
        if !provenance_problems.is_empty() {
            return Err(McpCatalogPublishError::Registry(
                ToolRegistryError::invalid(provenance_problems),
            ));
        }

        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state = self.state.load();
        let managed_openapi_definitions = state.managed_openapi_definitions.clone();
        let mcp_proxy_definitions = state.mcp_proxy_definitions.clone();
        drop(state);

        let merged = combined_definitions(
            &local_definitions,
            &managed_openapi_definitions,
            &mcp_proxy_definitions,
        );
        let semantic_problems = tool_definition_problems(&merged);
        if !semantic_problems.is_empty() {
            return Err(McpCatalogPublishError::Registry(
                ToolRegistryError::invalid(semantic_problems),
            ));
        }
        self.validate_definitions(&merged)
            .map_err(McpCatalogPublishError::Registry)?;
        persist().map_err(McpCatalogPublishError::Persist)?;
        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local_definitions,
                managed_openapi_definitions,
                mcp_proxy_definitions,
            )));
        Ok(())
    }

    /// Validate a candidate local lane exactly the way an install would
    /// (provenance, semantic checks, and the registered validator hook
    /// over the merged set) without installing anything. Cluster mode
    /// commits the candidate to the authority between this validation and
    /// [`ToolRegistry::install_local_definitions`]; the install
    /// re-validates against the lanes current at install time.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Only the
                                                             // cluster-mode register path calls it; the file path validates inside
                                                             // `replace_local_definitions_with_persist`.
    pub fn validate_local_definitions(
        &self,
        local_definitions: &[ToolDefinition],
    ) -> Result<(), ToolRegistryError> {
        let provenance_problems = local_definition_provenance_problems(local_definitions);
        if !provenance_problems.is_empty() {
            return Err(ToolRegistryError::invalid(provenance_problems));
        }
        let state = self.state.load();
        let merged = combined_definitions(
            local_definitions,
            &state.managed_openapi_definitions,
            &state.mcp_proxy_definitions,
        );
        drop(state);
        let semantic_problems = tool_definition_problems(&merged);
        if !semantic_problems.is_empty() {
            return Err(ToolRegistryError::invalid(semantic_problems));
        }
        self.validate_definitions(&merged)
    }

    /// Install a local lane that was validated and committed to the
    /// authority (cluster mode): re-validates against the current lanes
    /// (managed lanes may have moved since validation) and swaps. A
    /// rejected install keeps the existing registry active -- fail
    /// closed, exactly like a rejected file reload.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Only the
                                                             // cluster-mode register path and the tools reconciler call it.
    pub fn install_local_definitions(
        &self,
        local_definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        self.replace_local_definitions_with(local_definitions, LaneConflicts::Refuse)
    }

    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // The cluster reconciler's install.
    pub fn install_local_definitions_with(
        &self,
        local_definitions: Vec<ToolDefinition>,
        conflicts: LaneConflicts,
    ) -> Result<(), ToolRegistryError> {
        self.replace_local_definitions_with(local_definitions, conflicts)
    }

    pub(crate) fn from_definitions_with_audit(
        definitions: Vec<ToolDefinition>,
        audit: Option<AuditLog>,
    ) -> Self {
        Self {
            state: Arc::new(ArcSwap::from_pointee(ToolRegistryState::from_definitions(
                definitions,
            ))),
            write_lock: Arc::new(Mutex::new(())),
            definition_validator: Arc::new(Mutex::new(None)),
            audit,
        }
    }

    pub fn set_definition_validator(
        &self,
        validator: ToolDefinitionsValidator,
    ) -> Result<(), ToolRegistryError> {
        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state = self.state.load();
        let definitions = combined_definitions(
            &state.local_definitions,
            &state.managed_openapi_definitions,
            &state.mcp_proxy_definitions,
        );
        drop(state);
        validator(&definitions).map_err(ToolRegistryError::invalid)?;
        match self.definition_validator.lock() {
            Ok(mut current) => *current = Some(validator),
            Err(poisoned) => *poisoned.into_inner() = Some(validator),
        }
        Ok(())
    }

    /// The currently installed local lane (the document-owned tools), in
    /// document order. Tests and cluster wiring observe reconciliation
    /// through this; serving paths use the merged snapshot.
    #[allow(dead_code)] // Read by the cluster-mode tests; a production
                        // consumer (cluster status) arrives with #241 PR 14.
    pub fn current_local_definitions(&self) -> Vec<ToolDefinition> {
        self.state.load().local_definitions.clone()
    }

    fn replace_local_definitions(
        &self,
        local_definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        self.replace_local_definitions_with(local_definitions, LaneConflicts::Refuse)
    }

    fn replace_local_definitions_with(
        &self,
        local_definitions: Vec<ToolDefinition>,
        conflicts: LaneConflicts,
    ) -> Result<(), ToolRegistryError> {
        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let state = self.state.load();
        let mut managed_openapi_definitions = state.managed_openapi_definitions.clone();
        let mut mcp_proxy_definitions = state.mcp_proxy_definitions.clone();
        drop(state);
        if conflicts == LaneConflicts::EvictStale {
            let incoming = local_definitions
                .iter()
                .map(|definition| definition.name.clone())
                .collect::<BTreeSet<_>>();
            evict_stale_holders(
                "local",
                "tools",
                &incoming,
                [&mut managed_openapi_definitions, &mut mcp_proxy_definitions],
                |_| false,
            );
        }

        self.replace_definition_sources_locked(
            local_definitions,
            managed_openapi_definitions,
            mcp_proxy_definitions,
        )
    }

    fn replace_local_and_legacy_mcp_definitions(
        &self,
        local_definitions: Vec<ToolDefinition>,
        legacy_mcp_proxy_definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        let _guard = match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let state = self.state.load();
        let managed_openapi_definitions = state.managed_openapi_definitions.clone();
        let managed_mcp_proxy_definitions = state
            .mcp_proxy_definitions
            .iter()
            .filter(|definition| matches!(definition.source, ToolSource::Mcp { .. }))
            .cloned()
            .collect::<Vec<_>>();
        drop(state);
        let mut mcp_proxy_definitions = legacy_mcp_proxy_definitions;
        mcp_proxy_definitions.extend(managed_mcp_proxy_definitions);
        self.replace_definition_sources_locked(
            local_definitions,
            managed_openapi_definitions,
            mcp_proxy_definitions,
        )
    }

    fn replace_definition_sources_locked(
        &self,
        local_definitions: Vec<ToolDefinition>,
        managed_openapi_definitions: Vec<ToolDefinition>,
        mcp_proxy_definitions: Vec<ToolDefinition>,
    ) -> Result<(), ToolRegistryError> {
        let provenance_problems = local_definition_provenance_problems(&local_definitions);
        if !provenance_problems.is_empty() {
            return Err(ToolRegistryError::invalid(provenance_problems));
        }
        let merged = combined_definitions(
            &local_definitions,
            &managed_openapi_definitions,
            &mcp_proxy_definitions,
        );
        let semantic_problems = tool_definition_problems(&merged);
        if !semantic_problems.is_empty() {
            return Err(ToolRegistryError::invalid(semantic_problems));
        }
        self.validate_definitions(&merged)?;

        self.state
            .store(Arc::new(ToolRegistryState::from_definition_sources(
                local_definitions,
                managed_openapi_definitions,
                mcp_proxy_definitions,
            )));
        Ok(())
    }

    fn validate_definitions(
        &self,
        definitions: &[ToolDefinition],
    ) -> Result<(), ToolRegistryError> {
        let validator = match self.definition_validator.lock() {
            Ok(validator) => validator.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if let Some(validator) = validator {
            validator(definitions).map_err(ToolRegistryError::invalid)?;
        }
        Ok(())
    }

    fn emit_loaded(&self, path: &Path, tool_count: usize) {
        if let Some(audit) = &self.audit {
            audit.emit(AuditEvent::new(
                audit::event::TOOL_REGISTRY_LOADED,
                "tool-registry",
                "internal",
                None,
                json!({
                    "tools_file": path.display().to_string(),
                    "tool_count": tool_count,
                    "outcome": "success",
                }),
            ));
        }
    }

    fn emit_reload_failed(&self, path: &Path, error: &ToolRegistryError) {
        emit_registry_failure(self.audit.as_ref(), path, error);
    }
}

impl ToolRegistryState {
    fn from_definitions(definitions: Vec<ToolDefinition>) -> Self {
        let (local_definitions, managed_openapi_definitions, mcp_proxy_definitions) =
            split_definitions_by_source(definitions);
        Self::from_definition_sources(
            local_definitions,
            managed_openapi_definitions,
            mcp_proxy_definitions,
        )
    }

    fn from_definition_sources(
        local_definitions: Vec<ToolDefinition>,
        managed_openapi_definitions: Vec<ToolDefinition>,
        mcp_proxy_definitions: Vec<ToolDefinition>,
    ) -> Self {
        let tools = local_definitions
            .iter()
            .chain(managed_openapi_definitions.iter())
            .chain(mcp_proxy_definitions.iter())
            .map(|definition| (definition.name.clone(), Arc::new(definition.clone())))
            .collect();

        Self {
            tools,
            local_definitions,
            managed_openapi_definitions,
            mcp_proxy_definitions,
        }
    }
}

fn split_definitions_by_source(
    definitions: Vec<ToolDefinition>,
) -> (
    Vec<ToolDefinition>,
    Vec<ToolDefinition>,
    Vec<ToolDefinition>,
) {
    let mut local_definitions = Vec::new();
    let mut managed_openapi_definitions = Vec::new();
    let mut mcp_proxy_definitions = Vec::new();

    for definition in definitions {
        if matches!(&definition.source, ToolSource::OpenApi { .. }) {
            managed_openapi_definitions.push(definition);
        } else if definition.upstream.is_mcp_proxy() {
            mcp_proxy_definitions.push(definition);
        } else {
            local_definitions.push(definition);
        }
    }

    (
        local_definitions,
        managed_openapi_definitions,
        mcp_proxy_definitions,
    )
}

fn combined_definitions(
    local_definitions: &[ToolDefinition],
    managed_openapi_definitions: &[ToolDefinition],
    mcp_proxy_definitions: &[ToolDefinition],
) -> Vec<ToolDefinition> {
    local_definitions
        .iter()
        .chain(managed_openapi_definitions.iter())
        .chain(mcp_proxy_definitions.iter())
        .cloned()
        .collect()
}

/// Every definition in a managed-MCP catalog must claim -- in both its
/// source and its target -- the connection whose lane it is being
/// installed into. A catalog that names another connection would let one
/// connection's refresh publish tools attributed to another.
fn mcp_catalog_provenance_problems(
    connection_id: &str,
    definitions: &[ToolDefinition],
) -> Vec<String> {
    if definitions.iter().any(|definition| {
        !matches!(
            &definition.source,
            ToolSource::Mcp {
                connection_id: source_connection_id,
                ..
            } if source_connection_id == connection_id
        ) || !matches!(
            &definition.target,
            Some(ToolTarget::Mcp {
                connection_id: target_connection_id,
                ..
            }) if target_connection_id == connection_id
        )
    }) {
        vec!["managed MCP catalog contains a definition for a different connection".to_owned()]
    } else {
        Vec::new()
    }
}

/// The managed-OpenAPI counterpart of [`mcp_catalog_provenance_problems`],
/// which additionally requires the catalog revision the definition was
/// derived from: an OpenAPI tool without one cannot be matched back to the
/// specification revision that authorized it.
fn openapi_source_is(definition: &ToolDefinition, connection_id: &str) -> bool {
    matches!(
        &definition.source,
        ToolSource::OpenApi { connection_id: source, .. } if source == connection_id
    )
}

fn mcp_source_is(definition: &ToolDefinition, connection_id: &str) -> bool {
    matches!(
        &definition.source,
        ToolSource::Mcp { connection_id: source, .. } if source == connection_id
    )
}

/// The names a lane install brings in: the entries of `lane` that belong
/// to the installing owner.
fn incoming_names(
    lane: &[ToolDefinition],
    is_incoming: impl Fn(&ToolDefinition) -> bool,
) -> BTreeSet<String> {
    lane.iter()
        .filter(|definition| is_incoming(definition))
        .map(|definition| definition.name.clone())
        .collect()
}

/// Remove from `lanes` every entry that holds one of `incoming`'s names and
/// is not the incoming owner's own: under [`LaneConflicts::EvictStale`] such
/// a holder is provably stale (the authority reserved the name for the
/// installing owner), and its own authoritative content follows.
///
/// Provably -- which is why a holder the authority never reserved is not
/// evicted: a legacy projection's MCP proxy (a `Legacy` source in the MCP
/// lane) comes from this replica's static configuration, not from the
/// authority, so an authoritative name colliding with it is a real
/// collision, not staleness. It stays, the merged validation refuses the
/// install, and the gate fails closed rather than silently rebinding what
/// an existing policy name invokes.
fn evict_stale_holders<const N: usize>(
    lane: &'static str,
    owner: &str,
    incoming: &BTreeSet<String>,
    lanes: [&mut Vec<ToolDefinition>; N],
    is_incoming: impl Fn(&ToolDefinition) -> bool,
) {
    let mut evicted = Vec::new();
    let mut unreserved = Vec::new();
    for entries in lanes {
        entries.retain(|definition| {
            if !incoming.contains(&definition.name) || is_incoming(definition) {
                return true;
            }
            if definition.upstream.is_mcp_proxy()
                && !matches!(definition.source, ToolSource::Mcp { .. })
            {
                unreserved.push(definition.name.clone());
                return true;
            }
            evicted.push(definition.name.clone());
            false
        });
    }
    if !unreserved.is_empty() {
        tracing::error!(
            lane,
            owner,
            names = ?unreserved,
            "authoritative install collides with tool names this replica's static \
             configuration holds; the install is refused rather than rebinding them"
        );
    }
    if !evicted.is_empty() {
        tracing::info!(
            lane,
            owner,
            evicted = ?evicted,
            "authoritative install evicted stale holders of names the authority reassigned"
        );
    }
}

fn openapi_catalog_provenance_problems(
    connection_id: &str,
    definitions: &[ToolDefinition],
) -> Vec<String> {
    if definitions.iter().any(|definition| {
        !matches!(
            &definition.source,
            ToolSource::OpenApi {
                connection_id: source_connection_id,
                catalog_revision: Some(_),
                ..
            } if source_connection_id == connection_id
        ) || !matches!(
            &definition.target,
            Some(ToolTarget::Http {
                connection_id: target_connection_id,
                ..
            }) | Some(ToolTarget::Composite {
                connection_id: target_connection_id,
            }) if target_connection_id == connection_id
        )
    }) {
        vec![
            "managed OpenAPI catalog contains a definition for a different connection or without a catalog revision".to_owned(),
        ]
    } else {
        Vec::new()
    }
}

#[allow(dead_code)] // Retained for callers that only reload local tool definitions.
pub fn reload_tool_registry_from_file(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
) -> Result<(), ToolRegistryError> {
    reload_tool_registry_from_file_with_optional_mcp_proxy_definitions(registry, path, None)
}

#[allow(dead_code)] // Used by config reload paths that can rediscover upstream MCP tools.
pub fn reload_tool_registry_from_file_with_mcp_proxy_definitions(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
    mcp_proxy_definitions: Vec<ToolDefinition>,
) -> Result<(), ToolRegistryError> {
    reload_tool_registry_from_file_with_optional_mcp_proxy_definitions(
        registry,
        path,
        Some(mcp_proxy_definitions),
    )
}

/// Reloads the registry, rediscovering MCP proxy definitions off the runtime.
///
/// The provider talks to configured MCP upstreams synchronously, so how long it
/// runs is the upstream's choice. Calling it inline from a reload task parks a
/// Tokio worker for that whole time; on a runtime sized from a sub-1-CPU quota
/// that is the only worker, and the accept loop and health endpoints stop with
/// it.
pub async fn reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
    mcp_proxy_definitions_provider: Option<&McpProxyDefinitionsProvider>,
) -> Result<(), ToolRegistryError> {
    let mcp_proxy_definitions = match mcp_proxy_definitions_provider.cloned() {
        Some(provider) => tokio::task::spawn_blocking(move || provider())
            .await
            .unwrap_or_else(|error| {
                tracing::error!(
                    error = %error,
                    "MCP upstream rediscovery task failed during tool registry reload; preserving existing MCP proxy tools"
                );
                None
            }),
        None => None,
    };
    reload_tool_registry_from_file_with_optional_mcp_proxy_definitions(
        registry,
        path,
        mcp_proxy_definitions,
    )
}

fn reload_tool_registry_from_file_with_optional_mcp_proxy_definitions(
    registry: &ToolRegistry,
    path: impl AsRef<Path>,
    mcp_proxy_definitions: Option<Vec<ToolDefinition>>,
) -> Result<(), ToolRegistryError> {
    let path = path.as_ref();

    match definitions_from_file(path) {
        Ok(definitions) => {
            let tool_count = definitions.len();
            let replace_result = match mcp_proxy_definitions {
                Some(mcp_proxy_definitions) => registry
                    .replace_local_and_legacy_mcp_definitions(definitions, mcp_proxy_definitions),
                None => registry.replace_local_definitions(definitions),
            };
            if let Err(err) = replace_result {
                registry.emit_reload_failed(path, &err);
                tracing::error!(
                    tools_file = %path.display(),
                    error = %err,
                    "tool registry reload rejected; existing registry remains active"
                );
                return Err(err);
            }
            registry.emit_loaded(path, tool_count);
            tracing::info!(
                tools_file = %path.display(),
                tool_count,
                "tool registry reload accepted"
            );
            Ok(())
        }
        Err(err) => {
            registry.emit_reload_failed(path, &err);
            tracing::error!(
                tools_file = %path.display(),
                error = %err,
                "tool registry reload rejected; existing registry remains active"
            );
            Err(err)
        }
    }
}

/// A watched or signalled reload of `tools_file`, once the
/// authority-evidence gate admits it (issue #425, PR 4). Standalone mode
/// records no evidence of what a reload publishes, so
/// `AUTHORITY_EVIDENCE_DURABILITY=required` refuses each one -- the gate
/// audits it -- and the registry, MCP proxy tools included, stays as it is
/// until a restart activates the file. Without a gate every reload runs.
async fn reload_tools_file_if_admitted(
    registry: &ToolRegistry,
    tools_file: &Path,
    mcp_proxy_definitions_provider: Option<&McpProxyDefinitionsProvider>,
    evidence: Option<&BackgroundEvidenceGate>,
    trigger: &'static str,
) -> bool {
    if evidence.is_some_and(|gate| !gate.admits(AuthorityOperation::ToolsPublish, trigger)) {
        tracing::warn!(
            tools_file = %tools_file.display(),
            trigger,
            "tool registry reload refused by AUTHORITY_EVIDENCE_DURABILITY=required; existing registry remains active until a restart activates the file"
        );
        return false;
    }
    reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
        registry,
        tools_file,
        mcp_proxy_definitions_provider,
    )
    .await
    .is_ok()
}

#[allow(dead_code)] // Retained for callers that do not refresh MCP proxy definitions.
pub fn spawn_tool_registry_reload_tasks(
    tools_file: impl Into<PathBuf>,
    registry: ToolRegistry,
) -> notify::Result<()> {
    spawn_tool_registry_reload_tasks_with_mcp_proxy_definitions_provider(tools_file, registry, None)
}

pub fn spawn_tool_registry_reload_tasks_with_mcp_proxy_definitions_provider(
    tools_file: impl Into<PathBuf>,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
) -> notify::Result<()> {
    spawn_tool_registry_reload_tasks_inner(
        tools_file.into(),
        registry,
        mcp_proxy_definitions_provider,
        None,
        CancellationToken::new(),
        None,
    )
}

pub fn spawn_tool_registry_reload_tasks_with_lifecycle(
    tools_file: impl Into<PathBuf>,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
    evidence: BackgroundEvidenceGate,
    lifecycle: &crate::lifecycle::GatewayLifecycle,
) -> notify::Result<()> {
    spawn_tool_registry_reload_tasks_inner(
        tools_file.into(),
        registry,
        mcp_proxy_definitions_provider,
        Some(evidence),
        lifecycle.background_cancellation(),
        Some(lifecycle),
    )
}

fn spawn_tool_registry_reload_tasks_inner(
    tools_file: PathBuf,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
    evidence: Option<BackgroundEvidenceGate>,
    cancellation: CancellationToken,
    lifecycle: Option<&crate::lifecycle::GatewayLifecycle>,
) -> notify::Result<()> {
    let watcher = spawn_tool_registry_file_watcher(
        tools_file.clone(),
        registry.clone(),
        mcp_proxy_definitions_provider.clone(),
        evidence.clone(),
        cancellation.clone(),
    )?;
    let sighup = spawn_sighup_reload_task(
        tools_file,
        registry,
        mcp_proxy_definitions_provider,
        evidence,
        cancellation,
    );
    if let Some(lifecycle) = lifecycle {
        lifecycle.register_background_task(watcher);
        if let Some(sighup) = sighup {
            lifecycle.register_background_task(sighup);
        }
    }
    Ok(())
}

fn spawn_tool_registry_file_watcher(
    tools_file: PathBuf,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
    evidence: Option<BackgroundEvidenceGate>,
    cancellation: CancellationToken,
) -> notify::Result<tokio::task::JoinHandle<()>> {
    let (sender, receiver) = mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = sender.send(event);
    })?;
    watcher.watch(&watch_directory(&tools_file), RecursiveMode::NonRecursive)?;

    Ok(tokio::spawn(tool_registry_file_watch_loop(
        tools_file,
        registry,
        mcp_proxy_definitions_provider,
        evidence,
        receiver,
        watcher,
        cancellation,
    )))
}

async fn tool_registry_file_watch_loop(
    tools_file: PathBuf,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
    evidence: Option<BackgroundEvidenceGate>,
    mut events: mpsc::UnboundedReceiver<notify::Result<notify::Event>>,
    _watcher: notify::RecommendedWatcher,
    cancellation: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            event = events.recv() => event,
            () = cancellation.cancelled() => return,
        };
        let Some(event) = event else {
            return;
        };
        if !handle_tool_registry_watch_event(&tools_file, event) {
            continue;
        }

        tokio::select! {
            () = tokio::time::sleep(TOOL_REGISTRY_RELOAD_DEBOUNCE) => {}
            () = cancellation.cancelled() => return,
        }
        while let Ok(event) = events.try_recv() {
            let _ = handle_tool_registry_watch_event(&tools_file, event);
        }

        reload_tools_file_if_admitted(
            &registry,
            &tools_file,
            mcp_proxy_definitions_provider.as_ref(),
            evidence.as_ref(),
            "file_watch",
        )
        .await;
    }
}

fn handle_tool_registry_watch_event(
    tools_file: &Path,
    event: notify::Result<notify::Event>,
) -> bool {
    match event {
        Ok(event) => tool_registry_reload_event(&event, tools_file),
        Err(err) => {
            tracing::error!(error = %err, "tool registry file watch error");
            false
        }
    }
}

fn tool_registry_reload_event(event: &notify::Event, tools_file: &Path) -> bool {
    !matches!(event.kind, notify::EventKind::Access(_))
        && event
            .paths
            .iter()
            .any(|path| path_matches_tools_file(path, tools_file))
}

fn path_matches_tools_file(path: &Path, tools_file: &Path) -> bool {
    path == tools_file
        || path
            .file_name()
            .is_some_and(|file_name| Some(file_name) == tools_file.file_name())
}

fn watch_directory(tools_file: &Path) -> PathBuf {
    tools_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_owned()
}

#[cfg(unix)]
fn spawn_sighup_reload_task(
    tools_file: PathBuf,
    registry: ToolRegistry,
    mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
    evidence: Option<BackgroundEvidenceGate>,
    cancellation: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    Some(tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to register SIGHUP tool registry reload handler"
                );
                return;
            }
        };

        loop {
            let signal = tokio::select! {
                signal = sighup.recv() => signal,
                () = cancellation.cancelled() => return,
            };
            if signal.is_none() {
                return;
            }
            reload_tools_file_if_admitted(
                &registry,
                &tools_file,
                mcp_proxy_definitions_provider.as_ref(),
                evidence.as_ref(),
                "signal",
            )
            .await;
        }
    }))
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(
    _tools_file: PathBuf,
    _registry: ToolRegistry,
    _mcp_proxy_definitions_provider: Option<McpProxyDefinitionsProvider>,
    _evidence: Option<BackgroundEvidenceGate>,
    _cancellation: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    None
}

fn definitions_from_file(path: &Path) -> Result<Vec<ToolDefinition>, ToolRegistryError> {
    let contents = read_tools_file_to_string(path)?;
    let value = serde_json::from_str(&contents).map_err(|source| ToolRegistryError::Parse {
        path: Some(path.to_owned()),
        source,
    })?;

    definitions_from_json_value(value, Some(path))
}

/// The TOOLS_FILE document as a cluster's tools control plane stores it
/// (issue #241, PR 15's standalone-to-cluster import).
///
/// The file is read through the same bounded reader and validated by the
/// same loader `definitions_from_file` uses, so a document the import
/// accepts is exactly a document this binary would serve; the JSON is then
/// returned verbatim, so the imported document is the operator's own bytes
/// rather than a re-serialization of the parsed definitions.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
pub(crate) fn tools_document_from_file(path: &Path) -> Result<Value, ToolRegistryError> {
    let contents = read_tools_file_to_string(path)?;
    let value: Value =
        serde_json::from_str(&contents).map_err(|source| ToolRegistryError::Parse {
            path: Some(path.to_owned()),
            source,
        })?;
    definitions_from_json_value(value.clone(), Some(path))?;
    Ok(value)
}

fn read_tools_file_to_string(path: &Path) -> Result<String, ToolRegistryError> {
    let file = fs::File::open(path).map_err(|source| ToolRegistryError::Io {
        path: path.to_owned(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| ToolRegistryError::Io {
        path: path.to_owned(),
        source,
    })?;
    if metadata.len() > MAX_TOOLS_FILE_BYTES {
        return Err(tools_file_too_large(path));
    }

    let mut contents = String::new();
    let mut reader = file.take(MAX_TOOLS_FILE_BYTES + 1);
    reader
        .read_to_string(&mut contents)
        .map_err(|source| ToolRegistryError::Io {
            path: path.to_owned(),
            source,
        })?;
    if contents.len() as u64 > MAX_TOOLS_FILE_BYTES {
        return Err(tools_file_too_large(path));
    }

    Ok(contents)
}

fn tools_file_too_large(path: &Path) -> ToolRegistryError {
    ToolRegistryError::Io {
        path: path.to_owned(),
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tools file exceeds maximum size of {MAX_TOOLS_FILE_BYTES} bytes"),
        ),
    }
}

fn emit_registry_failure(audit: Option<&AuditLog>, path: &Path, error: &ToolRegistryError) {
    if let Some(audit) = audit {
        audit.emit(AuditEvent::new(
            audit::event::TOOL_REGISTRY_RELOAD_FAILED,
            "tool-registry",
            "internal",
            None,
            json!({
                "tools_file": path.display().to_string(),
                "outcome": "failure",
                "reason": error.to_string(),
            }),
        ));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        fs,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc as std_mpsc, Arc, Barrier, Mutex as StdMutex,
        },
        thread,
        time::Duration,
    };

    use jsonschema::Validator;
    use serde_json::{json, Value};

    use super::*;
    use crate::audit::sink::tests::CaptureSink;
    use crate::config::{self, AuthMode, Config};

    const BUDGET_CONNECTION_ID: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn valid_tools_file_loads_registry_and_exposes_get_and_list() {
        let file = TempToolsFile::new(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));

        let registry = ToolRegistry::from_file(file.path()).expect("tools file should load");

        let echo = registry.get("echo").expect("echo tool should exist");
        assert_eq!(echo.name, "echo");
        assert_eq!(echo.description, "Echoes the provided message.");
        assert_eq!(echo.input_schema["type"], json!("object"));
        assert_eq!(echo.upstream.method, "POST");
        assert_eq!(echo.upstream.path_template, "/v1/echo");
        assert_eq!(
            echo.upstream.body,
            Some(BodyMapping {
                mode: BodyMappingMode::WholeArgsJson,
            })
        );

        let widget = registry
            .get("get_widget")
            .expect("get_widget tool should exist");
        assert_eq!(widget.upstream.method, "GET");
        assert_eq!(widget.upstream.path_template, "/v1/widgets/{widget_id}");
        assert_eq!(
            widget.upstream.query_params,
            vec![QueryParamMapping {
                arg_name: "include_details".to_owned(),
                query_name: "include_details".to_owned(),
                required: false,
                repeated: false,
            }]
        );

        let listed: Vec<_> = registry
            .list()
            .into_iter()
            .map(|tool| tool.name.clone())
            .collect();
        assert_eq!(listed, vec!["echo".to_owned(), "get_widget".to_owned()]);
    }

    fn openapi_definition(connection_id: &str, name: &str) -> ToolDefinition {
        let mapping = json!({
            "method": "GET",
            "path_template": format!("/v1/{name}"),
            "body": { "mode": "whole_args_json" }
        });
        serde_json::from_value(json!({
            "name": name,
            "description": "A managed operation.",
            "input_json_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "target": { "type": "http", "connection_id": connection_id, "mapping": mapping },
            "source": {
                "type": "open_api",
                "connection_id": connection_id,
                "catalog_revision": 1
            },
            "upstream": mapping
        }))
        .expect("managed OpenAPI definition should deserialize")
    }

    /// Inside a pinned request, lookups read the registry state the gate
    /// pinned at admission; a lane installed afterwards is invisible to it
    /// and visible outside the pin.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn dispatch_reads_the_pinned_registry_state_not_the_live_lane() {
        let registry = ToolRegistry::from_config(&crate::config::Config::test_defaults())
            .expect("an empty registry");
        registry
            .install_local_definitions_with(vec![local_definition("alpha")], LaneConflicts::Refuse)
            .expect("the live lane installs alpha");
        let pinned = registry.state_handle().load_full();
        registry
            .install_local_definitions_with(
                vec![local_definition("alpha"), local_definition("beta")],
                LaneConflicts::Refuse,
            )
            .expect("the live lane installs beta");
        assert!(registry.get("beta").is_some(), "the live lane has beta");
        let (alpha_inside, beta_inside, listed_inside) = with_pinned_tools(pinned, async {
            (
                registry.get("alpha").is_some(),
                registry.get("beta").is_some(),
                registry.list().len(),
            )
        })
        .await;
        assert!(alpha_inside);
        assert!(
            !beta_inside,
            "a pinned request never sees a lane installed after its admission"
        );
        assert_eq!(listed_inside, 1);
        assert!(
            registry.get("beta").is_some(),
            "outside the pin the live lane is read"
        );
    }

    fn local_definition(name: &str) -> ToolDefinition {
        serde_json::from_value(json!({
            "name": name,
            "description": "A local tool.",
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
        }))
        .expect("local definition should deserialize")
    }

    /// An authoritative install evicts a stale holder of a name the
    /// authority reassigned; a request-path install still refuses it.
    #[test]
    fn an_authoritative_install_evicts_the_stale_holder_of_a_moved_name() {
        let registry = ToolRegistry::disabled();
        registry
            .install_local_definitions(vec![local_definition("shared_tool")])
            .expect("the local lane installs");

        registry
            .install_openapi_connection_catalog(
                "conn-a",
                vec![openapi_definition("conn-a", "shared_tool")],
            )
            .expect_err("a request-path install refuses a name another lane holds");

        registry
            .install_openapi_connection_catalog_with(
                "conn-a",
                vec![openapi_definition("conn-a", "shared_tool")],
                LaneConflicts::EvictStale,
            )
            .expect("the authoritative install evicts the stale local holder");
        let served = registry.get("shared_tool").expect("the name is served");
        assert!(
            matches!(&served.source, ToolSource::OpenApi { connection_id, .. } if connection_id == "conn-a"),
            "the authority's owner serves the name: {:?}",
            served.source
        );
        assert!(
            registry
                .current_local_definitions()
                .iter()
                .all(|definition| definition.name != "shared_tool"),
            "the stale local entry is gone"
        );
    }

    /// A legacy projection's MCP proxy is not reserved at the authority, so
    /// an authoritative catalog claiming its name is a collision, not
    /// staleness: the install is refused and the legacy holder stays.
    #[test]
    fn an_unreserved_legacy_holder_is_never_evicted() {
        let registry = ToolRegistry::disabled();
        registry
            .replace_local_and_legacy_mcp_definitions(
                Vec::new(),
                vec![mcp_proxy_tool(
                    "weather:get_forecast",
                    "weather",
                    "get_forecast",
                )],
            )
            .expect("the legacy proxy installs");
        let managed = ToolDefinition::mcp_connection(
            "weather".to_owned(),
            "An authoritative catalog claiming the legacy name.".to_owned(),
            json!({"type": "object", "properties": {}, "additionalProperties": false}),
            "get_forecast".to_owned(),
        );
        registry
            .install_mcp_connection_catalog_with(
                "weather",
                vec![managed],
                LaneConflicts::EvictStale,
            )
            .expect_err("a name this replica's static configuration holds is refused");
        let served = registry
            .get("weather:get_forecast")
            .expect("the legacy proxy is still served");
        assert!(
            matches!(served.source, ToolSource::Legacy),
            "the legacy holder was not rebound: {:?}",
            served.source
        );
    }

    /// A cluster-mode boot merge evicts a stale holder the same way a
    /// reconcile does, so seeds read at different revisions cannot abort
    /// startup on a name that moved between them; a standalone merge still
    /// refuses.
    #[test]
    fn a_boot_merge_can_evict_a_stale_holder_when_asked() {
        let registry = ToolRegistry::disabled();
        registry
            .install_local_definitions(vec![local_definition("moved_tool")])
            .expect("the local seed installs");
        registry
            .merge_definitions(vec![openapi_definition("conn-a", "moved_tool")])
            .expect_err("a standalone merge refuses the collision");
        registry
            .merge_definitions_with(
                vec![openapi_definition("conn-a", "moved_tool")],
                LaneConflicts::EvictStale,
            )
            .expect("a cluster boot merge evicts the stale local holder");
        assert!(matches!(
            registry.get("moved_tool").expect("served").source,
            ToolSource::OpenApi { .. }
        ));
    }

    /// Two catalogs that swapped names converge on a lagging replica in
    /// either order: each authoritative install evicts the other's stale
    /// entry, and the other's authoritative content then installs cleanly.
    #[test]
    fn swapped_names_converge_in_either_reconcile_order() {
        for first in ["conn-a", "conn-b"] {
            let registry = ToolRegistry::disabled();
            registry
                .install_openapi_connection_catalog(
                    "conn-a",
                    vec![openapi_definition("conn-a", "x")],
                )
                .expect("A holds x");
            registry
                .install_openapi_connection_catalog(
                    "conn-b",
                    vec![openapi_definition("conn-b", "y")],
                )
                .expect("B holds y");
            // At the authority the names swapped: A now holds y, B holds x.
            let (second, second_name, first_name) = if first == "conn-a" {
                ("conn-b", "x", "y")
            } else {
                ("conn-a", "y", "x")
            };
            registry
                .install_openapi_connection_catalog_with(
                    first,
                    vec![openapi_definition(first, first_name)],
                    LaneConflicts::EvictStale,
                )
                .unwrap_or_else(|error| panic!("{first} installs its new name first: {error}"));
            registry
                .install_openapi_connection_catalog_with(
                    second,
                    vec![openapi_definition(second, second_name)],
                    LaneConflicts::EvictStale,
                )
                .unwrap_or_else(|error| panic!("{second} installs after {first}: {error}"));
            for (name, owner) in [("x", "conn-b"), ("y", "conn-a")] {
                let served = registry.get(name).expect("both names are served");
                assert!(
                    matches!(&served.source, ToolSource::OpenApi { connection_id, .. } if connection_id == owner),
                    "{name} is served by {owner} after starting with {first}: {:?}",
                    served.source
                );
            }
        }
    }

    #[test]
    fn duplicate_tool_name_is_rejected_with_clear_error() {
        let file = TempToolsFile::new(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("echo", "GET", "/v1/other"),
        ]));

        let error =
            ToolRegistry::from_file(file.path()).expect_err("duplicate tool names should reject");

        assert!(
            error
                .to_string()
                .contains("duplicate tool name 'echo' at tools[1]"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn unrecognized_http_method_is_rejected() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "BREW", "/v1/echo")]));

        let error =
            ToolRegistry::from_file(file.path()).expect_err("unknown methods should reject");

        assert!(
            error
                .to_string()
                .contains("tools[0].upstream.method contains unknown HTTP method 'BREW'"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn malformed_input_schema_is_rejected_and_names_tool() {
        let tool = malformed_input_schema_tool("bad_schema", "POST", "/v1/echo");
        let file = TempToolsFile::new(&tools_document(&[tool]));

        let error = ToolRegistry::from_file(file.path())
            .expect_err("invalid input_json_schema should reject");

        let message = error.to_string();
        assert!(
            message.contains("tool 'bad_schema' input_json_schema is not a valid JSON Schema"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("not-a-json-schema-type"),
            "schema compiler error should be included: {message}"
        );
    }

    #[test]
    fn deep_input_schema_reference_chain_is_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("deep_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = deep_ref_schema(65);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("overly deep input_json_schema references should reject");

        let message = error.to_string();
        assert!(
            message.contains("tool 'deep_schema' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn deep_input_schema_anchor_reference_chain_is_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("deep_anchor_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = deep_anchor_ref_schema(65);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("overly deep anchor input_json_schema references should reject");

        let message = error.to_string();
        assert!(
            message.contains("tool 'deep_anchor_schema' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn deep_input_schema_percent_encoded_reference_chain_is_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("deep_encoded_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = deep_percent_encoded_ref_schema(65);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("overly deep percent-encoded input_json_schema references should reject");

        let message = error.to_string();
        assert!(
            message
                .contains("tool 'deep_encoded_schema' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn deep_input_schema_dynamic_anchor_reference_chain_is_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("deep_dynamic_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = deep_dynamic_anchor_ref_schema(65);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("overly deep dynamic anchor input_json_schema references should reject");

        let message = error.to_string();
        assert!(
            message
                .contains("tool 'deep_dynamic_schema' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn unevaluated_reference_cycle_through_a_nested_resource_compiles_without_overflowing() {
        // The precheck follows only local `#` references, so a cycle back to
        // the root's `$id` from a nested resource reaches the compiler.
        // jsonschema 0.58.6 overflowed the stack, aborting the process, while
        // it compiled such a schema beside `unevaluated*`; 0.60.2 compiles it.
        for keyword in ["unevaluatedProperties", "unevaluatedItems"] {
            let mut tool = echo_tool("cyclic_schema", "POST", "/v1/echo");
            tool["input_json_schema"] = json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://schemas.example.test/echo",
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": { "type": "string" },
                    "include_details": { "type": "boolean" }
                },
                "anyOf": [{
                    "$id": "https://schemas.example.test/echo-branch",
                    "$ref": "https://schemas.example.test/echo",
                    keyword: false
                }],
                keyword: { "type": "boolean" }
            });

            ToolRegistry::from_json_value(json!({
                "schema_version": "0.1.0",
                "tools": [tool]
            }))
            .unwrap_or_else(|error| panic!("{keyword} cycle should compile: {error}"));
        }
    }

    #[test]
    fn duplicate_input_schema_anchor_names_are_rejected_before_jsonschema_compile() {
        let mut tool = echo_tool("duplicate_anchor_schema", "POST", "/v1/echo");
        tool["input_json_schema"] = duplicate_anchor_schema();

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("duplicate local anchor names should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'duplicate_anchor_schema' input_json_schema contains duplicate local schema anchor 'S0'"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn anchor_like_literal_schema_data_does_not_create_duplicate_anchor_rejection() {
        let mut tool = echo_tool("literal_anchor_data", "POST", "/v1/echo");
        tool["input_json_schema"] = literal_anchor_data_schema();

        ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect("literal data containing repeated $anchor keys should not count as schema anchors");
    }

    #[test]
    fn input_schema_numbers_too_wide_to_compare_exactly_are_rejected_before_jsonschema_compile() {
        for limit in [
            r#"{"type": "number", "minimum": 1e-99999}"#.to_owned(),
            format!(r#"{{"enum": [{}]}}"#, ["1e400"; 7].join(", ")),
        ] {
            let mut tool = echo_tool("wide_schema", "POST", "/v1/echo");
            tool["input_json_schema"]["properties"]["count"] =
                serde_json::from_str(&limit).expect("test schema fragment should parse");

            let error = ToolRegistry::from_json_value(json!({
                "schema_version": "0.1.0",
                "tools": [tool]
            }))
            .expect_err("schema numbers too wide to compare exactly should reject");

            let message = error.to_string();
            assert!(
                message.contains(
                    "tool 'wide_schema' input_json_schema contains numbers that would cost more to compare exactly than one 1024-digit number"
                ),
                "unexpected error for {limit}: {message}"
            );
        }
    }

    #[test]
    fn input_schema_numbers_beyond_f64_within_the_exact_comparison_budget_load() {
        let mut tool = echo_tool("beyond_f64_schema", "POST", "/v1/echo");
        tool["input_json_schema"]["properties"]["count"] = serde_json::from_str(
            r#"{"type": "integer", "maximum": 1e400, "multipleOf": 18446744073709551616}"#,
        )
        .expect("test schema fragment should parse");

        ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect("numbers beyond f64 inside the exact comparison budget should load");
    }

    #[test]
    fn exact_comparison_budget_charges_wide_numbers_by_their_squared_span() {
        assert_eq!(number_digit_span("1e400"), 401);
        assert_eq!(number_digit_span("-1.5E-400"), 402);
        assert_eq!(number_digit_span("-0.05"), 3);
        assert_eq!(number_digit_span("18446744073709551615"), 20);
        assert_eq!(number_digit_span("1e99999999999999999999999"), u64::MAX);

        let parse =
            |text: &str| serde_json::from_str::<Value>(text).expect("test JSON should parse");
        // One number may be exactly as wide as the budget, and no wider.
        assert!(!numbers_exceed_exact_comparison_budget(&parse(&format!(
            "[1{}]",
            "7".repeat(1_023)
        ))));
        assert!(numbers_exceed_exact_comparison_budget(&parse(&format!(
            "[1{}]",
            "7".repeat(1_024)
        ))));
        // The budget is shared: six 401-digit numbers fit and a seventh, even
        // nested elsewhere in the document, does not.
        let six = ["1e400"; 6].join(", ");
        assert!(!numbers_exceed_exact_comparison_budget(&parse(&format!(
            "[{six}]"
        ))));
        assert!(numbers_exceed_exact_comparison_budget(&parse(&format!(
            r#"{{"values": [{six}], "nested": {{"value": -1e400}}}}"#
        ))));
        // A few bytes of exponent are as wide as the value they write.
        assert!(numbers_exceed_exact_comparison_budget(&parse("1e-99999")));
        // Numbers no wider than u64::MAX are never charged, however many.
        assert!(!numbers_exceed_exact_comparison_budget(&parse(&format!(
            "[{}]",
            std::iter::repeat_n("18446744073709551615", 10_000)
                .collect::<Vec<_>>()
                .join(", ")
        ))));
    }

    #[test]
    fn schema_named_like_literal_keyword_is_still_traversed() {
        let mut tool = echo_tool("schema_named_default", "POST", "/v1/echo");
        tool["input_json_schema"] = schema_named_like_literal_keyword();

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("subschema named like a literal keyword should still be traversed");

        let message = error.to_string();
        assert!(
            message
                .contains("tool 'schema_named_default' input_json_schema reference depth exceeds"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn aggregate_input_schema_precheck_budget_is_shared_across_tools() {
        let tool_count =
            MAX_REGISTRY_INPUT_SCHEMA_PRECHECK_NODES / MAX_INPUT_SCHEMA_PRECHECK_NODES + 1;
        let definitions = (0..tool_count)
            .map(|index| {
                ToolDefinition::mcp_connection(
                    BUDGET_CONNECTION_ID.to_owned(),
                    format!("Budget tool {index}."),
                    schema_with_precheck_nodes(MAX_INPUT_SCHEMA_PRECHECK_NODES),
                    format!("budget_{index}"),
                )
            })
            .collect::<Vec<_>>();

        let registry = ToolRegistry::disabled();
        let error = registry
            .replace_mcp_connection_catalog(BUDGET_CONNECTION_ID, definitions, || {
                Ok::<(), Infallible>(())
            })
            .expect_err("registry-wide input_json_schema precheck budget should reject");

        let McpCatalogPublishError::Registry(ToolRegistryError::Invalid { problems }) = error
        else {
            panic!("budget exhaustion should return ToolRegistryError::Invalid");
        };
        let message = problems.join("; ");
        assert!(
            message.contains("input_json_schema") && message.contains("across the tool registry"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn one_oversized_input_schema_exceeds_the_per_tool_precheck_budget() {
        let registry = ToolRegistry::disabled();
        let error = registry
            .replace_mcp_connection_catalog(
                BUDGET_CONNECTION_ID,
                vec![ToolDefinition::mcp_connection(
                    BUDGET_CONNECTION_ID.to_owned(),
                    "Oversized schema tool.".to_owned(),
                    schema_with_precheck_nodes(MAX_INPUT_SCHEMA_PRECHECK_NODES + 1),
                    "oversized".to_owned(),
                )],
                || Ok::<(), Infallible>(()),
            )
            .expect_err("a single oversized schema should still reject");

        let McpCatalogPublishError::Registry(ToolRegistryError::Invalid { problems }) = error
        else {
            panic!("budget exhaustion should return ToolRegistryError::Invalid");
        };
        let message = problems.join("; ");
        assert!(
            message.contains("input_json_schema") && message.contains("for one tool"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn a_large_managed_mcp_catalog_of_ordinary_tools_publishes() {
        // A catalog this size is well inside the discovery and catalog-entry
        // limits, so the precheck must not be what rejects it.
        let catalog_size = 250;
        let definitions = (0..catalog_size)
            .map(|index| {
                ToolDefinition::mcp_connection(
                    BUDGET_CONNECTION_ID.to_owned(),
                    format!("Ordinary managed MCP tool {index}."),
                    object_schema_with_properties(8),
                    format!("ordinary_{index}"),
                )
            })
            .collect::<Vec<_>>();

        let registry = ToolRegistry::disabled();
        registry
            .replace_mcp_connection_catalog(BUDGET_CONNECTION_ID, definitions, || {
                Ok::<(), Infallible>(())
            })
            .expect("an ordinary large managed MCP catalog should publish");
        assert_eq!(registry.list().len(), catalog_size);
    }

    #[test]
    fn reasonable_multi_tool_input_schemas_stay_within_precheck_budget() {
        let tools = (0..3)
            .map(|index| {
                let mut tool = echo_tool(
                    &format!("reasonable_schema_{index}"),
                    "POST",
                    &format!("/v1/reasonable-schema/{index}"),
                );
                tool["input_json_schema"] = object_schema_with_properties(8);
                tool
            })
            .collect::<Vec<_>>();

        ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": tools
        }))
        .expect("reasonable multi-tool schemas should stay within the shared precheck budget");
    }

    #[test]
    fn semantic_validation_reports_all_tool_definition_problems() {
        let file = TempToolsFile::new(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("echo", "BREW", "/v1/other"),
        ]));

        let error = ToolRegistry::from_file(file.path())
            .expect_err("multiple semantic problems should reject");
        let ToolRegistryError::Invalid { problems } = error else {
            panic!("semantic problems should return ToolRegistryError::Invalid");
        };

        assert_eq!(problems.len(), 2, "unexpected problems: {problems:?}");
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("duplicate tool name 'echo' at tools[1]")),
            "duplicate tool name problem missing: {problems:?}"
        );
        assert!(
            problems.iter().any(|problem| {
                problem.contains("tools[1].upstream.method contains unknown HTTP method 'BREW'")
            }),
            "unknown HTTP method problem missing: {problems:?}"
        );
    }

    #[test]
    fn input_schema_without_properties_is_rejected_at_load_time() {
        let mut tool = echo_tool("properties_less", "GET", "/v1/widgets/{widget_id}");
        tool["input_json_schema"] = json!({
            "type": "object"
        });
        let file = TempToolsFile::new(&tools_document(&[tool]));

        let error = ToolRegistry::from_file(file.path())
            .expect_err("properties-less input_json_schema should reject");
        let ToolRegistryError::Invalid { problems } = error else {
            panic!("properties-less input_json_schema should fail schema validation");
        };
        let message = problems.join("; ");

        assert!(
            message.contains("/tools/0/input_json_schema"),
            "schema error should identify the tool input schema path: {message}"
        );
        assert!(
            message.contains("properties"),
            "schema error should mention the missing properties key: {message}"
        );
    }

    #[test]
    fn path_placeholder_missing_from_required_is_rejected_at_load_time() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}");
        tool["input_json_schema"] = json!({
            "type": "object",
            "required": ["message"],
            "properties": {
                "message": { "type": "string" },
                "widget_id": { "type": "string" }
            },
            "additionalProperties": false
        });

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("path placeholders missing from required should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'get_widget' path_template placeholder 'widget_id' must be listed in input_json_schema.required"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn required_query_mapping_missing_from_required_is_rejected_at_load_time() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets");
        tool["upstream"]["query_params"][0]["required"] = json!(true);

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("required query mappings missing from required should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'get_widget' required query argument 'include_details' must be listed in input_json_schema.required"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn path_mapped_argument_with_object_schema_is_rejected_at_load_time() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}");
        tool["input_json_schema"] = json!({
            "type": "object",
            "required": ["message", "widget_id"],
            "properties": {
                "message": { "type": "string" },
                "widget_id": { "type": "object" }
            },
            "additionalProperties": false
        });

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("path mapped object arguments should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'get_widget' path argument 'widget_id' must be constrained to scalar JSON Schema types"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn query_mapped_argument_with_array_schema_is_rejected_at_load_time() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets");
        tool["input_json_schema"]["properties"]["include_details"] = json!({ "type": "array" });

        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect_err("query mapped array arguments should reject");

        let message = error.to_string();
        assert!(
            message.contains(
                "tool 'get_widget' query argument 'include_details' must be constrained to scalar JSON Schema types"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn repeated_query_mappings_require_a_homogeneous_scalar_array() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets");
        tool["upstream"]["query_params"][0]["repeated"] = json!(true);
        for invalid in [
            json!({"type": "string"}),
            json!({"type": "array"}),
            json!({"type": "array", "items": {"type": ["string", "null"]}}),
            json!({"type": "array", "items": {"type": "object"}}),
            json!({"type": "array", "items": {"type": "string"}, "prefixItems": [{}]}),
        ] {
            tool["input_json_schema"]["properties"]["include_details"] = invalid;
            let definition: ToolDefinition =
                serde_json::from_value(tool.clone()).expect("typed tool");
            assert!(tool_definition_problems(&[definition])
                .iter()
                .any(|problem| problem.contains("must be an array of scalar JSON Schema types")));
        }
    }

    #[test]
    fn optional_query_params_may_remain_optional_when_mapped_schemas_are_scalar() {
        let mut tool = echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}");
        tool["input_json_schema"] = json!({
            "type": "object",
            "required": ["message", "widget_id"],
            "properties": {
                "message": { "type": "string" },
                "widget_id": { "type": "integer" },
                "include_details": { "type": ["boolean", "string"] }
            },
            "additionalProperties": false
        });

        ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect("optional query mappings with scalar schemas should load");
    }

    /// Required authority evidence refuses a standalone tools file reload
    /// (issue #425, PR 4) and keeps the registry; best effort reloads it.
    #[tokio::test]
    async fn required_authority_evidence_refuses_a_tools_file_reload_and_keeps_the_registry() {
        use crate::{
            authority_events::required::{AuthorityEvidenceGate, BackgroundEvidenceGate},
            config::{AuthorityEvidenceDurability, StateBackend},
        };

        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));
        let capture = CaptureSink::new();
        let audit = AuditLog::new(std::sync::Arc::new(capture.clone()));
        let required = BackgroundEvidenceGate::new(
            AuthorityEvidenceGate::new(AuthorityEvidenceDurability::Required, StateBackend::Sqlite),
            audit.clone(),
        );

        assert!(
            !reload_tools_file_if_admitted(&registry, file.path(), None, Some(&required), "signal")
                .await
        );
        assert!(registry.get("get_widget").is_none());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let refusal = loop {
            if let Some(event) = capture.events().into_iter().find(|event| {
                event.event_type == audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED
            }) {
                break event;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the refusal is audited"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(refusal.payload["operation"], json!("tools.publish"));
        assert_eq!(refusal.payload["trigger"], json!("signal"));

        let best_effort = BackgroundEvidenceGate::new(AuthorityEvidenceGate::best_effort(), audit);
        assert!(
            reload_tools_file_if_admitted(
                &registry,
                file.path(),
                None,
                Some(&best_effort),
                "file_watch"
            )
            .await
        );
        assert!(registry.get("get_widget").is_some());
    }

    #[tokio::test]
    async fn file_watch_reload_applies_valid_tools_update() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        assert!(registry.get("get_widget").is_none());

        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));

        wait_until(Duration::from_secs(5), || {
            registry.get("get_widget").is_some()
        })
        .await;
    }

    #[tokio::test]
    async fn file_watch_reload_preserves_merged_mcp_proxy_tools() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));

        wait_until(Duration::from_secs(5), || {
            registry.get("get_widget").is_some()
        })
        .await;
        let mcp_tool = registry
            .get("weather:get_forecast")
            .expect("local reload must preserve merged MCP proxy tool");
        assert_eq!(
            mcp_tool.upstream.mcp_proxy_mapping().unwrap().server_name,
            "weather"
        );
    }

    #[tokio::test]
    async fn file_watch_reload_updates_local_tools_when_mcp_proxy_tools_are_present() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        file.write(&tools_document(&[echo_tool(
            "get_widget",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        wait_until(Duration::from_secs(5), || {
            registry.get("echo").is_none() && registry.get("get_widget").is_some()
        })
        .await;
        assert!(registry.get("weather:get_forecast").is_some());
    }

    #[test]
    fn reload_rejects_local_tool_colliding_with_preserved_mcp_proxy_tool_name() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather.get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");

        file.write(&tools_document(&[echo_tool(
            "weather.get_forecast",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        let error = reload_tool_registry_from_file(&registry, file.path())
            .expect_err("local collision with preserved MCP proxy name should reject");
        assert!(
            error
                .to_string()
                .contains("duplicate tool name 'weather.get_forecast'"),
            "unexpected error: {error}"
        );
        assert!(registry.get("echo").is_some());
        let mcp_tool = registry
            .get("weather.get_forecast")
            .expect("rejected reload must keep existing MCP proxy tool");
        assert!(
            mcp_tool.upstream.is_mcp_proxy(),
            "collision must not replace MCP proxy tool with local HTTP tool"
        );
        assert_eq!(
            registry.list().len(),
            2,
            "rejected collision reload must keep last-known-good registry"
        );
    }

    #[test]
    fn refreshed_mcp_proxy_reload_prunes_missing_proxy_tools_and_keeps_local_tools() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![
                mcp_proxy_tool("weather:get_forecast", "weather", "get_forecast"),
                mcp_proxy_tool("weather:get_alerts", "weather", "get_alerts"),
            ])
            .expect("MCP proxy tools should merge");

        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}"),
        ]));

        reload_tool_registry_from_file_with_mcp_proxy_definitions(
            &registry,
            file.path(),
            vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )],
        )
        .expect("refreshed MCP proxy reload should apply");

        assert!(registry.get("echo").is_some());
        assert!(registry.get("get_widget").is_some());
        assert!(registry.get("weather:get_forecast").is_some());
        assert!(
            registry.get("weather:get_alerts").is_none(),
            "refreshed MCP proxy set should prune missing proxy tools"
        );
        assert_eq!(registry.list().len(), 3);
    }

    #[test]
    fn managed_mcp_catalog_publish_is_atomic_and_legacy_reload_preserves_it() {
        let connection_id = "11111111-1111-4111-8111-111111111111";
        let registry = ToolRegistry::disabled();
        registry
            .merge_definitions(vec![ToolDefinition::mcp_connection(
                connection_id.to_owned(),
                "Original managed tool".to_owned(),
                json!({"type": "object", "properties": {}}),
                "alpha".to_owned(),
            )])
            .expect("managed MCP tool should merge");

        let mut persisted = false;
        let result = registry.replace_mcp_connection_catalog(
            connection_id,
            vec![ToolDefinition::mcp_connection(
                connection_id.to_owned(),
                "Invalid replacement".to_owned(),
                json!({"type": 7}),
                "beta".to_owned(),
            )],
            || {
                persisted = true;
                Ok::<(), ()>(())
            },
        );
        assert!(matches!(result, Err(McpCatalogPublishError::Registry(_))));
        assert!(!persisted, "invalid candidate must not reach persistence");
        assert!(registry.get(&format!("{connection_id}:alpha")).is_some());
        assert!(registry.get(&format!("{connection_id}:beta")).is_none());

        registry
            .replace_openapi_connection_catalog(
                "billing-api",
                vec![openapi_connection_tool(
                    "billing-api",
                    "billing_get",
                    "/v1/billing",
                )],
                || Ok::<(), ()>(()),
            )
            .expect("managed OpenAPI catalog should publish");
        registry
            .replace_local_and_legacy_mcp_definitions(
                Vec::new(),
                vec![mcp_proxy_tool(
                    "weather:get_forecast",
                    "weather",
                    "get_forecast",
                )],
            )
            .expect("legacy MCP refresh should publish");
        assert!(registry.get("weather:get_forecast").is_some());
        assert!(
            registry.get(&format!("{connection_id}:alpha")).is_some(),
            "legacy rediscovery must retain managed MCP catalogs"
        );
        assert!(
            registry.get("billing_get").is_some(),
            "legacy MCP rediscovery must retain managed OpenAPI catalogs"
        );
    }

    #[test]
    fn managed_openapi_catalog_collision_rejects_before_persist() {
        let connection_id = "billing-api";
        let registry = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [echo_tool("shared_name", "POST", "/v1/echo")]
        }))
        .expect("local registry should load");
        let persisted = Arc::new(AtomicBool::new(false));
        let persisted_in_callback = Arc::clone(&persisted);

        let result = registry.replace_openapi_connection_catalog(
            connection_id,
            vec![openapi_connection_tool(
                connection_id,
                "shared_name",
                "/v1/shared",
            )],
            move || {
                persisted_in_callback.store(true, Ordering::SeqCst);
                Ok::<(), ()>(())
            },
        );

        assert!(matches!(result, Err(McpCatalogPublishError::Registry(_))));
        assert!(
            !persisted.load(Ordering::SeqCst),
            "a colliding catalog must not reach persistence"
        );
        assert_eq!(
            registry
                .get("shared_name")
                .expect("local tool must remain active")
                .source,
            ToolSource::Legacy
        );
    }

    #[test]
    fn managed_openapi_catalog_requires_matching_connection_and_revision() {
        let registry = ToolRegistry::disabled();
        let persisted = Arc::new(AtomicBool::new(false));

        let mut missing_revision =
            openapi_connection_tool("billing-api", "billing_get", "/v1/billing");
        let ToolSource::OpenApi {
            catalog_revision, ..
        } = &mut missing_revision.source
        else {
            panic!("test helper must create an OpenAPI source");
        };
        *catalog_revision = None;
        let persisted_in_callback = Arc::clone(&persisted);
        let result = registry.replace_openapi_connection_catalog(
            "billing-api",
            vec![missing_revision],
            move || {
                persisted_in_callback.store(true, Ordering::SeqCst);
                Ok::<(), ()>(())
            },
        );
        assert!(matches!(result, Err(McpCatalogPublishError::Registry(_))));

        let wrong_connection =
            openapi_connection_tool("inventory-api", "inventory_get", "/v1/inventory");
        let persisted_in_callback = Arc::clone(&persisted);
        let result = registry.replace_openapi_connection_catalog(
            "billing-api",
            vec![wrong_connection],
            move || {
                persisted_in_callback.store(true, Ordering::SeqCst);
                Ok::<(), ()>(())
            },
        );
        assert!(matches!(result, Err(McpCatalogPublishError::Registry(_))));
        assert!(
            !persisted.load(Ordering::SeqCst),
            "invalid managed provenance must reject before persistence"
        );
        assert!(registry.list().is_empty());
    }

    #[test]
    fn managed_openapi_catalog_persist_failure_keeps_last_known_good_state() {
        let connection_id = "billing-api";
        let registry = ToolRegistry::disabled();
        registry
            .replace_openapi_connection_catalog(
                connection_id,
                vec![openapi_connection_tool(
                    connection_id,
                    "billing_old",
                    "/v1/old",
                )],
                || Ok::<(), ()>(()),
            )
            .expect("initial managed OpenAPI catalog should publish");

        let result = registry.replace_openapi_connection_catalog(
            connection_id,
            vec![openapi_connection_tool(
                connection_id,
                "billing_new",
                "/v1/new",
            )],
            || Err::<(), _>("disk unavailable"),
        );

        assert!(matches!(result, Err(McpCatalogPublishError::Persist(_))));
        assert!(registry.get("billing_old").is_some());
        assert!(registry.get("billing_new").is_none());
    }

    #[test]
    fn managed_openapi_catalog_replacement_prunes_only_same_connection() {
        let registry = ToolRegistry::disabled();
        registry
            .replace_openapi_connection_catalog(
                "billing-api",
                vec![
                    openapi_connection_tool("billing-api", "billing_old", "/v1/old"),
                    openapi_connection_tool("billing-api", "billing_other", "/v1/other"),
                ],
                || Ok::<(), ()>(()),
            )
            .expect("billing catalog should publish");
        registry
            .replace_openapi_connection_catalog(
                "inventory-api",
                vec![openapi_connection_tool(
                    "inventory-api",
                    "inventory_get",
                    "/v1/inventory",
                )],
                || Ok::<(), ()>(()),
            )
            .expect("inventory catalog should publish");

        registry
            .replace_openapi_connection_catalog(
                "billing-api",
                vec![openapi_connection_tool(
                    "billing-api",
                    "billing_new",
                    "/v2/new",
                )],
                || Ok::<(), ()>(()),
            )
            .expect("billing replacement should publish");

        assert!(registry.get("billing_old").is_none());
        assert!(registry.get("billing_other").is_none());
        assert!(registry.get("billing_new").is_some());
        assert!(
            registry.get("inventory_get").is_some(),
            "replacing billing must preserve the inventory catalog"
        );
    }

    #[test]
    fn concurrent_openapi_catalog_replacements_for_different_connections_lose_nothing() {
        const CONNECTION_COUNT: usize = 32;

        let registry = Arc::new(ToolRegistry::disabled());
        let barrier = Arc::new(Barrier::new(CONNECTION_COUNT));
        let handles = (0..CONNECTION_COUNT)
            .map(|index| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let connection_id = format!("api-{index}");
                    let tool_name = format!("api_{index}_get");
                    barrier.wait();
                    registry
                        .replace_openapi_connection_catalog(
                            &connection_id,
                            vec![openapi_connection_tool(
                                &connection_id,
                                &tool_name,
                                &format!("/v1/{index}"),
                            )],
                            || Ok::<(), ()>(()),
                        )
                        .expect("concurrent catalog should publish");
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.join().expect("catalog publisher should not panic");
        }
        for index in 0..CONNECTION_COUNT {
            assert!(
                registry.get(&format!("api_{index}_get")).is_some(),
                "catalog for api-{index} was lost"
            );
        }
        assert_eq!(registry.list().len(), CONNECTION_COUNT);
    }

    #[test]
    fn file_reload_preserves_managed_openapi_catalog() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .replace_openapi_connection_catalog(
                "billing-api",
                vec![openapi_connection_tool(
                    "billing-api",
                    "billing_get",
                    "/v1/billing",
                )],
                || Ok::<(), ()>(()),
            )
            .expect("managed catalog should publish");
        file.write(&tools_document(&[echo_tool(
            "get_widget",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        reload_tool_registry_from_file(&registry, file.path())
            .expect("local tools-file reload should publish");

        assert!(registry.get("echo").is_none());
        assert!(registry.get("get_widget").is_some());
        assert!(
            registry.get("billing_get").is_some(),
            "local reload must preserve managed OpenAPI tools"
        );
    }

    #[test]
    fn local_atomic_replace_validates_managed_collisions_before_persist() {
        let registry = ToolRegistry::disabled();
        registry
            .replace_openapi_connection_catalog(
                "billing-api",
                vec![openapi_connection_tool(
                    "billing-api",
                    "reserved_name",
                    "/v1/billing",
                )],
                || Ok::<(), ()>(()),
            )
            .expect("managed catalog should publish");
        let persisted = Arc::new(AtomicBool::new(false));
        let persisted_in_callback = Arc::clone(&persisted);

        let result = registry.replace_local_definitions_with_persist(
            vec![local_http_tool("reserved_name", "/v1/local")],
            move || {
                persisted_in_callback.store(true, Ordering::SeqCst);
                Ok::<(), ()>(())
            },
        );

        assert!(matches!(result, Err(McpCatalogPublishError::Registry(_))));
        assert!(
            !persisted.load(Ordering::SeqCst),
            "a local collision must reject before writing TOOLS_FILE"
        );
        assert!(matches!(
            registry
                .get("reserved_name")
                .expect("managed tool must remain active")
                .source,
            ToolSource::OpenApi { .. }
        ));
    }

    #[test]
    fn local_atomic_replace_preserves_managed_lanes_and_rejects_spoofed_provenance() {
        let registry = ToolRegistry::disabled();
        registry
            .replace_openapi_connection_catalog(
                "billing-api",
                vec![openapi_connection_tool(
                    "billing-api",
                    "billing_get",
                    "/v1/billing",
                )],
                || Ok::<(), ()>(()),
            )
            .expect("managed OpenAPI catalog should publish");
        registry
            .replace_mcp_connection_catalog(
                "11111111-1111-4111-8111-111111111111",
                vec![ToolDefinition::mcp_connection(
                    "11111111-1111-4111-8111-111111111111".to_owned(),
                    "Managed MCP tool".to_owned(),
                    json!({"type": "object", "properties": {}}),
                    "alpha".to_owned(),
                )],
                || Ok::<(), ()>(()),
            )
            .expect("managed MCP catalog should publish");

        registry
            .replace_local_definitions_with_persist(
                vec![local_http_tool("legacy_registered", "/v1/legacy")],
                || Ok::<(), ()>(()),
            )
            .expect("legacy OpenAPI registration should publish local tools");
        assert!(registry.get("legacy_registered").is_some());
        assert!(registry.get("billing_get").is_some());
        assert!(registry
            .get("11111111-1111-4111-8111-111111111111:alpha")
            .is_some());

        let spoof = openapi_connection_tool("attacker-api", "spoofed", "/v1/spoofed");
        let result =
            registry.replace_local_definitions_with_persist(vec![spoof], || Ok::<(), ()>(()));
        assert!(matches!(result, Err(McpCatalogPublishError::Registry(_))));
        assert!(registry.get("spoofed").is_none());
        assert!(registry.get("legacy_registered").is_some());
    }

    #[test]
    fn refreshed_mcp_proxy_reload_rejects_collision_and_keeps_last_known_good_registry() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");

        let error = reload_tool_registry_from_file_with_mcp_proxy_definitions(
            &registry,
            file.path(),
            vec![mcp_proxy_tool("echo", "weather", "echo")],
        )
        .expect_err("refreshed MCP proxy collision should reject");

        assert!(
            error.to_string().contains("duplicate tool name 'echo'"),
            "unexpected error: {error}"
        );
        let local_tool = registry
            .get("echo")
            .expect("rejected refresh must keep local tool");
        assert!(
            !local_tool.upstream.is_mcp_proxy(),
            "collision must not replace local HTTP tool with MCP proxy tool"
        );
        assert!(registry.get("weather:get_forecast").is_some());
        assert_eq!(
            registry.list().len(),
            2,
            "rejected refreshed reload must keep last-known-good registry"
        );
    }

    #[tokio::test]
    async fn provider_backed_reload_keeps_the_async_runtime_serving_during_rediscovery() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");

        // The provider stands in for upstream MCP discovery, which blocks for
        // as long as the remote server takes. It only completes once another
        // task on the same runtime has been polled.
        let (release_sender, release_receiver) = std_mpsc::channel::<()>();
        let release_receiver = StdMutex::new(release_receiver);
        let runtime_kept_serving = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&runtime_kept_serving);
        let blocking_provider: McpProxyDefinitionsProvider = Arc::new(move || {
            let released = release_receiver
                .lock()
                .expect("release receiver should lock")
                .recv_timeout(Duration::from_secs(2))
                .is_ok();
            observed.store(released, Ordering::SeqCst);
            None
        });
        let concurrent = tokio::spawn(async move {
            tokio::task::yield_now().await;
            let _ = release_sender.send(());
        });

        reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
            &registry,
            file.path(),
            Some(&blocking_provider),
        )
        .await
        .expect("local reload should apply once rediscovery returns");
        concurrent.await.expect("concurrent task should not panic");

        assert!(
            runtime_kept_serving.load(Ordering::SeqCst),
            "MCP upstream rediscovery must not park the Tokio worker; no other task on the runtime was polled while it ran"
        );
    }

    #[tokio::test]
    async fn provider_backed_reload_preserves_mcp_proxy_tools_when_refresh_is_unavailable() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![
                mcp_proxy_tool("weather:get_forecast", "weather", "get_forecast"),
                mcp_proxy_tool("weather:get_alerts", "weather", "get_alerts"),
            ])
            .expect("MCP proxy tools should merge");
        let unavailable_provider: McpProxyDefinitionsProvider = Arc::new(|| None);

        file.write(&tools_document(&[echo_tool(
            "get_widget",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
            &registry,
            file.path(),
            Some(&unavailable_provider),
        )
        .await
        .expect("local reload should still apply when MCP proxy refresh is unavailable");

        assert!(registry.get("echo").is_none());
        assert!(registry.get("get_widget").is_some());
        assert!(registry.get("weather:get_forecast").is_some());
        assert!(registry.get("weather:get_alerts").is_some());
        assert_eq!(registry.list().len(), 3);
    }

    #[test]
    fn reload_rejects_colon_namespaced_local_tool_name_without_replacing_mcp_proxy_tool() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");

        file.write(&tools_document(&[echo_tool(
            "weather:get_forecast",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        let error = reload_tool_registry_from_file(&registry, file.path())
            .expect_err("colon namespaced local tool names should reject");
        assert!(
            error.to_string().contains("/tools/0/name"),
            "unexpected error: {error}"
        );
        assert!(registry.get("echo").is_some());
        let mcp_tool = registry
            .get("weather:get_forecast")
            .expect("schema-rejected reload must keep existing MCP proxy tool");
        assert!(
            mcp_tool.upstream.is_mcp_proxy(),
            "schema rejection must not replace MCP proxy tool with local HTTP tool"
        );
    }

    #[test]
    fn reload_rejects_invalid_tool_mapping_without_replacing_existing_registry() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let registry = ToolRegistry::from_file(file.path()).expect("initial registry should load");
        let mut invalid_tool = echo_tool("get_widget", "GET", "/v1/widgets/{widget_id}");
        invalid_tool["input_json_schema"] = json!({
            "type": "object",
            "required": ["message"],
            "properties": {
                "message": { "type": "string" },
                "widget_id": { "type": "string" },
                "include_details": { "type": "boolean" }
            },
            "additionalProperties": false
        });

        file.write(&tools_document(&[invalid_tool]));

        let error = reload_tool_registry_from_file(&registry, file.path())
            .expect_err("invalid path mapping should reject reload");
        assert!(
            error.to_string().contains(
                "tool 'get_widget' path_template placeholder 'widget_id' must be listed in input_json_schema.required"
            ),
            "unexpected error: {error}"
        );
        assert!(registry.get("echo").is_some());
        assert!(registry.get("get_widget").is_none());
        assert_eq!(
            registry.list().len(),
            1,
            "mapping validation failure must keep last-known-good registry"
        );
    }

    #[tokio::test]
    async fn file_watch_invalid_update_keeps_local_and_mcp_proxy_tools() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let capture = CaptureSink::new();
        let audit_log = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let registry = ToolRegistry::from_file_with_audit(file.path(), audit_log)
            .expect("initial registry should load");
        registry
            .merge_definitions(vec![mcp_proxy_tool(
                "weather:get_forecast",
                "weather",
                "get_forecast",
            )])
            .expect("MCP proxy tool should merge");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        let failure_count = audit_event_count(&capture, audit::event::TOOL_REGISTRY_RELOAD_FAILED);
        file.write(&tools_document(&[
            echo_tool("echo", "POST", "/v1/echo"),
            echo_tool("echo", "GET", "/v1/other"),
        ]));

        wait_until(Duration::from_secs(5), || {
            audit_event_count(&capture, audit::event::TOOL_REGISTRY_RELOAD_FAILED) > failure_count
        })
        .await;

        assert!(registry.get("echo").is_some());
        assert!(registry.get("weather:get_forecast").is_some());
        assert_eq!(
            registry.list().len(),
            2,
            "invalid watched reload must keep local and MCP proxy tools"
        );
    }

    #[tokio::test]
    async fn file_watch_invalid_updates_keep_old_registry_and_accept_later_valid_update() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let capture = CaptureSink::new();
        let audit_log = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let registry = ToolRegistry::from_file_with_audit(file.path(), audit_log)
            .expect("initial registry should load");
        spawn_tool_registry_reload_tasks(file.path().to_owned(), registry.clone())
            .expect("tool registry watcher should start");

        for invalid_update in [
            r#"{ "schema_version": "#.to_owned(),
            tools_document(&[
                echo_tool("echo", "POST", "/v1/echo"),
                echo_tool("echo", "GET", "/v1/other"),
            ]),
            tools_document(&[echo_tool("get_widget", "BREW", "/v1/widgets/{widget_id}")]),
            tools_document(&[malformed_input_schema_tool(
                "bad_schema",
                "POST",
                "/v1/echo",
            )]),
        ] {
            let failure_count =
                audit_event_count(&capture, audit::event::TOOL_REGISTRY_RELOAD_FAILED);

            file.write(&invalid_update);

            wait_until(Duration::from_secs(5), || {
                audit_event_count(&capture, audit::event::TOOL_REGISTRY_RELOAD_FAILED)
                    > failure_count
            })
            .await;

            assert!(
                registry.get("echo").is_some(),
                "invalid watched reload must keep last-known-good registry"
            );
            assert!(
                registry.get("get_widget").is_none(),
                "invalid watched reload must not partially apply"
            );
            assert_eq!(
                registry.list().len(),
                1,
                "invalid watched reload must not change tool count"
            );
        }

        file.write(&tools_document(&[echo_tool(
            "get_widget",
            "GET",
            "/v1/widgets/{widget_id}",
        )]));

        wait_until(Duration::from_secs(5), || registry.get("echo").is_none()).await;
        assert!(registry.get("get_widget").is_some());
    }

    #[test]
    fn from_config_returns_disabled_empty_registry_when_tools_file_unset() {
        let config = test_config(None);

        let registry =
            ToolRegistry::from_config(&config).expect("unset TOOLS_FILE should not error");

        assert!(registry.get("anything").is_none());
        assert!(registry.list().is_empty());
    }

    #[test]
    fn from_config_with_audit_returns_disabled_empty_registry_when_tools_file_unset() {
        let config = test_config(None);
        let capture = CaptureSink::new();
        let audit_log = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);

        let registry = ToolRegistry::from_config_with_audit(&config, audit_log)
            .expect("unset TOOLS_FILE should not error");

        assert!(registry.get("anything").is_none());
        assert!(registry.list().is_empty());
        assert_eq!(
            capture.len(),
            0,
            "unset TOOLS_FILE should not emit load events"
        );
    }

    #[test]
    fn from_config_loads_registry_when_tools_file_is_set() {
        let file = TempToolsFile::new(&tools_document(&[echo_tool("echo", "POST", "/v1/echo")]));
        let config = test_config(Some(file.path().to_string_lossy().into_owned()));

        let registry = ToolRegistry::from_config(&config).expect("TOOLS_FILE should load");

        assert!(registry.get("echo").is_some());
    }

    #[test]
    fn published_schema_accepts_valid_tools_file() {
        let validator = tools_schema_validator();
        let document = json!({
            "schema_version": "0.1.0",
            "tools": [
                {
                    "name": "echo",
                    "description": "Echoes the provided message.",
                    "input_json_schema": {
                        "type": "object",
                        "required": ["message"],
                        "properties": {
                            "message": { "type": "string" }
                        },
                        "additionalProperties": false
                    },
                    "upstream": {
                        "method": "POST",
                        "path_template": "/v1/echo",
                        "body": { "mode": "whole_args_json" }
                    }
                }
            ]
        });

        assert_schema_accepts(&validator, &document);
        ToolRegistry::from_json_value(document).expect("schema-valid tools should parse");
    }

    #[test]
    fn response_only_transform_installs_on_a_get_without_a_request_body() {
        let document = json!({
            "schema_version": "0.1.0",
            "tools": [{
                "name": "find_company",
                "description": "Find one company.",
                "input_json_schema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                },
                "upstream": {
                    "method": "GET",
                    "path_template": "/companies/current"
                },
                "transform": {
                    "response_fields": [{
                        "wire_property": "financials",
                        "agent": [{
                            "name": "amount",
                            "schema": {"type":"number"}
                        }],
                        "wire": [{
                            "pointer": "/amountMicros",
                            "from": "amount",
                            "codec": [{
                                "kind": "decimal_scale",
                                "scale": 6,
                                "wire_encoding": "integer_string"
                            }]
                        }],
                        "response": [{
                            "agent_property": "amount",
                            "from": "/amountMicros",
                            "codec": [{
                                "kind": "decimal_scale",
                                "scale": 6,
                                "wire_encoding": "integer_string"
                            }]
                        }]
                    }],
                    "response_root": "/data/company"
                }
            }]
        });

        assert_schema_accepts(&tools_schema_validator(), &document);
        let registry = ToolRegistry::from_json_value(document)
            .expect("response-only transforms must not require a request body");
        assert!(registry
            .get("find_company")
            .expect("tool should install")
            .transform
            .is_some());
    }

    #[test]
    fn absent_transform_keeps_legacy_definition_serialization_unchanged() {
        let definition = local_http_tool("legacy", "/legacy");
        let value = serde_json::to_value(definition).expect("definition should serialize");
        assert!(value.get("transform").is_none());
    }

    #[test]
    fn tools_file_rejects_spoofed_managed_openapi_provenance() {
        let mapping = json!({
            "method": "POST",
            "path_template": "/v1/echo",
            "body": { "mode": "whole_args_json" }
        });
        let document = json!({
            "schema_version": "0.1.0",
            "tools": [
                {
                    "name": "echo",
                    "description": "Echoes the provided message.",
                    "input_json_schema": {
                        "type": "object",
                        "properties": {
                            "message": { "type": "string" }
                        },
                        "additionalProperties": false
                    },
                    "target": {
                        "type": "http",
                        "connection_id": "billing-api",
                        "mapping": mapping
                    },
                    "source": {
                        "type": "open_api",
                        "connection_id": "billing-api",
                        "operation_id": "echoMessage"
                    },
                    "upstream": mapping
                }
            ]
        });

        assert_schema_accepts(&tools_schema_validator(), &document);
        let error = ToolRegistry::from_json_value(document)
            .expect_err("TOOLS_FILE must not claim managed OpenAPI provenance");
        assert!(
            error
                .to_string()
                .contains("must not claim managed OpenAPI provenance"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn legacy_tools_omit_typed_metadata_when_serialized() {
        let registry = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [echo_tool("echo", "POST", "/v1/echo")]
        }))
        .expect("legacy tool should parse");
        let serialized =
            serde_json::to_value(registry.get("echo").expect("tool should exist").as_ref())
                .expect("tool should serialize");

        assert!(serialized.get("target").is_none());
        assert!(serialized.get("source").is_none());
        assert!(serialized.get("upstream").is_some());
        assert!(serialized.get("composite").is_none());
        assert!(serialized.get("enum_bindings").is_none());
        assert!(serialized.get("title").is_none());
        assert!(serialized.get("annotations").is_none());
        assert_eq!(
            serialized,
            echo_tool("echo", "POST", "/v1/echo"),
            "adding optional MCP metadata must not change legacy definition bytes or digests"
        );
    }

    #[test]
    fn composite_definition_requires_the_exact_non_network_sentinel() {
        let value = json!({
            "name": "create_note_for_records",
            "description": "Create and attach a note.",
            "input_json_schema": {
                "type": "object",
                "properties": { "title": { "type": "string" } },
                "required": ["title"],
                "additionalProperties": false
            },
            "target": { "type": "composite", "connection_id": "crm" },
            "source": {
                "type": "open_api",
                "connection_id": "crm",
                "catalog_revision": 1
            },
            "upstream": { "method": "COMPOSITE", "path_template": "/" },
            "composite": {
                "steps": [{
                    "id": "create",
                    "tool": "createOneNote",
                    "arguments": { "title": { "$input": "title" } }
                }]
            }
        });
        let definition: ToolDefinition =
            serde_json::from_value(value.clone()).expect("composite model deserializes");
        assert!(tool_definition_problems(&[definition]).is_empty());
        assert_schema_accepts(
            &tools_schema_validator(),
            &json!({ "schema_version": "0.1.0", "tools": [value.clone()] }),
        );

        for malformed in [
            json!({ "method": "COMPOSITE", "path_template": "/network" }),
            json!({
                "method": "COMPOSITE",
                "path_template": "/",
                "query_params": [{ "arg_name": "x", "query_name": "x" }]
            }),
            json!({
                "method": "COMPOSITE",
                "path_template": "/",
                "body": { "mode": "whole_args_json" }
            }),
        ] {
            let mut candidate = value.clone();
            candidate["upstream"] = malformed;
            let definition: ToolDefinition =
                serde_json::from_value(candidate).expect("typed model retains semantic checks");
            let problems = tool_definition_problems(&[definition]);
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.contains("exact COMPOSITE")
                        || problem.contains("COMPOSITE sentinel")),
                "unexpected problems: {problems:?}"
            );
        }
    }

    #[test]
    fn dynamic_enum_binding_schema_and_stored_value_boundary_are_enforced() {
        let digest = "a".repeat(64);
        let mut tool = echo_tool("echo", "POST", "/v1/echo");
        tool["input_json_schema"]["properties"]["status"] = json!({"type": "string"});
        tool["enum_bindings"] = json!([{
            "property": "status",
            "source_id": "company_status",
            "source_digest": digest
        }]);
        let document = json!({"schema_version": "0.1.0", "tools": [tool]});
        assert_schema_accepts(&tools_schema_validator(), &document);
        let registry = ToolRegistry::from_json_value(document)
            .expect("a stable binding without current values should install");
        assert_eq!(
            registry.get("echo").expect("tool").enum_bindings,
            vec![EnumBinding {
                property: "status".to_owned(),
                source_id: "company_status".to_owned(),
                source_digest: "a".repeat(64),
            }]
        );

        let mut with_values = echo_tool("echo", "POST", "/v1/echo");
        with_values["input_json_schema"]["properties"]["status"] =
            json!({"type": "string", "enum": ["CURRENT"]});
        with_values["enum_bindings"] = json!([{
            "property": "status",
            "source_id": "company_status",
            "source_digest": "b".repeat(64)
        }]);
        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [with_values]
        }))
        .expect_err("current values must not enter the stored definition");
        assert!(error.to_string().contains("must not persist enum values"));

        let mut numeric = echo_tool("echo", "POST", "/v1/echo");
        numeric["input_json_schema"]["properties"]["status"] = json!({"type": "number"});
        numeric["enum_bindings"] = json!([{
            "property": "status",
            "source_id": "company_status",
            "source_digest": "c".repeat(64)
        }]);
        let error = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [numeric]
        }))
        .expect_err("numeric dynamic enums are never accepted");
        assert!(error.to_string().contains("type string or boolean"));
    }

    #[test]
    fn typed_metadata_cannot_disagree_with_legacy_execution_mapping() {
        let mut tool = echo_tool("echo", "POST", "/v1/echo");
        tool["target"] = json!({
            "type": "http",
            "connection_id": "billing-api",
            "mapping": {
                "method": "GET",
                "path_template": "/different"
            }
        });
        let document = json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        });

        let error = ToolRegistry::from_json_value(document)
            .expect_err("conflicting compatibility mappings must fail");
        assert!(error
            .to_string()
            .contains("target.mapping must equal the legacy upstream mapping"));
    }

    #[test]
    fn typed_http_target_rejects_authority_and_path_confusion_without_tightening_legacy() {
        for path_template in [
            "//attacker.example.test/resource",
            "/v1\\admin",
            "/v1/../admin",
            "/v1/%2e%2e/admin",
            "/v1/%2fadmin",
        ] {
            let mut typed = echo_tool("echo", "POST", path_template);
            typed["target"] = json!({
                "type": "http",
                "connection_id": "billing-api",
                "mapping": typed["upstream"].clone()
            });
            let error = ToolRegistry::from_json_value(json!({
                "schema_version": "0.1.0",
                "tools": [typed]
            }))
            .expect_err("typed unsafe mapping must fail");
            let message = error.to_string();
            assert!(
                message.contains("target.mapping.path_template")
                    || message.contains("tools file schema validation failed"),
                "unexpected error for {path_template}: {error}"
            );

            ToolRegistry::from_json_value(json!({
                "schema_version": "0.1.0",
                "tools": [echo_tool("echo", "POST", path_template)]
            }))
            .expect("legacy-only mapping behavior must remain unchanged");
        }
    }

    #[test]
    fn starter_and_dev_tools_files_parse_and_match_published_schema() {
        for path in [
            repo_root().join("docs/examples/tools.starter.json"),
            repo_root().join("dev/tools.json"),
        ] {
            let registry = ToolRegistry::from_file(&path)
                .unwrap_or_else(|err| panic!("{} should parse: {err}", path.display()));
            assert!(
                !registry.list().is_empty(),
                "{} should include at least one example tool",
                path.display()
            );

            let contents = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
            let value: Value = serde_json::from_str(&contents)
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));
            assert_schema_accepts(&tools_schema_validator(), &value);
        }
    }

    #[test]
    fn oversized_tools_file_is_rejected_with_clear_error() {
        let file = TempToolsFile::new(&" ".repeat(1_048_577));

        let error =
            ToolRegistry::from_file(file.path()).expect_err("oversized tools file should reject");
        let message = error.to_string();

        assert!(
            message.contains("tools file exceeds maximum size of 1048576 bytes"),
            "unexpected error: {message}"
        );
    }

    fn tools_document(tools: &[Value]) -> String {
        serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "tools": tools
        }))
        .expect("test tools document should serialize")
    }

    fn echo_tool(name: &str, method: &str, path_template: &str) -> Value {
        let mut tool = json!({
            "name": name,
            "description": "Echoes the provided message.",
            "input_json_schema": {
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": { "type": "string" },
                    "include_details": { "type": "boolean" }
                },
                "additionalProperties": false
            },
            "upstream": {
                "method": method,
                "path_template": path_template,
                "query_params": [
                    {
                        "arg_name": "include_details",
                        "query_name": "include_details",
                        "required": false
                    }
                ],
                "body": {
                    "mode": "whole_args_json"
                }
            }
        });

        if path_template.contains("{widget_id}") {
            tool["input_json_schema"]["required"] = json!(["message", "widget_id"]);
            tool["input_json_schema"]["properties"]["widget_id"] = json!({ "type": "string" });
        }

        tool
    }

    fn local_http_tool(name: &str, path_template: &str) -> ToolDefinition {
        let mapping = HttpToolMapping {
            method: "GET".to_owned(),
            path_template: path_template.to_owned(),
            query_params: Vec::new(),
            body: None,
        };
        ToolDefinition {
            name: name.to_owned(),
            title: None,
            description: format!("Local tool {name}"),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            target: None,
            source: ToolSource::Legacy,
            upstream: mapping,
            composite: None,
            visibility: ToolVisibility::Listed,
            transform: None,
            enum_bindings: Vec::new(),
            annotations: None,
        }
    }

    fn openapi_connection_tool(
        connection_id: &str,
        name: &str,
        path_template: &str,
    ) -> ToolDefinition {
        let mapping = HttpToolMapping {
            method: "GET".to_owned(),
            path_template: path_template.to_owned(),
            query_params: Vec::new(),
            body: None,
        };
        ToolDefinition {
            name: name.to_owned(),
            title: None,
            description: format!("Managed OpenAPI tool {name}"),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            target: Some(ToolTarget::Http {
                connection_id: connection_id.to_owned(),
                mapping: mapping.clone(),
            }),
            source: ToolSource::OpenApi {
                connection_id: connection_id.to_owned(),
                operation_id: Some(name.to_owned()),
                catalog_revision: Some(1),
            },
            upstream: mapping,
            composite: None,
            visibility: ToolVisibility::Listed,
            transform: None,
            enum_bindings: Vec::new(),
            annotations: None,
        }
    }

    fn malformed_input_schema_tool(name: &str, method: &str, path_template: &str) -> Value {
        let mut tool = echo_tool(name, method, path_template);
        tool["input_json_schema"] = json!({
            "type": "not-a-json-schema-type",
            "properties": {}
        });
        tool
    }

    fn deep_ref_schema(depth: usize) -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..depth {
            defs.insert(
                format!("S{index}"),
                json!({ "$ref": format!("#/$defs/S{}", index + 1) }),
            );
        }
        defs.insert(format!("S{depth}"), json!({ "type": "string" }));

        json!({
            "$ref": "#/$defs/S0",
            "properties": {},
            "$defs": defs
        })
    }

    fn deep_anchor_ref_schema(depth: usize) -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..depth {
            defs.insert(
                format!("S{index}"),
                json!({
                    "$anchor": format!("S{index}"),
                    "$ref": format!("#S{}", index + 1)
                }),
            );
        }
        defs.insert(
            format!("S{depth}"),
            json!({
                "$anchor": format!("S{depth}"),
                "type": "string"
            }),
        );

        json!({
            "$ref": "#S0",
            "properties": {},
            "$defs": defs
        })
    }

    fn deep_dynamic_anchor_ref_schema(depth: usize) -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..depth {
            defs.insert(
                format!("S{index}"),
                json!({
                    "$dynamicAnchor": format!("S{index}"),
                    "$dynamicRef": format!("#S{}", index + 1)
                }),
            );
        }
        defs.insert(
            format!("S{depth}"),
            json!({
                "$dynamicAnchor": format!("S{depth}"),
                "type": "string"
            }),
        );

        json!({
            "$dynamicRef": "#S0",
            "properties": {},
            "$defs": defs
        })
    }

    fn deep_percent_encoded_ref_schema(depth: usize) -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..depth {
            defs.insert(
                format!("S{index}"),
                json!({ "$ref": format!("#/%24defs/S{}", index + 1) }),
            );
        }
        defs.insert(format!("S{depth}"), json!({ "type": "string" }));

        json!({
            "$ref": "#/%24defs/S0",
            "properties": {},
            "$defs": defs
        })
    }

    fn literal_anchor_data_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "const_value": {
                    "const": { "$anchor": "literal" }
                },
                "default_value": {
                    "type": "object",
                    "default": { "$anchor": "literal" }
                },
                "example_value": {
                    "type": "object",
                    "examples": [{ "$anchor": "literal" }]
                },
                "include_details": {
                    "type": "boolean"
                }
            },
            "additionalProperties": false
        })
    }

    fn schema_named_like_literal_keyword() -> Value {
        let mut defs = serde_json::Map::new();
        for index in 0..65 {
            defs.insert(
                format!("S{index}"),
                json!({ "$ref": format!("#/$defs/S{}", index + 1) }),
            );
        }
        defs.insert("S65".to_owned(), json!({ "type": "string" }));

        json!({
            "type": "object",
            "properties": {
                "default": {
                    "$ref": "#/$defs/S0"
                }
            },
            "$defs": defs,
            "additionalProperties": false
        })
    }

    fn duplicate_anchor_schema() -> Value {
        json!({
            "$ref": "#S0",
            "properties": {},
            "$defs": {
                "first": {
                    "$anchor": "S0",
                    "type": "string"
                },
                "second": {
                    "$anchor": "S0",
                    "$ref": "#/$defs/second"
                }
            }
        })
    }

    /// Builds a schema whose precheck traversal visits exactly `node_count`
    /// values, using annotation entries so the cost lands on the walker rather
    /// than on JSON Schema compilation.
    fn schema_with_precheck_nodes(node_count: usize) -> Value {
        // The walker charges the root, the three keyword values, and every
        // annotation element.
        let annotation_count = node_count.saturating_sub(4);
        json!({
            "type": "object",
            "properties": {},
            "examples": (0..annotation_count).collect::<Vec<_>>()
        })
    }

    fn object_schema_with_properties(property_count: usize) -> Value {
        let mut properties = (0..property_count)
            .map(|index| (format!("field_{index}"), json!({ "type": "string" })))
            .collect::<serde_json::Map<_, _>>();
        properties.insert("include_details".to_owned(), json!({ "type": "boolean" }));

        json!({
            "type": "object",
            "properties": properties,
            "additionalProperties": false
        })
    }

    fn mcp_proxy_tool(name: &str, server_name: &str, tool_name: &str) -> ToolDefinition {
        ToolDefinition::mcp_proxy(
            name.to_owned(),
            "Gets the forecast from an upstream MCP server.".to_owned(),
            json!({
                "type": "object",
                "properties": {
                    "city": { "type": "string" }
                },
                "additionalProperties": false
            }),
            server_name.to_owned(),
            tool_name.to_owned(),
        )
    }

    fn tools_schema_validator() -> Validator {
        let schema_path = repo_root().join("docs/schemas/tools.v0.schema.json");
        let schema = fs::read_to_string(&schema_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", schema_path.display()));
        let schema = serde_json::from_str(&schema)
            .unwrap_or_else(|err| panic!("failed to parse {}: {err}", schema_path.display()));

        jsonschema::validator_for(&schema)
            .unwrap_or_else(|err| panic!("failed to compile {}: {err}", schema_path.display()))
    }

    fn assert_schema_accepts(validator: &Validator, value: &Value) {
        if let Err(error) = validator.validate(value) {
            panic!("published schema should accept tools document: {error}");
        }
    }

    fn audit_event_count(capture: &CaptureSink, event_type: &str) -> usize {
        capture
            .events()
            .iter()
            .filter(|event| event.event_type == event_type)
            .count()
    }

    async fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
        let started = std::time::Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("gateway crate should live directly under the repo root")
            .to_owned()
    }

    fn test_config(tools_file: Option<String>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            grpc_listen_addr: None,
            grpc_max_concurrent_streams: crate::config::DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
            grpc_max_metadata_bytes: crate::config::DEFAULT_GRPC_MAX_METADATA_BYTES,
            tls_cert_files: None,
            tls_key_files: None,
            admin_tls_cert_files: None,
            admin_tls_key_files: None,
            tls_min_version: crate::config::DEFAULT_TLS_MIN_VERSION,
            tls_handshake_timeout_ms: crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
            tls_max_concurrent_handshakes: crate::config::DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
            client_cert_auth: None,
            admin_client_cert_auth: None,
            admin_prefix: "/admin".to_owned(),
            admin_login_provider: None,
            admin_session: None,
            admin_login_pending_ttl_secs: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
            admin_login_pending_max_entries: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            admin_login_pending_max_per_ip: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
            admin_login_keyring: Vec::new(),
            rate_limit_keyring: Vec::new(),
            gateway_public_url: None,
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            audit_successful_probes_metrics_only: false,
            shutdown_drain_delay_ms: config::DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
            shutdown_timeout_ms: config::DEFAULT_SHUTDOWN_TIMEOUT_MS,
            audit_drain_timeout_ms: config::DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
            audit_durability: config::DEFAULT_AUDIT_DURABILITY,
            audit_durability_timeout_ms: config::DEFAULT_AUDIT_DURABILITY_TIMEOUT_MS,
            discovery_sqlite_path: None,
            discovery_endpoint_limit: config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            discovery_projector_lease_ttl_ms: config::DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS,
            discovery_projector_poll_ms: config::DEFAULT_DISCOVERY_PROJECTOR_POLL_MS,
            discovery_projector_batch: config::DEFAULT_DISCOVERY_PROJECTOR_BATCH,
            principal_sqlite_path: None,
            connections_sqlite_path: None,
            connection_local_secret_keyring: Vec::new(),
            connection_vault_provider:
                crate::connections::vault_secret::VaultProviderConfig::default(),
            connection_gcp_provider: crate::connections::gcp_secret::GcpProviderConfig::default(),
            connection_azure_provider:
                crate::connections::azure_secret::AzureProviderConfig::default(),
            connection_aws_provider: crate::connections::aws_secret::AwsProviderConfig::default(),
            connection_kubernetes_provider:
                crate::connections::kubernetes_secret::KubernetesProviderConfig::default(),
            connection_secret_aliases: Vec::new(),
            connection_secrets_root: None,
            payload_capture_enabled: false,
            payload_capture_sample_rate: config::DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
            schema_mismatch_signal_threshold:
                crate::discovery::signals::DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            error_rate_spike_signal_threshold:
                crate::discovery::signals::DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            principal_new_to_endpoint_signal_threshold:
                crate::discovery::signals::DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            volume_outlier_signal_threshold:
                crate::discovery::signals::DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
            rule_suggestion_baseline_window_hours:
                crate::discovery::suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            openapi_spec_path: None,
            policy_file: None,
            tools_file,
            policy_history_sqlite_path: None,
            policy_tests_required: false,
            cors_allow_origins: Vec::new(),
            max_body_size: 1_048_576,
            max_request_path_bytes: crate::config::DEFAULT_MAX_REQUEST_PATH_BYTES,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            rate_limit_max_buckets: crate::config::DEFAULT_RATE_LIMIT_MAX_BUCKETS,
            rate_limit_bucket_ttl_ms: crate::config::DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: Vec::new(),
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            validation_allowed_content_types: vec!["application/json".to_owned()],
            auth_enabled: true,
            auth_mode: AuthMode::Required,
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            auth_providers: Vec::new(),
            jwt_jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_jwks_max_key_age_secs: 300,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            service_token_sqlite_path: None,
            service_token_cache_ttl_ms: config::DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            tool_runtime_queue_depth: config::DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            tool_runtime_global_concurrency: config::DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            tool_runtime_queue_timeout_ms: config::DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            tool_lease_ttl_ms: config::DEFAULT_TOOL_LEASE_TTL_MS,
            cluster_heartbeat_ms: config::DEFAULT_CLUSTER_HEARTBEAT_MS,
            cluster_member_stale_ms: config::DEFAULT_CLUSTER_MEMBER_STALE_MS,
            cluster_maintenance_interval_ms: config::DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS,
            cluster_maintenance_lease_ttl_ms: config::DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS,
            readiness_probe_cache_ms: config::DEFAULT_READINESS_PROBE_CACHE_MS,
            cluster_status_expose_hostnames: false,
            audit_postgres_retention_days: None,
            authority_events: Default::default(),
            tool_runtime_default_timeout_ms: config::DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
            csrf_enabled: true,
            csrf_cookie_name: "csrf_token".to_owned(),
            csrf_header_name: "x-csrf-token".to_owned(),
            csrf_cookie_domain: None,
            csrf_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            upstream_url: None,
            upstream_routes: Vec::new(),
            mcp_upstream_servers: Vec::new(),
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_nat64_prefixes: Vec::new(),
            egress_deny_private_ips: true,
            state_backend: crate::config::StateBackend::Sqlite,
            deployment_id: None,
            database: crate::config::DatabaseSettings::default(),
        }
    }

    struct TempToolsFile {
        path: PathBuf,
    }

    impl TempToolsFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-tools-test-{}-{}.json",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, contents: &str) {
            fs::write(&self.path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", self.path.display()));
        }
    }

    impl Drop for TempToolsFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
