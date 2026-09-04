use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    auth::Principal,
    connections::{
        control_plane::{ConnectionControlPlane, ConnectionRuntimeSnapshot},
        model::{ConnectionId, ConnectionKind, ConnectionManagementSource},
        projection::projected_legacy_mcp_connection_id,
        status::{ConnectionOperationalState, ConnectionStatusReason, SafeConnectionStatus},
        store::{
            ConnectionStoreError, StoredMcpCatalog, StoredMcpCatalogEntry,
            StoredOpenApiCatalogEntry, StoredOpenApiInventoryCatalog,
        },
    },
    middleware::rbac::RbacState,
};

use super::definitions::{
    BodyMapping, HttpToolMapping, QueryParamMapping, ToolAnnotations, ToolDefinition, ToolRegistry,
    ToolSource, ToolTarget, ToolVisibility,
};
use super::enum_source::{EnumSourceRuntime, EnumSourceState};
use super::transforms::{ParameterShape, ToolTransform, WireSource};

pub const DEFAULT_CAPABILITY_LIST_LIMIT: usize = 50;
pub const MAX_CAPABILITY_LIST_LIMIT: usize = 100;
pub const MAX_CAPABILITY_INVENTORY_ENTRIES: usize = 8_192;
pub const MAX_CAPABILITY_LIST_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_CAPABILITY_DETAIL_RESPONSE_BYTES: usize = 2 * 1_048_576;

const MAX_CURSOR_BYTES: usize = 4_096;
const MAX_TEXT_FILTER_CHARS: usize = 128;
const MAX_TEXT_FILTER_BYTES: usize = 512;
const MAX_PUBLIC_DESCRIPTION_CHARS: usize = 1_024;
const CAPABILITY_ID_PREFIX: &str = "cap_";
const CAPABILITY_ID_HEX_BYTES: usize = 64;
const CAPABILITY_EXECUTION_ETAG_DOMAIN: &str = "greengateway-capability-execution-v1";

#[derive(Clone)]
pub struct CapabilityInventory {
    registry: ToolRegistry,
    control_plane: ConnectionControlPlane,
    enum_source_runtime: Option<EnumSourceRuntime>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Tool,
    Resource,
    ResourceTemplate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySourceFilter {
    #[serde(alias = "local_file")]
    ManualFile,
    Openapi,
    McpDiscovery,
    #[serde(alias = "legacy_config")]
    ProjectedLegacyConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAvailabilityFilter {
    Available,
    Unavailable,
    Stale,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityListParams {
    pub kind: Option<CapabilityKind>,
    #[serde(alias = "connection")]
    pub connection_id: Option<String>,
    pub source: Option<CapabilitySourceFilter>,
    pub available: Option<bool>,
    pub availability: Option<CapabilityAvailabilityFilter>,
    pub text: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CapabilitySource {
    ManualFile,
    Openapi {
        connection_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        operation_id: Option<String>,
        catalog_revision: u64,
        spec_revision: u64,
        spec_digest: String,
    },
    McpDiscovery {
        connection_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        remote_tool_name: Option<String>,
    },
    ProjectedLegacyConfig {
        connection_id: String,
        remote_tool_name: String,
    },
}

impl CapabilitySource {
    fn filter(&self) -> CapabilitySourceFilter {
        match self {
            Self::ManualFile => CapabilitySourceFilter::ManualFile,
            Self::Openapi { .. } => CapabilitySourceFilter::Openapi,
            Self::McpDiscovery { .. } => CapabilitySourceFilter::McpDiscovery,
            Self::ProjectedLegacyConfig { .. } => CapabilitySourceFilter::ProjectedLegacyConfig,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityConnection {
    pub id: ConnectionId,
    pub kind: ConnectionKind,
    pub management_source: ConnectionManagementSource,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityState {
    pub enabled: bool,
    pub available: bool,
    pub stale: bool,
    pub reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicyEligibility {
    pub eligible: bool,
    pub reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySummary {
    pub id: String,
    pub kind: CapabilityKind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub description_truncated: bool,
    pub source: CapabilitySource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<CapabilityConnection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<String>,
    /// Omitted for ordinary listed tools and all non-tool capabilities.  A
    /// composite-only tool remains visible to administrators even though it
    /// is hidden from agent discovery and direct calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<ToolVisibility>,
    pub state: CapabilityState,
    pub policy: CapabilityPolicyEligibility,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCompositeStep {
    pub id: String,
    pub tool: String,
    pub method: String,
    pub path_template: String,
    pub has_compensation: bool,
    pub for_each: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CapabilityMapping {
    Http {
        method: String,
        path_template: String,
        query_params: Vec<QueryParamMapping>,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<BodyMapping>,
    },
    Mcp {
        remote_tool_name: String,
    },
    Composite {
        steps: Vec<CapabilityCompositeStep>,
    },
    Resource {
        uri: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        size: Option<u64>,
    },
    ResourceTemplate {
        uri_template: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDetail {
    #[serde(flatten)]
    pub summary: CapabilitySummary,
    #[serde(rename = "input_json_schema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping: Option<CapabilityMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<CapabilityTransformSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dynamic_enums: Vec<CapabilityDynamicEnum>,
    pub actions: CapabilityActions,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDynamicEnum {
    pub property: String,
    pub source_id: String,
    pub state: EnumSourceState,
    pub item_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityTransformSummary {
    pub parameters: Vec<CapabilityTransformShapeSummary>,
    pub response_fields: Vec<CapabilityTransformShapeSummary>,
    pub has_response_root: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityTransformShapeSummary {
    pub wire_property: String,
    pub agent_properties: Vec<String>,
    pub wire_pointer_count: usize,
    pub response_properties: Vec<String>,
    pub constant_binding_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityActions {
    pub can_execute: bool,
    pub reason: &'static str,
}

#[derive(Clone, Debug)]
pub struct CapabilityDetailResult {
    pub detail: CapabilityDetail,
    execution_etag: String,
}

impl CapabilityDetailResult {
    pub fn execution_etag(&self) -> &str {
        &self.execution_etag
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityListPage {
    pub capabilities: Vec<CapabilitySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub total_count: usize,
    #[serde(skip)]
    collection_etag: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapabilityInventoryError {
    InvalidLimit,
    InvalidFilter,
    InvalidCursor,
    StaleCursor { current_etag: String },
    StoreUnavailable,
    CardinalityExceeded,
    ResponseTooLarge,
    IdentityCollision,
    CorruptState,
}

#[derive(Clone)]
struct BuiltCapability {
    summary: CapabilitySummary,
    input_schema: Option<Value>,
    mapping: Option<CapabilityMapping>,
    transform: Option<CapabilityTransformSummary>,
    dynamic_enums: Vec<CapabilityDynamicEnum>,
    registered_definition: Option<ToolDefinition>,
    execution_revision: Option<CapabilityExecutionRevision>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CapabilityExecutionRevision {
    Manual {
        #[serde(skip_serializing_if = "Option::is_none")]
        connection_etag: Option<String>,
    },
    Openapi {
        connection_etag: String,
        catalog_revision: u64,
        spec_revision: u64,
        spec_digest: String,
    },
    Mcp {
        connection_etag: String,
        catalog_revision: u64,
    },
}

#[derive(Clone)]
struct ConnectionContext {
    reference: CapabilityConnection,
    enabled: bool,
    etag: Option<String>,
    status: Option<SafeConnectionStatus>,
}

#[derive(Clone, Copy)]
enum DurableToolCatalog<'a> {
    Openapi {
        catalog: &'a StoredOpenApiInventoryCatalog,
        entry: &'a StoredOpenApiCatalogEntry,
    },
    Mcp {
        catalog: &'a StoredMcpCatalog,
        entry: &'a StoredMcpCatalogEntry,
    },
}

type ManagedInventory = (
    Vec<StoredMcpCatalog>,
    Vec<StoredOpenApiInventoryCatalog>,
    BTreeMap<ConnectionId, SafeConnectionStatus>,
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityCursor {
    after_id: String,
    collection_etag: String,
    filters: NormalizedFilters,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalizedFilters {
    kind: Option<CapabilityKind>,
    connection_id: Option<String>,
    source: Option<CapabilitySourceFilter>,
    available: Option<bool>,
    availability: Option<CapabilityAvailabilityFilter>,
    text: Option<String>,
}

impl CapabilityInventory {
    pub fn new(registry: ToolRegistry, control_plane: ConnectionControlPlane) -> Self {
        Self {
            registry,
            control_plane,
            enum_source_runtime: None,
        }
    }

    pub fn with_enum_source_runtime(
        mut self,
        enum_source_runtime: Option<EnumSourceRuntime>,
    ) -> Self {
        self.enum_source_runtime = enum_source_runtime;
        self
    }

    pub async fn list(
        &self,
        rbac_state: &RbacState,
        principal: &Principal,
        params: &CapabilityListParams,
    ) -> Result<CapabilityListPage, CapabilityInventoryError> {
        let limit = params.limit.unwrap_or(DEFAULT_CAPABILITY_LIST_LIMIT);
        if limit == 0 || limit > MAX_CAPABILITY_LIST_LIMIT {
            return Err(CapabilityInventoryError::InvalidLimit);
        }
        let filters = normalize_filters(params)?;
        let cursor = params.cursor.as_deref().map(decode_cursor).transpose()?;
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.filters != filters)
        {
            return Err(CapabilityInventoryError::InvalidCursor);
        }

        let mut capabilities = self.build(rbac_state, principal).await?;
        capabilities.sort_by(|left, right| left.summary.id.cmp(&right.summary.id));
        let collection_etag = collection_etag(&capabilities)?;
        if let Some(cursor) = cursor.as_ref() {
            if cursor.collection_etag != collection_etag {
                return Err(CapabilityInventoryError::StaleCursor {
                    current_etag: collection_etag,
                });
            }
        }

        let filtered = capabilities
            .into_iter()
            .filter(|capability| matches_filters(&capability.summary, &filters))
            .collect::<Vec<_>>();
        let total_count = filtered.len();
        let mut remaining = filtered
            .into_iter()
            .filter(|capability| {
                cursor
                    .as_ref()
                    .is_none_or(|cursor| capability.summary.id > cursor.after_id)
            })
            .collect::<Vec<_>>();
        let remaining_count = remaining.len();
        if remaining.len() > limit {
            remaining.truncate(limit);
        }

        let mut summaries = remaining
            .into_iter()
            .map(|capability| capability.summary)
            .collect::<Vec<_>>();
        loop {
            let consumed = summaries.len();
            let has_more = remaining_count > consumed;
            let next_cursor = if has_more {
                summaries
                    .last()
                    .map(|summary| {
                        encode_cursor(&CapabilityCursor {
                            after_id: summary.id.clone(),
                            collection_etag: collection_etag.clone(),
                            filters: filters.clone(),
                        })
                    })
                    .transpose()?
            } else {
                None
            };
            let page = CapabilityListPage {
                capabilities: summaries.clone(),
                next_cursor,
                total_count,
                collection_etag: collection_etag.clone(),
            };
            if serialized_len(&page)? <= MAX_CAPABILITY_LIST_RESPONSE_BYTES {
                return Ok(page);
            }
            if summaries.pop().is_none() {
                return Err(CapabilityInventoryError::ResponseTooLarge);
            }
        }
    }

    pub async fn detail(
        &self,
        rbac_state: &RbacState,
        principal: &Principal,
        raw_id: &str,
        has_execute_permission: bool,
        executor_available: bool,
    ) -> Result<Option<CapabilityDetailResult>, CapabilityInventoryError> {
        if !valid_capability_id(raw_id) {
            return Ok(None);
        }
        let Some(capability) = self
            .build(rbac_state, principal)
            .await?
            .into_iter()
            .find(|capability| capability.summary.id == raw_id)
        else {
            return Ok(None);
        };
        let result =
            capability_detail_result(capability, has_execute_permission, executor_available)?;
        let detail = &result.detail;
        if serialized_len(&detail)? > MAX_CAPABILITY_DETAIL_RESPONSE_BYTES {
            return Err(CapabilityInventoryError::ResponseTooLarge);
        }
        Ok(Some(result))
    }

    /// Resolves an opaque capability ID only against the active registry.
    ///
    /// This deliberately avoids connection, catalog, status, secret-provider,
    /// DNS, and upstream reads so an admin execution request can complete its
    /// authorization and normal tool-policy gates before reading target state.
    pub fn registered_tool(&self, raw_id: &str) -> Option<Arc<ToolDefinition>> {
        if !valid_capability_id(raw_id) {
            return None;
        }
        self.registry
            .list()
            .into_iter()
            .find(|definition| capability_id(&["tool", definition.name.as_str()]) == raw_id)
    }

    /// Recomputes the current execution validator for one exact registry
    /// definition. Callers must invoke this only after normal tool-policy,
    /// schema, mapping, and direct-rule authorization.
    pub async fn execution_etag_for_definition(
        &self,
        rbac_state: &RbacState,
        principal: &Principal,
        definition: &ToolDefinition,
    ) -> Result<Option<String>, CapabilityInventoryError> {
        let expected_id = capability_id(&["tool", definition.name.as_str()]);
        let Some(capability) = self
            .build(rbac_state, principal)
            .await?
            .into_iter()
            .find(|capability| capability.summary.id == expected_id)
        else {
            return Ok(None);
        };
        if capability.registered_definition.as_ref() != Some(definition) {
            return Ok(None);
        }
        let result = capability_detail_result(capability, true, true)?;
        if !result.detail.actions.can_execute {
            return Ok(None);
        }
        Ok(Some(result.execution_etag))
    }

    pub async fn connection_counts(
        &self,
        rbac_state: &RbacState,
        principal: &Principal,
    ) -> Result<BTreeMap<ConnectionId, usize>, CapabilityInventoryError> {
        Ok(connection_counts_from_capabilities(
            self.build(rbac_state, principal).await?,
        ))
    }

    async fn build(
        &self,
        rbac_state: &RbacState,
        principal: &Principal,
    ) -> Result<Vec<BuiltCapability>, CapabilityInventoryError> {
        let snapshot = self.control_plane.runtime_snapshot();
        let (mcp_catalogs, openapi_catalogs, statuses) =
            self.load_managed_inventory(&snapshot).await?;
        let connections = connection_contexts(&snapshot, &statuses);
        let registry = self
            .registry
            .list()
            .into_iter()
            .map(|definition| (definition.name.clone(), definition))
            .collect::<BTreeMap<_, _>>();
        let durable_tools = durable_tool_catalogs(&mcp_catalogs, &openapi_catalogs)?;
        let mut mapping_definitions = registry
            .iter()
            .map(|(name, definition)| (name.clone(), definition.as_ref().clone()))
            .collect::<BTreeMap<_, _>>();
        for (name, durable) in &durable_tools {
            let _ = mapping_definitions.insert(name.clone(), durable_tool_definition(durable)?);
        }
        let mut built = BTreeMap::new();
        let mut handled_names = BTreeSet::new();

        for (name, durable) in durable_tools {
            let (definition, source, refreshed_at, connection_id, state) =
                durable_tool_parts(&durable, &connections)?;
            let registered_definition = if let Some(active) = registry.get(&name) {
                if active.as_ref() != &definition {
                    return Err(CapabilityInventoryError::CorruptState);
                }
                Some(active.as_ref().clone())
            } else if state.enabled && !state.stale {
                return Err(CapabilityInventoryError::CorruptState);
            } else {
                None
            };
            handled_names.insert(name);
            let connection = connections
                .get(&connection_id)
                .map(|context| context.reference.clone());
            let policy = tool_policy(rbac_state, principal, &definition.name);
            let execution_revision = durable_execution_revision(&durable);
            let dynamic_enums = self.dynamic_enum_details(&definition)?;
            let capability = tool_capability(
                definition,
                source,
                connection,
                Some(refreshed_at),
                state,
                policy,
                (registered_definition, Some(execution_revision)),
                &mapping_definitions,
                dynamic_enums,
            )?;
            insert_capability(&mut built, capability)?;
        }

        for (name, definition) in registry {
            if handled_names.contains(&name) {
                continue;
            }
            if matches!(
                definition.source,
                ToolSource::OpenApi { .. } | ToolSource::Mcp { .. }
            ) {
                return Err(CapabilityInventoryError::CorruptState);
            }
            let (source, connection, state) =
                local_tool_context(&definition, &snapshot, &connections)?;
            let policy = tool_policy(rbac_state, principal, &definition.name);
            let execution_revision = local_execution_revision(&definition, &snapshot, &connections);
            let dynamic_enums = self.dynamic_enum_details(definition.as_ref())?;
            let capability = tool_capability(
                definition.as_ref().clone(),
                source,
                connection,
                None,
                state,
                policy,
                (Some(definition.as_ref().clone()), Some(execution_revision)),
                &mapping_definitions,
                dynamic_enums,
            )?;
            insert_capability(&mut built, capability)?;
        }

        for catalog in mcp_catalogs {
            let Some(connection) = connections.get(&catalog.connection_id) else {
                return Err(CapabilityInventoryError::CorruptState);
            };
            let state = managed_catalog_state(
                connection,
                catalog.observed_etag.as_str(),
                ConnectionKind::McpStreamableHttp,
            );
            for resource in catalog.resources {
                let (description, description_truncated) =
                    bounded_description(resource.description.as_deref());
                let summary = CapabilitySummary {
                    id: capability_id(&[
                        "resource",
                        catalog.connection_id.as_str(),
                        resource.uri.as_str(),
                    ]),
                    kind: CapabilityKind::Resource,
                    name: resource.name,
                    title: resource.title,
                    annotations: None,
                    uri: Some(resource.uri.clone()),
                    uri_template: None,
                    description,
                    description_truncated,
                    source: CapabilitySource::McpDiscovery {
                        connection_id: catalog.connection_id.to_string(),
                        remote_tool_name: None,
                    },
                    connection: Some(connection.reference.clone()),
                    schema_digest: None,
                    discovered_at: Some(catalog.refreshed_at.clone()),
                    last_success_at: Some(catalog.refreshed_at.clone()),
                    visibility: None,
                    state: state.clone(),
                    policy: metadata_only_policy(),
                };
                insert_capability(
                    &mut built,
                    BuiltCapability {
                        mapping: Some(CapabilityMapping::Resource {
                            uri: resource.uri,
                            mime_type: resource.mime_type,
                            size: resource.size,
                        }),
                        summary,
                        input_schema: None,
                        transform: None,
                        dynamic_enums: Vec::new(),
                        registered_definition: None,
                        execution_revision: None,
                    },
                )?;
            }
            for template in catalog.resource_templates {
                let (description, description_truncated) =
                    bounded_description(template.description.as_deref());
                let summary = CapabilitySummary {
                    id: capability_id(&[
                        "resource_template",
                        catalog.connection_id.as_str(),
                        template.uri_template.as_str(),
                    ]),
                    kind: CapabilityKind::ResourceTemplate,
                    name: template.name,
                    title: template.title,
                    annotations: None,
                    uri: None,
                    uri_template: Some(template.uri_template.clone()),
                    description,
                    description_truncated,
                    source: CapabilitySource::McpDiscovery {
                        connection_id: catalog.connection_id.to_string(),
                        remote_tool_name: None,
                    },
                    connection: Some(connection.reference.clone()),
                    schema_digest: None,
                    discovered_at: Some(catalog.refreshed_at.clone()),
                    last_success_at: Some(catalog.refreshed_at.clone()),
                    visibility: None,
                    state: state.clone(),
                    policy: metadata_only_policy(),
                };
                insert_capability(
                    &mut built,
                    BuiltCapability {
                        mapping: Some(CapabilityMapping::ResourceTemplate {
                            uri_template: template.uri_template,
                            mime_type: template.mime_type,
                        }),
                        summary,
                        input_schema: None,
                        transform: None,
                        dynamic_enums: Vec::new(),
                        registered_definition: None,
                        execution_revision: None,
                    },
                )?;
            }
        }

        Ok(built.into_values().collect())
    }

    fn dynamic_enum_details(
        &self,
        definition: &ToolDefinition,
    ) -> Result<Vec<CapabilityDynamicEnum>, CapabilityInventoryError> {
        if definition.enum_bindings.is_empty() {
            return Ok(Vec::new());
        }
        let connection_id = match &definition.source {
            ToolSource::OpenApi { connection_id, .. } => ConnectionId::parse(connection_id.clone())
                .map_err(|_| CapabilityInventoryError::CorruptState)?,
            _ => return Err(CapabilityInventoryError::CorruptState),
        };
        Ok(definition
            .enum_bindings
            .iter()
            .map(|binding| {
                let snapshot = self.enum_source_runtime.as_ref().map(|runtime| {
                    runtime.snapshot(&connection_id, &binding.source_id, &binding.source_digest)
                });
                CapabilityDynamicEnum {
                    property: binding.property.clone(),
                    source_id: binding.source_id.clone(),
                    state: snapshot
                        .as_ref()
                        .map_or(EnumSourceState::Missing, |snapshot| snapshot.state),
                    item_count: snapshot
                        .as_ref()
                        .map_or(0, |snapshot| snapshot.item_count()),
                    values_revision: snapshot.as_ref().and_then(|snapshot| {
                        (snapshot.values_revision > 0).then_some(snapshot.values_revision)
                    }),
                    resolved_at: snapshot.and_then(|snapshot| snapshot.resolved_at),
                }
            })
            .collect())
    }

    async fn load_managed_inventory(
        &self,
        snapshot: &ConnectionRuntimeSnapshot,
    ) -> Result<ManagedInventory, CapabilityInventoryError> {
        if !self.control_plane.is_managed_store_configured() {
            return Ok((Vec::new(), Vec::new(), BTreeMap::new()));
        }
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| CapabilityInventoryError::StoreUnavailable)?;
        let mcp = store.mcp_catalogs().await.map_err(store_inventory_error)?;
        let openapi = store
            .openapi_inventory_catalogs()
            .await
            .map_err(store_inventory_error)?;
        // One round trip for every status; the collection listing does
        // the same read for its own view, so a list request costs two bulk
        // reads rather than two per Connection.
        let ids = snapshot.managed().keys().cloned().collect::<Vec<_>>();
        let statuses = store
            .latest_statuses(&ids)
            .await
            .map_err(store_inventory_error)?;
        Ok((mcp, openapi, statuses))
    }
}

fn connection_counts_from_capabilities(
    capabilities: impl IntoIterator<Item = BuiltCapability>,
) -> BTreeMap<ConnectionId, usize> {
    let mut counts = BTreeMap::new();
    for capability in capabilities {
        if let Some(connection) = capability.summary.connection {
            *counts.entry(connection.id).or_default() += 1;
        }
    }
    counts
}

fn durable_tool_catalogs<'a>(
    mcp_catalogs: &'a [StoredMcpCatalog],
    openapi_catalogs: &'a [StoredOpenApiInventoryCatalog],
) -> Result<BTreeMap<String, DurableToolCatalog<'a>>, CapabilityInventoryError> {
    let mut tools = BTreeMap::new();
    for catalog in openapi_catalogs {
        for entry in &catalog.entries {
            if tools
                .insert(
                    entry.tool_name.clone(),
                    DurableToolCatalog::Openapi { catalog, entry },
                )
                .is_some()
            {
                return Err(CapabilityInventoryError::CorruptState);
            }
        }
    }
    for catalog in mcp_catalogs {
        for entry in &catalog.entries {
            let tool_name = format!("{}:{}", catalog.connection_id, entry.remote_tool_name);
            if tools
                .insert(tool_name, DurableToolCatalog::Mcp { catalog, entry })
                .is_some()
            {
                return Err(CapabilityInventoryError::CorruptState);
            }
        }
    }
    Ok(tools)
}

fn durable_tool_definition(
    durable: &DurableToolCatalog<'_>,
) -> Result<ToolDefinition, CapabilityInventoryError> {
    match durable {
        DurableToolCatalog::Openapi { entry, .. } => {
            serde_json::from_value::<ToolDefinition>(entry.definition.clone())
                .map_err(|_| CapabilityInventoryError::CorruptState)
        }
        DurableToolCatalog::Mcp { catalog, entry } => {
            let mut definition = ToolDefinition::mcp_connection(
                catalog.connection_id.to_string(),
                entry.description.clone(),
                entry.input_schema.clone(),
                entry.remote_tool_name.clone(),
            );
            definition.title = entry.title.clone();
            definition.annotations = entry.annotations.clone();
            Ok(definition)
        }
    }
}

fn durable_tool_parts(
    durable: &DurableToolCatalog<'_>,
    connections: &BTreeMap<ConnectionId, ConnectionContext>,
) -> Result<
    (
        ToolDefinition,
        CapabilitySource,
        String,
        ConnectionId,
        CapabilityState,
    ),
    CapabilityInventoryError,
> {
    let definition = durable_tool_definition(durable)?;
    match durable {
        DurableToolCatalog::Openapi { catalog, entry } => {
            if definition.name != entry.tool_name {
                return Err(CapabilityInventoryError::CorruptState);
            }
            let (source_connection_id, operation_id, source_revision) = match &definition.source {
                ToolSource::OpenApi {
                    connection_id,
                    operation_id,
                    catalog_revision,
                } => (connection_id, operation_id.clone(), *catalog_revision),
                _ => return Err(CapabilityInventoryError::CorruptState),
            };
            if source_connection_id != catalog.connection_id.as_str()
                || source_revision != Some(catalog.catalog_revision)
                || !matches!(
                    &definition.target,
                    Some(ToolTarget::Http { connection_id, .. })
                        | Some(ToolTarget::Composite { connection_id })
                        if connection_id == source_connection_id
                )
            {
                return Err(CapabilityInventoryError::CorruptState);
            }
            let connection = connections
                .get(&catalog.connection_id)
                .ok_or(CapabilityInventoryError::CorruptState)?;
            Ok((
                definition,
                CapabilitySource::Openapi {
                    connection_id: catalog.connection_id.to_string(),
                    operation_id,
                    catalog_revision: catalog.catalog_revision,
                    spec_revision: catalog.spec_revision,
                    spec_digest: catalog.spec_digest.clone(),
                },
                catalog.refreshed_at.clone(),
                catalog.connection_id.clone(),
                managed_catalog_state(
                    connection,
                    catalog.observed_etag.as_str(),
                    ConnectionKind::HttpApi,
                ),
            ))
        }
        DurableToolCatalog::Mcp { catalog, .. } => {
            let connection = connections
                .get(&catalog.connection_id)
                .ok_or(CapabilityInventoryError::CorruptState)?;
            let remote_tool_name = match &definition.source {
                ToolSource::Mcp {
                    connection_id,
                    remote_tool_name,
                } if connection_id == catalog.connection_id.as_str() => remote_tool_name.clone(),
                _ => return Err(CapabilityInventoryError::CorruptState),
            };
            if !matches!(
                &definition.target,
                Some(ToolTarget::Mcp {
                    connection_id,
                    remote_tool_name: target_name,
                }) if connection_id == catalog.connection_id.as_str()
                    && target_name == &remote_tool_name
            ) {
                return Err(CapabilityInventoryError::CorruptState);
            }
            Ok((
                definition,
                CapabilitySource::McpDiscovery {
                    connection_id: catalog.connection_id.to_string(),
                    remote_tool_name: Some(remote_tool_name),
                },
                catalog.refreshed_at.clone(),
                catalog.connection_id.clone(),
                managed_catalog_state(
                    connection,
                    catalog.observed_etag.as_str(),
                    ConnectionKind::McpStreamableHttp,
                ),
            ))
        }
    }
}

fn durable_execution_revision(durable: &DurableToolCatalog<'_>) -> CapabilityExecutionRevision {
    match durable {
        DurableToolCatalog::Openapi { catalog, .. } => CapabilityExecutionRevision::Openapi {
            connection_etag: catalog.observed_etag.to_string(),
            catalog_revision: catalog.catalog_revision,
            spec_revision: catalog.spec_revision,
            spec_digest: catalog.spec_digest.clone(),
        },
        DurableToolCatalog::Mcp { catalog, .. } => CapabilityExecutionRevision::Mcp {
            connection_etag: catalog.observed_etag.to_string(),
            catalog_revision: catalog.catalog_revision,
        },
    }
}

fn connection_contexts(
    snapshot: &ConnectionRuntimeSnapshot,
    statuses: &BTreeMap<ConnectionId, SafeConnectionStatus>,
) -> BTreeMap<ConnectionId, ConnectionContext> {
    let mut contexts = BTreeMap::new();
    for projection in snapshot.legacy() {
        let summary = projection.safe_summary();
        contexts.insert(
            summary.id.clone(),
            ConnectionContext {
                reference: CapabilityConnection {
                    id: summary.id,
                    kind: summary.kind,
                    management_source: summary.source,
                },
                enabled: summary.enabled,
                etag: None,
                status: Some(summary.status),
            },
        );
    }
    for (id, record) in snapshot.managed() {
        contexts.insert(
            id.clone(),
            ConnectionContext {
                reference: CapabilityConnection {
                    id: id.clone(),
                    kind: record.write.kind,
                    management_source: ConnectionManagementSource::Managed,
                },
                enabled: record.write.enabled,
                etag: Some(record.etag().to_string()),
                status: statuses.get(id).cloned(),
            },
        );
    }
    contexts
}

fn local_execution_revision(
    definition: &ToolDefinition,
    snapshot: &ConnectionRuntimeSnapshot,
    connections: &BTreeMap<ConnectionId, ConnectionContext>,
) -> CapabilityExecutionRevision {
    let context = match &definition.target {
        Some(ToolTarget::Http { connection_id, .. })
        | Some(ToolTarget::Mcp { connection_id, .. })
        | Some(ToolTarget::Composite { connection_id }) => {
            ConnectionId::parse(connection_id.clone())
                .ok()
                .and_then(|id| connections.get(&id))
        }
        None => {
            if let Some(proxy) = definition.upstream.mcp_proxy_mapping() {
                snapshot
                    .legacy()
                    .iter()
                    .find(|projection| {
                        projection.legacy_mcp_server_name() == Some(proxy.server_name.as_str())
                    })
                    .and_then(|projection| connections.get(projection.id()))
            } else {
                connections.values().find(|context| {
                    context.reference.kind == ConnectionKind::HttpApi
                        && context.reference.management_source
                            == ConnectionManagementSource::LegacyDefaultHttp
                })
            }
        }
    };
    CapabilityExecutionRevision::Manual {
        connection_etag: context.and_then(|context| context.etag.clone()),
    }
}

fn managed_catalog_state(
    connection: &ConnectionContext,
    observed_etag: &str,
    required_kind: ConnectionKind,
) -> CapabilityState {
    if !connection.enabled {
        return CapabilityState {
            enabled: false,
            available: false,
            stale: connection.etag.as_deref() != Some(observed_etag),
            reason: "connection_disabled",
        };
    }
    if connection.reference.kind != required_kind {
        return CapabilityState {
            enabled: true,
            available: false,
            stale: true,
            reason: "connection_kind_mismatch",
        };
    }
    let etag_current = connection.etag.as_deref() == Some(observed_etag);
    if !etag_current {
        return CapabilityState {
            enabled: true,
            available: false,
            stale: true,
            reason: "catalog_stale",
        };
    }
    let status_stale = connection
        .status
        .as_ref()
        .is_some_and(|status| status.reason == ConnectionStatusReason::CatalogStale);
    let unavailable = connection.status.as_ref().is_some_and(|status| {
        matches!(
            status.state,
            ConnectionOperationalState::Unavailable | ConnectionOperationalState::Disabled
        )
    });
    CapabilityState {
        enabled: true,
        available: !unavailable,
        stale: status_stale,
        reason: if unavailable {
            connection
                .status
                .as_ref()
                .map(|status| status_reason(status.reason))
                .unwrap_or("connection_unavailable")
        } else if status_stale {
            "catalog_stale"
        } else {
            "available"
        },
    }
}

fn local_tool_context(
    definition: &ToolDefinition,
    snapshot: &ConnectionRuntimeSnapshot,
    connections: &BTreeMap<ConnectionId, ConnectionContext>,
) -> Result<
    (
        CapabilitySource,
        Option<CapabilityConnection>,
        CapabilityState,
    ),
    CapabilityInventoryError,
> {
    if let Some(proxy) = definition.upstream.mcp_proxy_mapping() {
        let projection = snapshot.legacy().iter().find(|projection| {
            projection.legacy_mcp_server_name() == Some(proxy.server_name.as_str())
        });
        if let Some(projection) = projection {
            let id = projection.id();
            let connection = connections.get(id).map(|context| context.reference.clone());
            return Ok((
                CapabilitySource::ProjectedLegacyConfig {
                    connection_id: id.to_string(),
                    remote_tool_name: proxy.tool_name,
                },
                connection,
                CapabilityState {
                    enabled: true,
                    available: true,
                    stale: false,
                    reason: "available",
                },
            ));
        }
        if snapshot.omitted_legacy_projection_count() > 0
            && definition.target.is_none()
            && matches!(&definition.source, ToolSource::Legacy)
        {
            let id = projected_legacy_mcp_connection_id(&proxy.server_name)
                .map_err(|_| CapabilityInventoryError::CorruptState)?;
            let connection = CapabilityConnection {
                id: id.clone(),
                kind: ConnectionKind::McpStreamableHttp,
                management_source: ConnectionManagementSource::LegacyMcp,
            };
            return Ok((
                CapabilitySource::ProjectedLegacyConfig {
                    connection_id: id.to_string(),
                    remote_tool_name: proxy.tool_name,
                },
                Some(connection),
                CapabilityState {
                    enabled: true,
                    available: true,
                    stale: false,
                    reason: "available",
                },
            ));
        }
        return Ok((
            CapabilitySource::ManualFile,
            None,
            CapabilityState {
                enabled: true,
                available: false,
                stale: false,
                reason: "connection_not_found",
            },
        ));
    }

    let context = match &definition.target {
        Some(ToolTarget::Http { connection_id, .. })
        | Some(ToolTarget::Mcp { connection_id, .. })
        | Some(ToolTarget::Composite { connection_id }) => {
            ConnectionId::parse(connection_id.clone())
                .ok()
                .and_then(|id| connections.get(&id))
        }
        None => connections.values().find(|context| {
            context.reference.kind == ConnectionKind::HttpApi
                && context.reference.management_source
                    == ConnectionManagementSource::LegacyDefaultHttp
        }),
    };
    let state = match context {
        Some(context) if !context.enabled => CapabilityState {
            enabled: false,
            available: false,
            stale: false,
            reason: "connection_disabled",
        },
        Some(context)
            if context.status.as_ref().is_some_and(|status| {
                matches!(
                    status.state,
                    ConnectionOperationalState::Unavailable | ConnectionOperationalState::Disabled
                )
            }) =>
        {
            CapabilityState {
                enabled: true,
                available: false,
                stale: false,
                reason: "connection_unavailable",
            }
        }
        Some(_) => CapabilityState {
            enabled: true,
            available: true,
            stale: false,
            reason: "available",
        },
        None => CapabilityState {
            enabled: true,
            available: false,
            stale: false,
            reason: "connection_not_found",
        },
    };
    Ok((
        CapabilitySource::ManualFile,
        context.map(|context| context.reference.clone()),
        state,
    ))
}

#[allow(clippy::too_many_arguments)] // One input per independently reported capability dimension.
fn tool_capability(
    definition: ToolDefinition,
    source: CapabilitySource,
    connection: Option<CapabilityConnection>,
    refreshed_at: Option<String>,
    state: CapabilityState,
    policy: CapabilityPolicyEligibility,
    execution_binding: (Option<ToolDefinition>, Option<CapabilityExecutionRevision>),
    mapping_definitions: &BTreeMap<String, ToolDefinition>,
    dynamic_enums: Vec<CapabilityDynamicEnum>,
) -> Result<BuiltCapability, CapabilityInventoryError> {
    let (registered_definition, execution_revision) = execution_binding;
    let schema_digest = schema_digest(&definition.input_schema)?;
    let (description, description_truncated) =
        bounded_description(Some(definition.description.as_str()));
    let mapping = match &definition.target {
        Some(ToolTarget::Http { mapping, .. }) => Some(http_mapping(mapping)),
        Some(ToolTarget::Mcp {
            remote_tool_name, ..
        }) => Some(CapabilityMapping::Mcp {
            remote_tool_name: remote_tool_name.clone(),
        }),
        Some(ToolTarget::Composite { .. }) => Some(composite_mapping(
            definition
                .composite
                .as_ref()
                .ok_or(CapabilityInventoryError::CorruptState)?,
            mapping_definitions,
        )?),
        None => definition
            .upstream
            .mcp_proxy_mapping()
            .map(|mapping| CapabilityMapping::Mcp {
                remote_tool_name: mapping.tool_name,
            })
            .or_else(|| Some(http_mapping(&definition.upstream))),
    };
    let transform = definition.transform.as_ref().map(transform_summary);
    let visibility = (!definition.visibility.is_listed()).then_some(definition.visibility);
    Ok(BuiltCapability {
        summary: CapabilitySummary {
            id: capability_id(&["tool", definition.name.as_str()]),
            kind: CapabilityKind::Tool,
            name: definition.name,
            title: definition.title.clone(),
            annotations: definition.annotations.clone(),
            uri: None,
            uri_template: None,
            description,
            description_truncated,
            source,
            connection,
            schema_digest: Some(schema_digest),
            discovered_at: refreshed_at.clone(),
            last_success_at: refreshed_at,
            visibility,
            state,
            policy,
        },
        input_schema: Some(definition.input_schema),
        mapping,
        transform,
        dynamic_enums,
        registered_definition,
        execution_revision,
    })
}

fn composite_mapping(
    mapping: &crate::tools::composite::CompositeMapping,
    definitions: &BTreeMap<String, ToolDefinition>,
) -> Result<CapabilityMapping, CapabilityInventoryError> {
    let steps = mapping
        .steps
        .iter()
        .map(|step| {
            let definition = definitions
                .get(&step.tool)
                .ok_or(CapabilityInventoryError::CorruptState)?;
            let Some(ToolTarget::Http { mapping, .. }) = &definition.target else {
                return Err(CapabilityInventoryError::CorruptState);
            };
            Ok(CapabilityCompositeStep {
                id: step.id.clone(),
                tool: step.tool.clone(),
                method: mapping.method.clone(),
                path_template: mapping.path_template.clone(),
                has_compensation: step.compensate.is_some(),
                for_each: step.for_each.is_some(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CapabilityMapping::Composite { steps })
}

fn http_mapping(mapping: &HttpToolMapping) -> CapabilityMapping {
    CapabilityMapping::Http {
        method: mapping.method.clone(),
        path_template: mapping.path_template.clone(),
        query_params: mapping.query_params.clone(),
        body: mapping.body.clone(),
    }
}

fn transform_summary(transform: &ToolTransform) -> CapabilityTransformSummary {
    CapabilityTransformSummary {
        parameters: transform
            .parameters
            .iter()
            .map(transform_shape_summary)
            .collect(),
        response_fields: transform
            .response_fields
            .iter()
            .map(transform_shape_summary)
            .collect(),
        has_response_root: transform.response_root.is_some(),
    }
}

fn transform_shape_summary(shape: &ParameterShape) -> CapabilityTransformShapeSummary {
    CapabilityTransformShapeSummary {
        wire_property: shape.wire_property.clone(),
        agent_properties: shape
            .agent
            .iter()
            .map(|property| property.name.clone())
            .collect(),
        wire_pointer_count: shape.wire.len(),
        response_properties: shape
            .response
            .iter()
            .map(|binding| binding.agent_property.clone())
            .collect(),
        constant_binding_count: shape
            .wire
            .iter()
            .filter(|binding| matches!(&binding.source, WireSource::Const { .. }))
            .count(),
    }
}

fn tool_policy(
    rbac_state: &RbacState,
    principal: &Principal,
    tool_name: &str,
) -> CapabilityPolicyEligibility {
    let eligibility = rbac_state.tool_policy_eligibility(tool_name, principal);
    CapabilityPolicyEligibility {
        eligible: eligibility.eligible,
        reason: eligibility.reason,
    }
}

fn metadata_only_policy() -> CapabilityPolicyEligibility {
    CapabilityPolicyEligibility {
        eligible: false,
        reason: "metadata_only",
    }
}

fn insert_capability(
    capabilities: &mut BTreeMap<String, BuiltCapability>,
    capability: BuiltCapability,
) -> Result<(), CapabilityInventoryError> {
    if capabilities.len() >= MAX_CAPABILITY_INVENTORY_ENTRIES {
        return Err(CapabilityInventoryError::CardinalityExceeded);
    }
    if capabilities
        .insert(capability.summary.id.clone(), capability)
        .is_some()
    {
        return Err(CapabilityInventoryError::IdentityCollision);
    }
    Ok(())
}

fn normalize_filters(
    params: &CapabilityListParams,
) -> Result<NormalizedFilters, CapabilityInventoryError> {
    let connection_id = params
        .connection_id
        .as_ref()
        .map(|value| {
            ConnectionId::parse(value.clone())
                .map(|id| id.to_string())
                .map_err(|_| CapabilityInventoryError::InvalidFilter)
        })
        .transpose()?;
    let text = params
        .text
        .as_ref()
        .map(|value| {
            let value = value.trim();
            if value.is_empty()
                || value.chars().count() > MAX_TEXT_FILTER_CHARS
                || value.len() > MAX_TEXT_FILTER_BYTES
                || value.contains('\0')
            {
                return Err(CapabilityInventoryError::InvalidFilter);
            }
            Ok(value.to_lowercase())
        })
        .transpose()?;
    if let (Some(available), Some(availability)) = (params.available, params.availability) {
        let compatible = matches!(
            (available, availability),
            (true, CapabilityAvailabilityFilter::Available)
                | (false, CapabilityAvailabilityFilter::Unavailable)
                | (true, CapabilityAvailabilityFilter::Stale)
                | (false, CapabilityAvailabilityFilter::Stale)
        );
        if !compatible {
            return Err(CapabilityInventoryError::InvalidFilter);
        }
    }
    Ok(NormalizedFilters {
        kind: params.kind,
        connection_id,
        source: params.source,
        available: params.available,
        availability: params.availability,
        text,
    })
}

fn matches_filters(summary: &CapabilitySummary, filters: &NormalizedFilters) -> bool {
    filters.kind.is_none_or(|kind| kind == summary.kind)
        && filters.connection_id.as_ref().is_none_or(|connection_id| {
            summary
                .connection
                .as_ref()
                .is_some_and(|connection| connection.id.as_str() == connection_id)
        })
        && filters
            .source
            .is_none_or(|source| source == summary.source.filter())
        && filters
            .available
            .is_none_or(|available| available == summary.state.available)
        && filters
            .availability
            .is_none_or(|availability| match availability {
                CapabilityAvailabilityFilter::Available => summary.state.available,
                CapabilityAvailabilityFilter::Unavailable => {
                    !summary.state.available && !summary.state.stale
                }
                CapabilityAvailabilityFilter::Stale => summary.state.stale,
            })
        && filters.text.as_ref().is_none_or(|text| {
            [
                Some(summary.name.as_str()),
                summary.title.as_deref(),
                summary.uri.as_deref(),
                summary.uri_template.as_deref(),
                summary.description.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| value.to_lowercase().contains(text))
        })
}

fn collection_etag(capabilities: &[BuiltCapability]) -> Result<String, CapabilityInventoryError> {
    let summaries = capabilities
        .iter()
        .map(|capability| &capability.summary)
        .collect::<Vec<_>>();
    let bytes =
        serde_json::to_vec(&summaries).map_err(|_| CapabilityInventoryError::CorruptState)?;
    Ok(format!(
        "\"capabilities:sha256:{}\"",
        hex::encode(Sha256::digest(bytes))
    ))
}

fn capability_detail_result(
    capability: BuiltCapability,
    has_execute_permission: bool,
    executor_available: bool,
) -> Result<CapabilityDetailResult, CapabilityInventoryError> {
    let actions = capability_actions(&capability, has_execute_permission, executor_available);
    let BuiltCapability {
        summary,
        input_schema,
        mapping,
        transform,
        dynamic_enums,
        registered_definition,
        execution_revision,
    } = capability;
    let detail = CapabilityDetail {
        summary,
        input_schema,
        mapping,
        transform,
        dynamic_enums,
        actions,
    };
    // Dynamic values refresh independently of the stored catalog. Keep the
    // playground precondition bound to durable definition/revision state so
    // an enum refresh does not churn capability ETags.
    let binding = serde_json::to_vec(&(
        CAPABILITY_EXECUTION_ETAG_DOMAIN,
        &detail.summary,
        &detail.input_schema,
        &detail.mapping,
        &detail.actions,
        &registered_definition,
        &execution_revision,
    ))
    .map_err(|_| CapabilityInventoryError::CorruptState)?;
    let execution_etag = format!(
        "\"capability-execution:sha256:{}\"",
        hex::encode(Sha256::digest(binding))
    );
    Ok(CapabilityDetailResult {
        detail,
        execution_etag,
    })
}

fn capability_actions(
    capability: &BuiltCapability,
    has_execute_permission: bool,
    executor_available: bool,
) -> CapabilityActions {
    let reason = if capability.summary.kind != CapabilityKind::Tool {
        "metadata_only"
    } else if capability.registered_definition.is_none() {
        "stale"
    } else if !has_execute_permission {
        "permission_denied"
    } else if !executor_available {
        "executor_unavailable"
    } else if !capability.summary.state.enabled {
        "disabled"
    } else if capability.summary.state.stale {
        "stale"
    } else if !capability.summary.state.available {
        "unavailable"
    } else if !capability.summary.policy.eligible {
        "policy_denied"
    } else {
        "allowed"
    };
    CapabilityActions {
        can_execute: reason == "allowed",
        reason,
    }
}

fn capability_id(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"greengateway-capability-id-v1");
    for part in parts {
        digest.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("{CAPABILITY_ID_PREFIX}{}", hex::encode(digest.finalize()))
}

fn valid_capability_id(value: &str) -> bool {
    value.len() == CAPABILITY_ID_PREFIX.len() + CAPABILITY_ID_HEX_BYTES
        && value.starts_with(CAPABILITY_ID_PREFIX)
        && value[CAPABILITY_ID_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn schema_digest(schema: &Value) -> Result<String, CapabilityInventoryError> {
    let bytes = serde_json::to_vec(schema).map_err(|_| CapabilityInventoryError::CorruptState)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn bounded_description(value: Option<&str>) -> (Option<String>, bool) {
    let Some(value) = value else {
        return (None, false);
    };
    let mut chars = value.chars();
    let bounded = chars
        .by_ref()
        .take(MAX_PUBLIC_DESCRIPTION_CHARS)
        .collect::<String>();
    (Some(bounded), chars.next().is_some())
}

fn encode_cursor(cursor: &CapabilityCursor) -> Result<String, CapabilityInventoryError> {
    serde_json::to_vec(cursor)
        .map(hex::encode)
        .map_err(|_| CapabilityInventoryError::InvalidCursor)
}

fn decode_cursor(value: &str) -> Result<CapabilityCursor, CapabilityInventoryError> {
    if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
        return Err(CapabilityInventoryError::InvalidCursor);
    }
    let bytes = hex::decode(value).map_err(|_| CapabilityInventoryError::InvalidCursor)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(CapabilityInventoryError::InvalidCursor);
    }
    serde_json::from_slice(&bytes).map_err(|_| CapabilityInventoryError::InvalidCursor)
}

fn serialized_len<T: Serialize>(value: &T) -> Result<usize, CapabilityInventoryError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|_| CapabilityInventoryError::CorruptState)
}

fn store_inventory_error(error: ConnectionStoreError) -> CapabilityInventoryError {
    match error {
        ConnectionStoreError::LimitExceeded { .. } => CapabilityInventoryError::CardinalityExceeded,
        ConnectionStoreError::CorruptRecord { .. }
        | ConnectionStoreError::Validation { .. }
        | ConnectionStoreError::UnsupportedSchema { .. }
        | ConnectionStoreError::InvalidMigrationHistory => CapabilityInventoryError::CorruptState,
        _ => CapabilityInventoryError::StoreUnavailable,
    }
}

fn status_reason(reason: ConnectionStatusReason) -> &'static str {
    match reason {
        ConnectionStatusReason::NotTested => "not_tested",
        ConnectionStatusReason::LegacyConfigured => "legacy_configured",
        ConnectionStatusReason::Disabled => "connection_disabled",
        ConnectionStatusReason::TestSucceeded => "test_succeeded",
        ConnectionStatusReason::CatalogRefreshed => "catalog_refreshed",
        ConnectionStatusReason::RequestFailed => "request_failed",
        ConnectionStatusReason::EgressDenied => "egress_denied",
        ConnectionStatusReason::SecretUnavailable => "secret_unavailable",
        ConnectionStatusReason::InvalidResponse => "invalid_response",
        ConnectionStatusReason::CatalogStale => "catalog_stale",
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use serde_json::json;

    use crate::{
        audit::{sink::tests::CaptureSink, AuditLog, AuditSink},
        auth::AuthMethod,
        config::{Config, McpUpstreamServerConfig},
        connections::{
            model::{ConnectionWrite, MAX_CONNECTIONS},
            store::{
                StoredConnection, StoredMcpCatalogEntry, StoredMcpResource,
                StoredMcpResourceTemplate, StoredOpenApiCatalogEntry,
            },
        },
        rbac::policy::Policy,
    };

    use super::*;

    #[test]
    fn transform_summary_exposes_shape_metadata_without_constants_or_wire_pointers() {
        let transform: ToolTransform = serde_json::from_value(json!({
            "parameters": [{
                "wire_property": "billing",
                "agent": [{
                    "name": "amount",
                    "schema": { "type": "number" }
                }],
                "wire": [
                    {
                        "pointer": "/amountMicros",
                        "from": "amount",
                        "codec": [{
                            "kind": "decimal_scale",
                            "scale": 6,
                            "wire_encoding": "integer_string",
                            "max_integer_digits": 24
                        }]
                    },
                    {
                        "pointer": "/internalDefault",
                        "const": "FAKE_INTERNAL_DEFAULT_VALUE"
                    }
                ],
                "response": [{
                    "agent_property": "amount",
                    "from": "/amountMicros",
                    "codec": [{
                        "kind": "decimal_scale",
                        "scale": 6,
                        "wire_encoding": "integer_string",
                        "max_integer_digits": 24
                    }]
                }]
            }],
            "response_root": "/data/company"
        }))
        .expect("compiled transform fixture should deserialize");

        let serialized = serde_json::to_value(transform_summary(&transform))
            .expect("transform summary should serialize");
        assert_eq!(
            serialized,
            json!({
                "parameters": [{
                    "wire_property": "billing",
                    "agent_properties": ["amount"],
                    "wire_pointer_count": 2,
                    "response_properties": ["amount"],
                    "constant_binding_count": 1
                }],
                "response_fields": [],
                "has_response_root": true
            })
        );
        let text = serialized.to_string();
        assert!(!text.contains("FAKE_INTERNAL_DEFAULT_VALUE"));
        assert!(!text.contains("amountMicros"));
        assert!(!text.contains("decimal_scale"));
    }

    struct TemporaryInventoryDatabase {
        path: PathBuf,
    }

    impl TemporaryInventoryDatabase {
        fn new(test_name: &str) -> Self {
            Self {
                path: std::env::temp_dir().join(format!(
                    "greengateway-capability-inventory-{test_name}-{}.sqlite",
                    uuid::Uuid::new_v4()
                )),
            }
        }

        fn config(&self) -> Config {
            let mut config = Config::test_defaults();
            config.connections_sqlite_path = Some(self.path.to_string_lossy().into_owned());
            config
        }
    }

    impl Drop for TemporaryInventoryDatabase {
        fn drop(&mut self) {
            if self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("greengateway-capability-inventory-")
                        && name.ends_with(".sqlite")
                })
                && self.path.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    struct ManagedInventoryFixture {
        inventory: CapabilityInventory,
        control_plane: ConnectionControlPlane,
        rbac_state: RbacState,
        principal: Principal,
        mcp_record: StoredConnection,
        openapi_record: StoredConnection,
        mcp_tool_name: String,
        openapi_tool_name: String,
        _database: TemporaryInventoryDatabase,
    }

    impl ManagedInventoryFixture {
        async fn new(test_name: &str) -> Self {
            let database = TemporaryInventoryDatabase::new(test_name);
            let control_plane = ConnectionControlPlane::from_config(&database.config())
                .expect("managed inventory control plane should open");

            let mcp_record =
                create_managed_connection(&control_plane, managed_mcp_candidate()).await;
            let openapi_record =
                create_managed_connection(&control_plane, managed_openapi_candidate()).await;
            let mcp_tool_name = format!("{}:lookup", mcp_record.id);
            let openapi_tool_name = "inventory_openapi_lookup".to_owned();
            let mut mcp_definition = ToolDefinition::mcp_connection(
                mcp_record.id.to_string(),
                "Look up an MCP item".to_owned(),
                json!({
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
                "lookup".to_owned(),
            );
            mcp_definition.title = Some("Inventory MCP lookup".to_owned());
            mcp_definition.annotations = Some(ToolAnnotations {
                read_only_hint: Some(true),
                open_world_hint: Some(false),
                ..ToolAnnotations::default()
            });
            let openapi_mapping = HttpToolMapping {
                method: "GET".to_owned(),
                path_template: "/inventory/{id}".to_owned(),
                query_params: Vec::new(),
                body: None,
            };
            let openapi_definition = ToolDefinition {
                name: openapi_tool_name.clone(),
                title: None,
                description: "Look up an OpenAPI item".to_owned(),
                input_schema: json!({
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
                target: Some(ToolTarget::Http {
                    connection_id: openapi_record.id.to_string(),
                    mapping: openapi_mapping.clone(),
                }),
                source: ToolSource::OpenApi {
                    connection_id: openapi_record.id.to_string(),
                    operation_id: Some("inventoryLookup".to_owned()),
                    catalog_revision: Some(1),
                },
                upstream: openapi_mapping,
                composite: None,
                enum_bindings: Vec::new(),
                visibility: crate::tools::definitions::ToolVisibility::Listed,
                transform: None,
                annotations: None,
            };

            let store = control_plane
                .managed_store()
                .expect("managed inventory store should be configured");
            store
                .replace_mcp_catalog(
                    &mcp_record.id,
                    &mcp_record.etag(),
                    &[StoredMcpCatalogEntry {
                        remote_tool_name: "lookup".to_owned(),
                        title: mcp_definition.title.clone(),
                        description: "Look up an MCP item".to_owned(),
                        input_schema: mcp_definition.input_schema.clone(),
                        annotations: mcp_definition.annotations.clone(),
                    }],
                    &[StoredMcpResource {
                        uri: "urn:inventory:resource".to_owned(),
                        name: "inventory-resource".to_owned(),
                        title: Some("Inventory resource".to_owned()),
                        description: Some("Safe metadata only".to_owned()),
                        mime_type: Some("application/json".to_owned()),
                        size: Some(42),
                    }],
                    &[StoredMcpResourceTemplate {
                        uri_template: "urn:inventory:item:{id}".to_owned(),
                        name: "inventory-template".to_owned(),
                        title: Some("Inventory template".to_owned()),
                        description: Some("Safe template metadata only".to_owned()),
                        mime_type: Some("application/json".to_owned()),
                    }],
                    0,
                    "test-admin",
                )
                .await
                .expect("managed MCP inventory catalog should persist");

            let spec =
                r#"{"openapi":"3.0.3","info":{"title":"Inventory","version":"1"},"paths":{}}"#;
            let spec_digest = hex::encode(Sha256::digest(spec.as_bytes()));
            store
                .replace_openapi_catalog(
                    &openapi_record.id,
                    &openapi_record.etag(),
                    0,
                    0,
                    spec,
                    &spec_digest,
                    &[StoredOpenApiCatalogEntry {
                        tool_name: openapi_tool_name.clone(),
                        operation_id: Some("inventoryLookup".to_owned()),
                        selected_scheme_names: Vec::new(),
                        definition: serde_json::to_value(&openapi_definition)
                            .expect("OpenAPI definition should serialize"),
                    }],
                    "test-admin",
                )
                .await
                .expect("managed OpenAPI inventory catalog should persist");

            let registry = ToolRegistry::from_json_value(json!({
                "schema_version": "0.1.0",
                "tools": []
            }))
            .expect("empty registry should build");
            registry
                .merge_definitions(vec![mcp_definition, openapi_definition])
                .expect("managed inventory definitions should publish");

            let policy = Policy::validate_json_value(json!({
                "schema_version": "0.1.0",
                "id": "inventory-policy",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {
                    "admin": {
                        "permissions": []
                    }
                },
                "routes": [],
                "tools": {
                    mcp_tool_name.clone(): {
                        "allowed_roles": ["admin"],
                        "timeout_ms": 5_000,
                        "max_concurrent": 2
                    },
                    openapi_tool_name.clone(): {
                        "allowed_roles": ["admin"],
                        "timeout_ms": 5_000,
                        "max_concurrent": 2
                    }
                }
            }))
            .expect("inventory policy should validate");
            let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
            let rbac_state = RbacState::new(policy, Vec::new(), false, audit);
            let principal = Principal {
                user_id: "inventory-admin".to_owned(),
                issuer: None,
                email: Some("inventory-admin@example.test".to_owned()),
                org_id: None,
                roles: vec!["admin".to_owned()],
                session_id: "inventory-session".to_owned(),
                auth_method: AuthMethod::Bearer,
            };
            let inventory = CapabilityInventory::new(registry, control_plane.clone());

            Self {
                inventory,
                control_plane,
                rbac_state,
                principal,
                mcp_record,
                openapi_record,
                mcp_tool_name,
                openapi_tool_name,
                _database: database,
            }
        }

        async fn list(&self, params: CapabilityListParams) -> CapabilityListPage {
            self.inventory
                .list(&self.rbac_state, &self.principal, &params)
                .await
                .expect("managed capability inventory should list")
        }
    }

    async fn create_managed_connection(
        control_plane: &ConnectionControlPlane,
        candidate: ConnectionWrite,
    ) -> StoredConnection {
        let collection_etag = control_plane
            .runtime_snapshot()
            .collection_etag()
            .to_owned();
        control_plane
            .create_managed(&collection_etag, candidate, "test-admin")
            .await
            .expect("managed inventory Connection should create")
    }

    fn managed_mcp_candidate() -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": "Inventory MCP",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": "https://mcp.inventory.example.test",
                "base_path": "/mcp"
            },
            "authentication": {
                "type": "none"
            },
            "tls": {},
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": false
            }
        }))
        .expect("managed MCP candidate should deserialize")
    }

    fn managed_openapi_candidate() -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": "Inventory OpenAPI",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://api.inventory.example.test",
                "base_path": "/v1"
            },
            "authentication": {
                "type": "none"
            },
            "tls": {},
            "discovery": {
                "type": "managed_openapi",
                "path": "/openapi.json",
                "use_connection_authentication": false
            }
        }))
        .expect("managed OpenAPI candidate should deserialize")
    }

    #[tokio::test]
    async fn durable_tool_index_borrows_catalogs_and_entries() {
        let fixture = ManagedInventoryFixture::new("borrowed-durable-index").await;
        let snapshot = fixture.control_plane.runtime_snapshot();
        let (mcp_catalogs, openapi_catalogs, _) = fixture
            .inventory
            .load_managed_inventory(&snapshot)
            .await
            .expect("managed catalogs should load");
        let durable = durable_tool_catalogs(&mcp_catalogs, &openapi_catalogs)
            .expect("durable tool index should build");

        match *durable
            .get(&fixture.mcp_tool_name)
            .expect("MCP tool should be indexed")
        {
            DurableToolCatalog::Mcp { catalog, entry } => {
                assert!(std::ptr::eq(catalog, &mcp_catalogs[0]));
                assert!(std::ptr::eq(entry, &mcp_catalogs[0].entries[0]));
            }
            DurableToolCatalog::Openapi { .. } => panic!("MCP tool used OpenAPI provenance"),
        }
        match *durable
            .get(&fixture.openapi_tool_name)
            .expect("OpenAPI tool should be indexed")
        {
            DurableToolCatalog::Openapi { catalog, entry } => {
                assert!(std::ptr::eq(catalog, &openapi_catalogs[0]));
                assert!(std::ptr::eq(entry, &openapi_catalogs[0].entries[0]));
            }
            DurableToolCatalog::Mcp { .. } => panic!("OpenAPI tool used MCP provenance"),
        }
    }

    #[test]
    fn stale_filter_accepts_both_callable_and_unavailable_intersections() {
        for available in [true, false] {
            assert!(normalize_filters(&CapabilityListParams {
                available: Some(available),
                availability: Some(CapabilityAvailabilityFilter::Stale),
                ..CapabilityListParams::default()
            })
            .is_ok());
        }
    }

    #[test]
    fn composite_inventory_mapping_exposes_the_reviewable_grant() {
        let http = HttpToolMapping {
            method: "POST".to_owned(),
            path_template: "/notes".to_owned(),
            query_params: Vec::new(),
            body: None,
        };
        let definitions = BTreeMap::from([(
            "createOneNote".to_owned(),
            ToolDefinition {
                name: "createOneNote".to_owned(),
                title: None,
                description: "Create one note".to_owned(),
                input_schema: json!({"type": "object"}),
                target: Some(ToolTarget::Http {
                    connection_id: "crm".to_owned(),
                    mapping: http.clone(),
                }),
                source: ToolSource::OpenApi {
                    connection_id: "crm".to_owned(),
                    operation_id: Some("createOneNote".to_owned()),
                    catalog_revision: Some(1),
                },
                upstream: http,
                composite: None,
                visibility: ToolVisibility::Listed,
                transform: None,
                enum_bindings: Vec::new(),
                annotations: None,
            },
        )]);
        let mapping = crate::tools::composite::CompositeMapping {
            steps: vec![crate::tools::composite::CompositeStep {
                id: "note".to_owned(),
                tool: "createOneNote".to_owned(),
                arguments: BTreeMap::new(),
                for_each: Some(crate::tools::composite::CompositeForEach {
                    over: crate::tools::composite::CompositeBinding::Input {
                        input: "records".to_owned(),
                        pointer: None,
                    },
                    item_name: "record".to_owned(),
                }),
                success_statuses: None,
                ambiguous_statuses: None,
                compensate: Some(crate::tools::composite::CompositeCompensation {
                    tool: "deleteOneNote".to_owned(),
                    arguments: BTreeMap::new(),
                }),
            }],
            result: None,
            limits: crate::tools::composite::CompositeLimits::default(),
        };

        assert_eq!(
            composite_mapping(&mapping, &definitions).expect("composite projection"),
            CapabilityMapping::Composite {
                steps: vec![CapabilityCompositeStep {
                    id: "note".to_owned(),
                    tool: "createOneNote".to_owned(),
                    method: "POST".to_owned(),
                    path_template: "/notes".to_owned(),
                    has_compensation: true,
                    for_each: true,
                }]
            }
        );
    }

    #[test]
    fn capability_actions_use_only_the_stable_public_reason_vocabulary() {
        let definition = ToolDefinition {
            name: "playground_action_test".to_owned(),
            title: None,
            description: "Action-state test tool".to_owned(),
            input_schema: json!({"type": "object"}),
            target: None,
            source: ToolSource::Manual,
            upstream: HttpToolMapping {
                method: "GET".to_owned(),
                path_template: "/action-test".to_owned(),
                query_params: Vec::new(),
                body: None,
            },
            composite: None,
            enum_bindings: Vec::new(),
            visibility: crate::tools::definitions::ToolVisibility::Listed,
            transform: None,
            annotations: None,
        };
        let mut capability = BuiltCapability {
            summary: CapabilitySummary {
                id: capability_id(&["tool", definition.name.as_str()]),
                kind: CapabilityKind::Tool,
                name: definition.name.clone(),
                title: None,
                annotations: None,
                uri: None,
                uri_template: None,
                description: Some(definition.description.clone()),
                description_truncated: false,
                source: CapabilitySource::ManualFile,
                connection: None,
                schema_digest: None,
                discovered_at: None,
                last_success_at: None,
                visibility: None,
                state: CapabilityState {
                    enabled: true,
                    available: true,
                    stale: false,
                    reason: "internal-state-reason-must-not-leak",
                },
                policy: CapabilityPolicyEligibility {
                    eligible: true,
                    reason: "internal-policy-reason-must-not-leak",
                },
            },
            input_schema: Some(definition.input_schema.clone()),
            mapping: None,
            transform: None,
            dynamic_enums: Vec::new(),
            registered_definition: Some(definition),
            execution_revision: Some(CapabilityExecutionRevision::Manual {
                connection_etag: None,
            }),
        };

        assert_eq!(
            capability_actions(&capability, true, true),
            CapabilityActions {
                can_execute: true,
                reason: "allowed",
            }
        );

        capability.dynamic_enums = vec![CapabilityDynamicEnum {
            property: "status".to_owned(),
            source_id: "statuses".to_owned(),
            state: EnumSourceState::Fresh,
            item_count: 2,
            values_revision: Some(7),
            resolved_at: Some("2026-09-03T00:00:00Z".to_owned()),
        }];
        let fresh_detail = capability_detail_result(capability.clone(), true, true)
            .expect("fresh dynamic enum detail should build");
        capability.dynamic_enums[0].state = EnumSourceState::Stale;
        capability.dynamic_enums[0].item_count = 3;
        capability.dynamic_enums[0].values_revision = Some(8);
        let refreshed_detail = capability_detail_result(capability.clone(), true, true)
            .expect("refreshed dynamic enum detail should build");
        assert_eq!(
            refreshed_detail.detail.dynamic_enums[0].state,
            EnumSourceState::Stale
        );
        assert_eq!(refreshed_detail.detail.dynamic_enums[0].item_count, 3);
        assert_eq!(
            fresh_detail.execution_etag(),
            refreshed_detail.execution_etag(),
            "serve-time enum refreshes must not churn the playground execution ETag"
        );

        assert_eq!(
            capability_actions(&capability, false, true).reason,
            "permission_denied"
        );
        assert_eq!(
            capability_actions(&capability, true, false).reason,
            "executor_unavailable"
        );

        capability.summary.state.enabled = false;
        assert_eq!(
            capability_actions(&capability, true, true).reason,
            "disabled"
        );
        capability.summary.state.enabled = true;
        capability.summary.state.stale = true;
        assert_eq!(capability_actions(&capability, true, true).reason, "stale");
        capability.summary.state.stale = false;
        capability.summary.state.available = false;
        assert_eq!(
            capability_actions(&capability, true, true).reason,
            "unavailable"
        );
        capability.summary.state.available = true;
        capability.summary.policy.eligible = false;
        assert_eq!(
            capability_actions(&capability, true, true).reason,
            "policy_denied"
        );
        capability.summary.policy.eligible = true;
        capability.registered_definition = None;
        assert_eq!(capability_actions(&capability, true, true).reason, "stale");
        capability.summary.kind = CapabilityKind::Resource;
        assert_eq!(
            capability_actions(&capability, true, true).reason,
            "metadata_only"
        );
    }

    #[tokio::test]
    async fn execution_etag_binds_detail_action_definition_and_managed_revisions() {
        let fixture = ManagedInventoryFixture::new("execution-etag-binding").await;
        let built = fixture
            .inventory
            .build(&fixture.rbac_state, &fixture.principal)
            .await
            .expect("managed inventory should build")
            .into_iter()
            .find(|capability| capability.summary.name == fixture.openapi_tool_name)
            .expect("OpenAPI tool should exist");
        let capability_id = built.summary.id.clone();
        let definition = built
            .registered_definition
            .as_ref()
            .expect("OpenAPI tool should be registered")
            .clone();
        let detail = fixture
            .inventory
            .detail(
                &fixture.rbac_state,
                &fixture.principal,
                &capability_id,
                true,
                true,
            )
            .await
            .expect("detail should build")
            .expect("detail should exist");
        let recomputed = fixture
            .inventory
            .execution_etag_for_definition(&fixture.rbac_state, &fixture.principal, &definition)
            .await
            .expect("execution ETag should recompute")
            .expect("registered tool should remain executable");
        assert_eq!(detail.execution_etag(), recomputed);

        let permission_denied =
            capability_detail_result(built.clone(), false, true).expect("detail should hash");
        assert_ne!(
            detail.execution_etag(),
            permission_denied.execution_etag(),
            "action changes must change the validator"
        );

        let mut changed_definition = built.clone();
        changed_definition
            .registered_definition
            .as_mut()
            .expect("definition should exist")
            .description
            .push_str(" changed");
        let changed_definition =
            capability_detail_result(changed_definition, true, true).expect("detail should hash");
        assert_ne!(
            detail.execution_etag(),
            changed_definition.execution_etag(),
            "the exact full registered definition must be bound"
        );

        let mut changed_revision = built;
        let Some(CapabilityExecutionRevision::Openapi {
            connection_etag,
            catalog_revision,
            spec_revision,
            spec_digest,
        }) = changed_revision.execution_revision.as_mut()
        else {
            panic!("OpenAPI execution revision should exist");
        };
        connection_etag.push_str("-changed");
        *catalog_revision = catalog_revision.saturating_add(1);
        *spec_revision = spec_revision.saturating_add(1);
        spec_digest.push_str("-changed");
        let changed_revision =
            capability_detail_result(changed_revision, true, true).expect("detail should hash");
        assert_ne!(
            detail.execution_etag(),
            changed_revision.execution_etag(),
            "connection, catalog, and spec revisions must be bound"
        );

        let mut stale_definition = definition;
        stale_definition.description.push_str(" stale");
        assert_eq!(
            fixture
                .inventory
                .execution_etag_for_definition(
                    &fixture.rbac_state,
                    &fixture.principal,
                    &stale_definition,
                )
                .await
                .expect("stale definition check should complete"),
            None,
            "an exact definition not present in the current registry must fail closed"
        );
    }

    #[test]
    fn omitted_legacy_mcp_projection_keeps_safe_available_attribution() {
        let omitted_server_name = format!("server-{MAX_CONNECTIONS}");
        let mut config = Config::test_defaults();
        config.mcp_upstream_servers = (0..=MAX_CONNECTIONS)
            .map(|index| McpUpstreamServerConfig {
                name: format!("server-{index}"),
                url: format!("https://mcp-{index}.example.test"),
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
            })
            .collect();
        let control_plane = ConnectionControlPlane::from_config(&config)
            .expect("legacy projection overflow should remain supported");
        let snapshot = control_plane.runtime_snapshot();
        assert_eq!(snapshot.omitted_legacy_projection_count(), 1);
        assert!(snapshot.legacy().iter().all(|projection| {
            projection.legacy_mcp_server_name() != Some(omitted_server_name.as_str())
        }));

        let definition = ToolDefinition::mcp_proxy(
            "overflow:lookup".to_owned(),
            "Look up an overflow item".to_owned(),
            json!({"type": "object"}),
            omitted_server_name.clone(),
            "lookup".to_owned(),
        );
        let connections = connection_contexts(&snapshot, &BTreeMap::new());
        let (source, connection, state) = local_tool_context(&definition, &snapshot, &connections)
            .expect("overflow attribution should build");
        let expected_id = projected_legacy_mcp_connection_id(&omitted_server_name)
            .expect("overflow projection identity should be valid");

        assert!(matches!(
            &source,
            CapabilitySource::ProjectedLegacyConfig {
                connection_id,
                remote_tool_name,
            } if connection_id == expected_id.as_str() && remote_tool_name == "lookup"
        ));
        assert_eq!(
            connection,
            Some(CapabilityConnection {
                id: expected_id,
                kind: ConnectionKind::McpStreamableHttp,
                management_source: ConnectionManagementSource::LegacyMcp,
            })
        );
        assert!(state.enabled && state.available && !state.stale);
        assert_eq!(state.reason, "available");
        assert!(!serde_json::to_string(&source)
            .expect("safe attribution should serialize")
            .contains("example.test"));

        let mut unknown_manual = definition;
        unknown_manual.source = ToolSource::Manual;
        let (source, connection, state) =
            local_tool_context(&unknown_manual, &snapshot, &connections)
                .expect("manual missing-connection attribution should build");
        assert_eq!(source, CapabilitySource::ManualFile);
        assert!(connection.is_none());
        assert!(state.enabled && !state.available && !state.stale);
        assert_eq!(state.reason, "connection_not_found");
    }

    #[test]
    fn opaque_ids_are_stable_and_do_not_embed_identity() {
        let first = capability_id(&["tool", "billing.get"]);
        let second = capability_id(&["tool", "billing.get"]);
        assert_eq!(first, second);
        assert!(valid_capability_id(&first));
        assert!(!first.contains("billing"));
        assert_ne!(first, capability_id(&["tool", "billing.put"]));
        assert_ne!(
            capability_id(&["resource", "alpha", "file:///same"]),
            capability_id(&["resource", "beta", "file:///same"])
        );
    }

    #[test]
    fn cursor_is_bounded_and_bound_to_normalized_filters() {
        let filters = NormalizedFilters {
            kind: Some(CapabilityKind::Tool),
            connection_id: Some("billing".to_owned()),
            source: Some(CapabilitySourceFilter::ManualFile),
            available: Some(true),
            availability: None,
            text: Some("invoice".to_owned()),
        };
        let cursor = CapabilityCursor {
            after_id: capability_id(&["tool", "billing.get"]),
            collection_etag: "\"capabilities:sha256:test\"".to_owned(),
            filters,
        };
        let encoded = encode_cursor(&cursor).expect("cursor should encode");
        assert_eq!(decode_cursor(&encoded), Ok(cursor));
        assert_eq!(
            decode_cursor(&"f".repeat(MAX_CURSOR_BYTES + 1)),
            Err(CapabilityInventoryError::InvalidCursor)
        );
    }

    #[test]
    fn descriptions_are_bounded_without_exposing_hidden_text() {
        let input = format!("{}secret-tail", "x".repeat(MAX_PUBLIC_DESCRIPTION_CHARS));
        let (description, truncated) = bounded_description(Some(&input));
        assert!(truncated);
        let description = description.expect("description should be present");
        assert_eq!(description.chars().count(), MAX_PUBLIC_DESCRIPTION_CHARS);
        assert!(!description.contains("secret-tail"));
    }

    #[tokio::test]
    async fn managed_catalog_inventory_has_typed_provenance_and_metadata_only_resources() {
        let fixture = ManagedInventoryFixture::new("typed-provenance").await;
        let mcp_tools = fixture
            .list(CapabilityListParams {
                kind: Some(CapabilityKind::Tool),
                connection_id: Some(fixture.mcp_record.id.to_string()),
                source: Some(CapabilitySourceFilter::McpDiscovery),
                available: Some(true),
                ..CapabilityListParams::default()
            })
            .await;
        assert_eq!(mcp_tools.total_count, 1);
        let mcp_tool = &mcp_tools.capabilities[0];
        assert_eq!(mcp_tool.name, fixture.mcp_tool_name);
        assert_eq!(mcp_tool.title.as_deref(), Some("Inventory MCP lookup"));
        assert_eq!(
            mcp_tool
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.read_only_hint),
            Some(true)
        );
        assert!(matches!(
            &mcp_tool.source,
            CapabilitySource::McpDiscovery {
                connection_id,
                remote_tool_name: Some(remote_tool_name),
            } if connection_id == fixture.mcp_record.id.as_str()
                && remote_tool_name == "lookup"
        ));
        assert_eq!(
            mcp_tool
                .connection
                .as_ref()
                .map(|connection| &connection.id),
            Some(&fixture.mcp_record.id)
        );
        assert!(mcp_tool.policy.eligible);
        assert_eq!(mcp_tool.policy.reason, "eligible");

        let resources = fixture
            .list(CapabilityListParams {
                kind: Some(CapabilityKind::Resource),
                connection_id: Some(fixture.mcp_record.id.to_string()),
                source: Some(CapabilitySourceFilter::McpDiscovery),
                availability: Some(CapabilityAvailabilityFilter::Available),
                text: Some("inventory-resource".to_owned()),
                ..CapabilityListParams::default()
            })
            .await;
        assert_eq!(resources.total_count, 1);
        let resource = &resources.capabilities[0];
        assert_eq!(resource.uri.as_deref(), Some("urn:inventory:resource"));
        assert!(!resource.policy.eligible);
        assert_eq!(resource.policy.reason, "metadata_only");
        let detail = fixture
            .inventory
            .detail(
                &fixture.rbac_state,
                &fixture.principal,
                &resource.id,
                true,
                true,
            )
            .await
            .expect("resource detail should build")
            .expect("resource detail should exist")
            .detail;
        assert!(detail.input_schema.is_none());
        assert!(matches!(
            detail.mapping,
            Some(CapabilityMapping::Resource {
                ref uri,
                ref mime_type,
                size: Some(42),
            }) if uri == "urn:inventory:resource"
                && mime_type.as_deref() == Some("application/json")
        ));
        let encoded = serde_json::to_string(&detail).expect("resource detail should serialize");
        assert!(!encoded.contains("contents"));
        assert!(!encoded.contains("resource-content-canary"));

        let templates = fixture
            .list(CapabilityListParams {
                kind: Some(CapabilityKind::ResourceTemplate),
                connection_id: Some(fixture.mcp_record.id.to_string()),
                source: Some(CapabilitySourceFilter::McpDiscovery),
                ..CapabilityListParams::default()
            })
            .await;
        assert_eq!(templates.total_count, 1);
        assert_eq!(
            templates.capabilities[0].uri_template.as_deref(),
            Some("urn:inventory:item:{id}")
        );
        assert_eq!(templates.capabilities[0].policy.reason, "metadata_only");

        let openapi_tools = fixture
            .list(CapabilityListParams {
                kind: Some(CapabilityKind::Tool),
                source: Some(CapabilitySourceFilter::Openapi),
                ..CapabilityListParams::default()
            })
            .await;
        assert_eq!(openapi_tools.total_count, 1);
        let openapi_tool = &openapi_tools.capabilities[0];
        assert_eq!(openapi_tool.name, fixture.openapi_tool_name);
        assert!(matches!(
            &openapi_tool.source,
            CapabilitySource::Openapi {
                operation_id: Some(operation_id),
                catalog_revision: 1,
                spec_revision: 1,
                ..
            } if operation_id == "inventoryLookup"
        ));
        assert!(openapi_tool.policy.eligible);
    }

    #[tokio::test]
    async fn connection_counts_build_once_and_include_all_managed_capability_kinds() {
        let fixture = ManagedInventoryFixture::new("connection-counts").await;
        let manual_mapping = HttpToolMapping {
            method: "GET".to_owned(),
            path_template: "/unassociated".to_owned(),
            query_params: Vec::new(),
            body: None,
        };
        fixture
            .inventory
            .registry
            .merge_definitions(vec![ToolDefinition {
                name: "unassociated_manual_capability".to_owned(),
                title: None,
                description: "Manual capability without a connection".to_owned(),
                input_schema: json!({"type": "object"}),
                target: None,
                source: ToolSource::Manual,
                upstream: manual_mapping,
                composite: None,
                enum_bindings: Vec::new(),
                visibility: crate::tools::definitions::ToolVisibility::Listed,
                transform: None,
                annotations: None,
            }])
            .expect("unassociated manual capability should publish");

        let counts = fixture
            .inventory
            .connection_counts(&fixture.rbac_state, &fixture.principal)
            .await
            .expect("connection capability counts should build");

        assert_eq!(counts.get(&fixture.mcp_record.id), Some(&3));
        assert_eq!(counts.get(&fixture.openapi_record.id), Some(&1));
        assert_eq!(counts.values().sum::<usize>(), 4);
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn connection_count_fold_accepts_exact_inventory_bound_and_rejects_the_next_entry() {
        assert_eq!(MAX_CAPABILITY_INVENTORY_ENTRIES, 8_192);
        let first_connection = ConnectionId::parse("00000000-0000-0000-0000-000000000001")
            .expect("first connection ID should parse");
        let second_connection = ConnectionId::parse("00000000-0000-0000-0000-000000000002")
            .expect("second connection ID should parse");
        let mut capabilities = BTreeMap::new();
        for index in 0..MAX_CAPABILITY_INVENTORY_ENTRIES {
            let connection = if index % 2 == 0 {
                first_connection.clone()
            } else {
                second_connection.clone()
            };
            insert_capability(
                &mut capabilities,
                BuiltCapability {
                    summary: CapabilitySummary {
                        id: format!("bounded-capability-{index:05}"),
                        kind: CapabilityKind::Tool,
                        name: format!("bounded_tool_{index:05}"),
                        title: None,
                        annotations: None,
                        uri: None,
                        uri_template: None,
                        description: None,
                        description_truncated: false,
                        source: CapabilitySource::ManualFile,
                        connection: Some(CapabilityConnection {
                            id: connection,
                            kind: ConnectionKind::HttpApi,
                            management_source: ConnectionManagementSource::Managed,
                        }),
                        schema_digest: None,
                        discovered_at: None,
                        last_success_at: None,
                        visibility: None,
                        state: CapabilityState {
                            enabled: true,
                            available: true,
                            stale: false,
                            reason: "available",
                        },
                        policy: CapabilityPolicyEligibility {
                            eligible: true,
                            reason: "eligible",
                        },
                    },
                    input_schema: None,
                    mapping: None,
                    transform: None,
                    dynamic_enums: Vec::new(),
                    registered_definition: None,
                    execution_revision: None,
                },
            )
            .expect("capability at the exact bound should insert");
        }
        let overflow = insert_capability(
            &mut capabilities,
            BuiltCapability {
                summary: CapabilitySummary {
                    id: "bounded-capability-overflow".to_owned(),
                    kind: CapabilityKind::Tool,
                    name: "bounded_tool_overflow".to_owned(),
                    title: None,
                    annotations: None,
                    uri: None,
                    uri_template: None,
                    description: None,
                    description_truncated: false,
                    source: CapabilitySource::ManualFile,
                    connection: None,
                    schema_digest: None,
                    discovered_at: None,
                    last_success_at: None,
                    visibility: None,
                    state: CapabilityState {
                        enabled: true,
                        available: true,
                        stale: false,
                        reason: "available",
                    },
                    policy: CapabilityPolicyEligibility {
                        eligible: true,
                        reason: "eligible",
                    },
                },
                input_schema: None,
                mapping: None,
                transform: None,
                dynamic_enums: Vec::new(),
                registered_definition: None,
                execution_revision: None,
            },
        );
        assert_eq!(overflow, Err(CapabilityInventoryError::CardinalityExceeded));

        let counts = connection_counts_from_capabilities(capabilities.into_values());
        assert_eq!(
            counts.get(&first_connection),
            Some(&(MAX_CAPABILITY_INVENTORY_ENTRIES / 2))
        );
        assert_eq!(
            counts.get(&second_connection),
            Some(&(MAX_CAPABILITY_INVENTORY_ENTRIES / 2))
        );
        assert_eq!(
            counts.values().sum::<usize>(),
            MAX_CAPABILITY_INVENTORY_ENTRIES
        );
    }

    #[tokio::test]
    async fn disabled_connection_retains_catalog_as_stale_unavailable_metadata() {
        let fixture = ManagedInventoryFixture::new("disabled-stale").await;
        let mut disabled = fixture.mcp_record.write.clone();
        disabled.enabled = false;
        fixture
            .control_plane
            .replace_managed(
                &fixture.mcp_record.id,
                &fixture.mcp_record.etag(),
                disabled,
                "test-admin",
            )
            .await
            .expect("managed MCP Connection should disable");

        let stale = fixture
            .list(CapabilityListParams {
                connection_id: Some(fixture.mcp_record.id.to_string()),
                availability: Some(CapabilityAvailabilityFilter::Stale),
                ..CapabilityListParams::default()
            })
            .await;
        assert_eq!(
            stale.total_count, 3,
            "tool, resource, and template should remain visible as last-known-good metadata"
        );
        assert!(stale.capabilities.iter().all(|capability| {
            !capability.state.enabled
                && !capability.state.available
                && capability.state.stale
                && capability.state.reason == "connection_disabled"
        }));
        assert!(stale
            .capabilities
            .iter()
            .filter(|capability| capability.kind != CapabilityKind::Tool)
            .all(|capability| {
                !capability.policy.eligible && capability.policy.reason == "metadata_only"
            }));
    }
}
