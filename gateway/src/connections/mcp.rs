use std::{
    collections::BTreeMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::tools::{
    definitions::{
        McpCatalogPublishError, ToolDefinition, ToolRegistry, ToolRegistryError, ToolSource,
        ToolTarget,
    },
    mcp_upstream::{self, McpUpstreamCallError},
};

use super::{
    control_plane::{CatalogMutationGuard, CatalogRefreshGuard, ConnectionControlPlane},
    http::ConnectionHttpRuntime,
    model::{ConnectionId, ConnectionKind, DiscoveryConfig},
    status::{ConnectionOperationalState, ConnectionStatusReason, SafeConnectionStatus},
    store::{
        ConnectionEtag, ConnectionStatusUpdate, ConnectionStoreError, StoredConnection,
        StoredMcpCatalog, StoredMcpCatalogEntry, StoredMcpResource, StoredMcpResourceTemplate,
    },
};

#[derive(Clone)]
pub struct McpConnectionCatalogRuntime {
    state: Arc<ArcSwap<BTreeMap<ConnectionId, ActiveMcpCatalog>>>,
}

#[derive(Clone, Debug)]
struct ActiveMcpCatalog {
    observed_etag: String,
    catalog_revision: u64,
    refreshed_at: String,
    entry_count: usize,
    resources: Arc<[StoredMcpResource]>,
    resource_templates: Arc<[StoredMcpResourceTemplate]>,
}

#[derive(Clone)]
pub struct McpConnectionCatalogService {
    control_plane: ConnectionControlPlane,
    http: ConnectionHttpRuntime,
    registry: ToolRegistry,
    runtime: McpConnectionCatalogRuntime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpCatalogRefreshResult {
    pub connection_id: ConnectionId,
    pub catalog_revision: u64,
    pub status: SafeConnectionStatus,
    pub total_count: usize,
    pub added_count: usize,
    pub changed_count: usize,
    pub removed_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpCatalogRefreshError {
    StoreUnavailable,
    InvalidConnectionId,
    ConnectionNotFound,
    ConnectionDisabled,
    ConnectionKindMismatch,
    DiscoveryNotConfigured,
    PreconditionFailed,
    RefreshInProgress,
    EgressDenied,
    SecretUnavailable,
    AuthenticationFailed,
    RequestFailed,
    InvalidResponse,
    StorageUnavailable,
}

impl McpCatalogRefreshError {
    pub const fn safe_reason(self) -> &'static str {
        match self {
            Self::StoreUnavailable => "connection_store_not_configured",
            Self::InvalidConnectionId => "invalid_connection_id",
            Self::ConnectionNotFound => "connection_not_found",
            Self::ConnectionDisabled => "connection_disabled",
            Self::ConnectionKindMismatch => "connection_kind_mismatch",
            Self::DiscoveryNotConfigured => "discovery_not_configured",
            Self::PreconditionFailed => "connection_changed",
            Self::RefreshInProgress => "refresh_in_progress",
            Self::EgressDenied => "egress_denied",
            Self::SecretUnavailable => "secret_unavailable",
            Self::AuthenticationFailed => "auth_failed",
            Self::RequestFailed => "request_failed",
            Self::InvalidResponse => "invalid_response",
            Self::StorageUnavailable => "storage_unavailable",
        }
    }
}

impl fmt::Display for McpCatalogRefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed MCP catalog refresh failed: {}",
            self.safe_reason()
        )
    }
}

impl std::error::Error for McpCatalogRefreshError {}

impl McpConnectionCatalogRuntime {
    fn new(catalogs: &[StoredMcpCatalog]) -> Self {
        let state = catalogs
            .iter()
            .map(|catalog| {
                (
                    catalog.connection_id.clone(),
                    ActiveMcpCatalog {
                        observed_etag: catalog.observed_etag.to_string(),
                        catalog_revision: catalog.catalog_revision,
                        refreshed_at: catalog.refreshed_at.clone(),
                        entry_count: catalog_total_count(catalog),
                        resources: Arc::from(catalog.resources.clone()),
                        resource_templates: Arc::from(catalog.resource_templates.clone()),
                    },
                )
            })
            .collect();
        Self {
            state: Arc::new(ArcSwap::from_pointee(state)),
        }
    }

    pub fn expected_connection_etag(&self, connection_id: &str) -> Option<String> {
        let id = ConnectionId::parse(connection_id.to_owned()).ok()?;
        self.state
            .load()
            .get(&id)
            .map(|catalog| catalog.observed_etag.clone())
    }

    fn publish(&self, catalog: &StoredMcpCatalog) {
        self.publish_active(
            catalog.connection_id.clone(),
            ActiveMcpCatalog {
                observed_etag: catalog.observed_etag.to_string(),
                catalog_revision: catalog.catalog_revision,
                refreshed_at: catalog.refreshed_at.clone(),
                entry_count: catalog_total_count(catalog),
                resources: Arc::from(catalog.resources.clone()),
                resource_templates: Arc::from(catalog.resource_templates.clone()),
            },
        );
    }

    fn publish_active(&self, connection_id: ConnectionId, catalog: ActiveMcpCatalog) {
        self.state.rcu(|current| {
            let mut next = current.as_ref().clone();
            next.insert(connection_id.clone(), catalog.clone());
            Arc::new(next)
        });
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
            catalog_entry_count: Some(catalog.entry_count),
        })
    }
}

impl McpConnectionCatalogService {
    pub fn load(
        control_plane: ConnectionControlPlane,
        http: ConnectionHttpRuntime,
        registry: ToolRegistry,
    ) -> Result<Self, ConnectionStoreError> {
        let catalogs = if control_plane.is_managed_store_configured() {
            control_plane
                .managed_store()
                .map_err(|_| ConnectionStoreError::Validation {
                    problems: vec!["managed Connection store is unavailable".to_owned()],
                })?
                .mcp_catalogs()?
        } else {
            Vec::new()
        };
        let definitions = catalogs
            .iter()
            .flat_map(catalog_definitions)
            .collect::<Vec<_>>();
        registry
            .merge_definitions(definitions)
            .map_err(tool_registry_store_error)?;
        let runtime = McpConnectionCatalogRuntime::new(&catalogs);
        Ok(Self {
            control_plane,
            http,
            registry,
            runtime,
        })
    }

    pub fn runtime(&self) -> McpConnectionCatalogRuntime {
        self.runtime.clone()
    }

    pub(crate) fn begin_connection_mutation(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<CatalogMutationGuard, McpCatalogRefreshError> {
        self.control_plane
            .begin_catalog_mutation(connection_id)
            .map_err(|_| McpCatalogRefreshError::RefreshInProgress)
    }

    fn begin_connection_refresh(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<CatalogRefreshGuard, McpCatalogRefreshError> {
        self.control_plane
            .begin_catalog_refresh(connection_id)
            .map_err(|_| McpCatalogRefreshError::RefreshInProgress)
    }

    pub fn reconcile_connection(&self, record: &StoredConnection) {
        if !supports_managed_mcp_catalog(record) {
            self.runtime.remove(&record.id);
        }
    }

    pub fn remove_connection(&self, connection_id: &ConnectionId) {
        self.runtime.remove(connection_id);
    }

    pub fn status_fallback(
        &self,
        connection_id: &ConnectionId,
        current_etag: &ConnectionEtag,
        stored: Option<SafeConnectionStatus>,
    ) -> Option<SafeConnectionStatus> {
        stored.or_else(|| self.runtime.catalog_status(connection_id, current_etag))
    }

    pub async fn refresh(
        &self,
        raw_connection_id: &str,
        expected_etag: &str,
    ) -> Result<McpCatalogRefreshResult, McpCatalogRefreshError> {
        if !self.control_plane.is_managed_store_configured() {
            return Err(McpCatalogRefreshError::StoreUnavailable);
        }
        let connection_id = ConnectionId::parse(raw_connection_id.to_owned())
            .map_err(|_| McpCatalogRefreshError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(McpCatalogRefreshError::ConnectionNotFound)?;
        if record.etag().as_str() != expected_etag {
            return Err(McpCatalogRefreshError::PreconditionFailed);
        }
        if !record.write.enabled {
            return Err(McpCatalogRefreshError::ConnectionDisabled);
        }
        if record.write.kind != ConnectionKind::McpStreamableHttp {
            return Err(McpCatalogRefreshError::ConnectionKindMismatch);
        }
        if !matches!(
            &record.write.discovery,
            Some(DiscoveryConfig::ManagedMcp { .. })
        ) {
            return Err(McpCatalogRefreshError::DiscoveryNotConfigured);
        }
        let target_error = self.http.mcp_target(connection_id.as_str()).err();
        if let Some(error) = target_error {
            return Err(match error.safe_reason() {
                "connection_disabled" => McpCatalogRefreshError::ConnectionDisabled,
                "connection_kind_mismatch" => McpCatalogRefreshError::ConnectionKindMismatch,
                "invalid_connection_id" => McpCatalogRefreshError::InvalidConnectionId,
                "connection_not_found" => McpCatalogRefreshError::ConnectionNotFound,
                _ => McpCatalogRefreshError::DiscoveryNotConfigured,
            });
        }

        let active = self.begin_connection_refresh(&connection_id)?;
        let started = Instant::now();
        let store = self
            .control_plane
            .managed_store()
            .map_err(|_| McpCatalogRefreshError::StoreUnavailable)?;
        let prior = store
            .mcp_catalog(&connection_id)
            .map_err(|_| McpCatalogRefreshError::StorageUnavailable)?;

        let candidate = match mcp_upstream::discover_connection_catalog(
            &self.http,
            connection_id.as_str(),
            record.etag().as_str(),
        )
        .await
        {
            Ok(candidate) => candidate,
            Err(error) => {
                let failure = refresh_transport_error(&error);
                self.record_failed_status(
                    &connection_id,
                    &record.etag(),
                    prior.as_ref(),
                    failure,
                    started.elapsed(),
                );
                drop(active);
                return Err(failure);
            }
        };
        let stored_entries = match candidate
            .tools
            .iter()
            .map(definition_store_entry)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(entries) => entries,
            Err(failure) => {
                self.record_failed_status(
                    &connection_id,
                    &record.etag(),
                    prior.as_ref(),
                    failure,
                    started.elapsed(),
                );
                return Err(failure);
            }
        };
        let counts = catalog_change_counts(
            prior.as_ref(),
            &stored_entries,
            &candidate.resources,
            &candidate.resource_templates,
        );
        let mcp_upstream::McpDiscoveredCatalog {
            tools,
            resources,
            resource_templates,
        } = candidate;
        let mut persisted = None;
        let expected = record.etag();
        let publish =
            self.registry
                .replace_mcp_connection_catalog(connection_id.as_str(), tools, || {
                    let catalog = store.replace_mcp_catalog(
                        &connection_id,
                        &expected,
                        &stored_entries,
                        &resources,
                        &resource_templates,
                    )?;
                    persisted = Some(catalog);
                    Ok::<(), ConnectionStoreError>(())
                });
        if let Err(error) = publish {
            let failure = match error {
                McpCatalogPublishError::Registry(error) => {
                    drop(error);
                    McpCatalogRefreshError::InvalidResponse
                }
                McpCatalogPublishError::Persist(error) => refresh_store_error(&error),
            };
            self.record_failed_status(
                &connection_id,
                &expected,
                prior.as_ref(),
                failure,
                started.elapsed(),
            );
            drop(active);
            return Err(failure);
        }
        let catalog = persisted.ok_or(McpCatalogRefreshError::StorageUnavailable)?;
        let total_count = catalog_total_count(&catalog);
        self.runtime.publish(&catalog);
        let status = self
            .control_plane
            .append_status(
                &connection_id,
                &expected,
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::CatalogRefreshed,
                    latency_ms: Some(duration_millis(started.elapsed())),
                    catalog_age_secs: Some(0),
                    catalog_entry_count: Some(total_count),
                },
            )
            .unwrap_or_else(|error| {
                tracing::error!(
                    connection_id = %connection_id,
                    error = %error,
                    "MCP catalog was published but its safe status could not be recorded"
                );
                SafeConnectionStatus {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::CatalogRefreshed,
                    observed_at: Some(catalog.refreshed_at.clone()),
                    latency_ms: Some(duration_millis(started.elapsed())),
                    catalog_age_secs: Some(0),
                    catalog_entry_count: Some(total_count),
                }
            });
        drop(active);
        Ok(McpCatalogRefreshResult {
            connection_id,
            catalog_revision: catalog.catalog_revision,
            status,
            total_count,
            added_count: counts.0,
            changed_count: counts.1,
            removed_count: counts.2,
        })
    }

    fn record_failed_status(
        &self,
        connection_id: &ConnectionId,
        expected: &ConnectionEtag,
        prior: Option<&StoredMcpCatalog>,
        failure: McpCatalogRefreshError,
        elapsed: Duration,
    ) {
        let (state, reason, age, count) = if let Some(prior) = prior {
            (
                ConnectionOperationalState::Degraded,
                ConnectionStatusReason::CatalogStale,
                Some(timestamp_age_seconds(&prior.refreshed_at)),
                Some(catalog_total_count(prior)),
            )
        } else {
            let reason = match failure {
                McpCatalogRefreshError::EgressDenied => ConnectionStatusReason::EgressDenied,
                McpCatalogRefreshError::SecretUnavailable => {
                    ConnectionStatusReason::SecretUnavailable
                }
                McpCatalogRefreshError::InvalidResponse
                | McpCatalogRefreshError::AuthenticationFailed => {
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
        if let Err(error) = self.control_plane.append_status(
            connection_id,
            expected,
            ConnectionStatusUpdate {
                state,
                reason,
                latency_ms: Some(duration_millis(elapsed)),
                catalog_age_secs: age,
                catalog_entry_count: count,
            },
        ) {
            tracing::error!(
                connection_id = %connection_id,
                error = %error,
                "failed to persist bounded MCP refresh failure status"
            );
        }
    }
}

fn supports_managed_mcp_catalog(record: &StoredConnection) -> bool {
    record.write.kind == ConnectionKind::McpStreamableHttp
        && matches!(
            &record.write.discovery,
            Some(DiscoveryConfig::ManagedMcp { .. })
        )
}

fn catalog_definitions(catalog: &StoredMcpCatalog) -> impl Iterator<Item = ToolDefinition> + '_ {
    catalog.entries.iter().map(|entry| {
        ToolDefinition::mcp_connection(
            catalog.connection_id.to_string(),
            entry.description.clone(),
            entry.input_schema.clone(),
            entry.remote_tool_name.clone(),
        )
    })
}

fn definition_store_entry(
    definition: &ToolDefinition,
) -> Result<StoredMcpCatalogEntry, McpCatalogRefreshError> {
    let (target_connection_id, target_remote_tool_name) = match &definition.target {
        Some(ToolTarget::Mcp {
            connection_id,
            remote_tool_name,
        }) => (connection_id, remote_tool_name),
        _ => return Err(McpCatalogRefreshError::InvalidResponse),
    };
    match &definition.source {
        ToolSource::Mcp {
            connection_id,
            remote_tool_name,
        } if connection_id == target_connection_id
            && remote_tool_name == target_remote_tool_name =>
        {
            Ok(StoredMcpCatalogEntry {
                remote_tool_name: remote_tool_name.clone(),
                description: definition.description.clone(),
                input_schema: definition.input_schema.clone(),
            })
        }
        _ => Err(McpCatalogRefreshError::InvalidResponse),
    }
}

fn catalog_change_counts(
    prior: Option<&StoredMcpCatalog>,
    candidate_entries: &[StoredMcpCatalogEntry],
    candidate_resources: &[StoredMcpResource],
    candidate_resource_templates: &[StoredMcpResourceTemplate],
) -> (usize, usize, usize) {
    let prior_entries = prior
        .into_iter()
        .flat_map(|catalog| catalog.entries.iter())
        .map(|entry| (entry.remote_tool_name.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let candidate_entries = candidate_entries
        .iter()
        .map(|entry| (entry.remote_tool_name.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let prior_resources = prior
        .into_iter()
        .flat_map(|catalog| catalog.resources.iter())
        .map(|resource| (resource.uri.as_str(), resource))
        .collect::<BTreeMap<_, _>>();
    let candidate_resources = candidate_resources
        .iter()
        .map(|resource| (resource.uri.as_str(), resource))
        .collect::<BTreeMap<_, _>>();
    let prior_resource_templates = prior
        .into_iter()
        .flat_map(|catalog| catalog.resource_templates.iter())
        .map(|resource_template| (resource_template.uri_template.as_str(), resource_template))
        .collect::<BTreeMap<_, _>>();
    let candidate_resource_templates = candidate_resource_templates
        .iter()
        .map(|resource_template| (resource_template.uri_template.as_str(), resource_template))
        .collect::<BTreeMap<_, _>>();

    let (tool_added, tool_changed, tool_removed) =
        keyed_catalog_change_counts(&prior_entries, &candidate_entries);
    let (resource_added, resource_changed, resource_removed) =
        keyed_catalog_change_counts(&prior_resources, &candidate_resources);
    let (template_added, template_changed, template_removed) =
        keyed_catalog_change_counts(&prior_resource_templates, &candidate_resource_templates);
    (
        tool_added
            .saturating_add(resource_added)
            .saturating_add(template_added),
        tool_changed
            .saturating_add(resource_changed)
            .saturating_add(template_changed),
        tool_removed
            .saturating_add(resource_removed)
            .saturating_add(template_removed),
    )
}

fn keyed_catalog_change_counts<T: PartialEq>(
    prior: &BTreeMap<&str, &T>,
    candidate: &BTreeMap<&str, &T>,
) -> (usize, usize, usize) {
    let added = candidate
        .keys()
        .filter(|name| !prior.contains_key(**name))
        .count();
    let changed = candidate
        .iter()
        .filter(|(name, entry)| prior.get(**name).is_some_and(|old| *old != **entry))
        .count();
    let removed = prior
        .keys()
        .filter(|name| !candidate.contains_key(**name))
        .count();
    (added, changed, removed)
}

fn catalog_total_count(catalog: &StoredMcpCatalog) -> usize {
    catalog
        .entries
        .len()
        .saturating_add(catalog.resources.len())
        .saturating_add(catalog.resource_templates.len())
}

fn refresh_transport_error(error: &McpUpstreamCallError) -> McpCatalogRefreshError {
    match error {
        McpUpstreamCallError::EgressRejected => McpCatalogRefreshError::EgressDenied,
        McpUpstreamCallError::AuthenticationRejected => {
            McpCatalogRefreshError::AuthenticationFailed
        }
        McpUpstreamCallError::Connection {
            reason: "connection_changed",
        } => McpCatalogRefreshError::PreconditionFailed,
        McpUpstreamCallError::Connection { reason }
            if matches!(
                *reason,
                "credential_invalid"
                    | "credential_unavailable"
                    | "oauth_token_unavailable"
                    | "oauth_token_rejected"
                    | "oauth_token_invalid_response"
                    | "oauth_token_egress_denied"
            ) =>
        {
            McpCatalogRefreshError::SecretUnavailable
        }
        McpUpstreamCallError::DiscoveryPageLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryToolLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryResourceLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryResourceTemplateLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryCapabilityLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryResponseLimitExceeded { .. }
        | McpUpstreamCallError::InvalidDiscoveryMetadata
        | McpUpstreamCallError::RequestBodyTooLarge { .. }
        | McpUpstreamCallError::ResponseTooLarge { .. } => McpCatalogRefreshError::InvalidResponse,
        McpUpstreamCallError::ClientBuild
        | McpUpstreamCallError::Connect
        | McpUpstreamCallError::Call
        | McpUpstreamCallError::Connection { .. } => McpCatalogRefreshError::RequestFailed,
    }
}

fn refresh_store_error(error: &ConnectionStoreError) -> McpCatalogRefreshError {
    match error {
        ConnectionStoreError::Conflict { .. } => McpCatalogRefreshError::PreconditionFailed,
        ConnectionStoreError::Validation { .. } | ConnectionStoreError::LimitExceeded { .. } => {
            McpCatalogRefreshError::InvalidResponse
        }
        _ => McpCatalogRefreshError::StorageUnavailable,
    }
}

fn tool_registry_store_error(error: ToolRegistryError) -> ConnectionStoreError {
    drop(error);
    ConnectionStoreError::Validation {
        problems: vec!["stored MCP catalog failed safe validation".to_owned()],
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
    use std::{
        fs,
        net::Ipv4Addr,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Barrier,
        },
    };

    use http::StatusCode;
    use serde_json::{json, Value};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    use uuid::Uuid;

    use super::*;
    use crate::{
        config::Config,
        connections::model::{ConnectionWrite, MAX_CONCURRENT_REFRESHES},
        egress::{EgressClient, EgressConfig},
    };

    struct TemporaryDatabase(PathBuf);

    impl TemporaryDatabase {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "greengateway-managed-mcp-{}.sqlite",
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
    fn concurrent_runtime_publications_and_removals_do_not_lose_updates() {
        let runtime = McpConnectionCatalogRuntime::new(&[]);
        let publication_count = 64_usize;
        let barrier = Arc::new(Barrier::new(publication_count));
        let publications = (0..publication_count)
            .map(|index| {
                let runtime = runtime.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let connection_id =
                        ConnectionId::parse(format!("{index:08x}-1111-4111-8111-111111111111"))
                            .expect("concurrent test Connection ID should validate");
                    barrier.wait();
                    runtime.publish_active(
                        connection_id,
                        ActiveMcpCatalog {
                            observed_etag: format!("\"connection:{index}\""),
                            catalog_revision: 1,
                            refreshed_at: "2026-07-28T00:00:00Z".to_owned(),
                            entry_count: 1,
                            resources: Arc::from([]),
                            resource_templates: Arc::from([]),
                        },
                    );
                })
            })
            .collect::<Vec<_>>();
        for publication in publications {
            publication
                .join()
                .expect("concurrent runtime publication should not panic");
        }

        assert_eq!(
            runtime.state.load().len(),
            publication_count,
            "atomic runtime publication must retain every concurrent Connection"
        );

        let removals = (0..publication_count)
            .map(|index| {
                let runtime = runtime.clone();
                std::thread::spawn(move || {
                    let connection_id =
                        ConnectionId::parse(format!("{index:08x}-1111-4111-8111-111111111111"))
                            .expect("concurrent removal Connection ID should validate");
                    runtime.remove(&connection_id);
                })
            })
            .collect::<Vec<_>>();
        for removal in removals {
            removal
                .join()
                .expect("concurrent runtime removal should not panic");
        }
        assert!(
            runtime.state.load().is_empty(),
            "deleted or converted Connections must not accumulate in runtime state"
        );
    }

    #[tokio::test]
    async fn refresh_publishes_complete_catalog_and_failed_candidate_keeps_last_known_good() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("managed MCP test listener should bind");
        let address = listener
            .local_addr()
            .expect("managed MCP test address should be available");
        let list_count = Arc::new(AtomicUsize::new(0));
        let resource_method_count = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn(run_mcp_catalog_server(
            listener,
            Arc::clone(&list_count),
            Arc::clone(&resource_method_count),
        ));

        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        config.egress_allowed_hosts = vec![Ipv4Addr::LOCALHOST.to_string()];
        config.egress_deny_private_ips = false;
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let snapshot = control_plane.runtime_snapshot();
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Managed MCP",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": format!("http://{address}"),
                "base_path": "/mcp"
            },
            "authentication": { "type": "none" },
            "tls": {},
            "timeouts": {
                "connect_timeout_ms": 1000,
                "request_timeout_ms": 3000,
                "response_idle_timeout_ms": 1000
            },
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": false
            }
        }))
        .expect("managed MCP Connection should deserialize");
        let record = control_plane
            .create_managed(snapshot.collection_etag(), candidate)
            .expect("managed MCP Connection should create");
        let egress_client = Arc::new(
            EgressClient::new(EgressConfig::from_config(&config))
                .expect("managed MCP egress client should build"),
        );
        let http = ConnectionHttpRuntime::new(
            control_plane.clone(),
            EgressConfig::from_config(&config),
            egress_client,
        );
        let registry = ToolRegistry::disabled();
        let service =
            McpConnectionCatalogService::load(control_plane.clone(), http, registry.clone())
                .expect("managed MCP catalog service should load");

        let first = service
            .refresh(record.id.as_str(), record.etag().as_str())
            .await
            .expect("first complete MCP catalog should publish");
        assert_eq!(first.catalog_revision, 1);
        assert_eq!(first.total_count, 1);
        assert_eq!(first.added_count, 1);
        let public_name = format!("{}:alpha", record.id);
        assert!(registry.get(&public_name).is_some());

        let failure = service
            .refresh(record.id.as_str(), record.etag().as_str())
            .await
            .expect_err("duplicate remote names should reject the whole refresh");
        assert_eq!(failure, McpCatalogRefreshError::InvalidResponse);
        assert!(registry.get(&public_name).is_some());
        assert!(registry.get(&format!("{}:duplicate", record.id)).is_none());
        let retained = control_plane
            .managed_store()
            .expect("managed store should exist")
            .mcp_catalog(&record.id)
            .expect("catalog should load")
            .expect("last-known-good catalog should remain");
        assert_eq!(retained.catalog_revision, 1);
        assert_eq!(retained.entries[0].remote_tool_name, "alpha");
        let status = control_plane
            .managed_store()
            .expect("managed store should exist")
            .latest_status(&record.id)
            .expect("status should load")
            .expect("failed refresh should record status");
        assert_eq!(status.state, ConnectionOperationalState::Degraded);
        assert_eq!(status.reason, ConnectionStatusReason::CatalogStale);
        assert_eq!(status.catalog_entry_count, Some(1));

        let mut renamed = record.write.clone();
        renamed.display_name = "Managed MCP renamed".to_owned();
        let renamed = control_plane
            .replace_managed(&record.id, &record.etag(), renamed)
            .expect("presentation-only Connection update should succeed");
        let expected_catalog_etag = service
            .runtime()
            .expected_connection_etag(record.id.as_str())
            .expect("catalog runtime should retain its observed ETag");
        assert_ne!(expected_catalog_etag, renamed.etag().as_str());
        let discovery_requests_before_stale_check = list_count.load(Ordering::SeqCst);
        assert!(matches!(
            mcp_upstream::discover_connection_catalog(
                &service.http,
                record.id.as_str(),
                &expected_catalog_etag,
            )
            .await,
            Err(McpUpstreamCallError::Connection {
                reason: "connection_changed"
            })
        ));
        assert_eq!(
            list_count.load(Ordering::SeqCst),
            discovery_requests_before_stale_check,
            "a stale refresh precondition must fail before MCP discovery egress"
        );
        assert_eq!(
            resource_method_count.load(Ordering::SeqCst),
            0,
            "resource methods must not be called when the capability is absent"
        );
        assert!(matches!(
            mcp_upstream::call_connection_tool(
                &service.http,
                record.id.as_str(),
                &expected_catalog_etag,
                "alpha",
                json!({})
            )
            .await,
            Err(McpUpstreamCallError::Connection {
                reason: "catalog_stale"
            })
        ));

        server.abort();
    }

    #[tokio::test]
    async fn discovery_paginates_resource_metadata_without_reading_resource_contents() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("resource metadata test listener should bind");
        let address = listener
            .local_addr()
            .expect("resource metadata test address should be available");
        let resource_list_count = Arc::new(AtomicUsize::new(0));
        let resource_template_list_count = Arc::new(AtomicUsize::new(0));
        let resource_read_count = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn(run_mcp_resource_catalog_server(
            listener,
            Arc::clone(&resource_list_count),
            Arc::clone(&resource_template_list_count),
            Arc::clone(&resource_read_count),
        ));

        let database = TemporaryDatabase::new();
        let mut config = Config::test_defaults();
        config.connections_sqlite_path = Some(database.0.display().to_string());
        config.egress_allowed_hosts = vec![Ipv4Addr::LOCALHOST.to_string()];
        config.egress_deny_private_ips = false;
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let candidate: ConnectionWrite = serde_json::from_value(json!({
            "display_name": "Managed MCP resources",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": format!("http://{address}"),
                "base_path": "/mcp"
            },
            "authentication": { "type": "none" },
            "tls": {},
            "timeouts": {
                "connect_timeout_ms": 1000,
                "request_timeout_ms": 3000,
                "response_idle_timeout_ms": 1000
            },
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": false
            }
        }))
        .expect("managed MCP resource Connection should deserialize");
        let snapshot = control_plane.runtime_snapshot();
        let record = control_plane
            .create_managed(snapshot.collection_etag(), candidate)
            .expect("managed MCP resource Connection should create");
        let egress_client = Arc::new(
            EgressClient::new(EgressConfig::from_config(&config))
                .expect("managed MCP resource egress client should build"),
        );
        let http = ConnectionHttpRuntime::new(
            control_plane,
            EgressConfig::from_config(&config),
            egress_client,
        );

        let catalog = mcp_upstream::discover_connection_catalog(
            &http,
            record.id.as_str(),
            record.etag().as_str(),
        )
        .await
        .expect("resource metadata discovery should succeed");
        assert_eq!(catalog.tools.len(), 1);
        assert_eq!(
            catalog
                .resources
                .iter()
                .map(|resource| resource.uri.as_str())
                .collect::<Vec<_>>(),
            vec!["gg://resource/alpha", "gg://resource/beta"]
        );
        assert_eq!(
            catalog
                .resource_templates
                .iter()
                .map(|template| template.uri_template.as_str())
                .collect::<Vec<_>>(),
            vec!["gg://resource/{id}", "gg://asset/{name}"]
        );
        let safe_resource =
            serde_json::to_value(&catalog.resources[0]).expect("safe resource should serialize");
        assert!(safe_resource.get("icons").is_none());
        assert!(safe_resource.get("_meta").is_none());
        assert!(safe_resource.get("annotations").is_none());
        assert_eq!(resource_list_count.load(Ordering::SeqCst), 2);
        assert_eq!(resource_template_list_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            resource_read_count.load(Ordering::SeqCst),
            0,
            "metadata discovery must never read resource contents"
        );

        server.abort();
    }

    #[tokio::test]
    async fn refresh_coordination_rejects_same_connection_and_global_overflow() {
        let config = Config::test_defaults();
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let egress_client = Arc::new(
            EgressClient::new(EgressConfig::from_config(&config))
                .expect("test egress client should build"),
        );
        let service = McpConnectionCatalogService::load(
            control_plane.clone(),
            ConnectionHttpRuntime::new(
                control_plane,
                EgressConfig::from_config(&config),
                egress_client,
            ),
            ToolRegistry::disabled(),
        )
        .expect("managed MCP catalog service should load");
        let first_id = ConnectionId::parse("11111111-1111-4111-8111-111111111111".to_owned())
            .expect("test Connection ID should validate");
        let first = service
            .begin_connection_refresh(&first_id)
            .expect("first refresh should acquire");
        assert!(matches!(
            service.begin_connection_refresh(&first_id),
            Err(McpCatalogRefreshError::RefreshInProgress)
        ));
        assert!(matches!(
            service.begin_connection_mutation(&first_id),
            Err(McpCatalogRefreshError::RefreshInProgress)
        ));

        let mut guards = vec![first];
        for suffix in 2..=MAX_CONCURRENT_REFRESHES {
            let id = ConnectionId::parse(format!("{suffix:08}-1111-4111-8111-111111111111"))
                .expect("test Connection ID should validate");
            guards.push(
                service
                    .begin_connection_refresh(&id)
                    .expect("distinct refresh should acquire"),
            );
        }
        let overflow_id = ConnectionId::parse("00000005-1111-4111-8111-111111111111".to_owned())
            .expect("overflow test Connection ID should validate");
        assert_eq!(
            service.begin_connection_refresh(&overflow_id).err(),
            Some(McpCatalogRefreshError::RefreshInProgress),
            "the fifth concurrent MCP refresh must preserve the safe error mapping"
        );
        drop(guards);
        let mutation = service
            .begin_connection_mutation(&first_id)
            .expect("same-Connection mutation should acquire after refresh completion");
        drop(mutation);
    }

    async fn run_mcp_catalog_server(
        listener: TcpListener,
        list_count: Arc<AtomicUsize>,
        resource_method_count: Arc<AtomicUsize>,
    ) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let list_count = Arc::clone(&list_count);
            let resource_method_count = Arc::clone(&resource_method_count);
            tokio::spawn(async move {
                let request = read_json_request(&mut stream).await;
                let method = request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                match method {
                    "initialize" => {
                        let protocol_version = request
                            .pointer("/params/protocolVersion")
                            .cloned()
                            .unwrap_or_else(|| json!("2025-06-18"));
                        write_json_response(
                            &mut stream,
                            StatusCode::OK,
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "result": {
                                    "protocolVersion": protocol_version,
                                    "capabilities": { "tools": {} },
                                    "serverInfo": { "name": "catalog-test", "version": "1.0.0" }
                                }
                            }),
                        )
                        .await;
                    }
                    "tools/list" => {
                        let tools = if list_count.fetch_add(1, Ordering::SeqCst) == 0 {
                            json!([{
                                "name": "alpha",
                                "description": "Alpha tool",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {}
                                }
                            }])
                        } else {
                            json!([
                                {
                                    "name": "duplicate",
                                    "description": "First duplicate",
                                    "inputSchema": {"type": "object", "properties": {}}
                                },
                                {
                                    "name": "duplicate",
                                    "description": "Second duplicate",
                                    "inputSchema": {"type": "object", "properties": {}}
                                }
                            ])
                        };
                        write_json_response(
                            &mut stream,
                            StatusCode::OK,
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "result": { "tools": tools }
                            }),
                        )
                        .await;
                    }
                    "resources/list" | "resources/templates/list" | "resources/read" => {
                        resource_method_count.fetch_add(1, Ordering::SeqCst);
                        write_json_response(
                            &mut stream,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "error": {
                                    "code": -32601,
                                    "message": "unexpected resource method"
                                }
                            }),
                        )
                        .await;
                    }
                    _ => {
                        write_empty_response(&mut stream, StatusCode::ACCEPTED).await;
                    }
                }
            });
        }
    }

    async fn run_mcp_resource_catalog_server(
        listener: TcpListener,
        resource_list_count: Arc<AtomicUsize>,
        resource_template_list_count: Arc<AtomicUsize>,
        resource_read_count: Arc<AtomicUsize>,
    ) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let resource_list_count = Arc::clone(&resource_list_count);
            let resource_template_list_count = Arc::clone(&resource_template_list_count);
            let resource_read_count = Arc::clone(&resource_read_count);
            tokio::spawn(async move {
                let request = read_json_request(&mut stream).await;
                let method = request
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                match method {
                    "initialize" => {
                        let protocol_version = request
                            .pointer("/params/protocolVersion")
                            .cloned()
                            .unwrap_or_else(|| json!("2025-06-18"));
                        write_json_response(
                            &mut stream,
                            StatusCode::OK,
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "result": {
                                    "protocolVersion": protocol_version,
                                    "capabilities": {
                                        "tools": {},
                                        "resources": {
                                            "subscribe": false,
                                            "listChanged": false
                                        }
                                    },
                                    "serverInfo": {
                                        "name": "resource-catalog-test",
                                        "version": "1.0.0"
                                    }
                                }
                            }),
                        )
                        .await;
                    }
                    "tools/list" => {
                        write_json_response(
                            &mut stream,
                            StatusCode::OK,
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "result": {
                                    "tools": [{
                                        "name": "alpha",
                                        "description": "Alpha tool",
                                        "inputSchema": {
                                            "type": "object",
                                            "properties": {}
                                        }
                                    }]
                                }
                            }),
                        )
                        .await;
                    }
                    "resources/list" => {
                        resource_list_count.fetch_add(1, Ordering::SeqCst);
                        let second_page = request
                            .pointer("/params/cursor")
                            .and_then(Value::as_str)
                            .is_some();
                        let result = if second_page {
                            json!({
                                "resources": [{
                                    "uri": "gg://resource/beta",
                                    "name": "resource-beta",
                                    "mimeType": "text/plain",
                                    "size": 7
                                }]
                            })
                        } else {
                            json!({
                                "resources": [{
                                    "uri": "gg://resource/alpha",
                                    "name": "resource-alpha",
                                    "title": "Alpha resource",
                                    "description": "Safe metadata",
                                    "mimeType": "application/json",
                                    "size": 42,
                                    "icons": [{
                                        "src": "https://example.test/icon.png",
                                        "mimeType": "image/png"
                                    }],
                                    "_meta": { "private": "drop-me" }
                                }],
                                "nextCursor": "resource-page-2"
                            })
                        };
                        write_json_response(
                            &mut stream,
                            StatusCode::OK,
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "result": result
                            }),
                        )
                        .await;
                    }
                    "resources/templates/list" => {
                        resource_template_list_count.fetch_add(1, Ordering::SeqCst);
                        let second_page = request
                            .pointer("/params/cursor")
                            .and_then(Value::as_str)
                            .is_some();
                        let result = if second_page {
                            json!({
                                "resourceTemplates": [{
                                    "uriTemplate": "gg://asset/{name}",
                                    "name": "asset-by-name",
                                    "mimeType": "application/octet-stream"
                                }]
                            })
                        } else {
                            json!({
                                "resourceTemplates": [{
                                    "uriTemplate": "gg://resource/{id}",
                                    "name": "resource-by-id",
                                    "title": "Resource by ID",
                                    "description": "Safe template metadata",
                                    "mimeType": "application/json",
                                    "icons": [{
                                        "src": "https://example.test/template.png"
                                    }],
                                    "_meta": { "private": "drop-me" }
                                }],
                                "nextCursor": "template-page-2"
                            })
                        };
                        write_json_response(
                            &mut stream,
                            StatusCode::OK,
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "result": result
                            }),
                        )
                        .await;
                    }
                    "resources/read" => {
                        resource_read_count.fetch_add(1, Ordering::SeqCst);
                        write_json_response(
                            &mut stream,
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json!({
                                "jsonrpc": "2.0",
                                "id": request["id"],
                                "error": {
                                    "code": -32601,
                                    "message": "resource reads are forbidden during discovery"
                                }
                            }),
                        )
                        .await;
                    }
                    _ => write_empty_response(&mut stream, StatusCode::ACCEPTED).await,
                }
            });
        }
    }

    async fn read_json_request(stream: &mut TcpStream) -> Value {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 2048];
        let header_end = loop {
            let read = stream
                .read(&mut buffer)
                .await
                .expect("managed MCP server should read request");
            assert_ne!(read, 0, "managed MCP request should not end before headers");
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or_default();
        while bytes.len().saturating_sub(header_end) < content_length {
            let read = stream
                .read(&mut buffer)
                .await
                .expect("managed MCP server should read request body");
            assert_ne!(read, 0, "managed MCP request body should be complete");
            bytes.extend_from_slice(&buffer[..read]);
        }
        if content_length == 0 {
            Value::Null
        } else {
            serde_json::from_slice(&bytes[header_end..header_end + content_length])
                .expect("managed MCP request body should be JSON")
        }
    }

    async fn write_json_response(stream: &mut TcpStream, status: StatusCode, body: Value) {
        let body = serde_json::to_vec(&body).expect("managed MCP response should serialize");
        let head = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Response"),
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("managed MCP response headers should write");
        stream
            .write_all(&body)
            .await
            .expect("managed MCP response body should write");
    }

    async fn write_empty_response(stream: &mut TcpStream, status: StatusCode) {
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Response")
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("managed MCP empty response should write");
    }
}
