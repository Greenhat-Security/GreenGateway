use std::{collections::BTreeSet, error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::config::{Config, UpstreamRouteConfig};

use super::{
    model::{
        ConnectionId, ConnectionKind, ConnectionManagementSource, MAX_CONNECTIONS,
        MAX_DISPLAY_NAME_CHARS,
    },
    status::{
        ConnectionOperationalState, ConnectionRevisions, ConnectionStatusReason,
        SafeAuthenticationKind, SafeConnectionStatus, SafeConnectionSummary,
    },
};

const DEFAULT_HTTP_ID: &str = "legacy-default-http";
const ROUTE_ID_PREFIX: &str = "legacy-route-";
const MCP_ID_PREFIX: &str = "legacy-mcp-";
const MAX_NORMALIZED_MCP_NAME_BYTES: usize = 80;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyConnectionProjection {
    summary: SafeConnectionSummary,
    sanitized_origin: Option<String>,
    legacy_mcp_server_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyProjectionSet {
    pub connections: Vec<LegacyConnectionProjection>,
    pub omitted_count: usize,
}

struct LegacyProjectionSpec {
    id: String,
    display_name: String,
    kind: ConnectionKind,
    source: ConnectionManagementSource,
    authentication: SafeAuthenticationKind,
    endpoint_count: usize,
    sanitized_origin: Option<String>,
    legacy_mcp_server_name: Option<String>,
}

impl LegacyConnectionProjection {
    pub fn id(&self) -> &ConnectionId {
        &self.summary.id
    }

    pub fn safe_summary(&self) -> SafeConnectionSummary {
        self.summary.clone()
    }

    pub fn sanitized_origin(&self) -> Option<&str> {
        self.sanitized_origin.as_deref()
    }

    pub fn legacy_mcp_server_name(&self) -> Option<&str> {
        self.legacy_mcp_server_name.as_deref()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LegacyProjectionError {
    IdCollision { id: String },
    InvalidGeneratedId { id: String },
}

impl fmt::Display for LegacyProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdCollision { id } => {
                write!(
                    formatter,
                    "legacy connection projection ID collision for '{id}'"
                )
            }
            Self::InvalidGeneratedId { id } => write!(
                formatter,
                "legacy connection projection generated invalid stable ID '{id}'"
            ),
        }
    }
}

impl Error for LegacyProjectionError {}

pub fn project_legacy_connections(
    config: &Config,
) -> Result<LegacyProjectionSet, LegacyProjectionError> {
    let legacy_route_count = config
        .upstream_routes
        .iter()
        .filter(|route| route.connection_id.is_none())
        .count();
    let count = usize::from(config.upstream_url.is_some())
        + legacy_route_count
        + config.mcp_upstream_servers.len();
    let mut projected = Vec::with_capacity(count.min(MAX_CONNECTIONS));
    let mut ids = BTreeSet::new();

    if config.upstream_url.is_some() {
        push_projection(
            &mut projected,
            &mut ids,
            LegacyProjectionSpec {
                id: DEFAULT_HTTP_ID.to_owned(),
                display_name: "Legacy default HTTP".to_owned(),
                kind: ConnectionKind::HttpApi,
                source: ConnectionManagementSource::LegacyDefaultHttp,
                authentication: SafeAuthenticationKind::None,
                endpoint_count: 1,
                sanitized_origin: config.upstream_url.as_deref().and_then(sanitized_origin),
                legacy_mcp_server_name: None,
            },
        )?;
    }

    for (index, route) in config.upstream_routes.iter().enumerate() {
        if route.connection_id.is_some() {
            continue;
        }
        let id = projected_route_id(route);
        let display_name = bounded_display_name(match route.id.as_deref() {
            Some(route_id) => format!("Legacy route {route_id}"),
            None => format!("Legacy route {}", index + 1),
        });
        let authentication = if route.add_request_headers.is_empty() {
            SafeAuthenticationKind::None
        } else {
            SafeAuthenticationKind::LegacyConfigured
        };
        let endpoint_count = route.upstreams.len().max(1);
        push_projection(
            &mut projected,
            &mut ids,
            LegacyProjectionSpec {
                id,
                display_name,
                kind: ConnectionKind::HttpApi,
                source: ConnectionManagementSource::LegacyRoute,
                authentication,
                endpoint_count,
                sanitized_origin: legacy_route_sanitized_origin(route),
                legacy_mcp_server_name: None,
            },
        )?;
    }

    for server in &config.mcp_upstream_servers {
        let id = projected_legacy_mcp_connection_id(&server.name)?;
        push_projection(
            &mut projected,
            &mut ids,
            LegacyProjectionSpec {
                id: id.to_string(),
                display_name: bounded_display_name(server.name.clone()),
                kind: ConnectionKind::McpStreamableHttp,
                source: ConnectionManagementSource::LegacyMcp,
                authentication: SafeAuthenticationKind::None,
                endpoint_count: 1,
                sanitized_origin: sanitized_origin(&server.url),
                legacy_mcp_server_name: Some(server.name.clone()),
            },
        )?;
    }

    Ok(LegacyProjectionSet {
        omitted_count: count.saturating_sub(projected.len()),
        connections: projected,
    })
}

pub(crate) fn projected_legacy_mcp_connection_id(
    server_name: &str,
) -> Result<ConnectionId, LegacyProjectionError> {
    let normalized_name = normalize_mcp_name(server_name);
    let id = format!(
        "{MCP_ID_PREFIX}{normalized_name}-{}",
        stable_digest(server_name)
    );
    ConnectionId::parse(id.clone()).map_err(|_| LegacyProjectionError::InvalidGeneratedId { id })
}

fn push_projection(
    projected: &mut Vec<LegacyConnectionProjection>,
    ids: &mut BTreeSet<String>,
    spec: LegacyProjectionSpec,
) -> Result<(), LegacyProjectionError> {
    if projected.len() == MAX_CONNECTIONS {
        return Ok(());
    }
    let LegacyProjectionSpec {
        id,
        display_name,
        kind,
        source,
        authentication,
        endpoint_count,
        sanitized_origin,
        legacy_mcp_server_name,
    } = spec;
    if !ids.insert(id.clone()) {
        return Err(LegacyProjectionError::IdCollision { id });
    }
    let id = ConnectionId::parse(id.clone())
        .map_err(|_| LegacyProjectionError::InvalidGeneratedId { id })?;
    projected.push(LegacyConnectionProjection {
        summary: SafeConnectionSummary {
            id,
            display_name,
            enabled: true,
            kind,
            source,
            read_only: true,
            authentication,
            endpoint_count,
            revisions: ConnectionRevisions::LEGACY_PROJECTION,
            status: SafeConnectionStatus {
                state: ConnectionOperationalState::Configured,
                reason: ConnectionStatusReason::LegacyConfigured,
                observed_at: None,
                latency_ms: None,
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        },
        sanitized_origin,
        legacy_mcp_server_name,
    });
    Ok(())
}

fn legacy_route_sanitized_origin(route: &UpstreamRouteConfig) -> Option<String> {
    if route.upstreams.len() == 1 {
        return sanitized_origin(&route.upstreams[0].url);
    }
    if route.upstreams.is_empty() {
        return sanitized_origin(&route.upstream_url);
    }
    None
}

fn sanitized_origin(value: &str) -> Option<String> {
    let parsed = url::Url::parse(value).ok()?;
    matches!(parsed.scheme(), "http" | "https").then(|| parsed.origin().ascii_serialization())
}

fn projected_route_id(route: &UpstreamRouteConfig) -> String {
    match route.id.as_deref() {
        Some(id) => format!("{ROUTE_ID_PREFIX}{id}"),
        None => {
            let identity = format!("host={:?}\npath={:?}", route.host, route.path_prefix);
            format!("{ROUTE_ID_PREFIX}{}", stable_digest(&identity))
        }
    }
}

fn normalize_mcp_name(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len().min(MAX_NORMALIZED_MCP_NAME_BYTES));
    let mut previous_separator = false;
    for character in value.chars() {
        if normalized.len() >= MAX_NORMALIZED_MCP_NAME_BYTES {
            break;
        }
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            previous_separator = false;
        } else if matches!(character, '.' | '_' | '-') {
            normalized.push(character);
            previous_separator = false;
        } else if !previous_separator && !normalized.is_empty() {
            normalized.push('-');
            previous_separator = true;
        }
    }
    let normalized = normalized.trim_matches(['.', '_', '-']).to_owned();
    if normalized.is_empty() {
        "server".to_owned()
    } else {
        normalized
    }
}

fn stable_digest(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..16])
}

fn bounded_display_name(value: String) -> String {
    value.chars().take(MAX_DISPLAY_NAME_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use crate::config::{McpUpstreamServerConfig, UpstreamRouteConfig};

    use super::*;

    fn config() -> Config {
        Config::test_defaults()
    }

    fn route(value: serde_json::Value) -> UpstreamRouteConfig {
        serde_json::from_value(value).expect("legacy route should deserialize")
    }

    #[test]
    fn projects_legacy_sources_without_exposing_destinations() {
        let mut config = config();
        config.upstream_url = Some("https://default.example.test".to_owned());
        config.upstream_routes = vec![route(serde_json::json!({
            "id": "payments",
            "path_prefix": "/payments",
            "upstream_url": "https://payments.example.test"
        }))];
        config.mcp_upstream_servers = vec![McpUpstreamServerConfig {
            name: "Issue Tracker".to_owned(),
            url: "https://mcp.example.test".to_owned(),
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
        }];

        let projected = project_legacy_connections(&config).expect("projection should succeed");
        let summaries = projected
            .connections
            .iter()
            .map(LegacyConnectionProjection::safe_summary)
            .collect::<Vec<_>>();
        let ids = summaries
            .iter()
            .map(|summary| summary.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids[0], "legacy-default-http");
        assert_eq!(ids[1], "legacy-route-payments");
        assert!(ids[2].starts_with("legacy-mcp-issue-tracker-"));
        assert_eq!(
            projected.connections[2].id(),
            &projected_legacy_mcp_connection_id("Issue Tracker")
                .expect("shared MCP projection identity should be valid")
        );
        assert_eq!(projected.connections[0].legacy_mcp_server_name(), None);
        assert_eq!(projected.connections[1].legacy_mcp_server_name(), None);
        assert_eq!(
            projected.connections[2].legacy_mcp_server_name(),
            Some("Issue Tracker")
        );
        let serialized = serde_json::to_string(&summaries).expect("summaries should serialize");
        assert!(!serialized.contains("example.test"));
        assert!(!serialized.contains("/payments"));
        assert!(!serialized.contains("legacy_mcp_server_name"));
        assert!(!serialized.contains("server_name"));
    }

    #[test]
    fn mcp_projection_preserves_exact_server_name_beyond_display_bound() {
        let original_name = format!(
            "Case Sensitive MCP {}",
            "x".repeat(MAX_DISPLAY_NAME_CHARS + 16)
        );
        let mut config = config();
        config.mcp_upstream_servers = vec![McpUpstreamServerConfig {
            name: original_name.clone(),
            url: "https://mcp.example.test".to_owned(),
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
        }];

        let projected = project_legacy_connections(&config).expect("projection should succeed");
        let projection = projected
            .connections
            .first()
            .expect("MCP projection should be present");

        assert_eq!(
            projection.legacy_mcp_server_name(),
            Some(original_name.as_str())
        );
        assert_eq!(
            projection.safe_summary().display_name.chars().count(),
            MAX_DISPLAY_NAME_CHARS
        );
    }

    #[test]
    fn route_without_id_is_stable_across_reordering() {
        let first = route(serde_json::json!({
            "host": "a.example.test",
            "path_prefix": "/v1",
            "upstream_url": "https://one.example.test"
        }));
        let second = route(serde_json::json!({
            "host": "b.example.test",
            "path_prefix": "/v2",
            "upstream_url": "https://two.example.test"
        }));
        let mut left = config();
        left.upstream_routes = vec![first.clone(), second.clone()];
        let mut right = config();
        right.upstream_routes = vec![second, first];

        let mut left_ids = project_legacy_connections(&left)
            .expect("left should project")
            .connections
            .into_iter()
            .map(|projection| projection.id().to_string())
            .collect::<Vec<_>>();
        let mut right_ids = project_legacy_connections(&right)
            .expect("right should project")
            .connections
            .into_iter()
            .map(|projection| projection.id().to_string())
            .collect::<Vec<_>>();
        left_ids.sort();
        right_ids.sort();
        assert_eq!(left_ids, right_ids);
    }

    #[test]
    fn route_projection_id_is_logical_and_survives_destination_change() {
        let first = route(serde_json::json!({
            "host": "api.example.test",
            "path_prefix": "/v1",
            "upstream_url": "https://one.example.test"
        }));
        let second = route(serde_json::json!({
            "host": "api.example.test",
            "path_prefix": "/v1",
            "upstream_url": "https://two.example.test"
        }));
        assert_eq!(projected_route_id(&first), projected_route_id(&second));
    }

    #[test]
    fn mcp_projection_identity_survives_collision_addition_and_reordering() {
        let mut config = config();
        config.mcp_upstream_servers = ["Issue Tracker"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| McpUpstreamServerConfig {
                name: name.to_owned(),
                url: format!("https://mcp-{index}.example.test"),
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
            })
            .collect();
        let original_id = project_legacy_connections(&config)
            .expect("sole server should project")
            .connections[0]
            .id()
            .clone();
        config.mcp_upstream_servers.push(McpUpstreamServerConfig {
            name: "issue tracker".to_owned(),
            url: "https://mcp-collision.example.test".to_owned(),
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
        });
        let with_collision =
            project_legacy_connections(&config).expect("collisions should be disambiguated");
        assert_ne!(
            with_collision.connections[0].id(),
            with_collision.connections[1].id()
        );
        assert_eq!(with_collision.connections[0].id(), &original_id);
        assert!(with_collision
            .connections
            .iter()
            .all(|projection| projection.id().as_str().starts_with(MCP_ID_PREFIX)));

        config.mcp_upstream_servers.reverse();
        config.mcp_upstream_servers.push(McpUpstreamServerConfig {
            name: "Issue-Tracker".to_owned(),
            url: "https://mcp-added.example.test".to_owned(),
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
        });
        let reordered =
            project_legacy_connections(&config).expect("reordered names should project");
        assert!(reordered
            .connections
            .iter()
            .any(|projection| projection.id() == &original_id));
    }

    #[test]
    fn projection_count_is_bounded_before_allocation() {
        let mut config = config();
        config.mcp_upstream_servers = (0..=MAX_CONNECTIONS)
            .map(|index| McpUpstreamServerConfig {
                name: format!("server-{index}"),
                url: format!("https://mcp-{index}.example.test"),
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
            })
            .collect();

        let projected =
            project_legacy_connections(&config).expect("legacy overflow should be truncated");
        assert_eq!(projected.connections.len(), MAX_CONNECTIONS);
        assert_eq!(projected.omitted_count, 1);
    }
}
