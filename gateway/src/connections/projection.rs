use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

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
const MAX_NORMALIZED_MCP_NAME_BYTES: usize = 96;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyConnectionProjection {
    summary: SafeConnectionSummary,
}

struct LegacyProjectionSpec {
    id: String,
    display_name: String,
    kind: ConnectionKind,
    source: ConnectionManagementSource,
    authentication: SafeAuthenticationKind,
    endpoint_count: usize,
}

impl LegacyConnectionProjection {
    pub fn id(&self) -> &ConnectionId {
        &self.summary.id
    }

    pub fn safe_summary(&self) -> SafeConnectionSummary {
        self.summary.clone()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LegacyProjectionError {
    LimitExceeded { count: usize, maximum: usize },
    IdCollision { id: String },
    InvalidGeneratedId { id: String },
}

impl fmt::Display for LegacyProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded { count, maximum } => write!(
                formatter,
                "legacy configuration projects {count} connections, exceeding the maximum of {maximum}"
            ),
            Self::IdCollision { id } => {
                write!(formatter, "legacy connection projection ID collision for '{id}'")
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
) -> Result<Vec<LegacyConnectionProjection>, LegacyProjectionError> {
    let count = usize::from(config.upstream_url.is_some())
        + config.upstream_routes.len()
        + config.mcp_upstream_servers.len();
    if count > MAX_CONNECTIONS {
        return Err(LegacyProjectionError::LimitExceeded {
            count,
            maximum: MAX_CONNECTIONS,
        });
    }

    let mut projected = Vec::with_capacity(count);
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
            },
        )?;
    }

    for (index, route) in config.upstream_routes.iter().enumerate() {
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
            },
        )?;
    }

    let normalized_mcp_names = normalized_mcp_names(config);
    for (server, normalized_name) in config.mcp_upstream_servers.iter().zip(normalized_mcp_names) {
        push_projection(
            &mut projected,
            &mut ids,
            LegacyProjectionSpec {
                id: format!("{MCP_ID_PREFIX}{normalized_name}"),
                display_name: bounded_display_name(server.name.clone()),
                kind: ConnectionKind::McpStreamableHttp,
                source: ConnectionManagementSource::LegacyMcp,
                authentication: SafeAuthenticationKind::None,
                endpoint_count: 1,
            },
        )?;
    }

    Ok(projected)
}

fn push_projection(
    projected: &mut Vec<LegacyConnectionProjection>,
    ids: &mut BTreeSet<String>,
    spec: LegacyProjectionSpec,
) -> Result<(), LegacyProjectionError> {
    let LegacyProjectionSpec {
        id,
        display_name,
        kind,
        source,
        authentication,
        endpoint_count,
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
    });
    Ok(())
}

fn projected_route_id(route: &UpstreamRouteConfig) -> String {
    match route.id.as_deref() {
        Some(id) => format!("{ROUTE_ID_PREFIX}{id}"),
        None => {
            let identity = format!("host={:?}\npath={:?}", route.host, route.path_prefix);
            format!("{ROUTE_ID_PREFIX}{}", short_digest(&identity))
        }
    }
}

fn normalized_mcp_names(config: &Config) -> Vec<String> {
    let bases = config
        .mcp_upstream_servers
        .iter()
        .map(|server| normalize_mcp_name(&server.name))
        .collect::<Vec<_>>();
    let counts = bases.iter().fold(BTreeMap::new(), |mut counts, value| {
        *counts.entry(value.clone()).or_insert(0usize) += 1;
        counts
    });

    config
        .mcp_upstream_servers
        .iter()
        .zip(bases)
        .map(|(server, base)| {
            if counts.get(&base).copied().unwrap_or_default() > 1 {
                format!("{base}-{}", short_digest(&server.name))
            } else {
                base
            }
        })
        .collect()
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
        format!("server-{}", short_digest(value))
    } else {
        normalized
    }
}

fn short_digest(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(&digest[..8])
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
            .iter()
            .map(LegacyConnectionProjection::safe_summary)
            .collect::<Vec<_>>();
        assert_eq!(
            summaries
                .iter()
                .map(|summary| summary.id.as_str())
                .collect::<Vec<_>>(),
            [
                "legacy-default-http",
                "legacy-route-payments",
                "legacy-mcp-issue-tracker"
            ]
        );
        let serialized = serde_json::to_string(&summaries).expect("summaries should serialize");
        assert!(!serialized.contains("example.test"));
        assert!(!serialized.contains("/payments"));
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
            .into_iter()
            .map(|projection| projection.id().to_string())
            .collect::<Vec<_>>();
        let mut right_ids = project_legacy_connections(&right)
            .expect("right should project")
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
    fn normalized_mcp_name_collisions_receive_stable_suffixes() {
        let mut config = config();
        config.mcp_upstream_servers = ["Issue Tracker", "issue tracker"]
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

        let projected =
            project_legacy_connections(&config).expect("collisions should be disambiguated");
        assert_ne!(projected[0].id(), projected[1].id());
        assert!(projected
            .iter()
            .all(|projection| projection.id().as_str().starts_with(MCP_ID_PREFIX)));
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

        assert_eq!(
            project_legacy_connections(&config),
            Err(LegacyProjectionError::LimitExceeded {
                count: MAX_CONNECTIONS + 1,
                maximum: MAX_CONNECTIONS,
            })
        );
    }
}
