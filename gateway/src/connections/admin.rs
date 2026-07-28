use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    control_plane::ConnectionRuntimeSnapshot,
    model::{
        ConnectionAuthentication, ConnectionEndpoint, ConnectionId, ConnectionKind,
        ConnectionManagementSource, ConnectionTestProfile, ConnectionTimeouts, ConnectionWrite,
        DiscoveryConfig, OAuthClientAuthMethod,
    },
    status::{SafeConnectionStatus, SafeConnectionSummary},
    store::{ConnectionDependency, StoredConnection},
};

pub const MAX_CONNECTION_ADMIN_BODY_BYTES: usize = 64 * 1024;
pub const DEFAULT_CONNECTION_LIST_LIMIT: usize = 50;
pub const MAX_CONNECTION_LIST_LIMIT: usize = 100;
const MAX_CURSOR_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionPermissions {
    pub read: bool,
    pub write: bool,
    pub secrets_write: bool,
    pub test: bool,
    pub refresh: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionActions {
    pub can_update: bool,
    pub can_bind_secret: bool,
    pub can_test: bool,
    pub can_refresh: bool,
    pub can_delete: bool,
}

impl ConnectionActions {
    fn managed(
        permissions: ConnectionPermissions,
        record: &StoredConnection,
        dependency_count: usize,
    ) -> Self {
        let has_test_target = match record.write.kind {
            ConnectionKind::HttpApi => record.write.test_profile.is_some(),
            ConnectionKind::McpStreamableHttp => matches!(
                &record.write.discovery,
                Some(DiscoveryConfig::ManagedMcp { .. })
            ),
        };
        Self {
            can_update: permissions.write,
            can_bind_secret: permissions.write && permissions.secrets_write,
            // Persisted tests intentionally support disabled managed connections so
            // operators can validate them before enabling production traffic.
            can_test: permissions.test && has_test_target,
            can_refresh: permissions.refresh
                && record.write.enabled
                && record.write.kind == ConnectionKind::McpStreamableHttp
                && matches!(
                    &record.write.discovery,
                    Some(DiscoveryConfig::ManagedMcp { .. })
                ),
            can_delete: permissions.write
                && dependency_count == 0
                && (!record.write.requires_secrets_write_to_delete() || permissions.secrets_write),
        }
    }

    fn read_only() -> Self {
        Self {
            can_update: false,
            can_bind_secret: false,
            can_test: false,
            can_refresh: false,
            can_delete: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSummaryView {
    #[serde(flatten)]
    pub summary: SafeConnectionSummary,
    pub actions: ConnectionActions,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionListPage {
    pub connections: Vec<ConnectionSummaryView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub omitted_legacy_projection_count: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionListParams {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
    pub enabled: Option<bool>,
    pub kind: Option<ConnectionKind>,
    pub source: Option<ConnectionManagementSource>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionListError {
    InvalidLimit,
    InvalidCursor,
    StaleCursor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDetailView {
    #[serde(flatten)]
    pub summary: SafeConnectionSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<SafeConnectionConfiguration>,
    pub dependencies: Vec<ConnectionDependency>,
    pub actions: ConnectionActions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeConnectionConfiguration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub endpoint: ConnectionEndpoint,
    pub authentication: SafeConnectionAuthentication,
    pub tls: SafeTlsConfiguration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeouts: Option<ConnectionTimeouts>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoveryConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_profile: Option<ConnectionTestProfile>,
}

impl SafeConnectionConfiguration {
    fn from_write(write: &ConnectionWrite) -> Self {
        Self {
            description: write.description.clone(),
            endpoint: write.endpoint.clone(),
            authentication: SafeConnectionAuthentication::from_authentication(
                &write.authentication,
            ),
            tls: SafeTlsConfiguration {
                ca_bundle_configured: write.tls.ca_bundle_alias.is_some(),
                client_certificate_configured: write.tls.client_certificate_id.is_some(),
                client_private_key_configured: write.tls.client_private_key_id.is_some(),
            },
            timeouts: write.timeouts.clone(),
            discovery: write.discovery.clone(),
            test_profile: write.test_profile.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SafeConnectionAuthentication {
    None,
    HeaderApiKey {
        header_name: String,
        secret_configured: bool,
    },
    StaticBearer {
        secret_configured: bool,
    },
    #[serde(rename = "oauth2_client_credentials")]
    OAuth2ClientCredentials {
        client_id: String,
        token_url: String,
        scopes: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        resource: Option<String>,
        client_auth_method: OAuthClientAuthMethod,
        client_secret_configured: bool,
    },
}

impl SafeConnectionAuthentication {
    fn from_authentication(authentication: &ConnectionAuthentication) -> Self {
        match authentication {
            ConnectionAuthentication::None => Self::None,
            ConnectionAuthentication::HeaderApiKey {
                header_name,
                secret_id,
            } => Self::HeaderApiKey {
                header_name: header_name.clone(),
                secret_configured: secret_id.is_some(),
            },
            ConnectionAuthentication::StaticBearer { secret_id } => Self::StaticBearer {
                secret_configured: secret_id.is_some(),
            },
            ConnectionAuthentication::OAuth2ClientCredentials {
                client_id,
                client_secret_id,
                token_url,
                scopes,
                audience,
                resource,
                client_auth_method,
            } => Self::OAuth2ClientCredentials {
                client_id: client_id.clone(),
                token_url: token_url.clone(),
                scopes: scopes.clone(),
                audience: audience.clone(),
                resource: resource.clone(),
                client_auth_method: *client_auth_method,
                client_secret_configured: client_secret_id.is_some(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeTlsConfiguration {
    pub ca_bundle_configured: bool,
    pub client_certificate_configured: bool,
    pub client_private_key_configured: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionCursor {
    after_id: ConnectionId,
    collection_etag: String,
    enabled: Option<bool>,
    kind: Option<ConnectionKind>,
    source: Option<ConnectionManagementSource>,
}

pub fn build_connection_list_page(
    snapshot: &ConnectionRuntimeSnapshot,
    statuses: &BTreeMap<ConnectionId, SafeConnectionStatus>,
    dependency_counts: &BTreeMap<ConnectionId, usize>,
    params: &ConnectionListParams,
    permissions: ConnectionPermissions,
) -> Result<ConnectionListPage, ConnectionListError> {
    let limit = params.limit.unwrap_or(DEFAULT_CONNECTION_LIST_LIMIT);
    if limit == 0 || limit > MAX_CONNECTION_LIST_LIMIT {
        return Err(ConnectionListError::InvalidLimit);
    }
    let cursor = params.cursor.as_deref().map(decode_cursor).transpose()?;
    if let Some(cursor) = cursor.as_ref() {
        if cursor.collection_etag != snapshot.collection_etag() {
            return Err(ConnectionListError::StaleCursor);
        }
        if cursor.enabled != params.enabled
            || cursor.kind != params.kind
            || cursor.source != params.source
        {
            return Err(ConnectionListError::InvalidCursor);
        }
    }

    let mut views = Vec::with_capacity(snapshot.managed().len() + snapshot.legacy().len());
    for projection in snapshot.legacy() {
        views.push(ConnectionSummaryView {
            summary: projection.safe_summary(),
            actions: ConnectionActions::read_only(),
        });
    }
    for (id, record) in snapshot.managed() {
        views.push(ConnectionSummaryView {
            summary: record.safe_summary(statuses.get(id).cloned()),
            actions: ConnectionActions::managed(
                permissions,
                record,
                dependency_counts.get(id).copied().unwrap_or_default(),
            ),
        });
    }
    views.sort_by(|left, right| left.summary.id.cmp(&right.summary.id));
    views.retain(|view| {
        params
            .enabled
            .is_none_or(|enabled| view.summary.enabled == enabled)
            && params.kind.is_none_or(|kind| view.summary.kind == kind)
            && params
                .source
                .is_none_or(|source| view.summary.source == source)
            && cursor
                .as_ref()
                .is_none_or(|cursor| view.summary.id.as_str() > cursor.after_id.as_str())
    });

    let has_more = views.len() > limit;
    if has_more {
        views.truncate(limit);
    }
    let next_cursor = if has_more {
        views
            .last()
            .map(|view| {
                encode_cursor(&ConnectionCursor {
                    after_id: view.summary.id.clone(),
                    collection_etag: snapshot.collection_etag().to_owned(),
                    enabled: params.enabled,
                    kind: params.kind,
                    source: params.source,
                })
            })
            .transpose()?
    } else {
        None
    };

    Ok(ConnectionListPage {
        connections: views,
        next_cursor,
        omitted_legacy_projection_count: snapshot.omitted_legacy_projection_count(),
    })
}

pub fn managed_detail_view(
    record: &StoredConnection,
    status: Option<SafeConnectionStatus>,
    dependencies: Vec<ConnectionDependency>,
    permissions: ConnectionPermissions,
) -> ConnectionDetailView {
    let dependency_count = dependencies.len();
    ConnectionDetailView {
        summary: record.safe_summary(status),
        configuration: Some(SafeConnectionConfiguration::from_write(&record.write)),
        dependencies,
        actions: ConnectionActions::managed(permissions, record, dependency_count),
        created_at: Some(record.created_at.clone()),
        updated_at: Some(record.updated_at.clone()),
    }
}

pub fn legacy_detail_view(summary: SafeConnectionSummary) -> ConnectionDetailView {
    ConnectionDetailView {
        summary,
        configuration: None,
        dependencies: Vec::new(),
        actions: ConnectionActions::read_only(),
        created_at: None,
        updated_at: None,
    }
}

pub fn changed_connection_fields(
    before: Option<&ConnectionWrite>,
    after: Option<&ConnectionWrite>,
) -> Vec<&'static str> {
    let mut fields = Vec::new();

    match (before, after) {
        (Some(before), Some(after)) => {
            if before.display_name != after.display_name {
                fields.push("display_name");
            }
            if before.description != after.description {
                fields.push("description");
            }
            if before.enabled != after.enabled {
                fields.push("enabled");
            }
            if before.kind != after.kind {
                fields.push("kind");
            }
            if before.endpoint != after.endpoint {
                fields.push("endpoint");
            }
            if before.authentication != after.authentication {
                fields.push("authentication");
            }
            if before.tls != after.tls {
                fields.push("tls");
            }
            if before.timeouts != after.timeouts {
                fields.push("timeouts");
            }
            if before.discovery != after.discovery {
                fields.push("discovery");
            }
            if before.test_profile != after.test_profile {
                fields.push("test_profile");
            }
        }
        (None, Some(_)) | (Some(_), None) => {
            fields.extend([
                "display_name",
                "description",
                "enabled",
                "kind",
                "endpoint",
                "authentication",
                "tls",
                "timeouts",
                "discovery",
                "test_profile",
            ]);
        }
        (None, None) => {}
    }
    fields
}

fn encode_cursor(cursor: &ConnectionCursor) -> Result<String, ConnectionListError> {
    serde_json::to_vec(cursor)
        .map(hex::encode)
        .map_err(|_| ConnectionListError::InvalidCursor)
}

fn decode_cursor(value: &str) -> Result<ConnectionCursor, ConnectionListError> {
    if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
        return Err(ConnectionListError::InvalidCursor);
    }
    let bytes = hex::decode(value).map_err(|_| ConnectionListError::InvalidCursor)?;
    if bytes.len() > MAX_CURSOR_BYTES {
        return Err(ConnectionListError::InvalidCursor);
    }
    serde_json::from_slice(&bytes).map_err(|_| ConnectionListError::InvalidCursor)
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn credentialed_write() -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": "Billing API",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {
                "type": "static_bearer",
                "secret_id": "billing-secret-id-canary"
            },
            "tls": {
                "ca_bundle_alias": "billing-ca-id-canary"
            },
            "test_profile": {
                "method": "HEAD",
                "path": "/ready",
                "expected_statuses": [200]
            }
        }))
        .expect("test connection should deserialize")
    }

    #[test]
    fn safe_configuration_never_serializes_secret_ids() {
        let write = credentialed_write();
        let serialized = serde_json::to_string(&SafeConnectionConfiguration::from_write(&write))
            .expect("safe configuration should serialize");
        assert!(!serialized.contains("billing-secret-id-canary"));
        assert!(!serialized.contains("billing-ca-id-canary"));
        assert!(serialized.contains("\"secret_configured\":true"));
        assert!(serialized.contains("\"ca_bundle_configured\":true"));
        assert!(serialized.contains("\"client_certificate_configured\":false"));
        assert!(serialized.contains("\"client_private_key_configured\":false"));
    }

    #[test]
    fn changed_fields_are_names_only() {
        let before = credentialed_write();
        let mut after = before.clone();
        after.endpoint.base_url = "https://replacement.example.test".to_owned();
        after.authentication = ConnectionAuthentication::None;

        let fields = changed_connection_fields(Some(&before), Some(&after));
        assert_eq!(fields, vec!["endpoint", "authentication"]);
        let value: Value = serde_json::to_value(fields).expect("fields should serialize");
        let serialized = value.to_string();
        assert!(!serialized.contains("replacement.example.test"));
        assert!(!serialized.contains("billing-secret-id-canary"));
    }

    #[test]
    fn actions_are_derived_from_live_permissions_and_dependencies() {
        let mut record = StoredConnection {
            id: ConnectionId::parse("00000000-0000-0000-0000-000000000001")
                .expect("ID should parse"),
            write: credentialed_write(),
            revisions: crate::connections::status::ConnectionRevisions {
                connection: 1,
                credential: 1,
                tls: 1,
                discovery: 0,
                status: 0,
            },
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let ordinary_writer = ConnectionPermissions {
            read: true,
            write: true,
            test: true,
            ..ConnectionPermissions::default()
        };
        let ordinary_actions = ConnectionActions::managed(ordinary_writer, &record, 0);
        assert!(ordinary_actions.can_update);
        assert!(!ordinary_actions.can_bind_secret);
        assert!(ordinary_actions.can_test);
        assert!(!ordinary_actions.can_delete);

        record.write.enabled = false;
        assert!(
            ConnectionActions::managed(ordinary_writer, &record, 0).can_test,
            "disabled HTTP connections remain testable when a stored profile exists"
        );
        record.write.test_profile = None;
        assert!(
            !ConnectionActions::managed(ordinary_writer, &record, 0).can_test,
            "HTTP connections require a stored test profile"
        );

        record.write.kind = ConnectionKind::McpStreamableHttp;
        record.write.discovery = Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication: true,
        });
        assert!(
            ConnectionActions::managed(ordinary_writer, &record, 0).can_test,
            "disabled managed MCP connections do not require an HTTP test profile"
        );
        record.write.enabled = true;
        assert!(
            ConnectionActions::managed(ordinary_writer, &record, 0).can_test,
            "enabled managed MCP connections are testable"
        );
        record.write.discovery = None;
        assert!(
            !ConnectionActions::managed(ordinary_writer, &record, 0).can_test,
            "MCP connections require managed MCP discovery"
        );
        record.write.test_profile = Some(ConnectionTestProfile {
            method: "HEAD".to_owned(),
            path: "/ready".to_owned(),
            expected_statuses: vec![200],
        });
        assert!(
            !ConnectionActions::managed(ordinary_writer, &record, 0).can_test,
            "an HTTP test profile alone must not make an unmanaged MCP connection testable"
        );
        let no_test_permission = ConnectionPermissions {
            test: false,
            ..ordinary_writer
        };
        record.write.discovery = Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication: false,
        });
        assert!(
            !ConnectionActions::managed(no_test_permission, &record, 0).can_test,
            "the test action requires admin:connections:test"
        );
        assert!(!ConnectionActions::read_only().can_test);

        record.write = credentialed_write();
        let secrets_writer = ConnectionPermissions {
            secrets_write: true,
            ..ordinary_writer
        };
        let secrets_actions = ConnectionActions::managed(secrets_writer, &record, 0);
        assert!(secrets_actions.can_delete);
        assert!(secrets_actions.can_bind_secret);

        let dependent_actions = ConnectionActions::managed(secrets_writer, &record, 1);
        assert!(!dependent_actions.can_delete);
    }
}
