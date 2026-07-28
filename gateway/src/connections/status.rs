use serde::Serialize;

use super::model::{ConnectionId, ConnectionKind, ConnectionManagementSource};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeAuthenticationKind {
    None,
    HeaderApiKey,
    StaticBearer,
    Oauth2ClientCredentials,
    LegacyConfigured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionOperationalState {
    Unknown,
    Configured,
    Healthy,
    Degraded,
    Unavailable,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatusReason {
    NotTested,
    LegacyConfigured,
    Disabled,
    TestSucceeded,
    CatalogRefreshed,
    RequestFailed,
    EgressDenied,
    SecretUnavailable,
    InvalidResponse,
    CatalogStale,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRevisions {
    pub connection: u64,
    pub credential: u64,
    pub tls: u64,
    pub discovery: u64,
    pub status: u64,
}

impl ConnectionRevisions {
    pub const LEGACY_PROJECTION: Self = Self {
        connection: 0,
        credential: 0,
        tls: 0,
        discovery: 0,
        status: 0,
    };
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeConnectionStatus {
    pub state: ConnectionOperationalState,
    pub reason: ConnectionStatusReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_entry_count: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SafeConnectionSummary {
    pub id: ConnectionId,
    pub display_name: String,
    pub enabled: bool,
    pub kind: ConnectionKind,
    pub source: ConnectionManagementSource,
    pub read_only: bool,
    pub authentication: SafeAuthenticationKind,
    pub endpoint_count: usize,
    pub revisions: ConnectionRevisions,
    pub status: SafeConnectionStatus,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn safe_summary_shape_has_no_topology_or_secret_fields() {
        let summary = SafeConnectionSummary {
            id: ConnectionId::parse("legacy-default-http").expect("id should validate"),
            display_name: "Legacy default HTTP".to_owned(),
            enabled: true,
            kind: ConnectionKind::HttpApi,
            source: ConnectionManagementSource::LegacyDefaultHttp,
            read_only: true,
            authentication: SafeAuthenticationKind::None,
            endpoint_count: 1,
            revisions: ConnectionRevisions::LEGACY_PROJECTION,
            status: SafeConnectionStatus {
                state: ConnectionOperationalState::Configured,
                reason: ConnectionStatusReason::LegacyConfigured,
                observed_at: None,
                latency_ms: None,
                catalog_age_secs: None,
                catalog_entry_count: None,
            },
        };

        let value = serde_json::to_value(summary).expect("summary should serialize");
        let object = value.as_object().expect("summary should be an object");
        for forbidden in [
            "base_url",
            "url",
            "secret_id",
            "locator",
            "headers",
            "resolved_ip",
        ] {
            assert!(
                !contains_key_recursive(&value, forbidden),
                "safe summary must not contain {forbidden}"
            );
        }
        assert_eq!(
            object.get("source"),
            Some(&Value::String("legacy_default_http".to_owned()))
        );
    }

    fn contains_key_recursive(value: &Value, needle: &str) -> bool {
        match value {
            Value::Object(object) => {
                object.contains_key(needle)
                    || object
                        .values()
                        .any(|value| contains_key_recursive(value, needle))
            }
            Value::Array(values) => values
                .iter()
                .any(|value| contains_key_recursive(value, needle)),
            _ => false,
        }
    }
}
