use std::{
    collections::HashMap,
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use http::{
    header::{self, HeaderName},
    HeaderMap, HeaderValue, Uri,
};
use zeroize::Zeroizing;

use crate::egress::{EgressClient, EgressConfig};

use super::{
    control_plane::ConnectionControlPlane,
    model::{
        normalize_origin_relative_path, ConnectionAuthentication, ConnectionId, ConnectionKind,
        MAX_CONNECTIONS, MAX_URL_BYTES,
    },
    secret::{ResolvedSecret, SecretPurpose, SecretResolveErrorKind},
    store::{ConnectionDependencyKind, StoredConnection},
};

#[derive(Clone)]
pub struct ConnectionHttpRuntime {
    control_plane: ConnectionControlPlane,
    base_egress_config: EgressConfig,
    base_egress_client: Arc<EgressClient>,
    clients: Arc<Mutex<HashMap<String, Arc<EgressClient>>>>,
}

impl fmt::Debug for ConnectionHttpRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionHttpRuntime")
            .field("cached_client_count", &self.client_guard().len())
            .finish_non_exhaustive()
    }
}

pub struct ConnectionHttpTarget {
    connection_id: ConnectionId,
    url: String,
    client: Arc<EgressClient>,
    authentication: StaticAuthenticationBinding,
}

enum StaticAuthenticationBinding {
    None,
    HeaderApiKey {
        header_name: HeaderName,
        secret_id: String,
    },
    StaticBearer {
        secret_id: String,
    },
}

pub enum ResolvedStaticCredential {
    HeaderApiKey {
        header_name: HeaderName,
        secret: ResolvedSecret,
    },
    StaticBearer {
        secret: ResolvedSecret,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHttpError {
    InvalidConnectionId,
    ConnectionNotFound,
    ConnectionDisabled,
    WrongConnectionKind,
    UnsupportedAuthentication,
    UnsupportedTls,
    InvalidTargetPath,
    CredentialHeaderConflict,
    CredentialInvalid,
    CredentialUnavailable,
    TransportUnavailable,
}

impl ConnectionHttpRuntime {
    pub fn new(
        control_plane: ConnectionControlPlane,
        base_egress_config: EgressConfig,
        base_egress_client: Arc<EgressClient>,
    ) -> Self {
        Self {
            control_plane,
            base_egress_config,
            base_egress_client,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn target(
        &self,
        connection_id: &str,
        path_and_query: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(ConnectionHttpError::ConnectionNotFound)?;
        validate_static_http_connection(record)?;
        let url = connection_target_url(record, path_and_query)?;
        let client = self.client_for(record)?;
        let authentication = static_authentication_binding(record)?;

        Ok(ConnectionHttpTarget {
            connection_id,
            url,
            client,
            authentication,
        })
    }

    pub fn validate_binding(&self, connection_id: &str) -> Result<(), ConnectionHttpError> {
        self.target(connection_id, "/").map(|_| ())
    }

    pub fn replace_dependencies(
        &self,
        kind: ConnectionDependencyKind,
        desired: &[(String, String)],
    ) -> Result<(), ConnectionHttpError> {
        let desired = desired
            .iter()
            .map(|(connection_id, consumer_id)| {
                ConnectionId::parse(connection_id.clone())
                    .map(|connection_id| (connection_id, consumer_id.clone()))
                    .map_err(|_| ConnectionHttpError::InvalidConnectionId)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.control_plane
            .replace_runtime_dependencies(kind, &desired)
            .map_err(|_| ConnectionHttpError::TransportUnavailable)
    }

    pub async fn resolve_credential(
        &self,
        target: &ConnectionHttpTarget,
    ) -> Result<Option<ResolvedStaticCredential>, ConnectionHttpError> {
        let (secret_id, purpose) = match &target.authentication {
            StaticAuthenticationBinding::None => return Ok(None),
            StaticAuthenticationBinding::HeaderApiKey { secret_id, .. } => {
                (secret_id.as_str(), SecretPurpose::HeaderApiKey)
            }
            StaticAuthenticationBinding::StaticBearer { secret_id } => {
                (secret_id.as_str(), SecretPurpose::StaticBearer)
            }
        };
        let secret = self
            .control_plane
            .secret_resolver()
            .resolve(secret_id, purpose)
            .await
            .map_err(|error| match error.kind() {
                SecretResolveErrorKind::UnknownAlias
                | SecretResolveErrorKind::SourceDenied
                | SecretResolveErrorKind::InvalidMaterial => ConnectionHttpError::CredentialInvalid,
                SecretResolveErrorKind::ProviderBusy
                | SecretResolveErrorKind::SourceUnavailable
                | SecretResolveErrorKind::UnsafeSource
                | SecretResolveErrorKind::ProviderFailure => {
                    ConnectionHttpError::CredentialUnavailable
                }
            })?;

        Ok(Some(match &target.authentication {
            StaticAuthenticationBinding::HeaderApiKey { header_name, .. } => {
                ResolvedStaticCredential::HeaderApiKey {
                    header_name: header_name.clone(),
                    secret,
                }
            }
            StaticAuthenticationBinding::StaticBearer { .. } => {
                ResolvedStaticCredential::StaticBearer { secret }
            }
            StaticAuthenticationBinding::None => {
                unreachable!("no-auth targets return before secret resolution")
            }
        }))
    }

    fn client_for(
        &self,
        record: &StoredConnection,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        let cache_key = format!("{}:{}", record.id, record.etag().as_str());
        if let Some(client) = self.client_guard().get(&cache_key).cloned() {
            return Ok(client);
        }

        let timeouts = record.write.timeouts.clone().unwrap_or_default();
        let mut config = self.base_egress_config.clone();
        config.apply_timeout_overrides(
            Some(timeouts.request_timeout_ms),
            Some(timeouts.response_idle_timeout_ms),
            Some(timeouts.connect_timeout_ms),
        );
        let client = Arc::new(
            self.base_egress_client
                .reconfigured(config)
                .map_err(|_| ConnectionHttpError::TransportUnavailable)?,
        );
        let mut clients = self.client_guard();
        if clients.len() >= MAX_CONNECTIONS && !clients.contains_key(&cache_key) {
            clients.clear();
        }
        Ok(Arc::clone(clients.entry(cache_key).or_insert(client)))
    }

    fn client_guard(&self) -> MutexGuard<'_, HashMap<String, Arc<EgressClient>>> {
        match self.clients.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    "Connection HTTP client cache lock poisoned; discarding stale cache state"
                );
                let mut guard = poisoned.into_inner();
                guard.clear();
                guard
            }
        }
    }
}

impl ConnectionHttpTarget {
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn client(&self) -> &Arc<EgressClient> {
        &self.client
    }

    pub fn credential_header_name(&self) -> Option<&HeaderName> {
        match &self.authentication {
            StaticAuthenticationBinding::None => None,
            StaticAuthenticationBinding::HeaderApiKey { header_name, .. } => Some(header_name),
            StaticAuthenticationBinding::StaticBearer { .. } => Some(&header::AUTHORIZATION),
        }
    }

    pub fn authentication_kind(&self) -> &'static str {
        match self.authentication {
            StaticAuthenticationBinding::None => "none",
            StaticAuthenticationBinding::HeaderApiKey { .. } => "header_api_key",
            StaticAuthenticationBinding::StaticBearer { .. } => "static_bearer",
        }
    }
}

impl ResolvedStaticCredential {
    pub fn inject(&self, headers: &mut HeaderMap) -> Result<(), ConnectionHttpError> {
        let (name, mut value) = match self {
            Self::HeaderApiKey {
                header_name,
                secret,
            } => (
                header_name.clone(),
                HeaderValue::from_bytes(secret.expose())
                    .map_err(|_| ConnectionHttpError::CredentialInvalid)?,
            ),
            Self::StaticBearer { secret } => {
                let mut bearer =
                    Zeroizing::new(Vec::with_capacity("Bearer ".len() + secret.expose().len()));
                bearer.extend_from_slice(b"Bearer ");
                bearer.extend_from_slice(secret.expose());
                (
                    header::AUTHORIZATION,
                    HeaderValue::from_bytes(bearer.as_slice())
                        .map_err(|_| ConnectionHttpError::CredentialInvalid)?,
                )
            }
        };
        value.set_sensitive(true);
        headers.insert(name, value);
        Ok(())
    }
}

impl ConnectionHttpError {
    pub fn safe_reason(self) -> &'static str {
        match self {
            Self::InvalidConnectionId => "invalid_connection_id",
            Self::ConnectionNotFound => "connection_not_found",
            Self::ConnectionDisabled => "connection_disabled",
            Self::WrongConnectionKind => "connection_kind_mismatch",
            Self::UnsupportedAuthentication => "authentication_not_supported",
            Self::UnsupportedTls => "tls_not_supported",
            Self::InvalidTargetPath => "invalid_target_path",
            Self::CredentialHeaderConflict => "credential_header_conflict",
            Self::CredentialInvalid => "credential_invalid",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::TransportUnavailable => "transport_unavailable",
        }
    }
}

impl fmt::Display for ConnectionHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "connection-bound HTTP request failed: {}",
            self.safe_reason()
        )
    }
}

impl Error for ConnectionHttpError {}

fn validate_static_http_connection(record: &StoredConnection) -> Result<(), ConnectionHttpError> {
    if !record.write.enabled {
        return Err(ConnectionHttpError::ConnectionDisabled);
    }
    if record.write.kind != ConnectionKind::HttpApi {
        return Err(ConnectionHttpError::WrongConnectionKind);
    }
    if !record.write.tls.is_empty() {
        return Err(ConnectionHttpError::UnsupportedTls);
    }
    match &record.write.authentication {
        ConnectionAuthentication::None
        | ConnectionAuthentication::HeaderApiKey {
            secret_id: Some(_), ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: Some(_) } => Ok(()),
        ConnectionAuthentication::HeaderApiKey {
            secret_id: None, ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: None }
        | ConnectionAuthentication::OAuth2ClientCredentials { .. } => {
            Err(ConnectionHttpError::UnsupportedAuthentication)
        }
    }
}

fn static_authentication_binding(
    record: &StoredConnection,
) -> Result<StaticAuthenticationBinding, ConnectionHttpError> {
    match &record.write.authentication {
        ConnectionAuthentication::None => Ok(StaticAuthenticationBinding::None),
        ConnectionAuthentication::HeaderApiKey {
            header_name,
            secret_id: Some(secret_id),
        } => Ok(StaticAuthenticationBinding::HeaderApiKey {
            header_name: HeaderName::from_bytes(header_name.as_bytes())
                .map_err(|_| ConnectionHttpError::UnsupportedAuthentication)?,
            secret_id: secret_id.clone(),
        }),
        ConnectionAuthentication::StaticBearer {
            secret_id: Some(secret_id),
        } => Ok(StaticAuthenticationBinding::StaticBearer {
            secret_id: secret_id.clone(),
        }),
        ConnectionAuthentication::HeaderApiKey {
            secret_id: None, ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: None }
        | ConnectionAuthentication::OAuth2ClientCredentials { .. } => {
            Err(ConnectionHttpError::UnsupportedAuthentication)
        }
    }
}

fn connection_target_url(
    record: &StoredConnection,
    path_and_query: &str,
) -> Result<String, ConnectionHttpError> {
    let uri = path_and_query
        .parse::<Uri>()
        .map_err(|_| ConnectionHttpError::InvalidTargetPath)?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(ConnectionHttpError::InvalidTargetPath);
    }
    let normalized_path = normalize_origin_relative_path("connection.request_path", uri.path())
        .map_err(|_| ConnectionHttpError::InvalidTargetPath)?;
    let base_path = record.write.endpoint.base_path.as_str();
    let combined_path = if base_path == "/" {
        normalized_path
    } else if normalized_path == "/" {
        base_path.to_owned()
    } else {
        format!("{}{}", base_path.trim_end_matches('/'), normalized_path)
    };
    let mut target = format!("{}{}", record.write.endpoint.base_url, combined_path);
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }
    if target.len() > MAX_URL_BYTES {
        return Err(ConnectionHttpError::InvalidTargetPath);
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs, path::PathBuf};

    use super::*;
    use crate::{
        config::Config,
        connections::{
            model::{ConnectionEndpoint, ConnectionTimeouts, ConnectionWrite, TlsProfile},
            secret::{OperatorSecretAliasConfig, OperatorSecretAliasSource, SecretRootConfig},
            status::ConnectionRevisions,
        },
    };

    struct TemporaryRuntime {
        root: PathBuf,
        runtime: ConnectionHttpRuntime,
        connection_id: ConnectionId,
    }

    impl TemporaryRuntime {
        fn header_api_key(name: &str, header_name: &str, secret: &[u8]) -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-static-auth-{name}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary secret root should create");
            let secret_path = root.join("api-key");
            fs::write(&secret_path, secret).expect("temporary secret should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("temporary secret root permissions should set");
                fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                    .expect("temporary secret permissions should set");
            }

            let mut config = Config::test_defaults();
            config.connections_sqlite_path =
                Some(root.join("connections.sqlite").display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
            config.connection_secret_aliases = vec![OperatorSecretAliasConfig {
                id: "billing-api-key".to_owned(),
                label: "Billing API key".to_owned(),
                source: OperatorSecretAliasSource::File {
                    key: "api-key".to_owned(),
                },
            }];
            let control_plane =
                ConnectionControlPlane::from_config(&config).expect("control plane should build");
            let initial = control_plane.runtime_snapshot();
            let mut write = record("/v1").write;
            write.authentication = ConnectionAuthentication::HeaderApiKey {
                header_name: header_name.to_owned(),
                secret_id: Some("billing-api-key".to_owned()),
            };
            let created = control_plane
                .create_managed(initial.collection_etag(), write)
                .expect("connection should create");
            let egress_config = EgressConfig {
                allowed_hosts: HashSet::from(["billing.example.test".to_owned()]),
                ..EgressConfig::default()
            };
            let egress_client = Arc::new(
                EgressClient::new(egress_config.clone()).expect("egress client should build"),
            );
            let runtime = ConnectionHttpRuntime::new(control_plane, egress_config, egress_client);

            Self {
                root,
                runtime,
                connection_id: created.id,
            }
        }
    }

    impl Drop for TemporaryRuntime {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-static-auth-"))
                && self.root.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn record(base_path: &str) -> StoredConnection {
        StoredConnection {
            id: ConnectionId::parse("billing").expect("test connection ID"),
            write: ConnectionWrite {
                display_name: "Billing".to_owned(),
                description: None,
                enabled: true,
                kind: ConnectionKind::HttpApi,
                endpoint: ConnectionEndpoint {
                    base_url: "https://billing.example.test".to_owned(),
                    base_path: base_path.to_owned(),
                },
                authentication: ConnectionAuthentication::None,
                tls: TlsProfile::default(),
                timeouts: Some(ConnectionTimeouts::default()),
                discovery: None,
                test_profile: None,
            },
            revisions: ConnectionRevisions {
                connection: 1,
                credential: 1,
                tls: 1,
                discovery: 1,
                status: 0,
            },
            created_at: "2026-07-28T00:00:00Z".to_owned(),
            updated_at: "2026-07-28T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn target_url_stays_inside_connection_base_path() {
        assert_eq!(
            connection_target_url(&record("/v1"), "/charges/123?expand=customer")
                .expect("safe target"),
            "https://billing.example.test/v1/charges/123?expand=customer"
        );
        assert_eq!(
            connection_target_url(&record("/v1/"), "/").expect("base target"),
            "https://billing.example.test/v1/"
        );
    }

    #[test]
    fn authority_and_path_confusion_forms_fail_closed() {
        for path in [
            "https://attacker.example/",
            "//attacker.example/",
            "/safe/../escape",
            "/safe/%2fescape",
            "/safe\\escape",
        ] {
            assert_eq!(
                connection_target_url(&record("/v1"), path),
                Err(ConnectionHttpError::InvalidTargetPath),
                "{path}"
            );
        }
    }

    #[test]
    fn static_credentials_are_sensitive_and_replace_existing_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("attacker"));
        let credential = ResolvedStaticCredential::HeaderApiKey {
            header_name: HeaderName::from_static("x-api-key"),
            secret: ResolvedSecret::new(SecretPurpose::HeaderApiKey, b"real-key".to_vec())
                .expect("test secret"),
        };
        credential
            .inject(&mut headers)
            .expect("credential injection");

        let value = headers.get("x-api-key").expect("injected API key");
        assert_eq!(value, "real-key");
        assert!(value.is_sensitive());
    }

    #[test]
    fn static_bearer_replaces_authorization_and_marks_it_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer caller-value"),
        );
        let credential = ResolvedStaticCredential::StaticBearer {
            secret: ResolvedSecret::new(SecretPurpose::StaticBearer, b"operator-token".to_vec())
                .expect("test secret"),
        };
        credential.inject(&mut headers).expect("bearer injection");

        let value = headers
            .get(header::AUTHORIZATION)
            .expect("injected bearer should exist");
        assert_eq!(value, "Bearer operator-token");
        assert!(value.is_sensitive());
    }

    #[tokio::test]
    async fn runtime_binds_url_and_secret_resolution_to_the_stored_connection() {
        let temporary =
            TemporaryRuntime::header_api_key("bound-runtime", "x-api-key", b"operator-key");
        let target = temporary
            .runtime
            .target(
                temporary.connection_id.as_str(),
                "/charges/123?expand=customer",
            )
            .expect("stored connection target should resolve");
        assert_eq!(
            target.url(),
            "https://billing.example.test/v1/charges/123?expand=customer"
        );
        assert_eq!(target.authentication_kind(), "header_api_key");
        assert_eq!(
            target.credential_header_name(),
            Some(&HeaderName::from_static("x-api-key"))
        );

        let credential = temporary
            .runtime
            .resolve_credential(&target)
            .await
            .expect("operator-owned credential should resolve")
            .expect("API-key connection should have a credential");
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("caller-value"));
        credential
            .inject(&mut headers)
            .expect("credential should inject");
        let value = headers
            .get("x-api-key")
            .expect("configured credential header should exist");
        assert_eq!(value, "operator-key");
        assert!(value.is_sensitive());
    }

    #[tokio::test]
    async fn secret_provider_failure_returns_only_a_safe_bounded_reason() {
        let temporary =
            TemporaryRuntime::header_api_key("provider-failure", "x-api-key", b"do-not-leak");
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("stored connection target should resolve");
        fs::remove_file(temporary.root.join("api-key"))
            .expect("test should remove the provider file after activation");

        let error = match temporary.runtime.resolve_credential(&target).await {
            Ok(_) => panic!("missing provider file must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, ConnectionHttpError::CredentialUnavailable);
        let rendered = format!("{error:?}\n{error}");
        assert!(!rendered.contains("do-not-leak"));
        assert!(!rendered.contains("api-key"));
    }
}
