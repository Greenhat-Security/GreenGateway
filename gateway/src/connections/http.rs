use std::{
    collections::HashMap,
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use http::{
    header::{self, HeaderName},
    HeaderMap, HeaderValue, Method, Uri,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::egress::{CheckedEgressDestination, EgressClient, EgressConfig};

use super::{
    control_plane::ConnectionControlPlane,
    model::{
        normalize_origin_relative_path, ConnectionAuthentication, ConnectionId, ConnectionKind,
        ConnectionTestProfile, ConnectionTimeouts, DiscoveryConfig, OAuthClientAuthMethod,
        TlsProfile, MAX_CONNECTIONS, MAX_EXPECTED_STATUSES, MAX_URL_BYTES,
    },
    oauth::{
        OAuthBinding, OAuthClientCredentialsRuntime, OAuthError, OAuthTokenLease,
        OAUTH_MAX_REQUEST_BYTES, OAUTH_MAX_RESPONSE_BYTES,
    },
    secret::{ResolvedSecret, SecretPurpose, SecretResolveError, SecretResolveErrorKind},
    status::ConnectionRevisions,
    store::{ConnectionDependencyKind, StoredConnection},
};

#[derive(Clone)]
pub struct ConnectionHttpRuntime {
    control_plane: ConnectionControlPlane,
    base_egress_config: EgressConfig,
    base_egress_client: Arc<EgressClient>,
    clients: Arc<Mutex<HashMap<ConnectionClientCacheKey, Arc<EgressClient>>>>,
    oauth: OAuthClientCredentialsRuntime,
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
    connection_etag: String,
    url: String,
    client: Arc<EgressClient>,
    authentication: HttpAuthenticationBinding,
    transport: ConnectionTransportBinding,
}

#[derive(Clone)]
struct ConnectionTransportBinding {
    tls: TlsProfile,
    timeouts: ConnectionTimeouts,
    revisions: ConnectionRevisions,
}

struct ResolvedTlsProfile {
    ca_bundle: Option<ResolvedSecret>,
    client_identity: Option<(ResolvedSecret, ResolvedSecret)>,
}

pub struct PreparedConnectionTransport {
    client: Arc<EgressClient>,
    destination: CheckedEgressDestination,
}

pub struct ConnectionHttpTestTarget {
    target: ConnectionHttpTarget,
    method: Method,
    expected_statuses: Vec<u16>,
}

enum HttpAuthenticationBinding {
    None,
    HeaderApiKey {
        header_name: HeaderName,
        secret_id: String,
    },
    StaticBearer {
        secret_id: String,
    },
    OAuth2ClientCredentials(OAuthBinding),
}

pub struct ResolvedConnectionCredential {
    material: ResolvedCredentialMaterial,
}

enum ResolvedCredentialMaterial {
    HeaderApiKey {
        header_name: HeaderName,
        secret: ResolvedSecret,
    },
    StaticBearer {
        secret: ResolvedSecret,
    },
    OAuthBearer(OAuthTokenLease),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHttpError {
    InvalidConnectionId,
    ConnectionNotFound,
    ConnectionDisabled,
    WrongConnectionKind,
    UnsupportedAuthentication,
    TlsInvalid,
    TlsUnavailable,
    InvalidTargetPath,
    CredentialHeaderConflict,
    CredentialInvalid,
    CredentialUnavailable,
    OAuthTokenEgressDenied,
    OAuthTokenUnavailable,
    OAuthTokenRejected,
    OAuthTokenInvalidResponse,
    UpstreamAuthenticationRejected,
    TransportUnavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionClientProfile {
    Upstream,
    OAuthToken,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ConnectionClientCacheKey {
    Preflight([u8; 32]),
    Prepared([u8; 32]),
}

impl ConnectionClientProfile {
    const fn key(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::OAuthToken => "oauth-token",
        }
    }
}

impl ConnectionHttpRuntime {
    pub fn new(
        control_plane: ConnectionControlPlane,
        base_egress_config: EgressConfig,
        base_egress_client: Arc<EgressClient>,
    ) -> Self {
        let oauth = OAuthClientCredentialsRuntime::new(control_plane.clone());
        Self {
            control_plane,
            base_egress_config,
            base_egress_client,
            clients: Arc::new(Mutex::new(HashMap::new())),
            oauth,
        }
    }

    pub fn with_audit(mut self, audit: crate::audit::AuditLog) -> Self {
        self.oauth = self.oauth.with_audit(audit);
        self
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
        validate_http_connection(record)?;
        let url = connection_target_url(record, path_and_query)?;
        let client = self.client_for(record)?;
        let authentication = self.authentication_binding(record)?;

        Ok(ConnectionHttpTarget {
            connection_id,
            connection_etag: record.etag().to_string(),
            url,
            client,
            authentication,
            transport: connection_transport_binding(record),
        })
    }

    pub fn mcp_target(
        &self,
        connection_id: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(ConnectionHttpError::ConnectionNotFound)?;
        let use_connection_authentication = validate_mcp_connection(record)?;
        let url = connection_target_url(record, "/")?;
        let client = self.client_for(record)?;
        let authentication = if use_connection_authentication {
            self.authentication_binding(record)?
        } else {
            HttpAuthenticationBinding::None
        };

        Ok(ConnectionHttpTarget {
            connection_id,
            connection_etag: record.etag().to_string(),
            url,
            client,
            authentication,
            transport: connection_transport_binding(record),
        })
    }

    pub fn openapi_discovery_target(
        &self,
        connection_id: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(ConnectionHttpError::ConnectionNotFound)?;
        let (path, use_connection_authentication) = validate_openapi_connection(record)?;
        let url = connection_target_url(record, path)?;
        let client = self.client_for(record)?;
        let authentication = if use_connection_authentication {
            self.authentication_binding(record)?
        } else {
            HttpAuthenticationBinding::None
        };

        Ok(ConnectionHttpTarget {
            connection_id,
            connection_etag: record.etag().to_string(),
            url,
            client,
            authentication,
            transport: connection_transport_binding(record),
        })
    }

    /// Builds the exact persisted HTTP test target, including for a disabled
    /// managed connection. Normal data-plane target constructors remain
    /// fail-closed for disabled connections. A missing target indicates that
    /// the persisted connection no longer matches `expected_connection_etag`.
    pub fn test_target(
        &self,
        connection_id: &str,
        expected_connection_etag: &str,
    ) -> Result<Option<ConnectionHttpTestTarget>, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(ConnectionHttpError::ConnectionNotFound)?;
        let connection_etag = record.etag();
        if connection_etag.as_str() != expected_connection_etag {
            return Ok(None);
        }
        if record.write.kind != ConnectionKind::HttpApi {
            return Err(ConnectionHttpError::WrongConnectionKind);
        }
        validate_authentication(record)?;
        let ConnectionTestProfile {
            method,
            path,
            expected_statuses,
        } = record
            .write
            .test_profile
            .as_ref()
            .ok_or(ConnectionHttpError::InvalidTargetPath)?;
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| ConnectionHttpError::InvalidTargetPath)?;
        if !matches!(method, Method::GET | Method::HEAD) {
            return Err(ConnectionHttpError::InvalidTargetPath);
        }
        if expected_statuses.is_empty()
            || expected_statuses.len() > MAX_EXPECTED_STATUSES
            || expected_statuses
                .iter()
                .any(|status| !(100..=599).contains(status))
            || expected_statuses
                .iter()
                .enumerate()
                .any(|(index, status)| expected_statuses[..index].contains(status))
        {
            return Err(ConnectionHttpError::InvalidTargetPath);
        }
        let url = connection_target_url(record, path)?;
        let client = self.client_for(record)?;
        let authentication = self.authentication_binding(record)?;

        Ok(Some(ConnectionHttpTestTarget {
            target: ConnectionHttpTarget {
                connection_id,
                connection_etag: connection_etag.to_string(),
                url,
                client,
                authentication,
                transport: connection_transport_binding(record),
            },
            method,
            expected_statuses: expected_statuses.clone(),
        }))
    }

    /// Builds a managed MCP test target without requiring the persisted
    /// connection to be enabled. No caller-provided target or authentication
    /// override is accepted. A missing target indicates that the persisted
    /// connection no longer matches `expected_connection_etag`.
    pub fn mcp_test_target(
        &self,
        connection_id: &str,
        expected_connection_etag: &str,
    ) -> Result<Option<ConnectionHttpTarget>, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(ConnectionHttpError::ConnectionNotFound)?;
        let connection_etag = record.etag();
        if connection_etag.as_str() != expected_connection_etag {
            return Ok(None);
        }
        let use_connection_authentication = validate_mcp_connection_mode(record, false)?;
        let url = connection_target_url(record, "/")?;
        let client = self.client_for(record)?;
        let authentication = if use_connection_authentication {
            self.authentication_binding(record)?
        } else {
            HttpAuthenticationBinding::None
        };

        Ok(Some(ConnectionHttpTarget {
            connection_id,
            connection_etag: connection_etag.to_string(),
            url,
            client,
            authentication,
            transport: connection_transport_binding(record),
        }))
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
    ) -> Result<Option<ResolvedConnectionCredential>, ConnectionHttpError> {
        let (secret_id, purpose) = match &target.authentication {
            HttpAuthenticationBinding::None => return Ok(None),
            HttpAuthenticationBinding::HeaderApiKey { secret_id, .. } => {
                (secret_id.as_str(), SecretPurpose::HeaderApiKey)
            }
            HttpAuthenticationBinding::StaticBearer { secret_id } => {
                (secret_id.as_str(), SecretPurpose::StaticBearer)
            }
            HttpAuthenticationBinding::OAuth2ClientCredentials(binding) => {
                let token = self
                    .oauth
                    .access_token(binding)
                    .await
                    .map_err(connection_oauth_error)?;
                return Ok(Some(ResolvedConnectionCredential {
                    material: ResolvedCredentialMaterial::OAuthBearer(token),
                }));
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

        Ok(Some(ResolvedConnectionCredential {
            material: match &target.authentication {
                HttpAuthenticationBinding::HeaderApiKey { header_name, .. } => {
                    ResolvedCredentialMaterial::HeaderApiKey {
                        header_name: header_name.clone(),
                        secret,
                    }
                }
                HttpAuthenticationBinding::StaticBearer { .. } => {
                    ResolvedCredentialMaterial::StaticBearer { secret }
                }
                HttpAuthenticationBinding::None
                | HttpAuthenticationBinding::OAuth2ClientCredentials(_) => {
                    unreachable!("no-auth and OAuth targets return before static secret resolution")
                }
            },
        }))
    }

    /// Applies connection-owned TLS only after the caller has completed the
    /// ordinary egress preflight. The exact checked socket is rebound without
    /// another DNS lookup.
    pub async fn prepare_transport(
        &self,
        target: &ConnectionHttpTarget,
        checked: &CheckedEgressDestination,
    ) -> Result<PreparedConnectionTransport, ConnectionHttpError> {
        if target.transport.tls.is_empty() {
            let destination = target
                .client
                .rebind_checked_destination(checked, target.url())
                .map_err(|_| ConnectionHttpError::TransportUnavailable)?;
            return Ok(PreparedConnectionTransport {
                client: Arc::clone(&target.client),
                destination,
            });
        }

        let versions_before = self.tls_secret_versions(&target.transport.tls);
        let resolved = self.resolve_tls_profile(&target.transport.tls).await?;
        let versions_after = self.tls_secret_versions(&target.transport.tls);
        if versions_before != versions_after {
            return Err(ConnectionHttpError::TlsUnavailable);
        }

        let mut config = self.config_for_timeouts(&target.transport.timeouts);
        if let Some(ca_bundle) = resolved.ca_bundle.as_ref() {
            config
                .apply_tls_ca_bundle_pem(ca_bundle.expose())
                .map_err(|_| ConnectionHttpError::TlsInvalid)?;
        }
        if let Some((certificate, private_key)) = resolved.client_identity.as_ref() {
            let separator_len = usize::from(!certificate.expose().ends_with(b"\n"));
            let identity_len = certificate
                .expose()
                .len()
                .checked_add(separator_len)
                .and_then(|length| length.checked_add(private_key.expose().len()))
                .ok_or(ConnectionHttpError::TlsInvalid)?;
            let mut identity = Zeroizing::new(Vec::with_capacity(identity_len));
            identity.extend_from_slice(certificate.expose());
            if separator_len == 1 {
                identity.push(b'\n');
            }
            identity.extend_from_slice(private_key.expose());
            config
                .apply_tls_client_identity_pem(identity.as_slice())
                .map_err(|_| ConnectionHttpError::TlsInvalid)?;
        }
        config.apply_transport_partition(&connection_transport_partition(
            &target.connection_id,
            &target.transport.revisions,
            ConnectionClientProfile::Upstream,
            versions_after,
        ));
        let client = self.cached_client(config)?;
        let destination = client
            .rebind_checked_destination(checked, target.url())
            .map_err(|_| ConnectionHttpError::TransportUnavailable)?;

        Ok(PreparedConnectionTransport {
            client,
            destination,
        })
    }

    fn authentication_binding(
        &self,
        record: &StoredConnection,
    ) -> Result<HttpAuthenticationBinding, ConnectionHttpError> {
        match &record.write.authentication {
            ConnectionAuthentication::None => Ok(HttpAuthenticationBinding::None),
            ConnectionAuthentication::HeaderApiKey {
                header_name,
                secret_id: Some(secret_id),
            } => Ok(HttpAuthenticationBinding::HeaderApiKey {
                header_name: HeaderName::from_bytes(header_name.as_bytes())
                    .map_err(|_| ConnectionHttpError::UnsupportedAuthentication)?,
                secret_id: secret_id.clone(),
            }),
            ConnectionAuthentication::StaticBearer {
                secret_id: Some(secret_id),
            } => Ok(HttpAuthenticationBinding::StaticBearer {
                secret_id: secret_id.clone(),
            }),
            ConnectionAuthentication::OAuth2ClientCredentials {
                client_id,
                client_secret_id: Some(client_secret_id),
                token_url,
                scopes,
                audience,
                resource,
                client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
            } => Ok(HttpAuthenticationBinding::OAuth2ClientCredentials(
                OAuthBinding {
                    connection_id: record.id.clone(),
                    connection_etag: record.etag().to_string(),
                    client_id: client_id.clone(),
                    client_secret_id: client_secret_id.clone(),
                    token_url: token_url.clone(),
                    scopes: scopes.clone(),
                    audience: audience.clone(),
                    resource: resource.clone(),
                    token_client: self.oauth_client_for(record)?,
                },
            )),
            ConnectionAuthentication::HeaderApiKey {
                secret_id: None, ..
            }
            | ConnectionAuthentication::StaticBearer { secret_id: None }
            | ConnectionAuthentication::OAuth2ClientCredentials {
                client_secret_id: None,
                ..
            } => Err(ConnectionHttpError::UnsupportedAuthentication),
        }
    }

    fn oauth_client_for(
        &self,
        record: &StoredConnection,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        self.client_for_profile(record, ConnectionClientProfile::OAuthToken)
    }

    fn client_for(
        &self,
        record: &StoredConnection,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        self.client_for_profile(record, ConnectionClientProfile::Upstream)
    }

    fn client_for_profile(
        &self,
        record: &StoredConnection,
        profile: ConnectionClientProfile,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        let partition = connection_transport_partition(
            &record.id,
            &record.revisions,
            profile,
            [None, None, None],
        );
        let cache_key = ConnectionClientCacheKey::Preflight(partition);
        if let Some(client) = self.client_guard().get(&cache_key).cloned() {
            return Ok(client);
        }

        let timeouts = record.write.timeouts.clone().unwrap_or_default();
        let mut config = self.config_for_timeouts(&timeouts);
        if profile == ConnectionClientProfile::OAuthToken {
            config.max_response_bytes = OAUTH_MAX_RESPONSE_BYTES;
            config.max_request_body_bytes = OAUTH_MAX_REQUEST_BYTES;
        }
        config.apply_transport_partition(&partition);
        let candidate = self.build_client(config)?;
        Ok(self.insert_cached_client(cache_key, candidate))
    }

    fn config_for_timeouts(&self, timeouts: &ConnectionTimeouts) -> EgressConfig {
        let mut config = self.base_egress_config.clone();
        config.apply_timeout_overrides(
            Some(timeouts.request_timeout_ms),
            Some(timeouts.response_idle_timeout_ms),
            Some(timeouts.connect_timeout_ms),
        );
        config
    }

    fn cached_client(
        &self,
        config: EgressConfig,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        let candidate = self.build_client(config)?;
        let cache_key = ConnectionClientCacheKey::Prepared(candidate.configuration_generation());
        if let Some(client) = self.client_guard().get(&cache_key).cloned() {
            return Ok(client);
        }
        Ok(self.insert_cached_client(cache_key, candidate))
    }

    fn build_client(&self, config: EgressConfig) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        Ok(Arc::new(
            self.base_egress_client
                .reconfigured(config)
                .map_err(|_| ConnectionHttpError::TransportUnavailable)?,
        ))
    }

    fn insert_cached_client(
        &self,
        cache_key: ConnectionClientCacheKey,
        candidate: Arc<EgressClient>,
    ) -> Arc<EgressClient> {
        let mut clients = self.client_guard();
        if clients.len() >= MAX_CONNECTIONS.saturating_mul(2) && !clients.contains_key(&cache_key) {
            clients.clear();
        }
        Arc::clone(clients.entry(cache_key).or_insert(candidate))
    }

    fn tls_secret_versions(&self, tls: &TlsProfile) -> [Option<u64>; 3] {
        [
            tls.ca_bundle_alias
                .as_deref()
                .and_then(|id| self.control_plane.local_secret_version(id)),
            tls.client_certificate_id
                .as_deref()
                .and_then(|id| self.control_plane.local_secret_version(id)),
            tls.client_private_key_id
                .as_deref()
                .and_then(|id| self.control_plane.local_secret_version(id)),
        ]
    }

    async fn resolve_tls_profile(
        &self,
        tls: &TlsProfile,
    ) -> Result<ResolvedTlsProfile, ConnectionHttpError> {
        let ca_bundle = match tls.ca_bundle_alias.as_deref() {
            Some(id) => Some(
                self.control_plane
                    .secret_resolver()
                    .resolve(id, SecretPurpose::TlsCaBundle)
                    .await
                    .map_err(connection_tls_secret_error)?,
            ),
            None => None,
        };
        let client_identity = match (
            tls.client_certificate_id.as_deref(),
            tls.client_private_key_id.as_deref(),
        ) {
            (Some(certificate_id), Some(private_key_id)) => {
                let certificate = self
                    .control_plane
                    .secret_resolver()
                    .resolve(certificate_id, SecretPurpose::TlsCertificate)
                    .await
                    .map_err(connection_tls_secret_error)?;
                let private_key = self
                    .control_plane
                    .secret_resolver()
                    .resolve(private_key_id, SecretPurpose::TlsPrivateKey)
                    .await
                    .map_err(connection_tls_secret_error)?;
                Some((certificate, private_key))
            }
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => return Err(ConnectionHttpError::TlsInvalid),
        };

        Ok(ResolvedTlsProfile {
            ca_bundle,
            client_identity,
        })
    }

    fn client_guard(&self) -> MutexGuard<'_, HashMap<ConnectionClientCacheKey, Arc<EgressClient>>> {
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

    pub fn connection_etag(&self) -> &str {
        &self.connection_etag
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn client(&self) -> &Arc<EgressClient> {
        &self.client
    }

    pub fn preflight_client(&self) -> &Arc<EgressClient> {
        &self.client
    }

    pub fn credential_header_name(&self) -> Option<&HeaderName> {
        match &self.authentication {
            HttpAuthenticationBinding::None => None,
            HttpAuthenticationBinding::HeaderApiKey { header_name, .. } => Some(header_name),
            HttpAuthenticationBinding::StaticBearer { .. }
            | HttpAuthenticationBinding::OAuth2ClientCredentials(_) => Some(&header::AUTHORIZATION),
        }
    }

    pub fn authentication_kind(&self) -> &'static str {
        match self.authentication {
            HttpAuthenticationBinding::None => "none",
            HttpAuthenticationBinding::HeaderApiKey { .. } => "header_api_key",
            HttpAuthenticationBinding::StaticBearer { .. } => "static_bearer",
            HttpAuthenticationBinding::OAuth2ClientCredentials(_) => "oauth2_client_credentials",
        }
    }
}

impl ResolvedConnectionCredential {
    pub fn inject(&self, headers: &mut HeaderMap) -> Result<(), ConnectionHttpError> {
        let (name, mut value) = match &self.material {
            ResolvedCredentialMaterial::HeaderApiKey {
                header_name,
                secret,
            } => (
                header_name.clone(),
                HeaderValue::from_bytes(secret.expose())
                    .map_err(|_| ConnectionHttpError::CredentialInvalid)?,
            ),
            ResolvedCredentialMaterial::StaticBearer { secret } => {
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
            ResolvedCredentialMaterial::OAuthBearer(token) => {
                return token.inject(headers).map_err(connection_oauth_error);
            }
        };
        value.set_sensitive(true);
        headers.insert(name, value);
        Ok(())
    }

    pub async fn invalidate_after_unauthorized(&self) {
        if let ResolvedCredentialMaterial::OAuthBearer(token) = &self.material {
            token.invalidate_after_unauthorized().await;
        }
    }

    pub fn is_oauth(&self) -> bool {
        matches!(self.material, ResolvedCredentialMaterial::OAuthBearer(_))
    }

    #[cfg(test)]
    pub(crate) fn header_api_key_for_test(
        header_name: HeaderName,
        value: &[u8],
    ) -> ResolvedConnectionCredential {
        ResolvedConnectionCredential {
            material: ResolvedCredentialMaterial::HeaderApiKey {
                header_name,
                secret: ResolvedSecret::new(SecretPurpose::HeaderApiKey, value.to_vec())
                    .expect("test API-key material should be valid"),
            },
        }
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
            Self::TlsInvalid => "tls_invalid",
            Self::TlsUnavailable => "tls_unavailable",
            Self::InvalidTargetPath => "invalid_target_path",
            Self::CredentialHeaderConflict => "credential_header_conflict",
            Self::CredentialInvalid => "credential_invalid",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::OAuthTokenEgressDenied => "oauth_token_egress_denied",
            Self::OAuthTokenUnavailable => "oauth_token_unavailable",
            Self::OAuthTokenRejected => "oauth_token_rejected",
            Self::OAuthTokenInvalidResponse => "oauth_token_invalid_response",
            Self::UpstreamAuthenticationRejected => "auth_failed",
            Self::TransportUnavailable => "transport_unavailable",
        }
    }

    pub fn is_secret_resolution_failure(self) -> bool {
        matches!(
            self,
            Self::CredentialInvalid
                | Self::CredentialUnavailable
                | Self::TlsInvalid
                | Self::TlsUnavailable
        )
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

fn connection_transport_binding(record: &StoredConnection) -> ConnectionTransportBinding {
    ConnectionTransportBinding {
        tls: record.write.tls.clone(),
        timeouts: record.write.timeouts.clone().unwrap_or_default(),
        revisions: record.revisions.clone(),
    }
}

fn connection_transport_partition(
    connection_id: &ConnectionId,
    revisions: &ConnectionRevisions,
    profile: ConnectionClientProfile,
    local_tls_versions: [Option<u64>; 3],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"greengateway:connection-transport:v1\0");
    hasher.update((connection_id.as_str().len() as u64).to_be_bytes());
    hasher.update(connection_id.as_str().as_bytes());
    for revision in [
        revisions.connection,
        revisions.credential,
        revisions.tls,
        revisions.discovery,
        revisions.status,
    ] {
        hasher.update(revision.to_be_bytes());
    }
    hasher.update((profile.key().len() as u64).to_be_bytes());
    hasher.update(profile.key().as_bytes());
    for version in local_tls_versions {
        match version {
            Some(version) => {
                hasher.update([1]);
                hasher.update(version.to_be_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hasher.finalize().into()
}

fn connection_tls_secret_error(error: SecretResolveError) -> ConnectionHttpError {
    match error.kind() {
        SecretResolveErrorKind::UnknownAlias
        | SecretResolveErrorKind::SourceDenied
        | SecretResolveErrorKind::InvalidMaterial => ConnectionHttpError::TlsInvalid,
        SecretResolveErrorKind::ProviderBusy
        | SecretResolveErrorKind::SourceUnavailable
        | SecretResolveErrorKind::UnsafeSource
        | SecretResolveErrorKind::ProviderFailure => ConnectionHttpError::TlsUnavailable,
    }
}

fn validate_http_connection(record: &StoredConnection) -> Result<(), ConnectionHttpError> {
    if !record.write.enabled {
        return Err(ConnectionHttpError::ConnectionDisabled);
    }
    if record.write.kind != ConnectionKind::HttpApi {
        return Err(ConnectionHttpError::WrongConnectionKind);
    }
    validate_authentication(record)
}

fn validate_authentication(record: &StoredConnection) -> Result<(), ConnectionHttpError> {
    match &record.write.authentication {
        ConnectionAuthentication::None
        | ConnectionAuthentication::HeaderApiKey {
            secret_id: Some(_), ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: Some(_) }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: Some(_),
            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
            ..
        } => Ok(()),
        ConnectionAuthentication::HeaderApiKey {
            secret_id: None, ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: None }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: None,
            ..
        } => Err(ConnectionHttpError::UnsupportedAuthentication),
    }
}

fn validate_mcp_connection(record: &StoredConnection) -> Result<bool, ConnectionHttpError> {
    validate_mcp_connection_mode(record, true)
}

fn validate_mcp_connection_mode(
    record: &StoredConnection,
    require_enabled: bool,
) -> Result<bool, ConnectionHttpError> {
    if require_enabled && !record.write.enabled {
        return Err(ConnectionHttpError::ConnectionDisabled);
    }
    if record.write.kind != ConnectionKind::McpStreamableHttp {
        return Err(ConnectionHttpError::WrongConnectionKind);
    }
    let use_connection_authentication = match &record.write.discovery {
        Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication,
        }) => *use_connection_authentication,
        _ => return Err(ConnectionHttpError::WrongConnectionKind),
    };
    if !use_connection_authentication {
        return Ok(false);
    }
    validate_authentication(record)?;
    Ok(true)
}

impl PreparedConnectionTransport {
    pub fn client(&self) -> &Arc<EgressClient> {
        &self.client
    }

    pub fn destination(&self) -> &CheckedEgressDestination {
        &self.destination
    }
}

impl ConnectionHttpTestTarget {
    pub fn target(&self) -> &ConnectionHttpTarget {
        &self.target
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn expected_statuses(&self) -> &[u16] {
        &self.expected_statuses
    }

    pub fn into_target(self) -> ConnectionHttpTarget {
        self.target
    }
}

fn validate_openapi_connection(
    record: &StoredConnection,
) -> Result<(&str, bool), ConnectionHttpError> {
    validate_http_connection(record)?;
    match &record.write.discovery {
        Some(DiscoveryConfig::ManagedOpenapi {
            path: Some(path),
            use_connection_authentication,
        }) => Ok((path.as_str(), *use_connection_authentication)),
        Some(DiscoveryConfig::ManagedOpenapi { path: None, .. }) | None => {
            Err(ConnectionHttpError::InvalidTargetPath)
        }
        Some(DiscoveryConfig::ManagedMcp { .. }) => Err(ConnectionHttpError::WrongConnectionKind),
    }
}

fn connection_oauth_error(error: OAuthError) -> ConnectionHttpError {
    match error {
        OAuthError::CredentialInvalid => ConnectionHttpError::CredentialInvalid,
        OAuthError::CredentialUnavailable => ConnectionHttpError::CredentialUnavailable,
        OAuthError::TokenEgressDenied => ConnectionHttpError::OAuthTokenEgressDenied,
        OAuthError::TokenUnavailable => ConnectionHttpError::OAuthTokenUnavailable,
        OAuthError::TokenRejected => ConnectionHttpError::OAuthTokenRejected,
        OAuthError::InvalidTokenResponse => ConnectionHttpError::OAuthTokenInvalidResponse,
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
    use std::{
        collections::HashSet,
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        time::{Duration, Instant},
    };

    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    use http::StatusCode;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, SanType};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{
        rustls::{
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
            ServerConfig,
        },
        TlsAcceptor,
    };

    use super::*;
    use crate::{
        audit::{self, sink::tests::CaptureSink, AuditSink},
        config::Config,
        connections::{
            model::{
                ConnectionEndpoint, ConnectionTimeouts, ConnectionWrite, OAuthClientAuthMethod,
                TlsProfile,
            },
            secret::{OperatorSecretAliasConfig, OperatorSecretAliasSource, SecretRootConfig},
            status::{ConnectionOperationalState, ConnectionRevisions, ConnectionStatusReason},
            test::{
                ConnectionTestReason, ConnectionTestService, ConnectionTestStage,
                ConnectionTestStageName,
            },
        },
    };

    const OAUTH_CLIENT_SECRET_CANARY: &[u8] = b"oauth-client-secret-canary";
    const OAUTH_ACCESS_TOKEN_CANARY: &str = "oauth-access-token-canary";
    const OAUTH_REFRESH_TOKEN_CANARY: &str = "oauth-refresh-token-canary";

    struct CapturedTokenRequest {
        head: String,
        body: String,
        response_sent: bool,
    }

    async fn one_request_tls_token_server(
        status: StatusCode,
        content_type: &str,
        body: Vec<u8>,
    ) -> (
        SocketAddr,
        String,
        tokio::task::JoinHandle<CapturedTokenRequest>,
    ) {
        let (addr, ca_pem, handle, _received) =
            one_request_delayed_tls_token_server(status, content_type, body, Duration::ZERO).await;
        (addr, ca_pem, handle)
    }

    async fn one_request_delayed_tls_token_server(
        status: StatusCode,
        content_type: &str,
        body: Vec<u8>,
        response_delay: Duration,
    ) -> (
        SocketAddr,
        String,
        tokio::task::JoinHandle<CapturedTokenRequest>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "GreenGateway OAuth Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("test CA certificate should build");
        let mut server_params = CertificateParams::default();
        server_params.distinguished_name = DistinguishedName::new();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "127.0.0.1");
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let server_key = rcgen::KeyPair::generate().expect("test server key should generate");
        let server_certificate = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .expect("test server certificate should build");
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    server_certificate.der().as_ref().to_vec(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("test TLS server config should build");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test TLS listener should bind");
        let addr = listener.local_addr().expect("test TLS address");
        let content_type = content_type.to_owned();
        let (request_received_tx, request_received_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("token server should accept one request");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("token server TLS should succeed");
            let request = read_http_request(&mut stream).await;
            let _ = request_received_tx.send(());
            let mut disconnected = [0_u8; 1];
            let response_sent = tokio::select! {
                () = tokio::time::sleep(response_delay) => {
                    let reason = status.canonical_reason().unwrap_or("Response");
                    let response = format!(
                        "HTTP/1.1 {} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status.as_u16(),
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("token response headers should write");
                    stream
                        .write_all(&body)
                        .await
                        .expect("token response body should write");
                    true
                }
                _ = stream.read(&mut disconnected) => false,
            };
            let mut request = request;
            request.response_sent = response_sent;
            request
        });
        (addr, ca.pem(), handle, request_received_rx)
    }

    async fn read_http_request<T>(stream: &mut T) -> CapturedTokenRequest
    where
        T: AsyncReadExt + Unpin,
    {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 2048];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("token request should read");
            assert!(read > 0, "token request closed before headers completed");
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let content_length = String::from_utf8_lossy(&bytes[..header_end])
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while bytes.len() < header_end.saturating_add(content_length) {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("token request body should read");
            assert!(read > 0, "token request closed before body completed");
            bytes.extend_from_slice(&chunk[..read]);
        }
        CapturedTokenRequest {
            head: String::from_utf8_lossy(&bytes[..header_end]).into_owned(),
            body: String::from_utf8_lossy(
                &bytes[header_end..header_end.saturating_add(content_length)],
            )
            .into_owned(),
            response_sent: false,
        }
    }

    async fn captured_audit_events(
        capture: &CaptureSink,
        expected_count: usize,
    ) -> Vec<audit::AuditEvent> {
        let started = Instant::now();
        while capture.len() < expected_count && started.elapsed() < Duration::from_secs(1) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        capture.events()
    }

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

    struct TemporaryManagedRuntime {
        root: PathBuf,
        runtime: ConnectionHttpRuntime,
        connection_id: ConnectionId,
        ca_path: Option<PathBuf>,
    }

    impl TemporaryManagedRuntime {
        fn from_write(name: &str, write: ConnectionWrite) -> Self {
            Self::build(name, write, Vec::new(), None)
        }

        fn tls_identity(name: &str) -> Self {
            Self::tls_identity_with_oauth(name, false)
        }

        fn tls_identity_with_oauth(name: &str, with_oauth: bool) -> Self {
            let root = temporary_managed_root(name);
            fs::create_dir(&root).expect("temporary managed root should create");
            let identity_key = rcgen::KeyPair::generate().expect("test identity key should build");
            let identity_certificate = CertificateParams::default()
                .self_signed(&identity_key)
                .expect("test identity certificate should build");
            let ca_path = root.join("ca.pem");
            let certificate_path = root.join("client-certificate.pem");
            let private_key_path = root.join("client-private-key.pem");
            let oauth_secret_path = root.join("oauth-secret");
            fs::write(&ca_path, identity_certificate.pem()).expect("test CA bundle should write");
            fs::write(&certificate_path, identity_certificate.pem())
                .expect("test client certificate should write");
            fs::write(&private_key_path, identity_key.serialize_pem())
                .expect("test client private key should write");
            if with_oauth {
                fs::write(&oauth_secret_path, OAUTH_CLIENT_SECRET_CANARY)
                    .expect("test OAuth secret should write");
            }

            let mut write = record("/").write;
            write.endpoint.base_url = "https://127.0.0.1".to_owned();
            write.tls = TlsProfile {
                ca_bundle_alias: Some("test-ca".to_owned()),
                client_certificate_id: Some("test-client-certificate".to_owned()),
                client_private_key_id: Some("test-client-private-key".to_owned()),
            };
            if with_oauth {
                write.authentication = ConnectionAuthentication::OAuth2ClientCredentials {
                    client_id: "test-client".to_owned(),
                    client_secret_id: Some("test-oauth-secret".to_owned()),
                    token_url: "https://token.example.test/oauth/token".to_owned(),
                    scopes: vec![],
                    audience: None,
                    resource: None,
                    client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
                };
            }
            let mut aliases = vec![
                OperatorSecretAliasConfig {
                    id: "test-ca".to_owned(),
                    label: "Test CA".to_owned(),
                    source: OperatorSecretAliasSource::File {
                        key: "ca.pem".to_owned(),
                    },
                },
                OperatorSecretAliasConfig {
                    id: "test-client-certificate".to_owned(),
                    label: "Test client certificate".to_owned(),
                    source: OperatorSecretAliasSource::File {
                        key: "client-certificate.pem".to_owned(),
                    },
                },
                OperatorSecretAliasConfig {
                    id: "test-client-private-key".to_owned(),
                    label: "Test client private key".to_owned(),
                    source: OperatorSecretAliasSource::File {
                        key: "client-private-key.pem".to_owned(),
                    },
                },
            ];
            if with_oauth {
                aliases.push(OperatorSecretAliasConfig {
                    id: "test-oauth-secret".to_owned(),
                    label: "Test OAuth secret".to_owned(),
                    source: OperatorSecretAliasSource::File {
                        key: "oauth-secret".to_owned(),
                    },
                });
            }
            Self::build_with_root(name, root, write, aliases, Some(ca_path))
        }

        fn build(
            name: &str,
            write: ConnectionWrite,
            aliases: Vec<OperatorSecretAliasConfig>,
            ca_path: Option<PathBuf>,
        ) -> Self {
            let root = temporary_managed_root(name);
            fs::create_dir(&root).expect("temporary managed root should create");
            Self::build_with_root(name, root, write, aliases, ca_path)
        }

        fn build_with_root(
            _name: &str,
            root: PathBuf,
            write: ConnectionWrite,
            aliases: Vec<OperatorSecretAliasConfig>,
            ca_path: Option<PathBuf>,
        ) -> Self {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("temporary managed root permissions should set");
                for entry in fs::read_dir(&root).expect("temporary managed root should read") {
                    let path = entry.expect("temporary managed entry should read").path();
                    if path.is_file() {
                        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                            .expect("temporary managed file permissions should set");
                    }
                }
            }
            let mut config = Config::test_defaults();
            config.connections_sqlite_path =
                Some(root.join("connections.sqlite").display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
            config.connection_secret_aliases = aliases;
            let control_plane =
                ConnectionControlPlane::from_config(&config).expect("control plane should build");
            let initial = control_plane.runtime_snapshot();
            let created = control_plane
                .create_managed(initial.collection_etag(), write)
                .expect("managed connection should create");
            let egress_config = EgressConfig {
                allowed_hosts: HashSet::from([
                    "127.0.0.1".to_owned(),
                    "billing.example.test".to_owned(),
                    "token.example.test".to_owned(),
                ]),
                deny_private_ips: false,
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
                ca_path,
            }
        }

        fn stored_connection(&self) -> StoredConnection {
            self.runtime
                .control_plane
                .runtime_snapshot()
                .managed()
                .get(&self.connection_id)
                .expect("managed test connection should remain present")
                .clone()
        }

        fn cached_client_count(&self) -> usize {
            self.runtime.client_guard().len()
        }
    }

    impl Drop for TemporaryManagedRuntime {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-managed-http-"))
                && self.root.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn temporary_managed_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "greengateway-managed-http-{name}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    struct TemporaryOAuthRuntime {
        root: PathBuf,
        secret_path: PathBuf,
        runtime: ConnectionHttpRuntime,
        connection_id: ConnectionId,
        capture: CaptureSink,
    }

    impl TemporaryOAuthRuntime {
        fn new(
            name: &str,
            base_url: String,
            token_url: String,
            allowed_hosts: HashSet<String>,
            ca_pem: Option<&str>,
        ) -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-oauth-{name}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary OAuth root should create");
            let secret_path = root.join("client-secret");
            fs::write(&secret_path, OAUTH_CLIENT_SECRET_CANARY)
                .expect("temporary OAuth secret should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("temporary OAuth root permissions should set");
                fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                    .expect("temporary OAuth secret permissions should set");
            }

            let mut config = Config::test_defaults();
            config.connections_sqlite_path =
                Some(root.join("connections.sqlite").display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
            config.connection_secret_aliases = vec![OperatorSecretAliasConfig {
                id: "billing-oauth-secret".to_owned(),
                label: "Billing OAuth client secret".to_owned(),
                source: OperatorSecretAliasSource::File {
                    key: "client-secret".to_owned(),
                },
            }];
            let control_plane =
                ConnectionControlPlane::from_config(&config).expect("control plane should build");
            let initial = control_plane.runtime_snapshot();
            let mut write = record("/v1").write;
            write.endpoint.base_url = base_url;
            write.authentication = ConnectionAuthentication::OAuth2ClientCredentials {
                client_id: "billing:client".to_owned(),
                client_secret_id: Some("billing-oauth-secret".to_owned()),
                token_url,
                scopes: vec!["invoices.read".to_owned(), "payments.write".to_owned()],
                audience: Some("billing-api".to_owned()),
                resource: Some("urn:billing".to_owned()),
                client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
            };
            let created = control_plane
                .create_managed(initial.collection_etag(), write)
                .expect("OAuth connection should create");

            let mut egress_config = EgressConfig {
                allowed_hosts,
                deny_private_ips: false,
                ..EgressConfig::default()
            };
            if let Some(ca_pem) = ca_pem {
                let ca_path = root.join("oauth-ca.pem");
                fs::write(&ca_path, ca_pem).expect("OAuth CA should write");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
                        .expect("OAuth CA permissions should set");
                }
                egress_config
                    .apply_tls_ca_bundle_path(ca_path)
                    .expect("OAuth CA should configure");
            }
            let egress_client = Arc::new(
                EgressClient::new(egress_config.clone()).expect("egress client should build"),
            );
            let capture = CaptureSink::new();
            let audit = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
            let runtime = ConnectionHttpRuntime::new(control_plane, egress_config, egress_client)
                .with_audit(audit);

            Self {
                root,
                secret_path,
                runtime,
                connection_id: created.id,
                capture,
            }
        }

        fn stored_connection(&self) -> StoredConnection {
            self.runtime
                .control_plane
                .runtime_snapshot()
                .managed()
                .get(&self.connection_id)
                .expect("managed OAuth test connection should remain present")
                .clone()
        }
    }

    impl Drop for TemporaryOAuthRuntime {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-oauth-"))
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

    #[tokio::test]
    async fn connection_tls_is_resolved_only_after_egress_preflight() {
        let temporary = TemporaryManagedRuntime::tls_identity("tls-preflight-order");
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/health")
            .expect("TLS target creation must not resolve secret material");
        fs::remove_file(
            temporary
                .ca_path
                .as_ref()
                .expect("TLS helper should retain CA path"),
        )
        .expect("test CA should be removed after target creation");

        let checked = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .expect("egress preflight must not require TLS secret material");
        let error = match temporary.runtime.prepare_transport(&target, &checked).await {
            Ok(_) => panic!("missing TLS material must fail closed"),
            Err(error) => error,
        };

        assert_eq!(error, ConnectionHttpError::TlsUnavailable);
        assert_eq!(error.safe_reason(), "tls_unavailable");
        assert!(!error.to_string().contains("ca.pem"));
    }

    #[tokio::test]
    async fn malformed_runtime_tls_material_has_only_stable_redacted_error() {
        const INVALID_TLS_CANARY: &[u8] = b"invalid-tls-private-canary";
        let temporary = TemporaryManagedRuntime::tls_identity("invalid-runtime-tls");
        fs::write(
            temporary
                .ca_path
                .as_ref()
                .expect("TLS helper should retain CA path"),
            INVALID_TLS_CANARY,
        )
        .expect("test CA should be corrupted after activation");
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/health")
            .expect("target construction must stay TLS-material-free");
        let checked = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .expect("egress preflight should precede TLS resolution");
        let error = match temporary.runtime.prepare_transport(&target, &checked).await {
            Ok(_) => panic!("malformed TLS material must fail closed"),
            Err(error) => error,
        };

        assert_eq!(error, ConnectionHttpError::TlsInvalid);
        assert_eq!(error.safe_reason(), "tls_invalid");
        assert!(!error.to_string().contains(
            std::str::from_utf8(INVALID_TLS_CANARY).expect("test canary should be UTF-8")
        ));
    }

    #[tokio::test]
    async fn prepared_upstream_applies_identity_without_leaking_it_to_oauth() {
        let temporary =
            TemporaryManagedRuntime::tls_identity_with_oauth("tls-oauth-isolation", true);
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/health")
            .expect("TLS OAuth target should build");
        let oauth_client = match &target.authentication {
            HttpAuthenticationBinding::OAuth2ClientCredentials(binding) => &binding.token_client,
            _ => panic!("test connection should use OAuth"),
        };
        assert_eq!(
            oauth_client.client_identity_fingerprint(),
            None,
            "connection-owned mTLS must not be applied to the OAuth token host"
        );

        let checked = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .expect("upstream preflight should succeed");
        let prepared = temporary
            .runtime
            .prepare_transport(&target, &checked)
            .await
            .expect("valid in-memory TLS material should prepare");

        assert!(
            prepared.client().client_identity_fingerprint().is_some(),
            "prepared upstream must carry the connection-owned identity"
        );
        assert_ne!(
            target.preflight_client().configuration_generation(),
            prepared.client().configuration_generation(),
            "resolved TLS material must select a distinct final transport"
        );
        assert_eq!(prepared.destination().host, "127.0.0.1");
    }

    #[tokio::test]
    async fn tls_material_is_resolved_again_before_each_cache_selection() {
        let temporary = TemporaryManagedRuntime::tls_identity("tls-runtime-rotation");
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/health")
            .expect("TLS target should build");
        let checked = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .expect("upstream preflight should succeed");
        let first = temporary
            .runtime
            .prepare_transport(&target, &checked)
            .await
            .expect("first TLS material should prepare");

        let replacement_key =
            rcgen::KeyPair::generate().expect("replacement identity key should build");
        let replacement_certificate = CertificateParams::default()
            .self_signed(&replacement_key)
            .expect("replacement identity certificate should build");
        fs::write(temporary.root.join("ca.pem"), replacement_certificate.pem())
            .expect("replacement CA should write");
        fs::write(
            temporary.root.join("client-certificate.pem"),
            replacement_certificate.pem(),
        )
        .expect("replacement certificate should write");
        fs::write(
            temporary.root.join("client-private-key.pem"),
            replacement_key.serialize_pem(),
        )
        .expect("replacement private key should write");

        let second = temporary
            .runtime
            .prepare_transport(&target, &checked)
            .await
            .expect("rotated TLS material should prepare");
        assert_ne!(
            first.client().client_identity_fingerprint(),
            second.client().client_identity_fingerprint(),
            "material rotation must not reuse the previous identity"
        );
        assert_ne!(
            first.client().configuration_generation(),
            second.client().configuration_generation(),
            "material rotation must select a distinct cached transport"
        );
    }

    #[test]
    fn persisted_http_test_target_can_probe_disabled_connection_without_widening_runtime() {
        let mut write = record("/v1").write;
        write.enabled = false;
        write.test_profile = Some(ConnectionTestProfile {
            method: "HEAD".to_owned(),
            path: "/ready".to_owned(),
            expected_statuses: vec![200, 204],
        });
        let temporary = TemporaryManagedRuntime::from_write("disabled-http-test", write);

        let normal_error = match temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/ready")
        {
            Ok(_) => panic!("normal target must reject a disabled connection"),
            Err(error) => error,
        };
        assert_eq!(normal_error, ConnectionHttpError::ConnectionDisabled);
        let expected_etag = temporary.stored_connection().etag().to_string();
        let test = temporary
            .runtime
            .test_target(temporary.connection_id.as_str(), &expected_etag)
            .expect("persisted test mode should permit a disabled connection")
            .expect("unchanged connection should return a test target");
        assert_eq!(test.method(), Method::HEAD);
        assert_eq!(test.target().url(), "https://billing.example.test/v1/ready");
        assert_eq!(test.expected_statuses(), &[200, 204]);
    }

    #[test]
    fn persisted_mcp_test_target_can_probe_disabled_managed_mcp_only() {
        let mut write = record("/mcp").write;
        write.enabled = false;
        write.kind = ConnectionKind::McpStreamableHttp;
        write.discovery = Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication: false,
        });
        let temporary = TemporaryManagedRuntime::from_write("disabled-mcp-test", write);

        let normal_error = match temporary
            .runtime
            .mcp_target(temporary.connection_id.as_str())
        {
            Ok(_) => panic!("normal MCP target must reject a disabled connection"),
            Err(error) => error,
        };
        assert_eq!(normal_error, ConnectionHttpError::ConnectionDisabled);
        let expected_etag = temporary.stored_connection().etag().to_string();
        let test = temporary
            .runtime
            .mcp_test_target(temporary.connection_id.as_str(), &expected_etag)
            .expect("persisted MCP test mode should permit a disabled managed MCP connection")
            .expect("unchanged connection should return an MCP test target");
        assert_eq!(test.url(), "https://billing.example.test/mcp");
        assert_eq!(test.authentication_kind(), "none");
    }

    #[tokio::test]
    async fn stale_http_test_etag_stops_before_client_tls_or_secret_preparation() {
        let temporary =
            TemporaryManagedRuntime::tls_identity_with_oauth("stale-http-test-etag", true);
        let original = temporary.stored_connection();
        let stale_etag = original.etag();
        let mut replacement = original.write.clone();
        replacement.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            expected_statuses: vec![200],
        });
        let record = temporary
            .runtime
            .control_plane
            .replace_managed(&original.id, &stale_etag, replacement)
            .expect("current connection should gain a valid persisted test profile");
        assert_ne!(record.etag(), stale_etag);
        for secret in [
            "ca.pem",
            "client-certificate.pem",
            "client-private-key.pem",
            "oauth-secret",
        ] {
            fs::remove_file(temporary.root.join(secret))
                .expect("test secret should be removed before the stale probe");
        }
        assert_eq!(temporary.cached_client_count(), 0);

        let execution = ConnectionTestService::new(temporary.runtime.clone())
            .execute(&record, stale_etag.as_str())
            .await;

        assert!(!execution.result.ok);
        assert_eq!(
            execution.result.stages,
            vec![ConnectionTestStage::failure(
                ConnectionTestStageName::ProtocolValid,
                ConnectionTestReason::ConnectionChanged,
            )]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::RequestFailed
        );
        assert_eq!(
            temporary.cached_client_count(),
            0,
            "stale tests must not prepare upstream or OAuth clients"
        );
    }

    #[test]
    fn stale_mcp_test_etag_stops_before_client_selection() {
        let mut write = record("/mcp").write;
        write.kind = ConnectionKind::McpStreamableHttp;
        write.discovery = Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication: false,
        });
        let temporary = TemporaryManagedRuntime::from_write("stale-mcp-test-etag", write);
        assert_eq!(temporary.cached_client_count(), 0);

        let target = temporary
            .runtime
            .mcp_test_target(
                temporary.connection_id.as_str(),
                "\"stale-connection-etag\"",
            )
            .expect("stale revision lookup should be safe");

        assert!(target.is_none());
        assert_eq!(temporary.cached_client_count(), 0);
    }

    #[tokio::test]
    async fn persisted_http_test_enforces_response_body_idle_timeout() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("test listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            let _ = read_http_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhi\r\n",
                )
                .await
                .expect("test response headers and first chunk should write");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut write = record("/").write;
        write.endpoint.base_url = format!("http://127.0.0.1:{}", addr.port());
        write.timeouts = Some(ConnectionTimeouts {
            connect_timeout_ms: 500,
            request_timeout_ms: 2_000,
            response_idle_timeout_ms: 50,
        });
        write.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            expected_statuses: vec![200],
        });
        let temporary = TemporaryManagedRuntime::from_write("http-test-response-idle", write);
        let record = temporary.stored_connection();
        let expected_etag = record.etag().to_string();

        let execution = tokio::time::timeout(
            Duration::from_secs(1),
            ConnectionTestService::new(temporary.runtime.clone()).execute(&record, &expected_etag),
        )
        .await
        .expect("saved response idle timeout should end the probe promptly");
        server.abort();
        let server_error = server
            .await
            .expect_err("aborted stalled server should stop promptly");
        assert!(server_error.is_cancelled());

        assert!(!execution.result.ok);
        assert_eq!(
            execution.result.state,
            ConnectionOperationalState::Unavailable
        );
        assert_eq!(
            execution.result.stages,
            vec![
                ConnectionTestStage::success(ConnectionTestStageName::EgressPolicy),
                ConnectionTestStage::not_applicable(ConnectionTestStageName::SecretAvailable),
                ConnectionTestStage::failure(
                    ConnectionTestStageName::Connected,
                    ConnectionTestReason::ResponseIdleTimeout,
                ),
            ]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::RequestFailed
        );
    }

    #[tokio::test]
    async fn timed_out_connection_test_drops_owned_oauth_mint_before_return() {
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let (addr, ca_pem, token_server, request_received) = one_request_delayed_tls_token_server(
            StatusCode::OK,
            "application/json",
            token_response,
            Duration::from_secs(30),
        )
        .await;
        let temporary = TemporaryOAuthRuntime::new(
            "probe-owned-timeout",
            format!("https://127.0.0.1:{}", addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&ca_pem),
        );
        let original = temporary.stored_connection();
        let mut replacement = original.write.clone();
        replacement.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            expected_statuses: vec![200],
        });
        let record = temporary
            .runtime
            .control_plane
            .replace_managed(&original.id, &original.etag(), replacement)
            .expect("OAuth test profile should replace");
        let expected_etag = record.etag().to_string();

        let execution = tokio::time::timeout(
            Duration::from_secs(3),
            ConnectionTestService::new(temporary.runtime.clone()).execute_before(
                &record,
                &expected_etag,
                tokio::time::Instant::now() + Duration::from_secs(1),
            ),
        )
        .await
        .expect("the hard probe deadline should return promptly");
        tokio::time::timeout(Duration::from_secs(1), request_received)
            .await
            .expect("the token request should start before the probe deadline")
            .expect("the token endpoint should observe the owned mint");
        let request = tokio::time::timeout(Duration::from_secs(1), token_server)
            .await
            .expect("no token-server I/O may survive the completed probe")
            .expect("the token server should observe a cleanly dropped request");

        assert!(
            !request.response_sent,
            "the cancelled mint must not complete"
        );
        assert_eq!(
            execution.result.stages,
            vec![ConnectionTestStage::failure(
                ConnectionTestStageName::Connected,
                ConnectionTestReason::DeadlineExceeded,
            )]
        );
        let events = captured_audit_events(&temporary.capture, 1).await;
        let refreshes = events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .collect::<Vec<_>>();
        assert_eq!(refreshes.len(), 1);
        assert_eq!(refreshes[0].payload["outcome"], json!("failure"));
        assert_eq!(
            refreshes[0].payload["reason"],
            json!("oauth_token_cancelled")
        );
    }

    #[tokio::test]
    async fn stalled_oauth_denial_is_classified_and_invalidates_the_cached_token() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut upstream_ca_params = CertificateParams::default();
        upstream_ca_params.distinguished_name = DistinguishedName::new();
        upstream_ca_params
            .distinguished_name
            .push(DnType::CommonName, "GreenGateway Upstream Test CA");
        upstream_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let upstream_ca_key =
            rcgen::KeyPair::generate().expect("upstream test CA key should generate");
        let upstream_ca = upstream_ca_params
            .self_signed(&upstream_ca_key)
            .expect("upstream test CA certificate should build");
        let mut upstream_server_params = CertificateParams::default();
        upstream_server_params.distinguished_name = DistinguishedName::new();
        upstream_server_params
            .distinguished_name
            .push(DnType::CommonName, "127.0.0.1");
        upstream_server_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let upstream_server_key =
            rcgen::KeyPair::generate().expect("upstream server key should generate");
        let upstream_server_certificate = upstream_server_params
            .signed_by(&upstream_server_key, &upstream_ca, &upstream_ca_key)
            .expect("upstream server certificate should build");
        let upstream_server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    upstream_server_certificate.der().as_ref().to_vec(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    upstream_server_key.serialize_der(),
                )),
            )
            .expect("upstream TLS server config should build");
        let upstream_acceptor = TlsAcceptor::from(Arc::new(upstream_server_config));
        let upstream_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream listener should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("upstream listener address");
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener
                .accept()
                .await
                .expect("upstream should accept one connection");
            let mut stream = upstream_acceptor
                .accept(stream)
                .await
                .expect("upstream TLS should succeed");
            let _ = read_http_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nno\r\n",
                )
                .await
                .expect("denial headers and first chunk should write");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let (token_addr, ca_pem, token_request) =
            one_request_tls_token_server(StatusCode::OK, "application/json", token_response).await;
        let trusted_ca_pem = format!("{ca_pem}\n{}", upstream_ca.pem());
        let temporary = TemporaryOAuthRuntime::new(
            "stalled-denial",
            format!("https://127.0.0.1:{}", upstream_addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", token_addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&trusted_ca_pem),
        );
        let original = temporary.stored_connection();
        let mut replacement = original.write.clone();
        replacement.timeouts = Some(ConnectionTimeouts {
            connect_timeout_ms: 500,
            request_timeout_ms: 2_000,
            response_idle_timeout_ms: 50,
        });
        replacement.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            expected_statuses: vec![200],
        });
        let record = temporary
            .runtime
            .control_plane
            .replace_managed(&original.id, &original.etag(), replacement)
            .expect("OAuth test profile should replace");
        let expected_etag = record.etag().to_string();

        let execution = tokio::time::timeout(
            Duration::from_secs(1),
            ConnectionTestService::new(temporary.runtime.clone()).execute(&record, &expected_etag),
        )
        .await
        .expect("authenticated denial must not wait for its stalled body");
        upstream.abort();
        let upstream_error = upstream
            .await
            .expect_err("aborted stalled upstream should stop promptly");
        assert!(upstream_error.is_cancelled());
        token_request
            .await
            .expect("initial OAuth token request should complete");

        assert!(!execution.result.ok);
        assert_eq!(execution.result.state, ConnectionOperationalState::Degraded);
        assert_eq!(
            execution.result.stages,
            vec![
                ConnectionTestStage::success(ConnectionTestStageName::EgressPolicy),
                ConnectionTestStage::success(ConnectionTestStageName::SecretAvailable),
                ConnectionTestStage::success(ConnectionTestStageName::Connected),
                ConnectionTestStage::not_applicable(ConnectionTestStageName::TlsValid),
                ConnectionTestStage::failure(
                    ConnectionTestStageName::Authenticated,
                    ConnectionTestReason::AuthenticationFailed,
                ),
            ]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::InvalidResponse
        );

        let target = temporary
            .runtime
            .test_target(temporary.connection_id.as_str(), &expected_etag)
            .expect("current OAuth test target should build")
            .expect("current OAuth test target should remain unchanged");
        let remint_error = match tokio::time::timeout(
            Duration::from_secs(1),
            temporary.runtime.resolve_credential(target.target()),
        )
        .await
        .expect("invalidated token should trigger a prompt replacement attempt")
        {
            Ok(_) => panic!("the rejected OAuth token must not remain cached"),
            Err(error) => error,
        };
        assert_eq!(
            remint_error,
            ConnectionHttpError::OAuthTokenUnavailable,
            "a second mint attempt proves the rejected cached token was invalidated"
        );
    }

    #[test]
    fn transport_partition_covers_identity_revisions_profile_and_local_tls_versions() {
        let base = record("/");
        let expected = connection_transport_partition(
            &base.id,
            &base.revisions,
            ConnectionClientProfile::Upstream,
            [None, None, None],
        );

        let mut other_id = base.clone();
        other_id.id = ConnectionId::parse("another").expect("test connection ID");
        assert_ne!(
            expected,
            connection_transport_partition(
                &other_id.id,
                &other_id.revisions,
                ConnectionClientProfile::Upstream,
                [None, None, None],
            )
        );
        for field in 0..5 {
            let mut revisions = base.revisions.clone();
            match field {
                0 => revisions.connection += 1,
                1 => revisions.credential += 1,
                2 => revisions.tls += 1,
                3 => revisions.discovery += 1,
                4 => revisions.status += 1,
                _ => unreachable!(),
            }
            assert_ne!(
                expected,
                connection_transport_partition(
                    &base.id,
                    &revisions,
                    ConnectionClientProfile::Upstream,
                    [None, None, None],
                ),
                "stored revision field {field} must partition transport identity"
            );
        }
        assert_ne!(
            expected,
            connection_transport_partition(
                &base.id,
                &base.revisions,
                ConnectionClientProfile::OAuthToken,
                [None, None, None],
            )
        );
        assert_ne!(
            expected,
            connection_transport_partition(
                &base.id,
                &base.revisions,
                ConnectionClientProfile::Upstream,
                [Some(1), Some(2), Some(3)],
            )
        );
    }

    #[test]
    fn static_credentials_are_sensitive_and_replace_existing_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("attacker"));
        let credential = ResolvedConnectionCredential {
            material: ResolvedCredentialMaterial::HeaderApiKey {
                header_name: HeaderName::from_static("x-api-key"),
                secret: ResolvedSecret::new(SecretPurpose::HeaderApiKey, b"real-key".to_vec())
                    .expect("test secret"),
            },
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
        let credential = ResolvedConnectionCredential {
            material: ResolvedCredentialMaterial::StaticBearer {
                secret: ResolvedSecret::new(
                    SecretPurpose::StaticBearer,
                    b"operator-token".to_vec(),
                )
                .expect("test secret"),
            },
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

    #[tokio::test]
    async fn oauth_runtime_uses_checked_basic_token_exchange_and_caches_bearer_safely() {
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": OAUTH_REFRESH_TOKEN_CANARY,
            "scope": "invoices.read payments.write"
        }))
        .expect("token response should serialize");
        let (addr, ca_pem, request_handle) =
            one_request_tls_token_server(StatusCode::OK, "application/json", token_response).await;
        let temporary = TemporaryOAuthRuntime::new(
            "success",
            format!("https://127.0.0.1:{}", addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&ca_pem),
        );
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("OAuth target should resolve");
        assert_eq!(target.authentication_kind(), "oauth2_client_credentials");
        assert_eq!(
            target.credential_header_name(),
            Some(&header::AUTHORIZATION)
        );
        target
            .client()
            .checked_destination(target.url())
            .await
            .expect("upstream destination should pass before token work");

        let first = temporary
            .runtime
            .resolve_credential(&target)
            .await
            .expect("OAuth token should mint")
            .expect("OAuth target should return a credential");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer caller-token"),
        );
        first
            .inject(&mut headers)
            .expect("OAuth bearer should inject");
        let authorization = headers
            .get(header::AUTHORIZATION)
            .expect("OAuth bearer should exist");
        assert_eq!(
            authorization,
            &HeaderValue::from_static("Bearer oauth-access-token-canary")
        );
        assert!(authorization.is_sensitive());

        let request = request_handle
            .await
            .expect("token request capture should complete");
        assert!(request.head.starts_with("POST /oauth/token HTTP/1.1\r\n"));
        let authorization = request
            .head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("authorization")
                    .then(|| value.trim().to_owned())
            })
            .expect("token request should contain client Basic authorization");
        let expected_basic = format!(
            "Basic {}",
            BASE64_STANDARD.encode("billing%3Aclient:oauth-client-secret-canary")
        );
        assert_eq!(authorization, expected_basic);
        let form = url::form_urlencoded::parse(request.body.as_bytes())
            .into_owned()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(
            form.get("scope").map(String::as_str),
            Some("invoices.read payments.write")
        );
        assert_eq!(
            form.get("audience").map(String::as_str),
            Some("billing-api")
        );
        assert_eq!(
            form.get("resource").map(String::as_str),
            Some("urn:billing")
        );

        let cached = temporary
            .runtime
            .resolve_credential(&target)
            .await
            .expect("cached OAuth token should resolve")
            .expect("cached OAuth credential should exist");
        let mut cached_headers = HeaderMap::new();
        cached
            .inject(&mut cached_headers)
            .expect("cached OAuth bearer should inject");
        assert_eq!(
            cached_headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static(
                "Bearer oauth-access-token-canary"
            ))
        );

        let events = captured_audit_events(&temporary.capture, 1).await;
        let refreshes = events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .collect::<Vec<_>>();
        assert_eq!(refreshes.len(), 1, "cache hit must not emit another mint");
        assert_eq!(refreshes[0].payload["outcome"], json!("success"));
        assert_eq!(refreshes[0].payload["reason"], json!("refreshed"));
        let audit_json = serde_json::to_string(&events).expect("audit should serialize");
        for canary in [
            std::str::from_utf8(OAUTH_CLIENT_SECRET_CANARY).expect("ASCII canary"),
            OAUTH_ACCESS_TOKEN_CANARY,
            OAUTH_REFRESH_TOKEN_CANARY,
            "/oauth/token",
        ] {
            assert!(!audit_json.contains(canary), "audit leaked {canary}");
        }
    }

    #[tokio::test]
    async fn cancelled_oauth_waiter_does_not_cancel_token_attempt_or_its_audit() {
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let (addr, ca_pem, request_handle, request_received) =
            one_request_delayed_tls_token_server(
                StatusCode::OK,
                "application/json",
                token_response,
                Duration::from_millis(50),
            )
            .await;
        let temporary = TemporaryOAuthRuntime::new(
            "cancelled-waiter",
            format!("https://127.0.0.1:{}", addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&ca_pem),
        );
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("OAuth target should resolve");
        let runtime = temporary.runtime.clone();
        let waiter = tokio::spawn(async move { runtime.resolve_credential(&target).await });

        request_received
            .await
            .expect("token endpoint should observe the detached mint");
        waiter.abort();
        assert!(
            matches!(waiter.await, Err(error) if error.is_cancelled()),
            "caller waiter should be cancelled"
        );
        request_handle
            .await
            .expect("detached token request should complete");

        let events = captured_audit_events(&temporary.capture, 1).await;
        let refreshes = events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .collect::<Vec<_>>();
        assert_eq!(refreshes.len(), 1);
        assert_eq!(refreshes[0].payload["outcome"], json!("success"));
        let rendered = serde_json::to_string(&events).expect("audit should serialize");
        assert!(!rendered.contains(OAUTH_ACCESS_TOKEN_CANARY));
        assert!(!rendered.contains("/oauth/token"));
    }

    #[tokio::test]
    async fn oauth_token_egress_is_checked_before_client_secret_resolution() {
        let temporary = TemporaryOAuthRuntime::new(
            "egress-before-secret",
            "https://allowed.example.test".to_owned(),
            "https://blocked.example.test/oauth/token".to_owned(),
            HashSet::from(["allowed.example.test".to_owned()]),
            None,
        );
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("OAuth target should resolve");
        fs::remove_file(&temporary.secret_path)
            .expect("secret should be removed after activation for ordering proof");

        let error = match temporary.runtime.resolve_credential(&target).await {
            Ok(_) => panic!("blocked token endpoint must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, ConnectionHttpError::OAuthTokenEgressDenied);
        let events = captured_audit_events(&temporary.capture, 1).await;
        let refresh = events
            .iter()
            .find(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .expect("failed mint should be audited");
        assert_eq!(refresh.payload["outcome"], json!("failure"));
        assert_eq!(
            refresh.payload["reason"],
            json!("oauth_token_egress_denied")
        );
        let rendered = format!("{error:?}\n{error}\n{}", refresh.payload);
        assert!(!rendered.contains("blocked.example.test"));
        assert!(!rendered.contains("billing-oauth-secret"));
        assert!(!rendered.contains("client-secret"));
    }

    #[tokio::test]
    async fn oauth_rejection_discards_and_redacts_response_secrets() {
        let rejected_body = format!(
            r#"{{"error":"invalid_client","access_token":"{OAUTH_ACCESS_TOKEN_CANARY}","refresh_token":"{OAUTH_REFRESH_TOKEN_CANARY}"}}"#
        )
        .into_bytes();
        let (addr, ca_pem, request_handle) = one_request_tls_token_server(
            StatusCode::BAD_REQUEST,
            "application/json",
            rejected_body,
        )
        .await;
        let temporary = TemporaryOAuthRuntime::new(
            "rejected",
            format!("https://127.0.0.1:{}", addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&ca_pem),
        );
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("OAuth target should resolve");

        let error = match temporary.runtime.resolve_credential(&target).await {
            Ok(_) => panic!("rejected token response must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, ConnectionHttpError::OAuthTokenRejected);
        request_handle
            .await
            .expect("rejected token request should complete");
        let events = captured_audit_events(&temporary.capture, 1).await;
        let rendered = format!(
            "{error:?}\n{error}\n{}",
            serde_json::to_string(&events).expect("audit should serialize")
        );
        for canary in [
            std::str::from_utf8(OAUTH_CLIENT_SECRET_CANARY).expect("ASCII canary"),
            OAUTH_ACCESS_TOKEN_CANARY,
            OAUTH_REFRESH_TOKEN_CANARY,
            "invalid_client",
        ] {
            assert!(!rendered.contains(canary), "failure leaked {canary}");
        }
        assert!(rendered.contains("oauth_token_rejected"));
    }

    #[tokio::test]
    async fn oauth_invalid_token_responses_fail_closed_with_safe_audits() {
        let valid_shape = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let wrong_token_type = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "DPoP",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let oversized = OAUTH_ACCESS_TOKEN_CANARY
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(super::OAUTH_MAX_RESPONSE_BYTES + 1)
            .collect::<Vec<_>>();
        let cases = [
            (
                "malformed-response",
                "application/json",
                format!("{{{OAUTH_ACCESS_TOKEN_CANARY}").into_bytes(),
            ),
            ("wrong-token-type", "application/json", wrong_token_type),
            ("wrong-content-type", "text/plain", valid_shape),
            ("oversized-response", "application/json", oversized),
        ];

        for (name, content_type, body) in cases {
            let (addr, ca_pem, request_handle) =
                one_request_tls_token_server(StatusCode::OK, content_type, body).await;
            let temporary = TemporaryOAuthRuntime::new(
                name,
                format!("https://127.0.0.1:{}", addr.port()),
                format!("https://127.0.0.1:{}/oauth/token", addr.port()),
                HashSet::from(["127.0.0.1".to_owned()]),
                Some(&ca_pem),
            );
            let target = temporary
                .runtime
                .target(temporary.connection_id.as_str(), "/charges")
                .expect("OAuth target should resolve");

            let error = match temporary.runtime.resolve_credential(&target).await {
                Ok(_) => panic!("{name} must fail closed"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                ConnectionHttpError::OAuthTokenInvalidResponse,
                "{name}"
            );
            request_handle
                .await
                .expect("invalid token request should complete");
            let events = captured_audit_events(&temporary.capture, 1).await;
            let rendered = format!(
                "{error:?}\n{error}\n{}",
                serde_json::to_string(&events).expect("audit should serialize")
            );
            for canary in [
                std::str::from_utf8(OAUTH_CLIENT_SECRET_CANARY).expect("ASCII canary"),
                OAUTH_ACCESS_TOKEN_CANARY,
                "/oauth/token",
            ] {
                assert!(!rendered.contains(canary), "{name} leaked {canary}");
            }
            assert!(rendered.contains("oauth_token_invalid_response"), "{name}");
        }
    }
}
