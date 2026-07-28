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
        OAuthClientAuthMethod, MAX_CONNECTIONS, MAX_URL_BYTES,
    },
    oauth::{
        OAuthBinding, OAuthClientCredentialsRuntime, OAuthError, OAuthTokenLease,
        OAUTH_MAX_REQUEST_BYTES, OAUTH_MAX_RESPONSE_BYTES,
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
    url: String,
    client: Arc<EgressClient>,
    authentication: HttpAuthenticationBinding,
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
    UnsupportedTls,
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
        let cache_key = format!("{}:{}:{}", record.id, record.etag().as_str(), profile.key());
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
        if profile == ConnectionClientProfile::OAuthToken {
            config.max_response_bytes = OAUTH_MAX_RESPONSE_BYTES;
            config.max_request_body_bytes = OAUTH_MAX_REQUEST_BYTES;
        }
        let client = Arc::new(
            self.base_egress_client
                .reconfigured(config)
                .map_err(|_| ConnectionHttpError::TransportUnavailable)?,
        );
        let mut clients = self.client_guard();
        if clients.len() >= MAX_CONNECTIONS.saturating_mul(2) && !clients.contains_key(&cache_key) {
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
            Self::OAuthTokenEgressDenied => "oauth_token_egress_denied",
            Self::OAuthTokenUnavailable => "oauth_token_unavailable",
            Self::OAuthTokenRejected => "oauth_token_rejected",
            Self::OAuthTokenInvalidResponse => "oauth_token_invalid_response",
            Self::UpstreamAuthenticationRejected => "auth_failed",
            Self::TransportUnavailable => "transport_unavailable",
        }
    }

    pub fn is_secret_resolution_failure(self) -> bool {
        matches!(self, Self::CredentialInvalid | Self::CredentialUnavailable)
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

fn validate_http_connection(record: &StoredConnection) -> Result<(), ConnectionHttpError> {
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
            status::ConnectionRevisions,
        },
    };

    const OAUTH_CLIENT_SECRET_CANARY: &[u8] = b"oauth-client-secret-canary";
    const OAUTH_ACCESS_TOKEN_CANARY: &str = "oauth-access-token-canary";
    const OAUTH_REFRESH_TOKEN_CANARY: &str = "oauth-refresh-token-canary";

    struct CapturedTokenRequest {
        head: String,
        body: String,
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
            tokio::time::sleep(response_delay).await;
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
