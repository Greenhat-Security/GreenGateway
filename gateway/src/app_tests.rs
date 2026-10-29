use super::*;
#[path = "admin_config_app_tests.rs"]
mod admin_config_app_tests;
#[path = "admin_connections_app_tests.rs"]
mod admin_connections_app_tests;
#[path = "admin_identity_app_tests.rs"]
mod admin_identity_app_tests;
#[path = "admin_observability_app_tests.rs"]
mod admin_observability_app_tests;
#[path = "admin_policy_app_tests.rs"]
mod admin_policy_app_tests;
#[path = "admin_policy_drafts_tests.rs"]
mod admin_policy_drafts_tests;
#[path = "admin_session_app_tests.rs"]
mod admin_session_app_tests;
#[path = "admin_suggestion_drafts_tests.rs"]
mod admin_suggestion_drafts_tests;
#[path = "admin_tokens_app_tests.rs"]
mod admin_tokens_app_tests;
#[path = "admin_tools_app_tests.rs"]
mod admin_tools_app_tests;
#[path = "audit_durability_app_tests.rs"]
mod audit_durability_app_tests;
#[path = "audit_stream_app_tests.rs"]
mod audit_stream_app_tests;
#[path = "auth_app_tests.rs"]
mod auth_app_tests;
#[path = "authority_evidence_app_tests.rs"]
mod authority_evidence_app_tests;
#[path = "cluster_app_tests.rs"]
mod cluster_app_tests;
#[path = "mcp_app_tests.rs"]
mod mcp_app_tests;
#[path = "routing_app_tests.rs"]
mod routing_app_tests;
use crate::auth::TokenStore;
use axum::{body::Body, http::StatusCode};
use futures_util::StreamExt;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rmcp::{
    model::{
        CallToolRequestParams as RmcpCallToolRequestParams,
        CallToolResponse as RmcpCallToolResponse, CallToolResult as RmcpCallToolResult,
        ErrorData as RmcpErrorData, Implementation, JsonObject as RmcpJsonObject,
        ListToolsResult as RmcpListToolsResult,
        PaginatedRequestParams as RmcpPaginatedRequestParams,
        ServerCapabilities as RmcpServerCapabilities, ServerConfig as RmcpServerConfig,
        Tool as RmcpTool,
    },
    service::{RequestContext as RmcpRequestContext, RoleServer as RmcpRoleServer},
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig,
        streamable_http_server::{
            session::never::NeverSessionManager as RmcpNeverSessionManager,
            StreamableHttpServerConfig as RmcpStreamableHttpServerConfig,
            StreamableHttpService as RmcpStreamableHttpService,
        },
        StreamableHttpClientTransport,
    },
    ServerHandler as RmcpServerHandler, ServiceExt as RmcpServiceExt,
};
use rusqlite::{params, Connection};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};
use tower::ServiceExt;

fn test_config(cors_allow_origins: Vec<&str>) -> config::Config {
    config::Config {
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
        tls_min_version: config::DEFAULT_TLS_MIN_VERSION,
        tls_handshake_timeout_ms: config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
        tls_max_concurrent_handshakes: config::DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
        client_cert_auth: None,
        admin_client_cert_auth: None,
        admin_prefix: config::DEFAULT_ADMIN_PREFIX.to_owned(),
        admin_login_provider: None,
        admin_session: None,
        admin_login_pending_ttl_secs: config::DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
        admin_login_pending_max_entries: config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
        admin_login_pending_max_per_ip: config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
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
        connection_vault_provider: crate::connections::vault_secret::VaultProviderConfig::default(),
        connection_gcp_provider: crate::connections::gcp_secret::GcpProviderConfig::default(),
        connection_azure_provider: crate::connections::azure_secret::AzureProviderConfig::default(),
        connection_aws_provider: crate::connections::aws_secret::AwsProviderConfig::default(),
        connection_kubernetes_provider:
            crate::connections::kubernetes_secret::KubernetesProviderConfig::default(),
        connection_secret_aliases: Vec::new(),
        connection_secrets_root: None,
        payload_capture_enabled: false,
        payload_capture_sample_rate: config::DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
        schema_mismatch_signal_threshold:
            discovery::signals::DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
        error_rate_spike_signal_threshold:
            discovery::signals::DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
        principal_new_to_endpoint_signal_threshold:
            discovery::signals::DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
        volume_outlier_signal_threshold:
            discovery::signals::DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
        rule_suggestion_baseline_window_hours:
            discovery::suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
        openapi_spec_path: None,
        policy_file: None,
        tools_file: None,
        policy_history_sqlite_path: None,
        cors_allow_origins: cors_allow_origins.into_iter().map(str::to_owned).collect(),
        max_body_size: 1_048_576,
        max_request_path_bytes: config::DEFAULT_MAX_REQUEST_PATH_BYTES,
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
            "/livez".to_owned(),
            "/startupz".to_owned(),
            "/readyz".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
            "/admin".to_owned(),
        ],
        validation_allowed_content_types: vec!["application/json".to_owned()],
        auth_enabled: true,
        auth_mode: config::AuthMode::Required,
        auth_cookie_name: "session".to_owned(),
        auth_exempt_paths: vec![
            "/health".to_owned(),
            "/livez".to_owned(),
            "/startupz".to_owned(),
            "/readyz".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
            "/admin".to_owned(),
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
            "/livez".to_owned(),
            "/startupz".to_owned(),
            "/readyz".to_owned(),
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

#[derive(Clone)]
struct NoopSink;

impl audit::AuditSink for NoopSink {
    fn emit(&self, _event: &audit::AuditEvent) {}
}

fn test_audit_log() -> audit::AuditLog {
    audit::AuditLog::new(Arc::new(NoopSink))
}

fn test_audit_event_sender() -> audit::AuditEventSender {
    let (sender, _) = tokio::sync::broadcast::channel(16);
    sender
}

fn audit_log_with_sqlite_and_broadcast(
    sqlite_path: &FsPath,
) -> (audit::AuditLog, audit::AuditEventSender) {
    let (sender, _) = tokio::sync::broadcast::channel(16);
    let sqlite_sink = Arc::new(
        audit::sqlite_sink::SqliteSink::new(audit::sqlite_sink::SqliteSinkConfig {
            path: sqlite_path.to_path_buf(),
            retention_days: None,
        })
        .expect("SQLite sink should create audit schema"),
    ) as Arc<dyn audit::AuditSink>;
    let broadcast_sink =
        Arc::new(audit::sink::BroadcastSink::new(sender.clone())) as Arc<dyn audit::AuditSink>;
    let audit_log = audit::AuditLog::new(Arc::new(audit::sink::CompositeSink::new(vec![
        sqlite_sink,
        broadcast_sink,
    ])) as Arc<dyn audit::AuditSink>);

    (audit_log, sender)
}

#[derive(Debug)]
struct CapturedRequest {
    method: Method,
    path_and_query: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

async fn spawn_capture_upstream() -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::Receiver<CapturedRequest>,
) {
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    let router = Router::new()
        .fallback(any(capture_upstream))
        .with_state(sender);
    let addr = spawn_router(router).await;

    (addr, receiver)
}

struct TlsCaptureUpstream {
    addr: std::net::SocketAddr,
    ca_pem: String,
    captured: tokio::sync::mpsc::Receiver<CapturedRequest>,
}

async fn spawn_tls_capture_upstream() -> TlsCaptureUpstream {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let (ca_pem, server_cert_der, server_key_der) = test_ca_signed_server_certificate();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der)),
        )
        .expect("test TLS server config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test TLS upstream should bind");
    let addr = listener
        .local_addr()
        .expect("test TLS upstream address should be available");
    let (sender, captured) = tokio::sync::mpsc::channel(16);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                capture_tls_http_request(&mut stream, sender).await;
            });
        }
    });

    TlsCaptureUpstream {
        addr,
        ca_pem,
        captured,
    }
}

fn test_ca_signed_server_certificate() -> (String, Vec<u8>, Vec<u8>) {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GreenGateway Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("test CA certificate should build");

    let mut server_params = rcgen::CertificateParams::default();
    server_params.distinguished_name = rcgen::DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "127.0.0.1");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server_key = rcgen::KeyPair::generate().expect("test server key should generate");
    let server = server_params
        .signed_by(
            &server_key,
            &rcgen::Issuer::from_params(&ca_params, &ca_key),
        )
        .expect("test server certificate should build");

    (
        ca.pem(),
        server.der().as_ref().to_vec(),
        server_key.serialize_der(),
    )
}

async fn capture_tls_http_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    sender: tokio::sync::mpsc::Sender<CapturedRequest>,
) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .await
            .expect("test TLS upstream should read request");
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break index;
        }
        assert!(
            buffer.len() <= 16 * 1024,
            "test TLS upstream request headers should stay bounded"
        );
    };
    let raw_headers = std::str::from_utf8(&buffer[..header_end])
        .expect("test TLS request headers should be UTF-8");
    let mut lines = raw_headers.split("\r\n");
    let request_line = lines
        .next()
        .expect("test TLS request should include request line");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .and_then(|method| Method::from_bytes(method.as_bytes()).ok())
        .expect("test TLS request method should parse");
    let path_and_query = request_parts
        .next()
        .expect("test TLS request should include path")
        .to_owned();
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .unwrap_or_else(|| panic!("test TLS request header should contain ':': {line}"));
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .expect("test TLS request header name should parse");
        let value = HeaderValue::from_str(value.trim())
            .expect("test TLS request header value should parse");
        headers.append(name, value);
    }
    let _ = sender
        .send(CapturedRequest {
            method,
            path_and_query,
            headers,
            body: Vec::new(),
        })
        .await;

    stream
        .write_all(
            b"HTTP/1.1 201 Created\r\nContent-Length: 12\r\nConnection: close\r\n\r\ntls upstream",
        )
        .await
        .expect("test TLS upstream should write response");
    stream
        .shutdown()
        .await
        .expect("test TLS upstream should close response");
}

async fn spawn_router(router: Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test upstream should bind");
    let addr = listener
        .local_addr()
        .expect("test upstream address should be available");
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("test upstream should serve");
    });

    addr
}

struct MockOidcDiscoveryEndpoint {
    issuer: String,
    authorization_endpoint: String,
    server: BlockingJsonServer,
}

impl MockOidcDiscoveryEndpoint {
    fn finish(self) {
        assert_eq!(self.server.finish(), 1);
    }
}

#[derive(Clone)]
struct MockOidcTokenState {
    access_token: Arc<Mutex<Option<String>>>,
    id_token: Arc<Mutex<Option<String>>>,
    requests: Arc<Mutex<Vec<CapturedTokenRequest>>>,
}

#[derive(Clone)]
struct MockOidcTokenEndpoint {
    url: String,
    access_token: Arc<Mutex<Option<String>>>,
    id_token: Arc<Mutex<Option<String>>>,
    requests: Arc<Mutex<Vec<CapturedTokenRequest>>>,
    handle: Arc<tokio::task::JoinHandle<()>>,
}

#[derive(Clone, Debug)]
struct CapturedTokenRequest {
    method: Method,
    headers: HeaderMap,
    body: String,
}

impl MockOidcTokenEndpoint {
    fn set_access_token(&self, token: String) {
        *self
            .access_token
            .lock()
            .expect("mock token state should lock") = Some(token);
    }

    fn set_id_token(&self, token: String) {
        *self.id_token.lock().expect("mock token state should lock") = Some(token);
    }

    fn requests(&self) -> Vec<CapturedTokenRequest> {
        self.requests
            .lock()
            .expect("mock token requests should lock")
            .clone()
    }

    fn abort(self) {
        self.handle.abort();
    }
}

fn spawn_mock_oidc_discovery_endpoint(token_endpoint: Option<String>) -> MockOidcDiscoveryEndpoint {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("mock OIDC discovery endpoint should bind");
    let addr = listener
        .local_addr()
        .expect("mock OIDC discovery endpoint address should be available");
    let issuer = format!("http://127.0.0.1:{}", addr.port());
    let authorization_endpoint = format!("{issuer}/authorize");
    let token_endpoint = token_endpoint.unwrap_or_else(|| format!("{issuer}/token"));
    let discovery = json!({
        "issuer": issuer.clone(),
        "jwks_uri": format!("{issuer}/jwks.json"),
        "authorization_endpoint": authorization_endpoint.clone(),
        "token_endpoint": token_endpoint
    });
    let server = spawn_blocking_json_server(
        listener,
        vec![(
            "/.well-known/openid-configuration".to_owned(),
            discovery.to_string(),
        )],
        1,
    );

    MockOidcDiscoveryEndpoint {
        issuer,
        authorization_endpoint,
        server,
    }
}

async fn spawn_mock_oidc_token_endpoint(
    host: Ipv4Addr,
    access_token: Option<String>,
) -> MockOidcTokenEndpoint {
    let listener = tokio::net::TcpListener::bind((host, 0))
        .await
        .expect("mock OIDC token endpoint should bind");
    let addr = listener
        .local_addr()
        .expect("mock OIDC token endpoint address should be available");
    let url = format!("http://{}:{}/token", host, addr.port());
    let access_token = Arc::new(Mutex::new(access_token));
    let id_token = Arc::new(Mutex::new(None));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = MockOidcTokenState {
        access_token: Arc::clone(&access_token),
        id_token: Arc::clone(&id_token),
        requests: Arc::clone(&requests),
    };
    let router = Router::new()
        .route("/token", post(mock_oidc_token))
        .with_state(state);
    let handle = Arc::new(tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("mock OIDC token endpoint should serve");
    }));

    MockOidcTokenEndpoint {
        url,
        access_token,
        id_token,
        requests,
        handle,
    }
}

async fn mock_oidc_token(
    State(state): State<MockOidcTokenState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let body = String::from_utf8(body.to_vec()).expect("token request body should be UTF-8");
    state
        .requests
        .lock()
        .expect("mock token requests should lock")
        .push(CapturedTokenRequest {
            method: Method::POST,
            headers,
            body,
        });
    let access_token = state
        .access_token
        .lock()
        .expect("mock token state should lock")
        .clone()
        .expect("mock access token should be set before token exchange");
    let id_token = state
        .id_token
        .lock()
        .expect("mock token state should lock")
        .clone();

    let mut response = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600
    });
    if let Some(id_token) = id_token {
        response["id_token"] = json!(id_token);
    }

    Json(response).into_response()
}

fn admin_oidc_login_router_from_config(mut config: config::Config) -> Router {
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("admin OIDC login app should build")
}

/// Discovery, JWKS and token-exchange deadline of the admin login test provider.
///
/// The 2 s production default bounds a real identity provider. Here every
/// provider endpoint is a local mock that answers at once, so the deadline only
/// bounds how long a loaded, coverage-instrumented test process takes to make
/// the request; at 2 s that scheduling delay surfaced as
/// `Upstream("OIDC discovery fetch failed")`. A wrong answer still fails at once.
const ADMIN_OIDC_TEST_FETCH_TIMEOUT_MS: u64 = 30_000;

fn admin_oidc_login_config(issuer: &str) -> config::Config {
    let mut config = test_config(Vec::new());
    config.admin_login_provider = Some("oidc".to_owned());
    for path in [ADMIN_AUTH_LOGIN_ROUTE, ADMIN_AUTH_CALLBACK_ROUTE] {
        config.auth_exempt_paths.push(path.to_owned());
        config.rbac_exempt_paths.push(path.to_owned());
    }
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer.to_owned()),
        audience: None,
        jwks_timeout_ms: ADMIN_OIDC_TEST_FETCH_TIMEOUT_MS,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: Some("admin-ui".to_owned()),
        client_secret: Some("secret-value".to_owned()),
        redirect_uri: Some("http://gateway.example.test/v1/admin/auth/callback".to_owned()),
    }];

    config
}

fn admin_oidc_cookies(response: &Response) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie header")
                .split(';')
                .next()
                .expect("cookie pair")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn response_location(response: &Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("response should include Location")
        .to_owned()
}

fn url_query_pairs(url: &Url) -> HashMap<String, String> {
    url.query_pairs().into_owned().collect()
}

fn base64url_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(b0 >> 2) as usize] as char);
        output.push(ALPHABET[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(b2 & 0b0011_1111) as usize] as char);
        }
    }

    output
}

async fn spawn_gateway_router(
    router: Router,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test gateway should bind");
    let addr = listener
        .local_addr()
        .expect("test gateway address should be available");
    let server = tokio::spawn(async move {
        serve_router(listener, router)
            .await
            .expect("test gateway should serve");
    });

    (addr, server)
}

async fn capture_upstream(
    State(sender): State<tokio::sync::mpsc::Sender<CapturedRequest>>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("upstream should read request body");
    let method = parts.method.clone();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", |value| value.as_str())
        .to_owned();
    let _ = sender
        .send(CapturedRequest {
            method: method.clone(),
            path_and_query: path_and_query.clone(),
            headers: parts.headers,
            body: body.to_vec(),
        })
        .await;

    let mut response = (
        StatusCode::CREATED,
        format!("upstream {method} {path_and_query}"),
    )
        .into_response();
    response
        .headers_mut()
        .insert("x-upstream-end-to-end", HeaderValue::from_static("kept"));
    response.headers_mut().insert(
        header::CONNECTION,
        HeaderValue::from_static("x-upstream-hop"),
    );
    response
        .headers_mut()
        .insert("x-upstream-hop", HeaderValue::from_static("strip"));
    response
        .headers_mut()
        .insert("keep-alive", HeaderValue::from_static("timeout=5"));
    response.headers_mut().insert(
        "proxy-authenticate",
        HeaderValue::from_static("Basic realm=\"upstream\""),
    );
    response
}

async fn assert_upstream_receives_no_request(
    captured: &mut tokio::sync::mpsc::Receiver<CapturedRequest>,
    context: &str,
) {
    let started = Instant::now();
    let timeout = Duration::from_millis(100);

    while started.elapsed() < timeout {
        let remaining = timeout.saturating_sub(started.elapsed());
        match tokio::time::timeout(remaining, captured.recv()).await {
            Ok(Some(request)) if is_upstream_health_probe(&request) => continue,
            Ok(Some(request)) => panic!(
                "{context}: unexpected upstream request {} {}",
                request.method, request.path_and_query
            ),
            Ok(None) | Err(_) => return,
        }
    }
}

async fn next_proxied_request(
    captured: &mut tokio::sync::mpsc::Receiver<CapturedRequest>,
    context: &str,
) -> CapturedRequest {
    let started = Instant::now();

    loop {
        let request = tokio::time::timeout(Duration::from_secs(1), captured.recv())
            .await
            .unwrap_or_else(|_| panic!("{context}: upstream did not receive request"))
            .unwrap_or_else(|| panic!("{context}: upstream capture channel closed"));

        if !is_upstream_health_probe(&request) {
            return request;
        }

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{context}: only upstream health probes were captured"
        );
    }
}

fn is_upstream_health_probe(request: &CapturedRequest) -> bool {
    request.method == Method::HEAD && request.path_and_query == "/" && request.body.is_empty()
}

fn proxy_config(upstream_addr: std::net::SocketAddr) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.csrf_enabled = false;
    config.validation_allowed_content_types = vec![
        "application/json".to_owned(),
        "application/octet-stream".to_owned(),
        "text/plain".to_owned(),
    ];
    config.upstream_url = Some(format!(
        "http://127.0.0.1:{}/ignored-base",
        upstream_addr.port()
    ));
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    config
}

fn routing_proxy_config(routes: Vec<config::UpstreamRouteConfig>) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.csrf_enabled = false;
    config.validation_allowed_content_types = vec![
        "application/json".to_owned(),
        "application/octet-stream".to_owned(),
        "text/plain".to_owned(),
    ];
    config.upstream_routes = routes;
    config.egress_deny_private_ips = false;
    config
}

fn path_route(
    path_prefix: &str,
    upstream_addr: std::net::SocketAddr,
) -> config::UpstreamRouteConfig {
    route(Some(path_prefix), None, upstream_addr)
}

fn host_path_route(
    host: &str,
    path_prefix: &str,
    upstream_addr: std::net::SocketAddr,
) -> config::UpstreamRouteConfig {
    route(Some(path_prefix), Some(host), upstream_addr)
}

fn route(
    path_prefix: Option<&str>,
    host: Option<&str>,
    upstream_addr: std::net::SocketAddr,
) -> config::UpstreamRouteConfig {
    config::UpstreamRouteConfig {
        id: None,
        forward_cookie_session: false,
        body_limit_profile: None,
        upstream_csrf_cookie_name: None,
        connection_id: None,
        path_prefix: path_prefix.map(str::to_owned),
        host: host.map(str::to_owned),
        upstream_url: format!("http://127.0.0.1:{}/ignored-base", upstream_addr.port()),
        upstreams: Vec::new(),
        load_balancing: config::UpstreamLoadBalancingConfig::default(),
        request_body: config::UpstreamRequestBodyConfig::default(),
        sse: None,
        websocket: None,
        grpc: None,
        limits: config::UpstreamPoolLimitsConfig::default(),
        health_check: None,
        retry: None,
        circuit_breaker: None,
        timeout_ms: None,
        response_idle_timeout_ms: None,
        connect_timeout_ms: None,
        add_request_headers: HashMap::new(),
        strip_request_headers: Vec::new(),
        tls_ca_bundle_path: None,
        openapi_spec_path: None,
    }
}

fn proxy_router(config: config::Config, audit_log: audit::AuditLog) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
}

struct CountingDnsResolver {
    calls: AtomicUsize,
    address_ip: IpAddr,
}

#[async_trait::async_trait]
impl egress::DnsResolver for CountingDnsResolver {
    async fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![SocketAddr::new(self.address_ip, port)])
    }
}

async fn health_response(router: Router) -> axum::response::Response {
    router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("health request should complete")
}

/// The metric name of a rendered sample line, without labels.
fn rendered_metric_name(line: &str) -> &str {
    let head = line.split_once(' ').map_or(line, |(head, _)| head);
    head.split_once('{').map_or(head, |(name, _)| name)
}

/// The `(name, value)` label pairs of a rendered sample line, with the
/// exporter's quoting removed.
fn rendered_labels(line: &str) -> Vec<(String, String)> {
    let Some(start) = line.find('{') else {
        return Vec::new();
    };
    let Some(end) = line.rfind('}') else {
        return Vec::new();
    };
    line[start + 1..end]
        .split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| {
            (
                name.trim().to_owned(),
                value.trim().trim_matches('"').to_owned(),
            )
        })
        .collect()
}

fn plain_connection_body(display_name: &str) -> String {
    json!({
        "display_name": display_name,
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "none"
        }
    })
    .to_string()
}

fn managed_openapi_connection_body(display_name: &str) -> String {
    json!({
        "display_name": display_name,
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://openapi.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "none"
        },
        "discovery": {
            "type": "managed_openapi",
            "use_connection_authentication": false
        }
    })
    .to_string()
}

/// Create a managed OpenAPI Connection with no authentication; returns its
/// ID and ETag.
async fn create_managed_openapi_connection(
    router: &Router,
    display_name: &str,
) -> (String, String) {
    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned();
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some(managed_openapi_connection_body(display_name)),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("managed OpenAPI connection create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let connection_etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created connection should include ETag")
        .to_owned();
    let connection_id = json_body(created).await["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();
    (connection_id, connection_etag)
}

/// Preview `spec` on a managed OpenAPI Connection and register `selected`
/// from exactly that preview; returns the registration response.
async fn preview_and_register_managed_openapi(
    router: &Router,
    connection_id: &str,
    connection_etag: &str,
    spec: &str,
    selected: &[&str],
) -> Response {
    let preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview"),
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": spec }).to_string()),
            None,
            true,
        ))
        .await
        .expect("managed OpenAPI preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = json_body(preview).await;
    let confirmations = preview["security_confirmations"]
        .as_array()
        .expect("preview should list security confirmations")
        .iter()
        .filter(|confirmation| {
            selected
                .iter()
                .any(|name| confirmation["tool_name"] == json!(name))
        })
        .cloned()
        .collect::<Vec<_>>();
    router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/register"),
            Some(test_principal(&["openapi-tools-writer"])),
            Some(
                json!({
                    "spec": spec,
                    "spec_digest": preview["spec_digest"],
                    "expected_spec_revision": preview["spec_revision"],
                    "expected_catalog_revision": preview["catalog_revision"],
                    "selected_tool_names": selected,
                    "security_confirmations": confirmations,
                })
                .to_string(),
            ),
            Some(connection_etag),
            true,
        ))
        .await
        .expect("managed OpenAPI registration should complete")
}

/// The connection admin router, gating converted managed OpenAPI catalogs
/// as cluster mode does (issue #443); `overrides` may supply the roster.
fn gated_connection_admin_router(
    connection_db: &TempDb,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
    overrides: GatewayAppBuildOverrides,
) -> Router {
    let config = connection_admin_config(connection_db, policy, config::DEFAULT_ADMIN_PREFIX);
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            gate_converted_openapi_catalogs: true,
            ..overrides
        },
    )
    .expect("gated connection admin app should build");
    match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("gated connection admin app should be unified"),
    }
}

/// A small Google Discovery document (issue #443): one unscoped method that
/// binds to a Connection without authentication, one scoped method, one
/// method left out, and Google's system parameters.
fn widget_discovery_document() -> String {
    json!({
        "kind": "discovery#restDescription",
        "discoveryVersion": "v1",
        "name": "widgets",
        "version": "v1",
        "rootUrl": "https://widgets.example.test/",
        "servicePath": "widgets/v1/",
        "parameters": { "key": { "type": "string", "location": "query" } },
        "auth": { "oauth2": { "scopes": { "https://widgets.example.test/read": { "description": "Read widgets" } } } },
        "schemas": {
            "Widget": { "id": "Widget", "type": "object", "properties": { "id": { "type": "string" } } }
        },
        "resources": {
            "widgets": {
                "methods": {
                    "get": {
                        "id": "widgets.widgets.get",
                        "path": "widgets/{widgetId}",
                        "httpMethod": "GET",
                        "parameters": {
                            "widgetId": { "type": "string", "location": "path", "required": true }
                        },
                        "response": { "$ref": "Widget" }
                    },
                    "list": {
                        "id": "widgets.widgets.list",
                        "path": "widgets",
                        "httpMethod": "GET",
                        "scopes": ["https://widgets.example.test/read"]
                    },
                    "move": {
                        "id": "widgets.widgets.move",
                        "path": "{+name}:move",
                        "httpMethod": "POST",
                        "parameters": {
                            "name": { "type": "string", "location": "path", "required": true }
                        }
                    }
                }
            }
        }
    })
    .to_string()
}

/// One standalone change-evidence row's action and actor.
#[derive(Debug)]
struct StandaloneChange {
    action: String,
    subject: String,
    issuer: Option<String>,
    kind: String,
    auth_mode: String,
}

impl StandaloneChange {
    /// The actor's issuer, kind and auth mode.
    fn metadata(&self) -> (Option<String>, String, String) {
        (
            self.issuer.clone(),
            self.kind.clone(),
            self.auth_mode.clone(),
        )
    }
}

/// The actions and actors of one standalone change-evidence table in commit
/// order, and every stored value rendered as text for canary checks.
fn standalone_change_evidence(path: &FsPath, table: &str) -> (Vec<StandaloneChange>, String) {
    let connection = rusqlite::Connection::open(path).expect("Connections database should open");
    let mut statement = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY sequence"))
        .expect("evidence query should prepare");
    let [action, subject, issuer, kind, auth_mode] = [
        "action",
        "actor_user_id",
        "actor_issuer",
        "actor_kind",
        "actor_auth_mode",
    ]
    .map(|name| {
        statement
            .column_index(name)
            .expect("evidence should have the column")
    });
    let columns = statement.column_count();
    let mut changes = Vec::new();
    let mut stored = String::new();
    let mut rows = statement.query([]).expect("evidence query should run");
    while let Some(row) = rows.next().expect("evidence row should read") {
        changes.push(StandaloneChange {
            action: row.get(action).expect("action should read"),
            subject: row.get(subject).expect("subject should read"),
            issuer: row.get(issuer).expect("issuer should read"),
            kind: row.get(kind).expect("kind should read"),
            auth_mode: row.get(auth_mode).expect("auth mode should read"),
        });
        for index in 0..columns {
            stored.push_str(&format!(
                "{:?}|",
                row.get_ref(index).expect("column should read")
            ));
        }
    }
    (changes, stored)
}

async fn assert_admin_denial(
    response: &Response,
    log: &audit::AuditLog,
    capture: &audit::sink::tests::CaptureSink,
    permission: &str,
) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<middleware::decision::PolicyDecision>()
        .unwrap();
    assert_eq!(
        decision.outcome,
        middleware::decision::PolicyDecisionOutcome::Denied
    );
    assert_eq!(decision.permission.as_deref(), Some(permission));
    log.close_and_drain(Duration::from_secs(2)).await.unwrap();
    let denied: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == "authz.denied")
        .collect();
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0].payload["permission"], permission);
    assert_eq!(denied[0].payload["authorization_layer"], "admin_endpoint");
}

fn audit_admin_policy_document_string() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "audit-admin-policy",
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_AUDIT_READ_PERMISSION,
                    ADMIN_AUDIT_STREAM_PERMISSION,
                    ADMIN_STATUS_READ_PERMISSION
                ]
            },
            "audit-reader": {
                "permissions": [ADMIN_AUDIT_READ_PERMISSION]
            },
            "audit-streamer": {
                "permissions": [ADMIN_AUDIT_STREAM_PERMISSION]
            },
            "status-reader": {
                "permissions": [ADMIN_STATUS_READ_PERMISSION]
            },
            "reader": {
                "permissions": []
            }
        },
        "routes": []
    })
    .to_string()
}

fn suggestions_admin_config(
    discovery_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
    policy: &TempPolicyFile,
) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.discovery_sqlite_path = discovery_path.map(|path| path.to_string_lossy().into_owned());
    config.audit_sqlite_path = audit_path.map(|path| path.to_string_lossy().into_owned());
    config.rule_suggestion_baseline_window_hours = 876_000;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push("/v1/admin/suggestions".to_owned());
    config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
    config
}

fn suggestions_admin_request(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Option<String>,
    if_match: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        builder = builder
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-token");
    }
    if let Some(if_match) = if_match {
        builder = builder.header(header::IF_MATCH, if_match);
    }

    let mut request = builder
        .body(Body::from(body.unwrap_or_default()))
        .expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

async fn suggestions_json(router: &Router, uri: &str, principal: Option<auth::Principal>) -> Value {
    let response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::GET,
            uri,
            principal,
            None,
            None,
        ))
        .await
        .expect("suggestions request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

fn suggestion_ids(body: &Value) -> Vec<String> {
    body["suggestions"]
        .as_array()
        .expect("suggestions should be an array")
        .iter()
        .map(|suggestion| {
            suggestion["id"]
                .as_str()
                .expect("suggestion id should be a string")
                .to_owned()
        })
        .collect()
}

async fn suggestions_policy_etag(router: &Router) -> String {
    let response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    assert_eq!(response.status(), StatusCode::OK);
    policy_etag_header(&response)
}

fn suggestions_policy_document_string() -> String {
    serde_json::to_string_pretty(&json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "suggestions-reader": {
                "permissions": [ADMIN_SUGGESTIONS_READ_PERMISSION]
            },
            "suggestions-writer": {
                "permissions": [
                    ADMIN_SUGGESTIONS_READ_PERMISSION,
                    ADMIN_SUGGESTIONS_WRITE_PERMISSION
                ]
            },
            "policy-reader": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION]
            },
            "policy-writer": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION
                ]
            },
            "suggestions-policy-writer": {
                "permissions": [
                    ADMIN_SUGGESTIONS_READ_PERMISSION,
                    ADMIN_SUGGESTIONS_WRITE_PERMISSION,
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION
                ]
            },
            "reader": {
                "permissions": []
            }
        },
        "rules": []
    }))
    .expect("suggestions policy should serialize")
}

fn status_router(config: config::Config, process_started_at: Instant) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    app_with_process_started_at(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        process_started_at,
    )
    .expect("app should build")
}

fn status_config_with_policy(
    mut config: config::Config,
    policy: &TempPolicyFile,
) -> config::Config {
    let status_route = GatewayRoutes::from_config(&config).admin.status_route;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(status_route);
    config
}

fn audit_query_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

fn policy_admin_config_with_sqlite(
    policy: Option<&TempPolicyFile>,
    sqlite_path: Option<&PathBuf>,
) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.audit_sqlite_path = sqlite_path.map(|path| path.to_string_lossy().into_owned());
    if let Some(policy) = policy {
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
    }

    config
}

fn policy_admin_config_with_history(
    policy: Option<&TempPolicyFile>,
    history_path: Option<&PathBuf>,
) -> config::Config {
    let mut config = policy_admin_config_with_sqlite(policy, None);
    config.policy_history_sqlite_path =
        history_path.map(|path| path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(POLICY_HISTORY_ADMIN_ROUTE.to_owned());
    config
        .rbac_exempt_paths
        .push(POLICY_ROLLBACK_ADMIN_ROUTE_PREFIX.to_owned());

    config
}

fn policy_admin_router(policy: Option<&TempPolicyFile>, audit_log: audit::AuditLog) -> Router {
    policy_admin_router_with_sqlite(policy, audit_log, None)
}

fn policy_admin_router_with_sqlite(
    policy: Option<&TempPolicyFile>,
    audit_log: audit::AuditLog,
    sqlite_path: Option<&PathBuf>,
) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        policy_admin_config_with_sqlite(policy, sqlite_path),
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
}

fn token_admin_router(
    token_db: &TempDb,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
) -> Router {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(TOKENS_ADMIN_ROUTE.to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();

    app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
}

fn connection_admin_router(
    connection_db: &TempDb,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
) -> Router {
    connection_admin_router_with_prefix(
        connection_db,
        policy,
        audit_log,
        config::DEFAULT_ADMIN_PREFIX,
    )
}

fn connection_admin_router_with_prefix(
    connection_db: &TempDb,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
    admin_prefix: &str,
) -> Router {
    let config = connection_admin_config(connection_db, policy, admin_prefix);
    let recorder = PrometheusBuilder::new().build_recorder();

    app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("connection admin app should build")
}

fn connection_admin_config(
    connection_db: &TempDb,
    policy: &TempPolicyFile,
    admin_prefix: &str,
) -> config::Config {
    let secret_root = connection_db.path.with_extension("secrets");
    fs::create_dir_all(&secret_root).expect("connection test secret root should create");
    let secret_file = secret_root.join("credential-token");
    fs::write(&secret_file, b"credential-material-value-canary")
        .expect("connection test secret should write");
    let local_master_key_file = secret_root.join("local-master-key");
    fs::write(&local_master_key_file, [0x42; 32])
        .expect("connection local-secret master key should write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("connection test secret root permissions should set");
        fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600))
            .expect("connection test secret permissions should set");
        fs::set_permissions(&local_master_key_file, fs::Permissions::from_mode(0o600))
            .expect("connection local-secret master-key permissions should set");
    }
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.admin_prefix = admin_prefix.to_owned();
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.connections_sqlite_path = Some(connection_db.path.to_string_lossy().into_owned());
    config.connection_secrets_root = Some(connections::secret::SecretRootConfig::new(secret_root));
    config.connection_secret_aliases = vec![connections::secret::OperatorSecretAliasConfig {
        id: "credential-secret-id-canary".to_owned(),
        label: "Credential test alias".to_owned(),
        source: connections::secret::OperatorSecretAliasSource::File {
            key: "credential-token".to_owned(),
        },
    }];
    config.connection_local_secret_keyring =
        vec![connections::local_secret::LocalSecretKeyConfig {
            id: "test-primary-key".to_owned(),
            file: "local-master-key".to_owned(),
            role: connections::local_secret::LocalSecretKeyRole::Primary,
        }];
    let admin_routes = AdminRoutes::from_prefix(admin_prefix);
    config
        .rbac_exempt_paths
        .push(admin_routes.connections_route);
    config
        .rbac_exempt_paths
        .push(admin_routes.connection_secrets_route);
    config
}

fn connection_admin_request(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Option<String>,
    if_match: Option<&str>,
    bearer: bool,
) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    if matches!(method, Method::POST | Method::PUT) {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if bearer {
        builder = builder.header(header::AUTHORIZATION, "Bearer test-token");
    }
    if let Some(if_match) = if_match {
        builder = builder.header(header::IF_MATCH, if_match);
    }
    let mut request = builder
        .body(Body::from(body.unwrap_or_default()))
        .expect("connection admin request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }
    request
}

fn token_admin_request(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    if matches!(method, Method::POST) {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if matches!(method, Method::POST | Method::DELETE) {
        builder = builder.header(header::AUTHORIZATION, "Bearer test-token");
    }

    let mut request = builder
        .body(Body::from(body.unwrap_or_default()))
        .expect("token admin request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

fn bearer_json_request(method: Method, uri: &str, token: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("bearer JSON request should build")
}

fn bearer_get_request(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("bearer GET request should build")
}

fn policy_admin_request(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Option<String>,
    if_match: Option<&str>,
) -> Request<Body> {
    policy_admin_request_with_body(
        method,
        uri,
        principal,
        Body::from(body.unwrap_or_default()),
        if_match,
    )
}

fn policy_admin_request_with_body(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Body,
    if_match: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);

    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        builder = builder.header(header::AUTHORIZATION, "Bearer test-token");
    }
    if let Some(if_match) = if_match {
        builder = builder.header(header::IF_MATCH, if_match);
    }

    let mut request = builder.body(body).expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

fn policy_etag_header(response: &Response) -> String {
    response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("policy response should include an ETag")
        .to_owned()
}

async fn current_policy(router: &Router) -> (String, Value) {
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let etag = policy_etag_header(&response);
    let body = json_body(response).await;

    (etag, body)
}

async fn policy_history_page(
    router: &Router,
    uri: &str,
    principal: Option<auth::Principal>,
) -> Value {
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            uri,
            principal,
            None,
            None,
        ))
        .await
        .expect("policy history request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn policy_history_entries(router: &Router, limit: Option<usize>) -> Vec<Value> {
    let uri = limit
        .map(|limit| format!("{POLICY_HISTORY_ADMIN_ROUTE}?limit={limit}&include_policy=true"))
        .unwrap_or_else(|| format!("{POLICY_HISTORY_ADMIN_ROUTE}?include_policy=true"));
    policy_history_page(router, &uri, Some(test_principal(&["admin"]))).await["versions"]
        .as_array()
        .expect("versions should be an array")
        .clone()
}

fn policy_document_string(id: &str, test_permission: &str) -> String {
    serde_json::to_string_pretty(&policy_document(id, test_permission))
        .expect("test policy should serialize")
}

fn policy_document_with_rules_string(id: &str, rules: Value) -> String {
    serde_json::to_string_pretty(&policy_document_with_rules(id, rules))
        .expect("test policy should serialize")
}

fn policy_document_with_rules(id: &str, rules: Value) -> Value {
    let mut policy = policy_document(id, "test:old");
    policy["rules"] = rules;
    policy
}

fn direct_rule_json(id: Option<&str>, methods: &[&str], path: &str, action: &str) -> Value {
    let mut rule = json!({
        "methods": methods,
        "path": path,
        "action": action,
    });
    if let Some(id) = id {
        rule["id"] = json!(id);
    }

    rule
}

fn policy_document(id: &str, test_permission: &str) -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": id,
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION
                ]
            },
            "policy-reader": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION]
            },
            "policy-audit-reader": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_AUDIT_READ_PERMISSION
                ]
            },
            "reader": {
                "permissions": []
            },
            "old-reader": {
                "permissions": ["test:old"]
            },
            "new-reader": {
                "permissions": ["test:new"]
            }
        },
        "routes": [
            {
                "methods": ["GET"],
                "path_prefix": POLICY_ADMIN_ROUTE,
                "permission": ADMIN_POLICY_READ_PERMISSION
            },
            {
                "methods": ["PUT"],
                "path_prefix": POLICY_ADMIN_ROUTE,
                "permission": ADMIN_POLICY_WRITE_PERMISSION
            },
            {
                "methods": ["GET"],
                "path_prefix": POLICY_HISTORY_ADMIN_ROUTE,
                "permission": ADMIN_POLICY_READ_PERMISSION
            },
            {
                "methods": ["POST"],
                "path_prefix": POLICY_ROLLBACK_ADMIN_ROUTE_PREFIX,
                "permission": ADMIN_POLICY_WRITE_PERMISSION
            },
            {
                "methods": ["POST"],
                "path_prefix": POLICY_VALIDATE_ADMIN_ROUTE,
                "permission": ADMIN_POLICY_READ_PERMISSION
            },
            {
                "methods": ["GET"],
                "path_prefix": "/__test",
                "permission": test_permission
            }
        ]
    })
}

fn token_policy_document_string() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "token-admin-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "tokens-reader": {
                "permissions": [ADMIN_TOKENS_READ_PERMISSION]
            },
            "tokens-writer": {
                "permissions": [ADMIN_TOKENS_WRITE_PERMISSION]
            },
            "token-admin": {
                "permissions": [
                    ADMIN_TOKENS_READ_PERMISSION,
                    ADMIN_TOKENS_WRITE_PERMISSION
                ]
            },
            "probe-reader": {
                "permissions": ["test:read"]
            },
            "superadmin": {
                "permissions": ["*"]
            },
            "service-admin": {
                "permissions": ["*"],
                "auth_methods": ["service_token"]
            }
        },
        "routes": []
    })
    .to_string()
}

fn connection_policy_document_string() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "connection-admin-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "connections-reader": {
                "permissions": [ADMIN_CONNECTIONS_READ_PERMISSION]
            },
            "connections-editor": {
                "permissions": [
                    ADMIN_CONNECTIONS_READ_PERMISSION,
                    ADMIN_CONNECTIONS_WRITE_PERMISSION
                ]
            },
            "connections-secrets-editor": {
                "permissions": [
                    ADMIN_CONNECTIONS_READ_PERMISSION,
                    ADMIN_CONNECTIONS_WRITE_PERMISSION,
                    ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION
                ]
            },
            "connections-secret-manager": {
                "permissions": [
                    ADMIN_CONNECTIONS_READ_PERMISSION,
                    ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION
                ]
            },
            "connections-refresher": {
                "permissions": [
                    ADMIN_CONNECTIONS_READ_PERMISSION,
                    ADMIN_CONNECTIONS_REFRESH_PERMISSION
                ]
            },
            "connections-tester": {
                "permissions": [
                    ADMIN_CONNECTIONS_READ_PERMISSION,
                    ADMIN_CONNECTIONS_TEST_PERMISSION
                ]
            },
            "openapi-tools-reader": {
                "permissions": [ADMIN_TOOLS_READ_PERMISSION]
            },
            "openapi-tools-writer": {
                "permissions": [
                    ADMIN_TOOLS_READ_PERMISSION,
                    ADMIN_TOOLS_WRITE_PERMISSION
                ]
            },
            "connections-observer": {
                "permissions": []
            },
            "connections-superadmin": {
                "permissions": ["*"]
            }
        },
        "routes": []
    })
    .to_string()
}

fn service_token_policy_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "service-token-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "probe-reader": {
                "permissions": ["test:read"]
            },
            "token-admin": {
                "permissions": [
                    ADMIN_TOKENS_READ_PERMISSION,
                    ADMIN_TOKENS_WRITE_PERMISSION
                ]
            }
        },
        "routes": [
            {
                "methods": ["GET"],
                "path_prefix": "/__test",
                "permission": "test:read"
            },
            {
                "methods": ["GET"],
                "path_prefix": TOKENS_ADMIN_ROUTE,
                "permission": ADMIN_TOKENS_READ_PERMISSION
            },
            {
                "methods": ["POST", "DELETE"],
                "path_prefix": TOKENS_ADMIN_ROUTE,
                "permission": ADMIN_TOKENS_WRITE_PERMISSION
            }
        ]
    })
    .to_string()
}

struct ToolsAdminTestHarness {
    router: Router,
    admin_token: String,
    reader_token: String,
    blocked_token: String,
    tools: TempToolsFile,
    _policy: TempPolicyFile,
    _token_db: TempDb,
}

async fn tools_admin_harness_with_options(
    tools_document: String,
    audit_log: audit::AuditLog,
    upstream_url: String,
    policy_document: String,
    configure: impl FnOnce(&mut config::Config),
    build_overrides: GatewayAppBuildOverrides,
) -> ToolsAdminTestHarness {
    let token_db = TempDb::new("tools-admin-service-tokens");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let admin_token = create_service_token(&token_store, &["admin"]);
    let reader_token = create_service_token(&token_store, &["tools-reader"]);
    let blocked_token = create_service_token(&token_store, &["blocked"]);
    let policy = TempPolicyFile::new(&policy_document);
    let tools = TempToolsFile::new(&tools_document);

    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.tools_file = Some(tools.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 20;
    config.upstream_url = Some(upstream_url);
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    configure(&mut config);

    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
        Instant::now(),
        build_overrides,
    )
    .expect("tools admin test app should build");
    let router = match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("tools admin test app should be unified"),
    };

    ToolsAdminTestHarness {
        router,
        admin_token,
        reader_token,
        blocked_token,
        tools,
        _policy: policy,
        _token_db: token_db,
    }
}

fn tools_inventory_request(token: Option<&str>, uri: &str) -> Request<Body> {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder
        .body(Body::empty())
        .expect("capability inventory request should build")
}

fn tool_playground_request(
    token: Option<&str>,
    capability_id: &str,
    if_match: Option<&str>,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("{TOOLS_ADMIN_ROUTE}/{capability_id}/execute"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(if_match) = if_match {
        builder = builder.header(header::IF_MATCH, if_match);
    }
    builder
        .body(body.into())
        .expect("tool playground request should build")
}

fn assert_managed_admin_no_store(response: &Response) {
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store")),
        "managed Connection, secret, OpenAPI, and capability responses must never be cached"
    );
}

fn assert_capability_inventory_no_store(response: &Response) {
    assert_managed_admin_no_store(response);
}

fn tools_openapi_register_request(
    token: &str,
    body: Value,
    if_match: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(if_match) = if_match {
        builder = builder.header(header::IF_MATCH, if_match);
    }

    builder
        .body(Body::from(body.to_string()))
        .expect("OpenAPI tools register request should build")
}

fn empty_tools_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "tools": []
    })
    .to_string()
}

fn tools_policy_document() -> String {
    tools_policy_document_with_execute_route_permission(ADMIN_TOOLS_EXECUTE_PERMISSION)
}

fn tools_policy_document_with_execute_route_permission(route_permission: &'static str) -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "tools-admin-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_TOOLS_READ_PERMISSION,
                    ADMIN_TOOLS_WRITE_PERMISSION,
                    ADMIN_TOOLS_EXECUTE_PERMISSION,
                    ADMIN_MCP_USE_PERMISSION
                ]
            },
            "tools-reader": {
                "permissions": [ADMIN_TOOLS_READ_PERMISSION]
            }
        },
        "routes": [
            {
                "methods": ["GET"],
                "path_prefix": TOOLS_ADMIN_ROUTE,
                "permission": ADMIN_TOOLS_READ_PERMISSION
            },
            {
                "methods": ["POST"],
                "path_prefix": TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE,
                "permission": ADMIN_TOOLS_READ_PERMISSION
            },
            {
                "methods": ["POST"],
                "path_prefix": TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE,
                "permission": ADMIN_TOOLS_WRITE_PERMISSION
            },
            {
                "methods": ["POST"],
                "path_prefix": TOOLS_ADMIN_ROUTE,
                "permission": route_permission
            },
            {
                "methods": ["POST"],
                "path_prefix": MCP_ROUTE,
                "permission": ADMIN_MCP_USE_PERMISSION
            }
        ],
        "tools": {
            "echo": {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            },
            "get_widget": {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            },
            "createWidget": {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            },
            "getWidget": {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            }
        }
    })
    .to_string()
}

fn widget_openapi_spec() -> &'static str {
    r#"
openapi: 3.0.3
info:
  title: Widget API
  version: 1.0.0
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
paths:
  /widgets:
    post:
      operationId: createWidget
      summary: Create a widget
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
  /widgets/{widgetId}:
    get:
      operationId: getWidget
      summary: Fetch a widget
      security:
        - ApiKeyAuth: []
      parameters:
        - in: path
          name: widgetId
          required: true
          schema:
            type: string
"#
}

struct McpTestHarness {
    router: Router,
    admin_token: String,
    reader_token: String,
    blocked_token: String,
    _policy: TempPolicyFile,
    _tools: TempToolsFile,
    _token_db: TempDb,
}

async fn mcp_test_harness(
    echo_allowed_roles: &[&str],
    audit_log: audit::AuditLog,
) -> McpTestHarness {
    let upstream_addr = spawn_echo_json_upstream().await;
    mcp_test_harness_with_upstream_url(
        echo_allowed_roles,
        audit_log,
        format!("http://{upstream_addr}"),
        mcp_tools_document(),
        vec!["127.0.0.1".to_owned()],
    )
    .await
}

async fn mcp_test_harness_with_upstream_url(
    echo_allowed_roles: &[&str],
    audit_log: audit::AuditLog,
    upstream_url: String,
    tools_document: String,
    egress_allowed_hosts: Vec<String>,
) -> McpTestHarness {
    mcp_test_harness_from_parts(
        echo_allowed_roles,
        audit_log,
        upstream_url,
        tools_document,
        egress_allowed_hosts,
        None,
        &["admin"],
    )
    .await
}

async fn mcp_test_harness_from_parts(
    echo_allowed_roles: &[&str],
    audit_log: audit::AuditLog,
    upstream_url: String,
    tools_document: String,
    egress_allowed_hosts: Vec<String>,
    gateway_public_url: Option<String>,
    admin_token_roles: &[&str],
) -> McpTestHarness {
    let token_db = TempDb::new("mcp-service-tokens");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let admin_token = create_service_token(&token_store, admin_token_roles);
    let reader_token = create_service_token(&token_store, &["reader"]);
    let blocked_token = create_service_token(&token_store, &["blocked"]);
    let policy = TempPolicyFile::new(&mcp_policy_document(echo_allowed_roles));
    let tools = TempToolsFile::new(&tools_document);

    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.tools_file = Some(tools.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 20;
    config.upstream_url = Some(upstream_url);
    config.egress_allowed_hosts = egress_allowed_hosts;
    config.egress_deny_private_ips = false;
    config.gateway_public_url = gateway_public_url;

    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("MCP test app should build");

    McpTestHarness {
        router,
        admin_token,
        reader_token,
        blocked_token,
        _policy: policy,
        _tools: tools,
        _token_db: token_db,
    }
}

struct TestMcpUpstream {
    addr: std::net::SocketAddr,
    url: String,
    calls: Arc<Mutex<Vec<Value>>>,
    shutdown: tokio_util::sync::CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl TestMcpUpstream {
    async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), self.handle).await;
    }
}

#[derive(Clone)]
struct TestMcpUpstreamServer {
    tool_name: String,
    calls: Arc<Mutex<Vec<Value>>>,
}

impl RmcpServerHandler for TestMcpUpstreamServer {
    fn get_info(&self) -> RmcpServerConfig {
        RmcpServerConfig::new(RmcpServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("greengateway-test-upstream", "0.0.0")
                    .with_title("GreenGateway Test Upstream"),
            )
    }

    async fn list_tools(
        &self,
        _request: Option<RmcpPaginatedRequestParams>,
        _context: RmcpRequestContext<RmcpRoleServer>,
    ) -> Result<RmcpListToolsResult, RmcpErrorData> {
        Ok(RmcpListToolsResult::with_all_items(vec![RmcpTool::new(
            self.tool_name.clone(),
            "Remote test tool",
            Arc::new(remote_echo_input_schema()),
        )]))
    }

    async fn call_tool(
        &self,
        request: RmcpCallToolRequestParams,
        _context: RmcpRequestContext<RmcpRoleServer>,
    ) -> Result<RmcpCallToolResponse, RmcpErrorData> {
        let arguments = request.arguments.unwrap_or_default();
        let call = json!({
            "name": request.name.to_string(),
            "arguments": Value::Object(arguments.clone()),
        });
        self.calls
            .lock()
            .expect("upstream calls lock should not poison")
            .push(call);

        Ok(RmcpCallToolResult::structured(json!({
            "remote_tool": request.name.to_string(),
            "arguments": Value::Object(arguments),
        }))
        .into())
    }
}

async fn spawn_test_mcp_upstream(tool_name: &str) -> TestMcpUpstream {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let handler = TestMcpUpstreamServer {
        tool_name: tool_name.to_owned(),
        calls: Arc::clone(&calls),
    };
    let config = RmcpStreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .disable_allowed_hosts();
    let service = RmcpStreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(RmcpNeverSessionManager::default()),
        config,
    );
    let router = Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test MCP upstream should bind");
    let addr = listener
        .local_addr()
        .expect("test MCP upstream address should be available");
    let shutdown = tokio_util::sync::CancellationToken::new();
    let shutdown_task = shutdown.clone();
    let handle = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_task.cancelled_owned())
            .await
            .expect("test MCP upstream should serve");
    });

    TestMcpUpstream {
        addr,
        url: format!("http://{addr}/mcp"),
        calls,
        shutdown,
        handle,
    }
}

fn remote_echo_input_schema() -> RmcpJsonObject {
    let Value::Object(schema) = json!({
        "type": "object",
        "required": ["message"],
        "properties": {
            "message": {
                "type": "string"
            }
        }
    }) else {
        unreachable!("remote echo schema is always an object")
    };

    schema
}

fn create_service_token(store: &auth::SqliteTokenStore, roles: &[&str]) -> String {
    store
        .create(auth::tokens::CreateTokenRequest {
            scopes: roles.iter().map(|role| (*role).to_owned()).collect(),
            created_by: "mcp-test-bootstrap".to_owned(),
            expires_at: None,
        })
        .expect("service token should create")
        .plaintext_token
}

async fn spawn_echo_json_upstream() -> std::net::SocketAddr {
    async fn echo(body: Bytes) -> Response {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response()
    }

    async fn get_widget(
        Path(widget_id): Path<String>,
        Query(params): Query<HashMap<String, String>>,
    ) -> Response {
        Json(json!({
            "widget_id": widget_id,
            "include_details": params
                .get("include_details")
                .is_some_and(|value| value == "true"),
        }))
        .into_response()
    }

    spawn_router(
        Router::new()
            .route("/v1/echo", post(echo))
            .route("/v1/widgets/{widget_id}", get(get_widget)),
    )
    .await
}

async fn mcp_rpc(
    router: &Router,
    token: Option<&str>,
    id: u64,
    method: &str,
    params: Option<Value>,
    request_id: &str,
) -> (StatusCode, Value) {
    let response = router
        .clone()
        .oneshot(mcp_request(token, id, method, params, request_id))
        .await
        .expect("MCP request should complete");
    let status = response.status();
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("MCP body should read");
    let body = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
        panic!(
            "MCP body should be JSON, status={status}, body={:?}: {err}",
            String::from_utf8_lossy(&body_bytes)
        )
    });

    (status, body)
}

fn mcp_request(
    token: Option<&str>,
    id: u64,
    method: &str,
    params: Option<Value>,
    request_id: &str,
) -> Request<Body> {
    mcp_request_to(MCP_ROUTE, token, id, method, params, request_id)
}

fn mcp_request_to(
    uri: &str,
    token: Option<&str>,
    id: u64,
    method: &str,
    params: Option<Value>,
    request_id: &str,
) -> Request<Body> {
    let mut body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
    });

    if let Some(params) = params {
        body["params"] = params;
    }

    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::COOKIE, "csrf_token=mcp-test-csrf")
        .header("x-csrf-token", "mcp-test-csrf")
        .header("MCP-Protocol-Version", "2025-11-25")
        .header(REQUEST_ID_HEADER, request_id);

    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    builder
        .body(Body::from(body.to_string()))
        .expect("MCP request should build")
}

/// How long the audit writer may take to hand an event to every sink of a
/// test harness's fan-out. It hands each event to the stdout sink before the
/// discovery aggregator, so a stalled stdout holds the aggregator up with it:
/// on the Windows coverage runner the test process's stdout stalled for 15 s
/// (run 40816060787) while the test's own inventory polls kept running, and
/// the row it was waiting for had not been observed yet. Delivery therefore
/// has its own, generous bound; the aggregation that follows keeps its own.
const AUDIT_DELIVERY_BOUND: Duration = Duration::from_secs(60);

/// Wait, without blocking the runtime, until the audit writer has delivered
/// every event `condition` needs to `capture`. A harness's capture sink is
/// the last member of its fan-out, after the configured sinks, so an event
/// it holds has already been handed to the discovery aggregator.
async fn wait_for_delivered_audit_events(
    capture: &audit::sink::tests::CaptureSink,
    what: &str,
    condition: impl Fn(&[audit::AuditEvent]) -> bool,
) {
    let started = Instant::now();
    loop {
        if condition(&capture.events()) {
            return;
        }
        assert!(
            started.elapsed() < AUDIT_DELIVERY_BOUND,
            "the audit writer did not deliver {what} within {AUDIT_DELIVERY_BOUND:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn mcp_initialize_params() -> Value {
    json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {
            "name": "greengateway-test-client",
            "version": "0.0.0"
        }
    })
}

fn mcp_tools_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "tools": [
            {
                "name": "echo",
                "description": "Echoes a message through a generic upstream endpoint.",
                "input_json_schema": {
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": {
                            "type": "string"
                        }
                    },
                    "additionalProperties": false
                },
                "upstream": {
                    "method": "POST",
                    "path_template": "/v1/echo",
                    "body": {
                        "mode": "whole_args_json"
                    }
                }
            },
            {
                "name": "get_widget",
                "description": "Looks up an illustrative widget by identifier.",
                "input_json_schema": {
                    "type": "object",
                    "required": ["widget_id"],
                    "properties": {
                        "widget_id": {
                            "type": "string"
                        },
                        "include_details": {
                            "type": "boolean",
                            "default": false
                        }
                    },
                    "additionalProperties": false
                },
                "upstream": {
                    "method": "GET",
                    "path_template": "/v1/widgets/{widget_id}",
                    "query_params": [
                        {
                            "arg_name": "include_details",
                            "query_name": "include_details",
                            "required": false
                        }
                    ]
                }
            }
        ]
    })
    .to_string()
}

fn mcp_policy_document(echo_allowed_roles: &[&str]) -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "mcp-test-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_MCP_USE_PERMISSION,
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION
                ]
            },
            "reader": {
                "permissions": [ADMIN_MCP_USE_PERMISSION]
            },
            "blocked": {
                "permissions": []
            }
        },
        "routes": [
            {
                "methods": ["POST"],
                "path_prefix": MCP_ROUTE,
                "permission": ADMIN_MCP_USE_PERMISSION
            },
            {
                "methods": ["PUT"],
                "path_prefix": POLICY_ADMIN_ROUTE,
                "permission": ADMIN_POLICY_WRITE_PERMISSION
            }
        ],
        "tools": {
            "echo": {
                "allowed_roles": echo_allowed_roles,
                "timeout_ms": 5000,
                "max_concurrent": 2
            },
            "get_widget": {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            }
        }
    })
    .to_string()
}

fn captured_tool_registry_change(
    capture: &audit::sink::tests::CaptureSink,
    action: &str,
) -> audit::AuditEvent {
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::TOOL_REGISTRY_CHANGED
                && event.payload["action"] == json!(action)
        })
    });

    capture
        .events()
        .into_iter()
        .find(|event| {
            event.event_type == audit::event::TOOL_REGISTRY_CHANGED
                && event.payload["action"] == json!(action)
        })
        .expect("tool_registry.changed event should be captured")
}

fn contains_event_id(body: &str, event_id: &str) -> bool {
    body.contains(&format!(r#""event_id":"{event_id}""#))
}

fn test_stream_event(event_type: &str, path: &str) -> audit::AuditEvent {
    audit::AuditEvent::new(
        event_type,
        "request-sse",
        "203.0.113.10",
        None,
        json!({
            "path": path,
            "status": 200
        }),
    )
}

fn principal_ids(body: &Value) -> Vec<String> {
    body["principals"]["principals"]
        .as_array()
        .expect("principals should be an array")
        .iter()
        .map(|principal| {
            principal["user_id"]
                .as_str()
                .expect("user_id should be a string")
                .to_owned()
        })
        .collect()
}

fn query_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![char::from(byte)]
            }
            _ => format!("%{byte:02X}").chars().collect::<Vec<_>>(),
        })
        .collect()
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read"),
    )
    .expect("body should be JSON")
}

async fn body_string(response: axum::response::Response) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read")
            .to_vec(),
    )
    .expect("body should be UTF-8")
}

async fn authenticated_principal_probe(router: &Router, token: &str) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete")
}

fn assert_content_type_starts_with(headers: &http::HeaderMap, expected: &str) {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("content type should be present");

    assert!(
        content_type.starts_with(expected),
        "expected content type to start with {expected}, got {content_type}"
    );
}

fn test_principal(roles: &[&str]) -> auth::Principal {
    auth::Principal {
        user_id: "user-123".to_owned(),
        issuer: None,
        email: Some("user@example.com".to_owned()),
        org_id: Some("org-456".to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: "session-789".to_owned(),
        auth_method: auth::AuthMethod::Bearer,
    }
}

const TEST_JWT_KID: &str = "test-kid";
const TEST_JWT_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnhXdj9xmwS1xg
0FSkz/Czegzbs7x52/LjNeVoaKsKFiiZh2X6TfeNv9FBHlqaP4crN3ONOutajg2o
jVy2LqOlmX0oWOsu7s9x1SZoy18N5jtOw/knSsYDc4y6ir/0H/WNRf+qMZXo/ZGU
eDU0C2fONU0XXaGWD3ypaQeqClnSInMIIjpJ0gATyGPJVNuVgmdeYdkNBdmlOKrX
dsRg7UjAmt9WXgCm6w1MRAIeZJ6cTNhQ5cx0JBVZRxeNRcVDpXx+IW6QC+HWTcbr
GxGpNzC1AaY9q67VyV/nLypaLF2m4SyKrYbkf5azoyH7zkpvpb6mgJPjdYlhO5M8
dVHvbB81AgMBAAECggEAByEJ7KomYLdETiZvg7gJsUmfZHYorjLrCjpP8fqKVNqO
jcISV+2bfF/OYuwMxQWxFei9NSRtwaPL9wFVEbe4ZSK8DcyC7bNiBqEgilMlT20d
1wNGBiMLfDgdpA6ljpkRlRqGf9KuY4Tu/heDhBx8JW1lQ3pLlxw/nOIIXnckTWny
I5qOpk5XZ/QzJNC2ze0F2VsQ5RAGNdDG9vKHm5qeYHzgM1z9SOUMXsfPYOiXvdZP
BPa59BdP7cmXDVCuh12ZhpVnDErYtA9iPXqmoAah14JP4xKju5QIvavsQt9S8gB5
cxhAu4LmT9p1iOsKaDsG44gxUzmHS0bcuoIgFzDh4QKBgQDp3q9If/ZfZuu3+NPr
F/o36JvUY5SPnbYf1p5hSyBkVhTzKyGiYq7W0Lxs/RcOhw8YlfNfzqRNnhjmZhlE
FXpUCSXVSAtdC3MpCx2XimZltJ+TdIzajeWmh2Wx6SpJJek10UL2n6ht2BBALWyz
Dt2s709dVlxfYwHnZWBe4xxJTQKBgQC3X4prVHXcIKTyNyMS8cC/iMgbOu+Q58CF
VnBuRWsL96vzrHUgUcoYNTPbMOjm98Wzrk2roW+fnDMp0Y8ZusceKOVraihDifN2
yQ2H053ctC8YEvZeOE6JlDq+llAGnRv+113pmfZ51qNeVFcwdR5ujhAunnW7UC28
+IGqI3H5iQKBgQDik2iUP8zsbqTuLrb5K9iyM7xND1DNtsjMnbwBnKw8KR3Q3LeQ
QDUNT1tN6AFfhL++XQBVkLijrgiHpuDRklFaeyZZNJw1v7MJT4iS2XYNEOoNDLyt
vQ2BwelnbPMXvQ/soNlUYCfoi4xq8Nc/vqZLNepZDiMeEqi0iwXLyBIOfQKBgQCv
wF1to2TXF16gXCI8vQKNUO7h0mncS5Mk+QUHW3dO4BGpmegkkt+Mtik+czE2ddHB
9lSxJChVJSOQeC6cbXz8thu1COkQWn7Doc1bGoLaDsR4YWxKP9NeX3iyRGTtAdXc
OdTj2VH30rV/6nwqkIYbVgPCetPCNQWxccjtJc3OaQKBgHGijhVSMmlnGeAIiPmq
0hj0A9bv7QQz5M2TS+yuhQjHDJWa4Asic+AkgfOu5belhSDd13QCou1r8CcUc9uv
mu96vvRxLhwFLatFo4mL0WnOwBvMrR+5YwboH7Er4PBhmVJ2UKiQn8bNX3qdhVTp
O2gecI9QwDJNpm29J9wJB2F8
-----END PRIVATE KEY-----"#;
const TEST_JWT_PUBLIC_KEY_N: &str = "p4V3Y_cZsEtcYNBUpM_ws3oM27O8edvy4zXlaGirChYomYdl-k33jb_RQR5amj-HKzdzjTrrWo4NqI1cti6jpZl9KFjrLu7PcdUmaMtfDeY7TsP5J0rGA3OMuoq_9B_1jUX_qjGV6P2RlHg1NAtnzjVNF12hlg98qWkHqgpZ0iJzCCI6SdIAE8hjyVTblYJnXmHZDQXZpTiq13bEYO1IwJrfVl4ApusNTEQCHmSenEzYUOXMdCQVWUcXjUXFQ6V8fiFukAvh1k3G6xsRqTcwtQGmPauu1clf5y8qWixdpuEsiq2G5H-Ws6Mh-85Kb6W-poCT43WJYTuTPHVR72wfNQ";
const TEST_JWT_PUBLIC_KEY_E: &str = "AQAB";

async fn spawn_test_jwks_server() -> std::net::SocketAddr {
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": TEST_JWT_KID,
            "use": "sig",
            "alg": "RS256",
            "n": TEST_JWT_PUBLIC_KEY_N,
            "e": TEST_JWT_PUBLIC_KEY_E
        }]
    });

    spawn_router(Router::new().route(
        "/jwks.json",
        get(move || {
            let jwks = jwks.clone();
            async move { Json(jwks) }
        }),
    ))
    .await
}

fn spawn_oidc_discovery_server(
    discovery: Value,
    request_count: usize,
) -> (String, BlockingJsonServer) {
    spawn_oidc_discovery_server_with(|_| discovery, request_count)
}

fn spawn_oidc_discovery_server_with(
    discovery: impl FnOnce(&str) -> Value,
    request_count: usize,
) -> (String, BlockingJsonServer) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("OIDC discovery test server should bind");
    let issuer = format!(
        "http://127.0.0.1:{}",
        listener
            .local_addr()
            .expect("OIDC discovery test server address should be available")
            .port()
    );
    let discovery = discovery(&issuer);
    spawn_oidc_server(listener, discovery, None, request_count)
}

fn spawn_blocking_cookie_session_server(
    host: Ipv4Addr,
    request_count: usize,
) -> (String, BlockingJsonServer) {
    let listener = std::net::TcpListener::bind((host, 0))
        .expect("cookie-session introspection test server should bind");
    let introspection_url = format!(
        "http://{}:{}/introspect",
        host,
        listener
            .local_addr()
            .expect("cookie-session introspection test server address should be available")
            .port()
    );
    let body = json!({
        "account": {
            "id": "cookie-user",
            "email": "Cookie.User@Example.TEST",
            "tenant": { "id": "cookie-org" },
            "scope": "admin member"
        }
    });
    let server = spawn_blocking_json_server(
        listener,
        vec![("/introspect".to_owned(), body.to_string())],
        request_count,
    );

    (introspection_url, server)
}

/// A blocking HTTP/1.1 test server that answers fixed JSON bodies by path.
///
/// It serves until it has answered `request_count` requests or until the test
/// calls [`BlockingJsonServer::finish`] (or drops it). It deliberately has no
/// wall-clock lifetime: the time between spawning it and the first request
/// (signing a test token, building the app) has no bound on a loaded runner,
/// and a listener that closed a fixed 2 s after spawn refused the gateway's
/// OIDC discovery fetch on the instrumented Windows coverage job.
struct BlockingJsonServer {
    finishing: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<usize>>,
}

impl BlockingJsonServer {
    /// Answers every connection already queued, closes the listener and
    /// returns how many requests were served.
    ///
    /// Call it after the test has seen the outcome of the requests it caused.
    /// Each of them was sent before this call, so it has been answered or is
    /// queued and is answered now: the count is exact without waiting.
    fn finish(mut self) -> usize {
        self.finishing.store(true, Ordering::SeqCst);
        let thread = self
            .thread
            .take()
            .expect("blocking JSON test server should finish once");
        thread
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    }
}

impl Drop for BlockingJsonServer {
    fn drop(&mut self) {
        // A test that fails before `finish` must not leave the thread polling.
        self.finishing.store(true, Ordering::SeqCst);
    }
}

fn spawn_blocking_json_server(
    listener: std::net::TcpListener,
    routes: Vec<(String, String)>,
    request_count: usize,
) -> BlockingJsonServer {
    listener
        .set_nonblocking(true)
        .expect("blocking JSON test server should set nonblocking mode");
    let finishing = Arc::new(AtomicBool::new(false));
    let finish_flag = Arc::clone(&finishing);
    let thread = std::thread::spawn(move || {
        let mut handled = 0;
        while handled < request_count {
            // Read the flag before accepting: an empty accept that follows a
            // `finish` request proves no connection made before it is left.
            let finish_requested = finish_flag.load(Ordering::SeqCst);
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(_) if finish_requested => break,
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            stream
                .set_nonblocking(false)
                .expect("blocking JSON test stream should use blocking reads");
            let path = read_blocking_http_path(&mut stream);
            let matched = routes
                .iter()
                .find(|(route_path, _)| route_path == &path)
                .map(|(_, body)| body.as_str());
            let (status, body) = match matched {
                Some(body) => ("200 OK", body),
                None => ("404 Not Found", "{}"),
            };
            let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            stream
                .write_all(response.as_bytes())
                .expect("blocking JSON test response should write");
            handled += 1;
        }
        handled
    });

    BlockingJsonServer {
        finishing,
        thread: Some(thread),
    }
}

fn spawn_oidc_server(
    listener: std::net::TcpListener,
    discovery: Value,
    jwks: Option<Value>,
    request_count: usize,
) -> (String, BlockingJsonServer) {
    let issuer = format!(
        "http://127.0.0.1:{}",
        listener
            .local_addr()
            .expect("OIDC discovery test server address should be available")
            .port()
    );
    let routes = vec![
        (
            "/.well-known/openid-configuration".to_owned(),
            discovery.to_string(),
        ),
        (
            "/jwks.json".to_owned(),
            jwks.map_or_else(|| "{}".to_owned(), |jwks| jwks.to_string()),
        ),
    ];

    (
        issuer,
        spawn_blocking_json_server(listener, routes, request_count),
    )
}

fn read_blocking_http_path(stream: &mut std::net::TcpStream) -> String {
    let mut buffer = [0; 2048];
    let read = stream
        .read(&mut buffer)
        .expect("OIDC discovery test request should read");
    let request = String::from_utf8_lossy(&buffer[..read]);
    request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned()
}

fn configure_test_jwt_provider(config: &mut config::Config, jwks_addr: std::net::SocketAddr) {
    let jwks_url = format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port());
    config.jwt_jwks_url = Some(jwks_url.clone());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "legacy".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: Some(jwks_url),
        issuer: None,
        audience: None,
        jwks_timeout_ms: config.jwt_jwks_timeout_ms,
        jwks_max_key_age_secs: 300,
        require_jti: config.jwt_require_jti,
        roles_claim: config.roles_claim.clone(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
}

fn configure_test_cookie_session_provider(config: &mut config::Config, introspection_url: String) {
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "app-session".to_owned(),
        provider_type: config::AuthProviderType::CookieSession,
        jwks_url: None,
        issuer: None,
        audience: None,
        jwks_timeout_ms: config.jwt_jwks_timeout_ms,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "account.scope".to_owned(),
        roles_claim_delimiter: Some(" ".to_owned()),
        org_claim: Some("account.tenant.id".to_owned()),
        introspection_url: Some(introspection_url),
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: 20,
        user_id_claim: Some("account.id".to_owned()),
        email_claim: Some("account.email".to_owned()),
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
}

fn signed_token(user_id: &str, roles: &[&str]) -> String {
    signed_token_with_claims(json!({
        "sub": user_id,
        "email": format!("{user_id}@example.test"),
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
        "jti": format!("{user_id}-session"),
        "roles": roles
    }))
}

fn signed_token_with_issuer(user_id: &str, roles: &[&str], issuer: &str) -> String {
    signed_token_with_claims(json!({
        "sub": user_id,
        "email": format!("{user_id}@example.test"),
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
        "jti": format!("{user_id}-session"),
        "roles": roles,
        "iss": issuer
    }))
}

fn signed_admin_id_token(issuer: &str, audience: &str, nonce: &str) -> String {
    signed_token_with_claims(json!({
        "sub": "admin-operator",
        "email": "admin-operator@example.test",
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
        "iss": issuer,
        "aud": audience,
        "nonce": nonce
    }))
}

fn signed_token_with_claims(claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_JWT_KID.to_owned());

    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_JWT_PRIVATE_KEY.as_bytes())
            .expect("test RSA private key should parse"),
    )
    .expect("test token should sign")
}

fn create_audit_schema(path: &FsPath) {
    drop(
        audit::sqlite_sink::SqliteSink::new(audit::sqlite_sink::SqliteSinkConfig {
            path: path.to_path_buf(),
            retention_days: None,
        })
        .expect("SQLite sink should create audit schema"),
    );
}

fn create_discovery_schema(path: &FsPath) {
    drop(
        discovery::aggregator::EndpointAggregatorSink::new(
            discovery::aggregator::EndpointAggregatorSinkConfig {
                path: path.to_path_buf(),
                payload_capture_enabled: false,
                endpoint_limit: config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
                signal_event_sender: None,
                signal_detector_config: discovery::signals::SignalDetectorConfig::default(),
            },
        )
        .expect("discovery aggregator should create schema"),
    );
}

fn create_rule_suggestion_schema(path: &PathBuf) {
    let connection = Connection::open(path).expect("test discovery database should open");
    discovery::suggestions::configure_connection(&connection)
        .expect("rule suggestion schema should create");
}

struct RuleSuggestionSeed<'a> {
    id: &'a str,
    suggestion_type: &'a str,
    method: &'a str,
    path_pattern: &'a str,
    role: Option<&'a str>,
    action: &'a str,
    rationale: &'a str,
    evidence: Value,
    state: &'a str,
    created_at: &'a str,
    transitioned_at: Option<&'a str>,
    transitioned_by: Option<&'a str>,
    source_signal_id: Option<&'a str>,
}

fn insert_rule_suggestion(path: &PathBuf, suggestion: RuleSuggestionSeed<'_>) {
    insert_rule_suggestion_with_identity_binding(path, suggestion, true);
}

fn insert_rule_suggestion_with_identity_binding(
    path: &PathBuf,
    suggestion: RuleSuggestionSeed<'_>,
    identity_bound: bool,
) {
    create_discovery_schema(path);
    let connection = Connection::open(path).expect("test discovery database should open");
    connection
        .execute(
            r#"
                INSERT OR IGNORE INTO discovery_endpoint_aggregates (
                    method,
                    endpoint_template,
                    first_seen,
                    last_seen,
                    call_count,
                    schema_mismatch_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?3, 1, 0, 1, 1, 1, 1, '[]', 0, ?3)
                "#,
            params![
                suggestion.method,
                suggestion.path_pattern,
                suggestion.created_at,
            ],
        )
        .expect("suggestion endpoint should insert");
    connection
        .execute(
            r#"
                INSERT OR IGNORE INTO discovery_endpoint_routing_classifications (
                    method, endpoint_template, first_classified_at
                ) VALUES (?1, ?2, ?3)
                "#,
            params![
                suggestion.method,
                suggestion.path_pattern,
                suggestion.created_at,
            ],
        )
        .expect("suggestion endpoint classification should insert");
    let roles = suggestion.role.into_iter().collect::<Vec<_>>();
    let principal = if identity_bound {
        json!({
            "roles": roles,
            "issuers": ["provider:test"],
            "auth_methods": ["bearer_token"],
            "principal_ids": []
        })
    } else {
        json!({
            "roles": roles,
            "issuers": [],
            "auth_methods": [],
            "principal_ids": []
        })
    };
    let tool_name = suggestion
        .method
        .eq_ignore_ascii_case("MCP")
        .then(|| suggestion.path_pattern.strip_prefix("/mcp/tools/"))
        .flatten()
        .filter(|tool_name| !tool_name.is_empty() && !tool_name.contains('/'));
    let proposed_rule_json = if let Some(tool_name) = tool_name {
        json!({
            "tool_name": tool_name,
            "principal": principal,
            "action": suggestion.action
        })
    } else {
        json!({
            "methods": [suggestion.method],
            "path": suggestion.path_pattern,
            "principal": principal,
            "action": suggestion.action
        })
    }
    .to_string();
    let principal_key = suggestion
        .role
        .map(|role| format!("role:{role}"))
        .unwrap_or_else(|| "principal:any".to_owned());
    let evidence_json =
        serde_json::to_string(&suggestion.evidence).expect("suggestion evidence should serialize");

    connection
        .execute(
            r#"
                INSERT INTO discovery_rule_suggestions (
                    id,
                    suggestion_type,
                    method,
                    path_pattern,
                    principal_key,
                    proposed_rule_json,
                    rationale,
                    evidence_json,
                    state,
                    created_at,
                    updated_at,
                    transitioned_at,
                    transitioned_by,
                    source_signal_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11, ?12, ?13)
                "#,
            params![
                suggestion.id,
                suggestion.suggestion_type,
                suggestion.method,
                suggestion.path_pattern,
                principal_key,
                proposed_rule_json,
                suggestion.rationale,
                evidence_json,
                suggestion.state,
                suggestion.created_at,
                suggestion.transitioned_at,
                suggestion.transitioned_by,
                suggestion.source_signal_id,
            ],
        )
        .expect("rule suggestion should insert");
}

fn clear_discovery_routing_classification(path: &PathBuf, method: &str, endpoint_template: &str) {
    let connection = Connection::open(path).expect("test discovery database should open");
    connection
        .execute(
            r#"
                DELETE FROM discovery_endpoint_routing_classifications
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
            params![method, endpoint_template],
        )
        .expect("routing classification should clear");
}

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(test_name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-main-{test_name}-{}.sqlite",
            uuid::Uuid::new_v4()
        ));

        Self { path }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_dir_all(self.path.with_extension("secrets"));
    }
}

struct TempPolicyFile {
    path: PathBuf,
}

impl TempPolicyFile {
    fn new(contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-app-policy-test-{}.json",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

        Self { path }
    }

    fn write(&self, contents: &str) {
        fs::write(&self.path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", self.path.display()));
    }
}

impl Drop for TempPolicyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let history_path = default_policy_history_sqlite_path(&self.path.to_string_lossy());
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{}", history_path.display(), suffix));
            let _ = fs::remove_file(path);
        }
    }
}

struct TempToolsFile {
    path: PathBuf,
}

impl TempToolsFile {
    fn new(contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-mcp-tools-test-{}.json",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

        Self { path }
    }
}

impl Drop for TempToolsFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn assert_eventually(timeout: Duration, condition: impl Fn() -> bool) {
    let started = Instant::now();

    while started.elapsed() < timeout {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(
        condition(),
        "condition did not become true within {timeout:?}"
    );
}
#[path = "tests/issue_240_acceptance_core.rs"]
mod issue_240_acceptance_core;
#[path = "tests/issue_240_acceptance_security.rs"]
mod issue_240_acceptance_security;
#[path = "tests/issue_256_acceptance_websocket.rs"]
mod issue_256_acceptance_websocket;
#[path = "tests/issue_257_acceptance_grpc.rs"]
mod issue_257_acceptance_grpc;
#[path = "tests/issue_360_composite_acceptance.rs"]
mod issue_360_composite_acceptance;
#[path = "tests/issue_373_oauth_bootstrap.rs"]
mod issue_373_oauth_bootstrap;
#[path = "tests/issue_463_caller_assertion_jwks.rs"]
mod issue_463_caller_assertion_jwks;

#[path = "admin_policy_test_runs_tests.rs"]
mod admin_policy_test_runs_tests;

#[path = "admin_policy_simulations_tests.rs"]
mod admin_policy_simulations_tests;

#[path = "admin_policy_replays_tests.rs"]
mod admin_policy_replays_tests;

#[path = "admin_policy_evidence_tests.rs"]
mod admin_policy_evidence_tests;
