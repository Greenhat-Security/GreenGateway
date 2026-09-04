use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use http::{
    header::{self, HeaderName, HeaderValue},
    HeaderMap, Method, StatusCode,
};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        server::WebPkiClientVerifier,
        RootCertStore, ServerConfig,
    },
    TlsAcceptor,
};
use tokio_util::sync::CancellationToken;

use crate::{
    connections::{
        control_plane::ConnectionControlPlane,
        http::ConnectionHttpRuntime,
        mcp::{McpCatalogRefreshError, McpConnectionCatalogService},
        model::{
            ConnectionAuthentication, ConnectionEndpoint, ConnectionId, ConnectionKind,
            ConnectionTestProfile, ConnectionTimeouts, ConnectionWrite, DiscoveryConfig,
            TlsProfile,
        },
        openapi::{OpenApiCatalogError, OpenApiConnectionCatalogService},
        secret::{OperatorSecretAliasConfig, OperatorSecretAliasSource, SecretRootConfig},
        store::{ConnectionDependencyKind, ConnectionStoreError, StoredConnection},
        test::{ConnectionTestReason, ConnectionTestService, ConnectionTestStageName},
    },
    egress::{DnsResolver, EgressClient, EgressConfig},
    tools::{
        definitions::{ToolRegistry, ToolSource, ToolTarget},
        executor::{ToolConnectionRuntimes, ToolExecutor},
        runtime::{
            DefaultToolPolicy, ToolInvocationContext, ToolRuntime, ToolRuntimeConfig,
            ToolRuntimeError,
        },
    },
};

use super::*;

const FORBIDDEN_CREDENTIAL_CANARY: &[u8] = b"acceptance-forbidden-bearer-canary";
const ACCEPTANCE_ACTOR: &str = "test-admin";

struct AcceptanceRoot {
    path: PathBuf,
}

impl AcceptanceRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-issue-240-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&path).expect("acceptance-test root should create");
        // The operator secret provider rejects a group/other-writable secrets root
        // and a group/other-accessible secret file. Both checks are `#[cfg(unix)]`,
        // so a default-permission temp tree silently passes on Windows (0o600 is
        // not enforced) and fails on Linux, where `fs::write` yields 0o644.
        set_directory_permissions(&path, 0o700);
        Self { path }
    }

    fn write(&self, relative: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path.join(relative);
        fs::write(&path, contents).expect("acceptance-test secret should write");
        set_file_permissions(&path, 0o600);
        path
    }
}

#[cfg(unix)]
fn set_directory_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("directory permissions should set");
}

#[cfg(not(unix))]
fn set_directory_permissions(_: &std::path::Path, _: u32) {}

#[cfg(unix)]
fn set_file_permissions(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("file permissions should set");
}

#[cfg(not(unix))]
fn set_file_permissions(_: &std::path::Path, _: u32) {}

impl Drop for AcceptanceRoot {
    fn drop(&mut self) {
        let safe_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("greengateway-issue-240-"));
        if safe_name && self.path.starts_with(std::env::temp_dir()) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Default)]
struct RoutingResolver {
    answers: Mutex<HashMap<String, Vec<IpAddr>>>,
    calls: Mutex<Vec<String>>,
}

impl RoutingResolver {
    fn with_answers<const N: usize>(answers: [(&str, Vec<IpAddr>); N]) -> Self {
        Self {
            answers: Mutex::new(
                answers
                    .into_iter()
                    .map(|(host, answers)| (host.to_owned(), answers))
                    .collect(),
            ),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self, host: &str) -> usize {
        self.calls
            .lock()
            .expect("resolver calls should lock")
            .iter()
            .filter(|called| called.as_str() == host)
            .count()
    }

    fn total_calls(&self) -> usize {
        self.calls.lock().expect("resolver calls should lock").len()
    }
}

#[async_trait]
impl DnsResolver for RoutingResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        self.calls
            .lock()
            .expect("resolver calls should lock")
            .push(host.to_owned());
        self.answers
            .lock()
            .expect("resolver answers should lock")
            .get(host)
            .cloned()
            .map(|answers| {
                answers
                    .into_iter()
                    .map(|address| SocketAddr::new(address, port))
                    .collect()
            })
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "acceptance resolver has no configured answer",
                )
            })
    }
}

struct RuntimeFixture {
    _root: AcceptanceRoot,
    config: config::Config,
    control_plane: ConnectionControlPlane,
    runtime: ConnectionHttpRuntime,
    egress: Arc<EgressClient>,
}

fn runtime_fixture(
    root: AcceptanceRoot,
    aliases: Vec<OperatorSecretAliasConfig>,
    allowed_hosts: impl IntoIterator<Item = String>,
    deny_private_ips: bool,
    resolver: Arc<dyn DnsResolver>,
) -> RuntimeFixture {
    let mut config = config::Config::test_defaults();
    config.connections_sqlite_path =
        Some(root.path.join("connections.sqlite").display().to_string());
    config.connection_secrets_root = Some(SecretRootConfig::new(root.path.clone()));
    config.connection_secret_aliases = aliases;
    let control_plane = ConnectionControlPlane::from_config(&config)
        .expect("Connection control plane should build");
    let egress_config = EgressConfig {
        allowed_hosts: allowed_hosts.into_iter().collect(),
        deny_private_ips,
        ..EgressConfig::default()
    };
    let egress = Arc::new(
        EgressClient::new_with_resolver(egress_config.clone(), resolver)
            .expect("acceptance egress client should build"),
    );
    let runtime =
        ConnectionHttpRuntime::new(control_plane.clone(), egress_config, Arc::clone(&egress));
    RuntimeFixture {
        _root: root,
        config,
        control_plane,
        runtime,
        egress,
    }
}

async fn create_managed(
    control_plane: &ConnectionControlPlane,
    write: ConnectionWrite,
) -> StoredConnection {
    let collection_etag = control_plane
        .runtime_snapshot()
        .collection_etag()
        .to_owned();
    control_plane
        .create_managed(&collection_etag, write, ACCEPTANCE_ACTOR)
        .await
        .expect("acceptance Connection should create")
}

fn http_connection(
    display_name: &str,
    base_url: String,
    authentication: ConnectionAuthentication,
    tls: TlsProfile,
) -> ConnectionWrite {
    ConnectionWrite {
        display_name: display_name.to_owned(),
        description: None,
        enabled: true,
        kind: ConnectionKind::HttpApi,
        endpoint: ConnectionEndpoint {
            base_url,
            base_path: "/".to_owned(),
        },
        authentication,
        additional_headers: Vec::new(),
        tls,
        timeouts: Some(ConnectionTimeouts {
            request_timeout_ms: 1_500,
            response_idle_timeout_ms: 1_500,
            connect_timeout_ms: 500,
        }),
        discovery: None,
        test_profile: Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/probe".to_owned(),
            expected_statuses: vec![200],
        }),
    }
}

fn bearer_auth(secret_id: &str) -> ConnectionAuthentication {
    ConnectionAuthentication::StaticBearer {
        secret_id: Some(secret_id.to_owned()),
    }
}

fn file_alias(id: &str, key: &str) -> OperatorSecretAliasConfig {
    OperatorSecretAliasConfig {
        id: id.to_owned(),
        label: format!("Acceptance alias {id}"),
        source: OperatorSecretAliasSource::File {
            key: key.to_owned(),
        },
    }
}

#[tokio::test]
async fn e2e_06_stored_tests_reject_ssrf_and_never_forward_credentials_to_redirects() {
    let root = AcceptanceRoot::new("e2e-06-policy");
    let credential_path = root.write("forbidden-token", FORBIDDEN_CREDENTIAL_CANARY);
    let resolver = Arc::new(RoutingResolver::with_answers([
        (
            "blocked.acceptance.test",
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        ),
        (
            "private.acceptance.test",
            vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))],
        ),
        (
            "mixed.acceptance.test",
            vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            ],
        ),
    ]));
    let resolver_trait: Arc<dyn DnsResolver> = resolver.clone();
    let fixture = runtime_fixture(
        root,
        vec![file_alias("forbidden-token", "forbidden-token")],
        [
            "private.acceptance.test".to_owned(),
            "mixed.acceptance.test".to_owned(),
        ],
        true,
        resolver_trait,
    );
    let blocked = create_managed(
        &fixture.control_plane,
        http_connection(
            "Blocked test",
            "https://blocked.acceptance.test".to_owned(),
            bearer_auth("forbidden-token"),
            TlsProfile::default(),
        ),
    )
    .await;
    let private = create_managed(
        &fixture.control_plane,
        http_connection(
            "Private test",
            "https://private.acceptance.test".to_owned(),
            bearer_auth("forbidden-token"),
            TlsProfile::default(),
        ),
    )
    .await;
    let mixed = create_managed(
        &fixture.control_plane,
        http_connection(
            "Mixed DNS test",
            "https://mixed.acceptance.test".to_owned(),
            bearer_auth("forbidden-token"),
            TlsProfile::default(),
        ),
    )
    .await;

    fs::remove_file(&credential_path)
        .expect("credential should be removed after Connection activation");
    let tests = ConnectionTestService::new(fixture.runtime.clone());
    for (record, expected_reason) in [
        (&blocked, ConnectionTestReason::HostNotAllowed),
        (&private, ConnectionTestReason::NonGlobalIpBlocked),
        (&mixed, ConnectionTestReason::NonGlobalIpBlocked),
    ] {
        let execution = tests.execute(record, record.etag().as_str()).await;
        assert!(!execution.result.ok);
        assert_eq!(
            execution.result.stages.first().map(|stage| stage.name),
            Some(ConnectionTestStageName::EgressPolicy)
        );
        assert_eq!(
            execution
                .result
                .stages
                .first()
                .and_then(|stage| stage.reason),
            Some(expected_reason)
        );
        let public_result =
            serde_json::to_string(&execution.result).expect("test result should serialize");
        for forbidden in [
            std::str::from_utf8(FORBIDDEN_CREDENTIAL_CANARY)
                .expect("credential canary should be UTF-8"),
            "blocked.acceptance.test",
            "private.acceptance.test",
            "mixed.acceptance.test",
        ] {
            assert!(
                !public_result.contains(forbidden),
                "sanitized test result exposed forbidden material: {public_result}"
            );
        }
    }
    assert_eq!(
        resolver.call_count("blocked.acceptance.test"),
        0,
        "host allowlisting must reject before DNS or secret resolution"
    );
    assert_eq!(resolver.call_count("private.acceptance.test"), 1);
    assert_eq!(resolver.call_count("mixed.acceptance.test"), 1);

    let (redirect_sink_addr, mut redirect_sink) = spawn_capture_upstream().await;
    let redirect_location = format!("http://{redirect_sink_addr}/forbidden-credential-sink");
    let (redirect_addr, redirect_ca, mut redirect_origin) =
        spawn_tls_redirect_upstream(redirect_location).await;
    let root = AcceptanceRoot::new("e2e-06-redirect");
    root.write("redirect-token", FORBIDDEN_CREDENTIAL_CANARY);
    root.write("redirect-ca.pem", redirect_ca);
    let resolver = Arc::new(RoutingResolver::with_answers([(
        "127.0.0.1",
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    )]));
    let resolver_trait: Arc<dyn DnsResolver> = resolver;
    let redirect_fixture = runtime_fixture(
        root,
        vec![
            file_alias("redirect-token", "redirect-token"),
            file_alias("redirect-ca", "redirect-ca.pem"),
        ],
        ["127.0.0.1".to_owned()],
        false,
        resolver_trait,
    );
    let redirect = create_managed(
        &redirect_fixture.control_plane,
        http_connection(
            "Redirect test",
            format!("https://127.0.0.1:{}", redirect_addr.port()),
            bearer_auth("redirect-token"),
            TlsProfile {
                ca_bundle_alias: Some("redirect-ca".to_owned()),
                client_certificate_id: None,
                client_private_key_id: None,
            },
        ),
    )
    .await;
    let execution = ConnectionTestService::new(redirect_fixture.runtime)
        .execute(&redirect, redirect.etag().as_str())
        .await;
    assert!(!execution.result.ok);
    assert_eq!(
        execution
            .result
            .stages
            .last()
            .and_then(|stage| stage.reason),
        Some(ConnectionTestReason::UnexpectedStatus)
    );
    let origin_request = tokio::time::timeout(Duration::from_secs(1), redirect_origin.recv())
        .await
        .expect("redirect origin request should arrive")
        .expect("redirect origin capture should remain open");
    assert_eq!(
        origin_request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer acceptance-forbidden-bearer-canary"),
        "the persisted credential should reach only its validated original authority"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), redirect_sink.recv())
            .await
            .is_err(),
        "redirect target must observe zero requests"
    );
    let public_result =
        serde_json::to_string(&execution.result).expect("redirect test result should serialize");
    assert!(!public_result.contains("acceptance-forbidden-bearer-canary"));
    assert!(!public_result.contains("forbidden-credential-sink"));
}

async fn spawn_tls_redirect_upstream(
    location: String,
) -> (
    SocketAddr,
    String,
    tokio::sync::mpsc::Receiver<CapturedRequest>,
) {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let (ca_pem, server_cert_der, server_key_der) = test_ca_signed_server_certificate();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der)),
        )
        .expect("redirect TLS server config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("redirect TLS server should bind");
    let address = listener
        .local_addr()
        .expect("redirect TLS server address should be available");
    let (captured_tx, captured_rx) = tokio::sync::mpsc::channel(2);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let captured_tx = captured_tx.clone();
            let location = location.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let Some(request) = read_tls_request(&mut stream).await else {
                    return;
                };
                let _ = captured_tx.send(request).await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, ca_pem, captured_rx)
}

async fn read_tls_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<CapturedRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index;
        }
        if bytes.len() > 16 * 1024 {
            return None;
        }
    };
    let head = std::str::from_utf8(&bytes[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = Method::from_bytes(request_line.next()?.as_bytes()).ok()?;
    let path_and_query = request_line.next()?.to_owned();
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        headers.append(
            HeaderName::from_bytes(name.trim().as_bytes()).ok()?,
            HeaderValue::from_str(value.trim()).ok()?,
        );
    }
    Some(CapturedRequest {
        method,
        path_and_query,
        headers,
        body: Vec::new(),
    })
}

struct CertificateAuthority {
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
}

fn certificate_authority(common_name: &str) -> CertificateAuthority {
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().expect("acceptance CA key should generate");
    let certificate = params
        .self_signed(&key)
        .expect("acceptance CA certificate should build");
    CertificateAuthority { certificate, key }
}

struct AcceptanceServerIdentity {
    ca_pem: String,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

fn server_identity(host: &str) -> AcceptanceServerIdentity {
    let ca = certificate_authority(&format!("{host} server CA"));
    let mut params = rcgen::CertificateParams::new(vec![host.to_owned()])
        .expect("server certificate params should build");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("server key should generate");
    let certificate = params
        .signed_by(&key, &ca.certificate, &ca.key)
        .expect("server certificate should build");
    AcceptanceServerIdentity {
        ca_pem: ca.certificate.pem(),
        certificate_der: certificate.der().as_ref().to_vec(),
        private_key_der: key.serialize_der(),
    }
}

struct AcceptanceClientIdentity {
    ca_der: Vec<u8>,
    certificate_pem: String,
    private_key_pem: String,
}

fn client_identity(name: &str) -> AcceptanceClientIdentity {
    let ca = certificate_authority(&format!("{name} client CA"));
    let mut params = rcgen::CertificateParams::new(vec![format!("{name}.acceptance.test")])
        .expect("client certificate params should build");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().expect("client key should generate");
    let certificate = params
        .signed_by(&key, &ca.certificate, &ca.key)
        .expect("client certificate should build");
    AcceptanceClientIdentity {
        ca_der: ca.certificate.der().as_ref().to_vec(),
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
    }
}

struct AcceptanceMtlsServer {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for AcceptanceMtlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_acceptance_mtls_server(
    server: &AcceptanceServerIdentity,
    trusted_client_ca_der: Vec<u8>,
) -> AcceptanceMtlsServer {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(trusted_client_ca_der))
        .expect("client CA should be accepted");
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("client verifier should build");
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server.certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.private_key_der.clone())),
        )
        .expect("mTLS server config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("mTLS acceptance server should bind");
    let address = listener
        .local_addr()
        .expect("mTLS acceptance server address should be available");
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let request_count = Arc::clone(&request_count);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut bytes = Vec::new();
                let mut chunk = [0_u8; 1024];
                loop {
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    bytes.extend_from_slice(&chunk[..read]);
                    if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    if bytes.len() > 16 * 1024 {
                        return;
                    }
                }
                request_count.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    AcceptanceMtlsServer {
        address,
        requests,
        task,
    }
}

fn mtls_profile(prefix: &str) -> TlsProfile {
    TlsProfile {
        ca_bundle_alias: Some(format!("{prefix}-server-ca")),
        client_certificate_id: Some(format!("{prefix}-client-cert")),
        client_private_key_id: Some(format!("{prefix}-client-key")),
    }
}

async fn call_connection(
    runtime: &ConnectionHttpRuntime,
    connection_id: &ConnectionId,
) -> Result<[u8; 32], &'static str> {
    let target = runtime
        .target(connection_id.as_str(), "/identity")
        .map_err(|_| "connection target")?;
    let checked = target
        .preflight_client()
        .checked_destination(target.url())
        .await
        .map_err(|_| "egress preflight")?;
    let prepared = runtime
        .prepare_transport(&target, &checked)
        .await
        .map_err(|_| "transport preparation")?;
    let fingerprint = prepared
        .client()
        .client_identity_fingerprint()
        .ok_or("missing client identity")?;
    let response = prepared
        .client()
        .request_with_headers_at_checked_destination(
            prepared.destination(),
            Method::GET,
            target.url(),
            HeaderMap::new(),
            None,
        )
        .await
        .map_err(|_| "mTLS request")?;
    if response.status != StatusCode::OK || response.body != b"ok" {
        return Err("unexpected mTLS response");
    }
    Ok(fingerprint)
}

#[tokio::test]
async fn e2e_07_mtls_rotation_preserves_two_origin_ca_and_client_isolation() {
    const ORIGIN_A: &str = "origin-a.acceptance.test";
    const ORIGIN_B: &str = "origin-b.acceptance.test";

    let server_identity_a = server_identity(ORIGIN_A);
    let server_identity_b = server_identity(ORIGIN_B);
    let client_identity_a = client_identity("origin-a");
    let client_identity_b = client_identity("origin-b");
    let server_a =
        spawn_acceptance_mtls_server(&server_identity_a, client_identity_a.ca_der.clone()).await;
    let server_b =
        spawn_acceptance_mtls_server(&server_identity_b, client_identity_b.ca_der.clone()).await;

    let root = AcceptanceRoot::new("e2e-07");
    root.write("a-server-ca.pem", &server_identity_a.ca_pem);
    root.write("a-client-cert.pem", &client_identity_a.certificate_pem);
    root.write("a-client-key.pem", &client_identity_a.private_key_pem);
    root.write("b-server-ca.pem", &server_identity_b.ca_pem);
    root.write("b-client-cert.pem", &client_identity_b.certificate_pem);
    root.write("b-client-key.pem", &client_identity_b.private_key_pem);
    let aliases = [
        ("a-server-ca", "a-server-ca.pem"),
        ("a-client-cert", "a-client-cert.pem"),
        ("a-client-key", "a-client-key.pem"),
        ("b-server-ca", "b-server-ca.pem"),
        ("b-client-cert", "b-client-cert.pem"),
        ("b-client-key", "b-client-key.pem"),
    ]
    .into_iter()
    .map(|(id, key)| file_alias(id, key))
    .collect();
    let resolver = Arc::new(RoutingResolver::with_answers([
        (ORIGIN_A, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        (ORIGIN_B, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
    ]));
    let resolver_trait: Arc<dyn DnsResolver> = resolver;
    let fixture = runtime_fixture(
        root,
        aliases,
        [ORIGIN_A.to_owned(), ORIGIN_B.to_owned()],
        false,
        resolver_trait,
    );
    let connection_a = create_managed(
        &fixture.control_plane,
        http_connection(
            "Origin A",
            format!("https://{ORIGIN_A}:{}", server_a.address.port()),
            ConnectionAuthentication::None,
            mtls_profile("a"),
        ),
    )
    .await;
    let connection_b = create_managed(
        &fixture.control_plane,
        http_connection(
            "Origin B",
            format!("https://{ORIGIN_B}:{}", server_b.address.port()),
            ConnectionAuthentication::None,
            mtls_profile("b"),
        ),
    )
    .await;

    let first_a_fingerprint = call_connection(&fixture.runtime, &connection_a.id)
        .await
        .expect("origin A should accept only its Connection identity");
    let first_b_fingerprint = call_connection(&fixture.runtime, &connection_b.id)
        .await
        .expect("origin B should accept only its Connection identity");
    assert_ne!(first_a_fingerprint, first_b_fingerprint);
    assert_eq!(server_a.requests.load(Ordering::SeqCst), 1);
    assert_eq!(server_b.requests.load(Ordering::SeqCst), 1);

    let crossed_identity = create_managed(
        &fixture.control_plane,
        http_connection(
            "Origin B with A client",
            format!("https://{ORIGIN_B}:{}", server_b.address.port()),
            ConnectionAuthentication::None,
            TlsProfile {
                ca_bundle_alias: Some("b-server-ca".to_owned()),
                client_certificate_id: Some("a-client-cert".to_owned()),
                client_private_key_id: Some("a-client-key".to_owned()),
            },
        ),
    )
    .await;
    assert!(
        call_connection(&fixture.runtime, &crossed_identity.id)
            .await
            .is_err(),
        "origin A's client identity must not authenticate to origin B"
    );
    let crossed_ca = create_managed(
        &fixture.control_plane,
        http_connection(
            "Origin B with A CA",
            format!("https://{ORIGIN_B}:{}", server_b.address.port()),
            ConnectionAuthentication::None,
            TlsProfile {
                ca_bundle_alias: Some("a-server-ca".to_owned()),
                client_certificate_id: Some("b-client-cert".to_owned()),
                client_private_key_id: Some("b-client-key".to_owned()),
            },
        ),
    )
    .await;
    assert!(
        call_connection(&fixture.runtime, &crossed_ca.id)
            .await
            .is_err(),
        "origin A's trust roots must not validate origin B"
    );
    assert_eq!(
        server_b.requests.load(Ordering::SeqCst),
        1,
        "failed, isolated TLS handshakes must deliver no HTTP request"
    );

    let rotated_identity_a = client_identity("origin-a-rotated");
    let rotated_server_a =
        spawn_acceptance_mtls_server(&server_identity_a, rotated_identity_a.ca_der.clone()).await;
    fixture
        ._root
        .write("a-client-cert.pem", &rotated_identity_a.certificate_pem);
    fixture
        ._root
        .write("a-client-key.pem", &rotated_identity_a.private_key_pem);
    let current_a = fixture
        .control_plane
        .runtime_snapshot()
        .managed()
        .get(&connection_a.id)
        .expect("origin A Connection should remain present")
        .clone();
    let mut rotated_write = current_a.write.clone();
    rotated_write.endpoint.base_url =
        format!("https://{ORIGIN_A}:{}", rotated_server_a.address.port());
    let rotated_a = fixture
        .control_plane
        .replace_managed(
            &connection_a.id,
            &current_a.etag(),
            rotated_write,
            ACCEPTANCE_ACTOR,
        )
        .await
        .expect("origin A rotation should publish atomically");
    let rotated_a_fingerprint = call_connection(&fixture.runtime, &rotated_a.id)
        .await
        .expect("rotated origin A identity should be selected immediately");
    assert_ne!(
        first_a_fingerprint, rotated_a_fingerprint,
        "identity rotation must select a new transport partition"
    );
    assert_eq!(rotated_server_a.requests.load(Ordering::SeqCst), 1);

    let second_b_fingerprint = call_connection(&fixture.runtime, &connection_b.id)
        .await
        .expect("origin A rotation must not disturb origin B");
    assert_eq!(first_b_fingerprint, second_b_fingerprint);
    assert_eq!(server_b.requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        server_a.requests.load(Ordering::SeqCst),
        1,
        "the old origin/identity pair must receive no post-rotation request"
    );
}

fn no_auth_openapi_connection() -> ConnectionWrite {
    let mut write = http_connection(
        "Managed OpenAPI",
        "https://openapi.acceptance.test".to_owned(),
        ConnectionAuthentication::None,
        TlsProfile::default(),
    );
    write.test_profile = None;
    write.discovery = Some(DiscoveryConfig::ManagedOpenapi {
        path: None,
        use_connection_authentication: false,
    });
    write
}

fn no_auth_mcp_connection() -> ConnectionWrite {
    let mut write = http_connection(
        "Managed MCP",
        "https://mcp.acceptance.test".to_owned(),
        ConnectionAuthentication::None,
        TlsProfile::default(),
    );
    write.kind = ConnectionKind::McpStreamableHttp;
    write.test_profile = None;
    write.discovery = Some(DiscoveryConfig::ManagedMcp {
        use_connection_authentication: false,
    });
    write
}

const ACCEPTANCE_OPENAPI_SPEC: &str = r#"
openapi: 3.0.3
info:
  title: Acceptance API
  version: 1.0.0
paths:
  /ping:
    get:
      operationId: ping
      responses:
        '200':
          description: pong
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_08_barrier_race_rejects_stale_openapi_and_mcp_publications() {
    let root = AcceptanceRoot::new("e2e-08");
    let resolver = Arc::new(RoutingResolver::default());
    let resolver_trait: Arc<dyn DnsResolver> = resolver.clone();
    let fixture = runtime_fixture(
        root,
        Vec::new(),
        [
            "openapi.acceptance.test".to_owned(),
            "mcp.acceptance.test".to_owned(),
        ],
        true,
        resolver_trait,
    );
    let openapi_record = create_managed(&fixture.control_plane, no_auth_openapi_connection()).await;
    let mcp_record = create_managed(&fixture.control_plane, no_auth_mcp_connection()).await;
    let captured_collection_etag = fixture
        .control_plane
        .runtime_snapshot()
        .collection_etag()
        .to_owned();
    let registry = ToolRegistry::disabled();
    let openapi = OpenApiConnectionCatalogService::load(
        fixture.control_plane.clone(),
        fixture.runtime.clone(),
        registry.clone(),
    )
    .expect("OpenAPI catalog service should load");
    let mcp = McpConnectionCatalogService::load(
        fixture.control_plane.clone(),
        fixture.runtime.clone(),
        registry.clone(),
    )
    .expect("MCP catalog service should load");
    let preview = openapi
        .preview(openapi_record.id.as_str(), ACCEPTANCE_OPENAPI_SPEC)
        .await
        .expect("OpenAPI preview should bind to the captured Connection revision");

    // OpenAPI and MCP are mutually exclusive Connection kinds. The update task therefore
    // advances both records captured by the same runtime snapshot while the two catalog
    // operations race from their respective old ETags. The second barrier fixes the
    // adversarial interleaving: all three tasks start together, then both stale catalog
    // publications are released only after the replacement snapshot is visible.
    let start = Arc::new(tokio::sync::Barrier::new(4));
    let updated_snapshot_visible = Arc::new(tokio::sync::Barrier::new(3));

    let update_control_plane = fixture.control_plane.clone();
    let update_openapi_record = openapi_record.clone();
    let update_mcp_record = mcp_record.clone();
    let update_start = Arc::clone(&start);
    let update_visible = Arc::clone(&updated_snapshot_visible);
    let update_task = tokio::spawn(async move {
        update_start.wait().await;
        let mut openapi_write = update_openapi_record.write.clone();
        openapi_write.display_name = "Managed OpenAPI updated".to_owned();
        let updated_openapi = update_control_plane
            .replace_managed(
                &update_openapi_record.id,
                &update_openapi_record.etag(),
                openapi_write,
                ACCEPTANCE_ACTOR,
            )
            .await;
        let mut mcp_write = update_mcp_record.write.clone();
        mcp_write.display_name = "Managed MCP updated".to_owned();
        let updated_mcp = update_control_plane
            .replace_managed(
                &update_mcp_record.id,
                &update_mcp_record.etag(),
                mcp_write,
                ACCEPTANCE_ACTOR,
            )
            .await;
        update_visible.wait().await;
        (updated_openapi, updated_mcp)
    });

    let registration_service = openapi.clone();
    let registration_id = openapi_record.id.to_string();
    let registration_etag = preview.connection_etag.to_string();
    let registration_digest = preview.spec_digest.clone();
    let registration_spec_revision = preview.spec_revision;
    let registration_catalog_revision = preview.catalog_revision;
    let registration_start = Arc::clone(&start);
    let registration_visible = Arc::clone(&updated_snapshot_visible);
    let registration_task = tokio::spawn(async move {
        registration_start.wait().await;
        registration_visible.wait().await;
        registration_service
            .register(
                &registration_id,
                &registration_etag,
                registration_spec_revision,
                registration_catalog_revision,
                &registration_digest,
                ACCEPTANCE_OPENAPI_SPEC,
                &["ping".to_owned()],
                &[],
                ACCEPTANCE_ACTOR,
            )
            .await
    });

    let refresh_service = mcp.clone();
    let refresh_id = mcp_record.id.to_string();
    let refresh_etag = mcp_record.etag().to_string();
    let refresh_start = Arc::clone(&start);
    let refresh_visible = Arc::clone(&updated_snapshot_visible);
    let refresh_task = tokio::spawn(async move {
        refresh_start.wait().await;
        refresh_visible.wait().await;
        refresh_service
            .refresh(&refresh_id, &refresh_etag, ACCEPTANCE_ACTOR)
            .await
    });

    start.wait().await;
    let (updates, raced_registration, raced_refresh) =
        tokio::join!(update_task, registration_task, refresh_task);
    let (updated_openapi, updated_mcp) = updates.expect("update task should join cleanly");
    let updated_openapi = updated_openapi.expect("OpenAPI Connection update should commit");
    let updated_mcp = updated_mcp.expect("MCP Connection update should commit");
    assert_eq!(
        raced_registration
            .expect("registration task should join cleanly")
            .expect_err("old OpenAPI preview must fail after the raced update"),
        OpenApiCatalogError::PreconditionFailed
    );
    assert_eq!(
        raced_refresh
            .expect("refresh task should join cleanly")
            .expect_err("old MCP ETag must fail after the raced update"),
        McpCatalogRefreshError::PreconditionFailed
    );
    assert!(
        registry.list().is_empty(),
        "neither stale operation may publish a capability"
    );
    assert_eq!(
        resolver.total_calls(),
        0,
        "stale revision checks must run before discovery DNS or network work"
    );

    let snapshot = fixture.control_plane.runtime_snapshot();
    assert_ne!(snapshot.collection_etag(), captured_collection_etag);
    assert_eq!(
        snapshot
            .managed()
            .get(&updated_openapi.id)
            .expect("updated OpenAPI Connection should remain present")
            .etag(),
        updated_openapi.etag()
    );
    assert_eq!(
        snapshot
            .managed()
            .get(&updated_mcp.id)
            .expect("updated MCP Connection should remain present")
            .etag(),
        updated_mcp.etag()
    );
    assert!(
        fixture
            .control_plane
            .managed_store()
            .expect("managed store should remain available")
            .mcp_catalog(&updated_mcp.id)
            .await
            .expect("MCP catalog lookup should succeed")
            .is_none(),
        "the stale MCP refresh must leave no durable catalog"
    );

    let fresh_preview = openapi
        .preview(updated_openapi.id.as_str(), ACCEPTANCE_OPENAPI_SPEC)
        .await
        .expect("the winning Connection revision should support a fresh preview");
    let selected = fresh_preview
        .binding
        .definitions
        .iter()
        .map(|definition| definition.name.clone())
        .collect::<Vec<_>>();
    let confirmations = fresh_preview.binding.security_selections.clone();
    openapi
        .register(
            updated_openapi.id.as_str(),
            fresh_preview.connection_etag.as_str(),
            fresh_preview.spec_revision,
            fresh_preview.catalog_revision,
            &fresh_preview.spec_digest,
            ACCEPTANCE_OPENAPI_SPEC,
            &selected,
            &confirmations,
            ACCEPTANCE_ACTOR,
        )
        .await
        .expect("a fresh post-race registration should publish");
    let definition = registry
        .get("ping")
        .expect("the fresh catalog should expose ping");
    assert!(matches!(
        (&definition.source, definition.target.as_ref()),
        (
            ToolSource::OpenApi {
                connection_id: source_id,
                ..
            },
            Some(ToolTarget::Http {
                connection_id: target_id,
                ..
            })
        ) if source_id == updated_openapi.id.as_str()
            && target_id == updated_openapi.id.as_str()
    ));
    assert!(snapshot.managed().contains_key(&updated_openapi.id));
}
fn manual_connection_tool(connection_id: &str) -> Value {
    let mapping = json!({
        "method": "GET",
        "path_template": "/charges/{charge_id}"
    });
    json!({
        "name": "get_charge",
        "description": "Looks up a charge through a referenced Connection.",
        "input_json_schema": {
            "type": "object",
            "required": ["charge_id"],
            "properties": {
                "charge_id": { "type": "string" }
            },
            "additionalProperties": false
        },
        "target": {
            "type": "http",
            "connection_id": connection_id,
            "mapping": mapping
        },
        "source": {
            "type": "manual"
        },
        "upstream": mapping
    })
}

async fn invoke_plain_connection(
    runtime: &ConnectionHttpRuntime,
    connection_id: &ConnectionId,
    path: &str,
) -> Result<StatusCode, &'static str> {
    let target = runtime
        .target(connection_id.as_str(), path)
        .map_err(|_| "connection target")?;
    let checked = target
        .preflight_client()
        .checked_destination(target.url())
        .await
        .map_err(|_| "egress preflight")?;
    let prepared = runtime
        .prepare_transport(&target, &checked)
        .await
        .map_err(|_| "transport preparation")?;
    let response = prepared
        .client()
        .request_with_headers_at_checked_destination(
            prepared.destination(),
            Method::GET,
            target.url(),
            HeaderMap::new(),
            None,
        )
        .await
        .map_err(|_| "connection request")?;
    Ok(response.status)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_09_all_references_disable_atomically_and_block_delete_without_orphans() {
    let (http_addr, mut http_captured) = spawn_capture_upstream().await;
    let mcp_upstream = spawn_test_mcp_upstream("remote_acceptance").await;
    let root = AcceptanceRoot::new("e2e-09");
    let resolver = Arc::new(RoutingResolver::with_answers([(
        "127.0.0.1",
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    )]));
    let resolver_trait: Arc<dyn DnsResolver> = resolver.clone();
    let mut fixture = runtime_fixture(
        root,
        Vec::new(),
        ["127.0.0.1".to_owned()],
        false,
        resolver_trait,
    );

    let mut http_write = no_auth_openapi_connection();
    http_write.endpoint.base_url = format!("http://127.0.0.1:{}", http_addr.port());
    http_write.endpoint.base_path = "/".to_owned();
    let http_connection = create_managed(&fixture.control_plane, http_write).await;
    let mut mcp_write = no_auth_mcp_connection();
    mcp_write.endpoint.base_url = format!("http://127.0.0.1:{}", mcp_upstream.addr.port());
    mcp_write.endpoint.base_path = "/mcp".to_owned();
    let mcp_connection = create_managed(&fixture.control_plane, mcp_write).await;

    let registry = ToolRegistry::from_json_value(json!({
        "schema_version": "0.1.0",
        "tools": [manual_connection_tool(http_connection.id.as_str())]
    }))
    .expect("referenced manual capability should load");
    fixture
        .runtime
        .replace_dependencies(
            ConnectionDependencyKind::ProxyRoute,
            &[(
                http_connection.id.to_string(),
                "acceptance-proxy".to_owned(),
            )],
        )
        .expect("proxy dependency should persist");
    fixture
        .runtime
        .replace_dependencies(
            ConnectionDependencyKind::ManualTool,
            &[(http_connection.id.to_string(), "get_charge".to_owned())],
        )
        .expect("manual capability dependency should persist");

    let openapi_catalogs = OpenApiConnectionCatalogService::load(
        fixture.control_plane.clone(),
        fixture.runtime.clone(),
        registry.clone(),
    )
    .expect("OpenAPI catalog service should load");
    let preview = openapi_catalogs
        .preview(http_connection.id.as_str(), ACCEPTANCE_OPENAPI_SPEC)
        .await
        .expect("OpenAPI preview should bind to the referenced Connection");
    let selected = preview
        .binding
        .definitions
        .iter()
        .map(|definition| definition.name.clone())
        .collect::<Vec<_>>();
    let confirmations = preview.binding.security_selections.clone();
    openapi_catalogs
        .register(
            http_connection.id.as_str(),
            preview.connection_etag.as_str(),
            preview.spec_revision,
            preview.catalog_revision,
            &preview.spec_digest,
            ACCEPTANCE_OPENAPI_SPEC,
            &selected,
            &confirmations,
            ACCEPTANCE_ACTOR,
        )
        .await
        .expect("managed OpenAPI capability should publish");

    let mcp_catalogs = McpConnectionCatalogService::load(
        fixture.control_plane.clone(),
        fixture.runtime.clone(),
        registry.clone(),
    )
    .expect("MCP catalog service should load");
    mcp_catalogs
        .refresh(
            mcp_connection.id.as_str(),
            mcp_connection.etag().as_str(),
            ACCEPTANCE_ACTOR,
        )
        .await
        .expect("managed MCP capability should publish");
    let mcp_tool_name = format!("{}:remote_acceptance", mcp_connection.id);

    let policy = TempPolicyFile::new(&connection_policy_document_string());
    fixture.config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let policy_before =
        fs::read_to_string(&policy.path).expect("acceptance policy should be readable");
    let audit_log = test_audit_log();
    let runtime_config = ToolRuntimeConfig {
        default_policy: DefaultToolPolicy::Allow,
        default_timeout: Duration::from_secs(1),
        ..ToolRuntimeConfig::default()
    };
    let tool_runtime = ToolRuntime::new(runtime_config, audit_log.clone());
    let executor = ToolExecutor::from_config(
        &fixture.config,
        registry.clone(),
        tool_runtime,
        Arc::clone(&fixture.egress),
        ToolConnectionRuntimes {
            http: Some(fixture.runtime.clone()),
            mcp_catalog: Some(mcp_catalogs.runtime()),
            openapi_catalog: Some(openapi_catalogs.runtime()),
        },
        audit_log,
    )
    .expect("Connection-bound executor should build");

    assert_eq!(
        invoke_plain_connection(&fixture.runtime, &http_connection.id, "/proxy")
            .await
            .expect("proxy Connection target should be active"),
        StatusCode::CREATED
    );
    executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_active" }),
            ToolInvocationContext::default(),
            CancellationToken::new(),
        )
        .await
        .expect("manual Connection capability should be active");
    executor
        .execute(
            "ping",
            json!({}),
            ToolInvocationContext::default(),
            CancellationToken::new(),
        )
        .await
        .expect("managed OpenAPI capability should be active");
    executor
        .execute(
            &mcp_tool_name,
            json!({ "message": "active" }),
            ToolInvocationContext::default(),
            CancellationToken::new(),
        )
        .await
        .expect("managed MCP capability should be active");
    for expected_path in ["/proxy", "/charges/ch_active", "/ping"] {
        let captured = tokio::time::timeout(Duration::from_secs(1), http_captured.recv())
            .await
            .expect("active HTTP capability should reach the local upstream")
            .expect("HTTP capture channel should remain open");
        assert_eq!(captured.path_and_query, expected_path);
    }
    assert_eq!(
        mcp_upstream
            .calls
            .lock()
            .expect("MCP call capture should lock")
            .len(),
        1
    );

    let inventory_policy = crate::rbac::Policy::validate_json_value(
        serde_json::from_str(&policy_before).expect("acceptance policy should parse"),
    )
    .expect("acceptance policy should validate");
    let rbac_state = crate::middleware::rbac::RbacState::new(
        inventory_policy,
        Vec::new(),
        false,
        test_audit_log(),
    );
    let inventory_principal = test_principal(&["connections-superadmin"]);
    let inventory = crate::tools::inventory::CapabilityInventory::new(
        registry.clone(),
        fixture.control_plane.clone(),
    );
    let inventory_ref = &inventory;
    let rbac_state_ref = &rbac_state;
    let inventory_principal_ref = &inventory_principal;
    let list_for = move |connection_id: &ConnectionId| {
        let params = crate::tools::inventory::CapabilityListParams {
            connection_id: Some(connection_id.to_string()),
            limit: Some(100),
            ..crate::tools::inventory::CapabilityListParams::default()
        };
        async move {
            inventory_ref
                .list(rbac_state_ref, inventory_principal_ref, &params)
                .await
                .expect("capability inventory should list")
        }
    };
    let active_http_inventory = list_for(&http_connection.id).await;
    let active_mcp_inventory = list_for(&mcp_connection.id).await;
    assert_eq!(active_http_inventory.total_count, 2);
    assert_eq!(active_mcp_inventory.total_count, 1);
    assert!(active_http_inventory
        .capabilities
        .iter()
        .chain(active_mcp_inventory.capabilities.iter())
        .all(|capability| capability.state.enabled && capability.state.available));

    let mut disabled_http_write = http_connection.write.clone();
    disabled_http_write.enabled = false;
    let disabled_http = fixture
        .control_plane
        .replace_managed(
            &http_connection.id,
            &http_connection.etag(),
            disabled_http_write,
            ACCEPTANCE_ACTOR,
        )
        .await
        .expect("HTTP Connection disable should publish atomically");
    openapi_catalogs.reconcile_connection(&disabled_http);
    let mut disabled_mcp_write = mcp_connection.write.clone();
    disabled_mcp_write.enabled = false;
    let disabled_mcp = fixture
        .control_plane
        .replace_managed(
            &mcp_connection.id,
            &mcp_connection.etag(),
            disabled_mcp_write,
            ACCEPTANCE_ACTOR,
        )
        .await
        .expect("MCP Connection disable should publish atomically");
    mcp_catalogs.reconcile_connection(&disabled_mcp);

    let resolver_calls_before_denials = resolver.total_calls();
    let mcp_calls_before_denials = mcp_upstream
        .calls
        .lock()
        .expect("MCP call capture should lock")
        .len();
    let proxy_error = fixture
        .runtime
        .target(disabled_http.id.as_str(), "/proxy")
        .err()
        .expect("disabled proxy target must fail");
    assert_eq!(proxy_error.safe_reason(), "connection_disabled");
    let manual_error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_disabled" }),
            ToolInvocationContext::default(),
            CancellationToken::new(),
        )
        .await
        .expect_err("disabled manual capability must be non-invocable");
    match manual_error {
        ToolRuntimeError::WorkFailed {
            message, reason, ..
        } => {
            assert!(message.contains("connection_disabled"), "{message}");
            assert_eq!(reason.as_deref(), Some("connection_disabled"));
        }
        other => panic!("unexpected disabled manual invocation result: {other:?}"),
    }
    assert!(
        executor
            .execute(
                "ping",
                json!({}),
                ToolInvocationContext::default(),
                CancellationToken::new(),
            )
            .await
            .is_err(),
        "disabled managed OpenAPI capability must be non-invocable"
    );
    assert!(
        executor
            .execute(
                &mcp_tool_name,
                json!({ "message": "disabled" }),
                ToolInvocationContext::default(),
                CancellationToken::new(),
            )
            .await
            .is_err(),
        "disabled managed MCP capability must be non-invocable"
    );
    let direct_mcp_error = crate::tools::mcp_upstream::call_connection_tool(
        &fixture.runtime,
        disabled_mcp.id.as_str(),
        disabled_mcp.etag().as_str(),
        "remote_acceptance",
        json!({ "message": "disabled-direct" }),
    )
    .await
    .expect_err("disabled MCP Connection must fail before connect");
    assert_eq!(direct_mcp_error.reason(), "connection_disabled");
    assert!(registry.get("ping").is_none());
    assert!(
        tokio::time::timeout(Duration::from_millis(200), http_captured.recv())
            .await
            .is_err(),
        "disabled HTTP references must emit zero new upstream request"
    );
    assert_eq!(resolver.total_calls(), resolver_calls_before_denials);
    assert_eq!(
        mcp_upstream
            .calls
            .lock()
            .expect("MCP call capture should lock")
            .len(),
        mcp_calls_before_denials
    );

    let disabled_http_inventory = list_for(&disabled_http.id).await;
    let disabled_mcp_inventory = list_for(&disabled_mcp.id).await;
    assert_eq!(disabled_http_inventory.total_count, 2);
    assert_eq!(disabled_mcp_inventory.total_count, 1);
    assert!(disabled_http_inventory
        .capabilities
        .iter()
        .chain(disabled_mcp_inventory.capabilities.iter())
        .all(|capability| {
            !capability.state.enabled
                && !capability.state.available
                && capability.state.reason == "connection_disabled"
        }));

    let store = fixture
        .control_plane
        .managed_store()
        .expect("managed store should remain available");
    let http_dependencies = store
        .dependencies(&disabled_http.id)
        .await
        .expect("HTTP dependencies should load");
    assert!(http_dependencies
        .iter()
        .any(|dependency| dependency.kind == ConnectionDependencyKind::ProxyRoute));
    assert!(http_dependencies
        .iter()
        .any(|dependency| dependency.kind == ConnectionDependencyKind::ManualTool));
    assert!(http_dependencies
        .iter()
        .any(|dependency| dependency.kind == ConnectionDependencyKind::ManagedTool));
    let mcp_dependencies = store
        .dependencies(&disabled_mcp.id)
        .await
        .expect("MCP dependencies should load");
    assert!(mcp_dependencies
        .iter()
        .any(|dependency| dependency.kind == ConnectionDependencyKind::ManagedTool));

    for disabled in [&disabled_http, &disabled_mcp] {
        let delete_error = fixture
            .control_plane
            .delete_managed(&disabled.id, &disabled.etag(), ACCEPTANCE_ACTOR)
            .await
            .expect_err("referenced disabled Connection deletion must conflict");
        assert!(matches!(
            delete_error,
            crate::connections::control_plane::ConnectionMutationError::Store(
                ConnectionStoreError::DependencyConflict { .. }
            )
        ));
    }
    let snapshot = fixture.control_plane.runtime_snapshot();
    assert!(snapshot.managed().contains_key(&disabled_http.id));
    assert!(snapshot.managed().contains_key(&disabled_mcp.id));
    for definition in registry.list() {
        if let Some(
            ToolTarget::Http { connection_id, .. }
            | ToolTarget::Mcp { connection_id, .. }
            | ToolTarget::Composite { connection_id },
        ) = definition.target.as_ref()
        {
            let id = ConnectionId::parse(connection_id.clone())
                .expect("remaining registry target ID should validate");
            assert!(
                snapshot.managed().contains_key(&id),
                "failed deletion must not leave an orphan registry target"
            );
        }
    }
    for capability in disabled_http_inventory
        .capabilities
        .iter()
        .chain(disabled_mcp_inventory.capabilities.iter())
    {
        let connection = capability
            .connection
            .as_ref()
            .expect("managed capability should retain Connection provenance");
        assert!(snapshot.managed().contains_key(&connection.id));
    }
    assert_eq!(
        fs::read_to_string(&policy.path).expect("acceptance policy should remain readable"),
        policy_before,
        "Connection lifecycle operations must never edit caller authorization policy"
    );
    mcp_upstream.shutdown().await;
}
