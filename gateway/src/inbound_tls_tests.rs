//! Inbound TLS termination tests. Each family is a module next to this one,
//! named for the part of `inbound_tls.rs` it exercises; this module holds the
//! fixtures more than one family uses.
use std::{
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    time::Instant,
};

use axum::{extract::ConnectInfo, routing::get, Extension, Router};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, IpAddr as PkiIpAddr, Ipv4Addr as PkiIpv4Addr, ServerName},
        ClientConfig, HandshakeKind, RootCertStore,
    },
    TlsConnector,
};

use super::*;
use crate::{config::Config, lifecycle::serve_router_with_shutdown};

#[path = "inbound_tls_client_certificate_tests.rs"]
mod client_certificates;
#[path = "inbound_tls_credential_precedence_tests.rs"]
mod credential_precedence;
#[path = "inbound_tls_listener_tests.rs"]
mod listener;
#[path = "inbound_tls_material_tests.rs"]
mod material;
#[path = "inbound_tls_reload_tests.rs"]
mod reload;
#[path = "inbound_tls_session_resumption_tests.rs"]
mod session_resumption;
#[path = "inbound_tls_sni_tests.rs"]
mod sni;

const SERVER_NAME: &str = "gateway.inbound-tls.test";

/// A certificate authority plus one leaf it signed, in PEM.
///
/// Modelled on the fixtures in `gateway/src/egress/mtls_tests.rs`: a leaf signed
/// by a throwaway CA rather than a self-signed leaf, so the client can trust the
/// CA the way a real deployment would.
#[derive(Clone)]
struct ServerIdentity {
    certificate_pem: String,
    private_key_pem: String,
    ca_der: Vec<u8>,
}

fn server_identity() -> ServerIdentity {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "GreenGateway Inbound TLS Test CA",
    );
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
    let ca_certificate = ca_params
        .self_signed(&ca_key)
        .expect("test CA certificate should build");

    let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.to_owned()])
        .expect("test server certificate parameters should build");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("test server key should generate");
    let certificate = params
        .signed_by(&key, &Issuer::from_params(&ca_params, &ca_key))
        .expect("test server certificate should build");

    ServerIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
        ca_der: ca_certificate.der().as_ref().to_vec(),
    }
}

/// A throwaway directory holding the mounted certificate and key.
struct MaterialDir {
    root: PathBuf,
}

impl MaterialDir {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("greengateway-inbound-tls-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("test material directory should create");
        Self { root }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, contents).expect("test material file should write");
        set_file_permissions(&path, 0o600);
        path
    }

    fn path(&self, name: &str) -> String {
        self.root
            .join(name)
            .to_str()
            .expect("test material path should be UTF-8")
            .to_owned()
    }
}

impl Drop for MaterialDir {
    fn drop(&mut self) {
        // Best effort: a permission fixture may have left the directory in a
        // state this process cannot clean, and a failed cleanup must not mask
        // the assertion that ran before it.
        #[cfg(unix)]
        set_directory_permissions(&self.root, 0o700);
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn set_file_permissions(path: &FsPath, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("test material permissions should set");
}

#[cfg(not(unix))]
fn set_file_permissions(_: &FsPath, _: u32) {}

#[cfg(unix)]
fn set_directory_permissions(path: &FsPath, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

/// A configuration with inbound TLS on the data listener and nothing else
/// changed, so a test asserting about TLS is not also asserting about the rest
/// of the gateway's defaults.
fn tls_config(material: &MaterialDir) -> Config {
    let mut config = Config::test_defaults();
    config.tls_cert_files = Some(vec![material.path("tls.crt")]);
    config.tls_key_files = Some(vec![material.path("tls.key")]);
    config
}

fn write_default_identity(material: &MaterialDir) -> ServerIdentity {
    let identity = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    material.write("tls.key", &identity.private_key_pem);
    identity
}

fn client_config(
    ca_der: &[u8],
    alpn_protocols: Vec<Vec<u8>>,
    protocol_versions: &[&'static SupportedProtocolVersion],
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .expect("test CA should be accepted as a root");
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(protocol_versions)
        .expect("test client protocol versions should be supported")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    config
}

fn default_client_config(ca_der: &[u8]) -> ClientConfig {
    client_config(
        ca_der,
        vec![b"http/1.1".to_vec()],
        &[&version::TLS12, &version::TLS13],
    )
}

fn scheme_router() -> Router {
    Router::new().route(
        "/scheme",
        get(
            |Extension(scheme): Extension<ConnectionScheme>,
             ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                format!("{} {}", scheme.as_str(), peer)
            },
        ),
    )
}

/// A running listener plus the handle needed to stop it.
struct RunningListener {
    addr: SocketAddr,
    shutdown: CancellationToken,
    server: tokio::task::JoinHandle<io::Result<()>>,
}

impl RunningListener {
    async fn stop(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.server).await;
    }
}

/// Serves `scheme_router` on a freshly bound listener, applying the same scheme
/// extension `serve_gateway` applies in production.
async fn serve(bindings: &InboundTlsBindings) -> RunningListener {
    serve_bound(bindings, InboundTlsBindings::bind_data).await
}

/// The same, on the admin half of the bindings.
///
/// The two listeners are separate `accept` loops with separate admission
/// budgets, and that separation is only checkable if a test can run both.
async fn serve_admin(bindings: &InboundTlsBindings) -> RunningListener {
    serve_bound(bindings, InboundTlsBindings::bind_admin).await
}

async fn serve_bound(
    bindings: &InboundTlsBindings,
    bind: fn(&InboundTlsBindings, TcpListener) -> io::Result<BoundListener>,
) -> RunningListener {
    let tcp = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let bound = bind(bindings, tcp).expect("test listener should wrap without error");
    let addr = bound
        .local_addr()
        .expect("bound address should be readable");
    let router = scheme_router().layer(Extension(bound.scheme()));
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(serve_router_with_shutdown(bound, router, shutdown.clone()));

    RunningListener {
        addr,
        shutdown,
        server,
    }
}

/// One completed request over TLS: what the server answered, and how the
/// connection under it was established.
///
/// The handshake kind travels with the body because the resumption tests assert
/// about both at once. "This connection was a full handshake" and "this
/// connection produced no principal" are different claims, and a test that
/// checked only the second could pass against a listener that resumed and
/// happened to fail for an unrelated reason.
struct TlsExchange {
    body: String,
    handshake_kind: Option<HandshakeKind>,
}

/// Completes a TLS handshake over a *shared* client configuration, sends one
/// request, and reads the response.
///
/// Taking `Arc<ClientConfig>` rather than `ClientConfig` is what makes
/// resumption reachable at all: rustls keeps the client's session store on the
/// configuration, so two connections built from one `Arc` are the only way a
/// test can offer a server the ticket it issued earlier. Every helper that
/// builds a fresh configuration per call can never resume -- which is precisely
/// why the resumption path went untested.
async fn tls_exchange(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    request: &str,
) -> Result<TlsExchange, String> {
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|error| format!("connect failed: {error}"))?;
    let server_name = ServerName::try_from(SERVER_NAME).expect("test server name should parse");
    let mut stream = TlsConnector::from(config)
        .connect(server_name, tcp)
        .await
        .map_err(|error| format!("handshake failed: {error}"))?;

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("request write failed: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|error| format!("response read failed: {error}"))?;
    // Read after the exchange rather than straight after `connect`: on TLS 1.3
    // the server's session tickets ride the first application flight, so this
    // is also the point by which the client has stored whatever it could resume
    // with next time.
    let handshake_kind = stream.get_ref().1.handshake_kind();

    Ok(TlsExchange {
        body: String::from_utf8_lossy(&response).into_owned(),
        handshake_kind,
    })
}

// --- client certificates ---------------------------------------------------
//
// The client CA, the identities it issues and the authenticating listener the
// client-certificate, session resumption, credential precedence, SNI and
// reload tests share.

use axum::{extract::Request, http::StatusCode, middleware::from_fn};
use rcgen::{
    string::Ia5String, BasicConstraints, CertificateParams, CertificateRevocationListParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType, SerialNumber,
};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{
    audit::{AuditEvent, AuditLog, AuditSink},
    auth::{
        chain::ChainValidator, AuthError, AuthMethod, ClientCertIdentitySource,
        ClientCertificateValidator, Principal, PrincipalDirectory, SessionCredential,
        SessionValidator,
    },
    client_ip::ClientIpPolicy,
    config::AuthMode,
    inbound_tls::ClientCertRequirement,
    middleware::{auth::AuthState, headers::header_hardening_middleware},
};

const CLIENT_SPIFFE_ID: &str = "spiffe://gateway.test/ns/payments/sa/api";

/// A throwaway client CA, kept alive so it can sign leaves and CRLs.
struct ClientCa {
    /// The CA's subject, key-identifier method, key usages and signing key:
    /// everything rcgen needs to issue a leaf or a CRL under this CA.
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

fn client_ca() -> ClientCa {
    client_ca_named("GreenGateway Client Test CA")
}

fn client_ca_named(common_name: &str) -> ClientCa {
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // webpki consults key usage to decide whether an issuer may sign
    // certificates and CRLs, so a CA that declares any usage must declare both.
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().expect("test client CA key should generate");
    let certificate = params
        .self_signed(&key)
        .expect("test client CA certificate should build");
    let pem = certificate.pem();

    ClientCa {
        issuer: Issuer::new(params, key),
        pem,
    }
}

/// One issued client certificate, in the form a rustls client wants it.
struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    serial: SerialNumber,
}

/// How a test wants its client certificate to differ from a good one.
struct ClientIdentitySpec {
    sans: Vec<SanType>,
    extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
    not_after: OffsetDateTime,
    serial: u64,
}

impl Default for ClientIdentitySpec {
    fn default() -> Self {
        Self {
            sans: vec![uri_san(CLIENT_SPIFFE_ID)],
            extended_key_usages: vec![ExtendedKeyUsagePurpose::ClientAuth],
            not_after: OffsetDateTime::now_utc() + TimeDuration::days(1),
            serial: 1,
        }
    }
}

fn uri_san(value: &str) -> SanType {
    SanType::URI(Ia5String::try_from(value).expect("test URI SAN should be IA5"))
}

fn issue_client_identity(ca: &ClientCa, spec: ClientIdentitySpec) -> ClientIdentity {
    let mut params = CertificateParams::default();
    params.subject_alt_names = spec.sans;
    params.extended_key_usages = spec.extended_key_usages;
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::days(1);
    params.not_after = spec.not_after;
    let serial = SerialNumber::from(spec.serial);
    params.serial_number = Some(serial.clone());
    let key = KeyPair::generate().expect("test client key should generate");
    let certificate = params
        .signed_by(&key, &ca.issuer)
        .expect("test client certificate should build");

    ClientIdentity {
        chain: vec![certificate.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        serial,
    }
}

/// A data-listener configuration that terminates TLS and asks for client
/// certificates.
fn client_auth_config(
    material: &MaterialDir,
    requirement: ClientCertRequirement,
    crl_file: Option<&str>,
) -> Config {
    let mut config = tls_config(material);
    config.client_cert_auth = Some(crate::config::InboundClientAuthConfig {
        mode_setting: "CLIENT_CERT_MODE",
        requirement,
        ca_setting: "CLIENT_CERT_CA_FILE",
        ca_file: material.path("client-ca.crt"),
        crl_setting: "CLIENT_CERT_CRL_FILE",
        crl_file: crl_file.map(|name| material.path(name)),
        identity_source: ClientCertIdentitySource::Spiffe,
    });
    config
}

fn client_config_with_identity(ca_der: &[u8], identity: Option<ClientIdentity>) -> ClientConfig {
    client_config_with_identity_at(ca_der, identity, &[&version::TLS12, &version::TLS13])
}

/// The same, pinned to a chosen set of protocol versions.
///
/// The resumption tests need this because TLS 1.2 and TLS 1.3 restore a
/// client's certificate chain through two entirely separate pieces of rustls --
/// an abbreviated handshake keyed on a session id, and a PSK keyed on a session
/// ticket. A test that only ever negotiated 1.3 would leave the 1.2 path
/// unexercised, and `TLS_MIN_VERSION` defaults to 1.2.
fn client_config_with_identity_at(
    ca_der: &[u8],
    identity: Option<ClientIdentity>,
    protocol_versions: &[&'static SupportedProtocolVersion],
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .expect("test CA should be accepted as a root");
    let builder = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(protocol_versions)
        .expect("test client protocol versions should be supported")
        .with_root_certificates(roots);
    let mut config = match identity {
        Some(identity) => builder
            .with_client_auth_cert(identity.chain, identity.key)
            .expect("test client identity should load"),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

struct SilentAuditSink;

impl AuditSink for SilentAuditSink {
    fn emit(&self, _event: &AuditEvent) {}
}

/// A router that runs the real authentication middleware over the real
/// certificate validator, and reports what it decided.
///
/// `/whoami` answers `200` with the authenticated principal id, or the
/// middleware answers `401` on its own. Nothing here fabricates a principal, so
/// "no principal was produced" is observable as a 401 rather than inferred.
fn authenticating_router() -> Router {
    authenticating_router_over(vec![
        Arc::new(ClientCertificateValidator) as Arc<dyn SessionValidator>
    ])
}

/// The same router over a chosen validator chain.
///
/// The credential-precedence tests need a chain that accepts bearer and cookie
/// credentials as well as certificates. Without one the middleware short-circuits
/// a bearer credential as `bearer_auth_unsupported` before any validator sees
/// it, and a test built on that would be asserting about a routing hint rather
/// than about which credential won.
fn authenticating_router_over(validators: Vec<Arc<dyn SessionValidator>>) -> Router {
    let state = AuthState {
        admin_sessions: None,
        validator: Some(Arc::new(ChainValidator::new(validators)) as Arc<dyn SessionValidator>),
        mode: AuthMode::Required,
        cookie_name: "session".to_owned(),
        exempt_paths: Vec::new(),
        audit: AuditLog::new(Arc::new(SilentAuditSink) as Arc<dyn AuditSink>),
        principal_directory: PrincipalDirectory::disabled(),
        client_ip_policy: ClientIpPolicy::default(),
        mcp_route_paths: Vec::new(),
        mcp_resource: None,
        mcp_resource_metadata_url: None,
    };

    Router::new()
        .route(
            "/whoami",
            get(|request: Request| async move {
                let principal = request.extensions().get::<Principal>().cloned();
                let asserted = request
                    .headers()
                    .get("x-ssl-client-verify")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("none")
                    .to_owned();
                match principal {
                    Some(principal) => {
                        format!("principal={} asserted={asserted}", principal.user_id)
                    }
                    None => format!("principal=none asserted={asserted}"),
                }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::middleware::auth::auth_middleware,
        ))
        .layer(from_fn(header_hardening_middleware))
}

async fn serve_authenticating(bindings: &InboundTlsBindings) -> RunningListener {
    serve_router(bindings, authenticating_router()).await
}

async fn serve_router(bindings: &InboundTlsBindings, router: Router) -> RunningListener {
    let tcp = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let bound = bindings
        .bind_data(tcp)
        .expect("test listener should wrap without error");
    let addr = bound
        .local_addr()
        .expect("bound address should be readable");
    let router = router.layer(Extension(bound.scheme()));
    let shutdown = CancellationToken::new();
    let server = tokio::spawn(serve_router_with_shutdown(bound, router, shutdown.clone()));

    RunningListener {
        addr,
        shutdown,
        server,
    }
}

/// Completes a handshake and asks `/whoami`, carrying the mTLS assertion
/// headers a fronting terminator would set.
///
/// The headers are always sent, in every case, so that "the certificate decided
/// this" is distinguishable from "a header decided this" in the negative cases
/// as well as the positive ones.
async fn whoami(addr: SocketAddr, config: ClientConfig) -> Result<String, String> {
    whoami_request(addr, Arc::new(config), "")
        .await
        .map(|exchange| exchange.body)
}

/// The same exchange over a shared client configuration, with room for extra
/// request headers.
///
/// The shared configuration is what the resumption tests need; the extra
/// headers are what the credential-precedence tests need, so that a request can
/// carry both a certificate and a bearer token.
async fn whoami_request(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    extra_headers: &str,
) -> Result<TlsExchange, String> {
    tls_exchange(
        addr,
        config,
        &format!(
            "GET /whoami HTTP/1.1\r\nHost: {SERVER_NAME}\r\n\
             x-ssl-client-verify: SUCCESS\r\n\
             x-ssl-client-s-dn: CN=admin\r\n\
             x-forwarded-client-cert: URI=spiffe://gateway.test/ns/payments/sa/admin\r\n\
             x-spiffe-id: spiffe://gateway.test/ns/payments/sa/admin\r\n\
             {extra_headers}Connection: close\r\n\r\n"
        ),
    )
    .await
}

/// Writes a server identity, a client CA, and optionally a CRL into one
/// directory.
fn write_client_auth_material(material: &MaterialDir, ca: &ClientCa) -> ServerIdentity {
    let identity = write_default_identity(material);
    material.write("client-ca.crt", &ca.pem);
    identity
}

fn assert_unauthorized(response: &str, context: &str) {
    assert!(
        response.starts_with(&format!("HTTP/1.1 {}", StatusCode::UNAUTHORIZED.as_u16())),
        "{context}: expected a 401, got: {response}"
    );
    assert!(
        !response.contains(CLIENT_SPIFFE_ID) && !response.contains("principal=spiffe"),
        "{context}: no principal may appear in the response: {response}"
    );
}

// --- SNI chains ------------------------------------------------------------
//
// The multi-chain server identities the SNI and reload tests share.

/// A server identity whose leaf carries exactly the given DNS names (and,
/// optionally, one IP SAN -- the only shape a caller connecting by address can
/// verify, and the only way to observe selection for a client that sends no
/// server name at all).
fn server_identity_named(dns_names: &[&str], ip_sans: &[std::net::IpAddr]) -> ServerIdentity {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GreenGateway SNI Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
    let ca_certificate = ca_params
        .self_signed(&ca_key)
        .expect("test CA certificate should build");

    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = dns_names
        .iter()
        .map(|name| SanType::DnsName(Ia5String::try_from(*name).expect("test SAN should be IA5")))
        .chain(ip_sans.iter().map(|ip| SanType::IpAddress(*ip)))
        .collect();
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("test server key should generate");
    let certificate = params
        .signed_by(&key, &Issuer::from_params(&ca_params, &ca_key))
        .expect("test server certificate should build");

    ServerIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
        ca_der: ca_certificate.der().as_ref().to_vec(),
    }
}

/// The leaf of a chain, as DER, for comparing against what a listener served.
fn leaf_der(identity: &ServerIdentity) -> Vec<u8> {
    CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
        .next()
        .expect("a test identity should carry at least a leaf")
        .expect("a test identity's leaf should parse")
        .as_ref()
        .to_vec()
}

/// Writes the given chains as numbered files and returns a configuration that
/// lists them in order, so the first entry is the listener's default.
fn write_chains(material: &MaterialDir, identities: &[ServerIdentity]) -> Config {
    let mut config = Config::test_defaults();
    let mut certificates = Vec::new();
    let mut keys = Vec::new();
    for (index, identity) in identities.iter().enumerate() {
        certificates.push(
            material
                .write(&format!("tls-{}.crt", index + 1), &identity.certificate_pem)
                .to_str()
                .expect("material path is UTF-8")
                .to_owned(),
        );
        keys.push(
            material
                .write(&format!("tls-{}.key", index + 1), &identity.private_key_pem)
                .to_str()
                .expect("material path is UTF-8")
                .to_owned(),
        );
    }
    config.tls_cert_files = Some(certificates);
    config.tls_key_files = Some(keys);
    config
}

/// Connects with a client that trusts every given identity's CA and returns the
/// leaf the listener served for that server name.
async fn served_leaf(
    addr: SocketAddr,
    identities: &[&ServerIdentity],
    server_name: ServerName<'static>,
) -> Result<Vec<u8>, String> {
    let mut roots = RootCertStore::empty();
    for identity in identities {
        roots
            .add(CertificateDer::from(identity.ca_der.clone()))
            .expect("test CA should be accepted as a root");
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&version::TLS12, &version::TLS13])
        .expect("test client protocol versions should be supported")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|error| format!("connect failed: {error}"))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|error| format!("handshake failed: {error}"))?;
    stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|leaf| leaf.as_ref().to_vec())
        .ok_or_else(|| "the listener served no certificate".to_owned())
}

fn dns_name(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_owned()).expect("test server name should parse")
}
