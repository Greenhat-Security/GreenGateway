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
        pki_types::{CertificateDer, ServerName},
        ClientConfig, RootCertStore,
    },
    TlsConnector,
};

use super::*;
use crate::{config::Config, lifecycle::serve_router_with_shutdown};

const SERVER_NAME: &str = "gateway.inbound-tls.test";

/// A certificate authority plus one leaf it signed, in PEM.
///
/// Modelled on the fixtures in `gateway/src/egress/mtls_tests.rs`: a leaf signed
/// by a throwaway CA rather than a self-signed leaf, so the client can trust the
/// CA the way a real deployment would.
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
        .signed_by(&key, &ca_certificate, &ca_key)
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
    config.tls_cert_file = Some(material.path("tls.crt"));
    config.tls_key_file = Some(material.path("tls.key"));
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

/// Completes a TLS handshake and reads one HTTP response, or reports why not.
async fn tls_request(addr: SocketAddr, config: ClientConfig) -> Result<String, String> {
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|error| format!("connect failed: {error}"))?;
    let server_name = ServerName::try_from(SERVER_NAME).expect("test server name should parse");
    let mut stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
        .map_err(|error| format!("handshake failed: {error}"))?;

    stream
        .write_all(
            format!("GET /scheme HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .map_err(|error| format!("request write failed: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|error| format!("response read failed: {error}"))?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

async fn plaintext_request(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("plaintext connect should succeed");
    stream
        .write_all(b"GET /scheme HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("plaintext request should write");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("plaintext response should read");
    String::from_utf8_lossy(&response).into_owned()
}

// --- default behaviour -----------------------------------------------------

/// Constraint: a deployment that sets nothing must behave exactly as it does
/// today, on the same code path.
#[tokio::test]
async fn an_unconfigured_gateway_still_serves_plaintext_on_the_same_listener_type() {
    let bindings =
        InboundTlsBindings::load(&Config::test_defaults()).expect("no TLS settings must load");
    let listener = serve(&bindings).await;

    let response = plaintext_request(listener.addr).await;

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "an unconfigured gateway must keep serving plaintext HTTP/1.1: {response}"
    );
    assert!(
        response.contains("http 127.0.0.1:"),
        "the plaintext listener must report the http scheme and preserve ConnectInfo: {response}"
    );
    listener.stop().await;
}

#[tokio::test]
async fn an_unconfigured_gateway_binds_a_plain_listener_and_reports_the_http_scheme() {
    let bindings =
        InboundTlsBindings::load(&Config::test_defaults()).expect("no TLS settings must load");
    let tcp = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let bound = bindings.bind_data(tcp).expect("plain bind should succeed");

    assert!(
        matches!(bound, BoundListener::Plain(_)),
        "TLS is opt-in; an unconfigured gateway must not be handed a TLS listener"
    );
    assert_eq!(bound.scheme(), ConnectionScheme::Http);
    assert_eq!(bindings.min_version(), None);
}

// --- end to end ------------------------------------------------------------

#[tokio::test]
async fn a_client_completing_a_handshake_is_served_and_sees_the_https_scheme() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let listener = serve(&bindings).await;

    let response = tls_request(listener.addr, default_client_config(&identity.ca_der))
        .await
        .expect("a well-formed TLS client must be served");

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the TLS listener must serve the router: {response}"
    );
    assert!(
        response.contains("https 127.0.0.1:"),
        "a request over TLS must report the https scheme and preserve ConnectInfo: {response}"
    );
    listener.stop().await;
}

// --- the denial-of-service bound -------------------------------------------

/// The central hazard: `Listener::accept` is awaited serially by the serve
/// loop, so a handshake performed inside it would let one client that connects
/// and sends nothing stall every other connection until its timeout.
///
/// The handshake timeout here is deliberately far longer than the deadline the
/// second client is held to. A serial implementation cannot pass: the silent
/// client would hold the accept path for the full 30 seconds.
#[tokio::test]
async fn a_client_that_sends_nothing_does_not_delay_other_clients() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let mut config = tls_config(&material);
    config.tls_handshake_timeout_ms = 30_000;
    config.tls_max_concurrent_handshakes = 8;
    let bindings = InboundTlsBindings::load(&config).expect("material should load");
    let listener = serve(&bindings).await;

    // Connects and then says nothing at all: no ClientHello, ever.
    let silent = TcpStream::connect(listener.addr)
        .await
        .expect("the silent client should connect");

    let served = tokio::time::timeout(
        Duration::from_secs(5),
        tls_request(listener.addr, default_client_config(&identity.ca_der)),
    )
    .await;

    let response = served
        .expect(
            "a client that connects and sends nothing must not delay other handshakes; the \
             second client was not served within 5s",
        )
        .expect("the second client must complete its handshake");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the second client must be served normally: {response}"
    );

    drop(silent);
    listener.stop().await;
}

/// The bound is only safe if a slot comes back promptly. With room for exactly
/// one handshake, a silent client holds the only slot until the timeout fires.
///
/// Both halves of what happens meanwhile are asserted here, because they are
/// what the admission policy is for: while the slot is held a new connection is
/// refused *at once* rather than left in the backlog, and the first attempt
/// after the timeout is served. A client that is told no can retry or fail
/// over; a client that is never accepted can do neither.
#[tokio::test]
async fn a_timed_out_handshake_releases_its_admission_slot() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let mut config = tls_config(&material);
    config.tls_handshake_timeout_ms = 500;
    config.tls_max_concurrent_handshakes = 1;
    let bindings = InboundTlsBindings::load(&config).expect("material should load");
    let listener = serve(&bindings).await;

    let silent = TcpStream::connect(listener.addr)
        .await
        .expect("the silent client should connect");
    // A tenth of the handshake timeout: long enough for the accept loop to have
    // taken the one slot, short enough that the slot cannot already have been
    // released by the time the real client connects.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let refusal = tokio::time::timeout(
        // Half the remaining handshake deadline: an answer this fast can only
        // be a refusal, never the slot coming free.
        Duration::from_millis(200),
        tls_request(listener.addr, default_client_config(&identity.ca_der)),
    )
    .await
    .expect(
        "a connection that cannot be admitted must be answered, not left unaccepted in the \
         kernel's backlog",
    )
    .expect_err("the only slot is held, so this attempt cannot be served");
    assert!(
        refusal.starts_with("handshake failed"),
        "the refusal must arrive as a closed connection rather than a silent one: {refusal}"
    );

    let served = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match tls_request(listener.addr, default_client_config(&identity.ca_der)).await {
                Ok(response) => break response,
                Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .expect(
        "the only handshake slot must be released when a handshake times out; the retrying \
         client was never served",
    );

    assert!(
        served.starts_with("HTTP/1.1 200 OK"),
        "the retrying client must be served normally once the slot is free: {served}"
    );

    drop(silent);
    listener.stop().await;
}

// --- saturation sheds, it does not stall -----------------------------------

/// Opens `count` sockets that connect and then say nothing at all: no
/// ClientHello, ever. The caller holds them open by keeping the vector.
async fn silent_clients(addr: SocketAddr, count: usize) -> Vec<TcpStream> {
    let mut sockets = Vec::with_capacity(count);
    for _ in 0..count {
        sockets.push(
            TcpStream::connect(addr)
                .await
                .expect("a silent client should connect"),
        );
    }
    sockets
}

/// Long enough for the accept loop to have taken every admission slot it is
/// going to take, and small next to the handshake deadlines these tests set.
const SATURATION_SETTLE: Duration = Duration::from_millis(250);

/// Reads until the peer closes, which is how a shed connection presents: the
/// gateway accepted the socket, found no admission slot, and dropped it.
///
/// A reset is the same answer as a clean FIN for this purpose -- the point is
/// that the client learns immediately rather than waiting on a server that is
/// never going to speak.
async fn wait_for_close(mut stream: TcpStream) {
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return,
            Ok(_) => continue,
        }
    }
}

/// Blocks until a probe connection is shed, which is the only observable proof
/// that every admission slot is held.
///
/// A probe that is *not* shed found a free slot and now holds one itself, which
/// moves saturation closer rather than away, so retrying is safe.
async fn wait_until_saturated(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let probe = TcpStream::connect(addr)
            .await
            .expect("a saturation probe should connect");
        if tokio::time::timeout(Duration::from_millis(200), wait_for_close(probe))
            .await
            .is_ok()
        {
            return;
        }
    }
    panic!(
        "the listener never closed a probe connection within 5s, so the admission bound never \
         saturated -- or the listener stopped accepting altogether"
    );
}

fn shed_count(recorder: &crate::audit::sink::tests::CountingRecorder, listener: &str) -> u64 {
    recorder.count(
        crate::metrics::INBOUND_TLS_HANDSHAKES_TOTAL,
        &[("listener", listener), ("outcome", "shed")],
    )
}

/// Constraint: when every admission slot is held, the listener must still
/// answer a new connection.
///
/// Taking the slot *before* the accept -- which is what this branch did first
/// -- stops the process draining the kernel's accept queue the moment the bound
/// fills. A client that arrives then is neither served nor refused: it sits in
/// the backlog until an attacker's slot expires. Holding a slot costs the
/// attacker nothing but an idle socket -- no TLS, no crypto, no auth -- and the
/// gateway's own readiness and liveness probes ride this listener, so the whole
/// deployment reads as wedged.
///
/// The handshake deadline here is ten times the deadline the legitimate client
/// is held to, so an implementation that parks the accept loop cannot pass by
/// being quick: it has to wait out a silent socket.
#[tokio::test]
async fn a_saturated_bound_refuses_a_new_connection_instead_of_leaving_it_in_the_backlog() {
    const BOUND: usize = 4;
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let mut config = tls_config(&material);
    config.tls_handshake_timeout_ms = 30_000;
    config.tls_max_concurrent_handshakes = BOUND;
    let bindings = InboundTlsBindings::load(&config).expect("material should load");
    let listener = serve(&bindings).await;

    let silent = silent_clients(listener.addr, BOUND).await;
    tokio::time::sleep(SATURATION_SETTLE).await;

    let started = Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        tls_request(listener.addr, default_client_config(&identity.ca_der)),
    )
    .await
    .expect(
        "a saturated admission bound must refuse a new connection, not stop accepting it: this \
         client got no answer at all within 3s and would have waited out the 30s handshake \
         deadline in the kernel's backlog",
    );
    let elapsed = started.elapsed();

    let refusal =
        outcome.expect_err("with every slot held, this connection must be shed rather than served");
    assert!(
        refusal.starts_with("handshake failed"),
        "the connection must be accepted and then closed, so the client learns at once: {refusal}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "a shed connection must be closed immediately rather than held open; took {elapsed:?}"
    );

    drop(silent);
    listener.stop().await;
}

/// Constraint: a flood larger than the bound must not queue ahead of a
/// legitimate client.
///
/// This is the sustained-attack shape. Sockets beyond the bound cost the
/// attacker nothing, so what matters is what happens to the ones that cannot be
/// admitted. Shedding them clears the queue immediately, and the next client is
/// served as soon as a slot expires -- about one handshake deadline. Leaving
/// them queued instead drains the backlog `BOUND` sockets per deadline, so a
/// legitimate client waits `FLOOD / BOUND` deadlines behind an attacker who
/// paid for none of it: twelve seconds here, and without end once the flood is
/// sustained rather than one-shot.
#[tokio::test]
async fn a_flood_larger_than_the_bound_does_not_queue_ahead_of_a_legitimate_client() {
    const BOUND: usize = 2;
    const FLOOD: usize = 24;
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let mut config = tls_config(&material);
    config.tls_handshake_timeout_ms = 1_000;
    config.tls_max_concurrent_handshakes = BOUND;
    let bindings = InboundTlsBindings::load(&config).expect("material should load");
    let listener = serve(&bindings).await;

    let silent = silent_clients(listener.addr, FLOOD).await;
    tokio::time::sleep(SATURATION_SETTLE).await;

    // A real client retries a refused connection. It must not have to retry for
    // longer than it takes the flood's admitted sockets to time out.
    let started = Instant::now();
    let response = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match tls_request(listener.addr, default_client_config(&identity.ca_der)).await {
                Ok(response) => break response,
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .expect(
        "a legitimate client must be served once the flood's admitted handshakes expire, not \
         after the whole backlog has drained one admission slot at a time",
    );
    let elapsed = started.elapsed();

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the legitimate client must be served normally: {response}"
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "service must resume about one handshake deadline after the flood, not {} of them: \
         took {elapsed:?}",
        FLOOD / BOUND
    );

    drop(silent);
    listener.stop().await;
}

/// Constraint: a shed connection is reported on the metric that already carries
/// handshake outcomes, so an operator alerting on saturation does not have to
/// learn a second metric name.
#[test]
fn a_shed_connection_is_counted_on_the_handshake_outcome_metric() {
    const BOUND: usize = 2;
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");

    // `metrics` resolves a thread-local recorder before the global one, and a
    // current-thread runtime polls every spawned task on this thread, so the
    // accept loop's emissions land in this recorder. The global recorder is not
    // an option: another suite in this test binary installs it.
    ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let material = MaterialDir::new();
            write_default_identity(&material);
            let mut config = tls_config(&material);
            config.tls_handshake_timeout_ms = 30_000;
            config.tls_max_concurrent_handshakes = BOUND;
            let bindings = InboundTlsBindings::load(&config).expect("material should load");
            let listener = serve(&bindings).await;

            let silent = silent_clients(listener.addr, BOUND).await;
            wait_until_saturated(listener.addr).await;

            // Measured as a delta: reaching saturation had to shed probes of
            // its own, and counting those would make the assertion untrue for
            // the wrong reason.
            let before = shed_count(&recorder, "data");
            let shed = TcpStream::connect(listener.addr)
                .await
                .expect("the shed client should connect");
            tokio::time::timeout(Duration::from_secs(3), wait_for_close(shed))
                .await
                .expect("a connection with no admission slot must be closed, not held");

            assert_eq!(
                shed_count(&recorder, "data") - before,
                1,
                "exactly one connection was refused for want of a slot, so exactly one shed \
                 outcome must be counted on {}",
                crate::metrics::INBOUND_TLS_HANDSHAKES_TOTAL
            );

            drop(silent);
            listener.stop().await;
        });
    });
}

/// Constraint: the admission budget is per listener, not per process.
///
/// The admin listener is how an operator reaches a deployment that is under
/// load, so a flood on the data listener must not spend the admin listener's
/// budget. Each accept loop owns its own semaphore; sharing one would make this
/// fail.
#[tokio::test]
async fn saturating_the_data_listener_leaves_the_admin_listener_serving() {
    const BOUND: usize = 2;
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let mut config = tls_config(&material);
    config.admin_tls_cert_file = Some(material.path("tls.crt"));
    config.admin_tls_key_file = Some(material.path("tls.key"));
    config.tls_handshake_timeout_ms = 30_000;
    config.tls_max_concurrent_handshakes = BOUND;
    let bindings = InboundTlsBindings::load(&config).expect("material should load");
    let data = serve(&bindings).await;
    let admin = serve_admin(&bindings).await;

    let silent = silent_clients(data.addr, BOUND).await;
    wait_until_saturated(data.addr).await;

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        tls_request(admin.addr, default_client_config(&identity.ca_der)),
    )
    .await
    .expect("a data-listener flood must not delay the admin listener")
    .expect("the admin listener keeps its own admission budget");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the admin listener must serve normally while the data listener is saturated: {response}"
    );

    drop(silent);
    data.stop().await;
    admin.stop().await;
}

// --- negotiated parameters -------------------------------------------------

#[tokio::test]
async fn a_tls_1_2_only_client_is_refused_when_the_floor_is_1_3() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let mut config = tls_config(&material);
    config.tls_min_version = TlsMinVersion::Tls13;
    let bindings = InboundTlsBindings::load(&config).expect("material should load");
    let listener = serve(&bindings).await;

    let refused = tls_request(
        listener.addr,
        client_config(
            &identity.ca_der,
            vec![b"http/1.1".to_vec()],
            &[&version::TLS12],
        ),
    )
    .await
    .expect_err("a TLS 1.2 client must be refused when the configured floor is 1.3");
    assert!(
        refused.starts_with("handshake failed"),
        "the refusal must come from the handshake, not from the connect or the request: {refused}"
    );

    // Non-vacuity: the same listener serves a client that meets the floor, so
    // the refusal above is about the version and not about a broken fixture.
    let served = tls_request(
        listener.addr,
        client_config(
            &identity.ca_der,
            vec![b"http/1.1".to_vec()],
            &[&version::TLS13],
        ),
    )
    .await
    .expect("a TLS 1.3 client must still be served");
    assert!(served.starts_with("HTTP/1.1 200 OK"), "{served}");

    listener.stop().await;
}

/// Constraint: do not advertise h2. Cargo feature unification means enabling
/// HTTP/2 anywhere turns `axum::serve`'s auto builder into an h2c server on
/// every listener, so ALPN must not invite a client to try.
#[tokio::test]
async fn alpn_offers_http_1_1_only_and_refuses_an_h2_only_client() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let listener = serve(&bindings).await;

    let refused = tls_request(
        listener.addr,
        client_config(
            &identity.ca_der,
            vec![b"h2".to_vec()],
            &[&version::TLS12, &version::TLS13],
        ),
    )
    .await
    .expect_err("a client offering only h2 must be refused, not silently served HTTP/1.1");
    assert!(
        refused.starts_with("handshake failed"),
        "the h2-only client must be refused during the handshake: {refused}"
    );

    // A client offering both must land on http/1.1 rather than h2.
    let tcp = TcpStream::connect(listener.addr)
        .await
        .expect("the dual-protocol client should connect");
    let server_name = ServerName::try_from(SERVER_NAME).expect("test server name should parse");
    let stream = TlsConnector::from(Arc::new(client_config(
        &identity.ca_der,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        &[&version::TLS12, &version::TLS13],
    )))
    .connect(server_name, tcp)
    .await
    .expect("a client offering h2 and http/1.1 must still be served");
    let negotiated = stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(<[u8]>::to_vec)
        .expect("the server must select an application protocol");
    assert_eq!(
        negotiated,
        b"http/1.1".to_vec(),
        "the gateway must negotiate http/1.1 even when the client prefers h2"
    );

    listener.stop().await;
}

// --- failing closed --------------------------------------------------------

#[test]
fn a_missing_certificate_fails_startup_and_names_the_setting() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.key", &identity.private_key_pem);

    let error = InboundTlsBindings::load(&tls_config(&material))
        .expect_err("a missing certificate must not start the gateway in plaintext");

    assert_eq!(
        error,
        InboundTlsError::MaterialUnavailable {
            setting: "TLS_CERT_FILE"
        }
    );
    assert!(error.to_string().contains("TLS_CERT_FILE"), "{error}");
}

#[test]
fn a_missing_private_key_fails_startup_and_names_the_setting() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", &identity.certificate_pem);

    let error = InboundTlsBindings::load(&tls_config(&material))
        .expect_err("a missing key must not start the gateway in plaintext");

    assert_eq!(
        error,
        InboundTlsError::MaterialUnavailable {
            setting: "TLS_KEY_FILE"
        }
    );
}

#[test]
fn malformed_pem_fails_startup() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", "-----BEGIN CERTIFICATE-----\nnot base64\n");
    material.write("tls.key", &identity.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a malformed certificate must fail startup"),
        InboundTlsError::MaterialInvalid {
            setting: "TLS_CERT_FILE"
        }
    );
}

#[test]
fn a_certificate_file_that_is_not_a_certificate_fails_startup() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", "no PEM here at all\n");
    material.write("tls.key", &identity.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a certificate file with no certificate in it must fail startup"),
        InboundTlsError::MaterialInvalid {
            setting: "TLS_CERT_FILE"
        }
    );
}

#[test]
fn a_key_that_does_not_match_the_certificate_fails_startup() {
    let material = MaterialDir::new();
    let identity = server_identity();
    let other = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    material.write("tls.key", &other.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a mismatched key must fail startup rather than serve a broken listener"),
        InboundTlsError::KeyDoesNotMatchCertificate {
            certificate_setting: "TLS_CERT_FILE",
            private_key_setting: "TLS_KEY_FILE",
        }
    );
}

/// A key concatenated into the certificate file inherits the certificate's
/// permissions, and a certificate is the one half of the pair an operator
/// reasonably mounts world-readable.
#[test]
fn a_certificate_file_containing_a_private_key_is_refused() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write(
        "tls.crt",
        &format!("{}{}", identity.certificate_pem, identity.private_key_pem),
    );
    material.write("tls.key", &identity.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a certificate file carrying a key must be refused"),
        InboundTlsError::CertificateContainsPrivateKey {
            setting: "TLS_CERT_FILE"
        }
    );
}

/// The key file here is a perfectly good key with a great deal of leading
/// filler, which the PEM reader would happily skip. Only the read bound refuses
/// it, so this fails if the bound is widened or dropped rather than passing for
/// the unrelated reason that the material was malformed.
#[test]
fn an_oversized_private_key_is_refused_by_the_bounded_read() {
    let material = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    let filler = "# padding
"
    .repeat(crate::connections::secret::MAX_TLS_PRIVATE_KEY_BYTES / 10);
    material.write("tls.key", &format!("{filler}{}", identity.private_key_pem));

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material)).expect_err(
            "a key file larger than the purpose's bound must be refused before parsing"
        ),
        InboundTlsError::MaterialInvalid {
            setting: "TLS_KEY_FILE"
        }
    );

    // Non-vacuity: the very same key, without the filler, loads.
    material.write("tls.key", &identity.private_key_pem);
    InboundTlsBindings::load(&tls_config(&material))
        .expect("the same key under the bound must load");
}

#[test]
fn a_path_with_no_file_component_fails_startup() {
    let mut config = Config::test_defaults();
    config.tls_cert_file = Some("/".to_owned());
    config.tls_key_file = Some("/run/tls/tls.key".to_owned());

    assert_eq!(
        InboundTlsBindings::load(&config)
            .expect_err("a path that names no file is not certificate material"),
        InboundTlsError::MaterialPathInvalid {
            setting: "TLS_CERT_FILE"
        }
    );
}

#[test]
fn a_directory_named_as_certificate_material_fails_startup() {
    let material = MaterialDir::new();
    let identity = server_identity();
    fs::create_dir_all(material.root.join("tls.crt")).expect("directory fixture should create");
    material.write("tls.key", &identity.private_key_pem);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a directory is not certificate material"),
        InboundTlsError::MaterialUnsafe {
            setting: "TLS_CERT_FILE"
        }
    );
}

/// Every startup failure is printed to stderr and routinely scraped into a log
/// aggregator, so no error may carry the material that produced it.
#[test]
fn startup_errors_never_carry_key_material() {
    let material = MaterialDir::new();
    let identity = server_identity();
    let other = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    material.write("tls.key", &other.private_key_pem);

    let error = InboundTlsBindings::load(&tls_config(&material))
        .expect_err("a mismatched key must fail startup");
    let rendered = format!("{error} {error:?}");

    for line in other
        .private_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
    {
        assert!(
            !rendered.contains(line),
            "a startup error must never render private key material: {rendered}"
        );
    }
    assert!(
        !rendered.contains(&material.path("tls.key")),
        "a startup error must name the setting, not the path it points at: {rendered}"
    );
}

/// `InboundTlsBindings` holds resolved `ServerConfig`s, whose signing keys a
/// derived `Debug` would happily walk into.
#[test]
fn bindings_debug_output_reports_state_without_material() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");

    let rendered = format!("{bindings:?}");

    assert!(rendered.contains("data: true"), "{rendered}");
    assert!(rendered.contains("admin: false"), "{rendered}");
    for line in identity
        .private_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
    {
        assert!(
            !rendered.contains(line),
            "Debug output must never render private key material: {rendered}"
        );
    }
}

// --- permission rules (unix only) ------------------------------------------

/// The private key inherits the connection-secret discipline: group or other
/// *write* on the leaf means another account could swap the key underneath the
/// gateway, so the read fails closed.
#[cfg(unix)]
#[test]
fn a_group_writable_private_key_fails_startup() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    let _ = identity;
    set_file_permissions(&material.root.join("tls.key"), 0o620);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a group-writable key must not start the gateway"),
        InboundTlsError::PrivateKeyMaterialUnsafe {
            setting: "TLS_KEY_FILE"
        }
    );
}

/// Constraint: a server private key readable by another account on the host is
/// refused, not warned about.
///
/// Reading this key is the whole compromise -- every session it ever protected,
/// retroactively -- so *read* is as disqualifying as *write*, which is the rule
/// every other private key in this codebase is already held to. Kubernetes
/// publishes Secret volume files `0644`, so this is the mode a default TLS
/// Secret mount arrives with, and refusing it is the point rather than an
/// accident: the operator sets `defaultMode: 0400`.
#[cfg(unix)]
#[test]
fn a_world_readable_private_key_fails_startup() {
    let material = MaterialDir::new();
    write_default_identity(&material);
    set_file_permissions(&material.root.join("tls.key"), 0o644);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a world-readable private key must not start the gateway"),
        InboundTlsError::PrivateKeyMaterialUnsafe {
            setting: "TLS_KEY_FILE"
        }
    );
}

/// Constraint: the refusal has to be actionable and still say nothing it
/// should not.
///
/// The operator whose Secret mount just stopped the gateway needs the setting
/// and the remedy in the line they are looking at; what they must not get is
/// the path the key was read from or a byte of the key itself.
#[cfg(unix)]
#[test]
fn the_world_readable_key_error_names_the_remedy_without_naming_the_file() {
    let material = MaterialDir::new();
    let identity = write_default_identity(&material);
    set_file_permissions(&material.root.join("tls.key"), 0o644);

    let error = InboundTlsBindings::load(&tls_config(&material))
        .expect_err("a world-readable private key must not start the gateway");
    let rendered = format!("{error} {error:?}");

    assert!(
        rendered.contains("TLS_KEY_FILE"),
        "the error must name the setting to fix: {rendered}"
    );
    assert!(
        rendered.contains("defaultMode: 0400"),
        "the error must name the remedy, because the default Kubernetes mount is what trips it:          {rendered}"
    );
    assert!(
        !rendered.contains(&material.path("tls.key")),
        "the error must not name the path it read: {rendered}"
    );
    for line in identity
        .private_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() > 16)
    {
        assert!(
            !rendered.contains(line),
            "the error must never render key material: {rendered}"
        );
    }
}

/// Constraint: the certificate is public material and keeps the looser policy.
///
/// A certificate is served to every client that connects, so world-readable is
/// its normal condition; tightening it in step with the key would refuse a
/// perfectly ordinary mount for no gain.
#[cfg(unix)]
#[test]
fn a_world_readable_certificate_still_loads() {
    let material = MaterialDir::new();
    write_default_identity(&material);
    set_file_permissions(&material.root.join("tls.crt"), 0o644);
    set_file_permissions(&material.root.join("tls.key"), 0o400);

    InboundTlsBindings::load(&tls_config(&material))
        .expect("a world-readable certificate is public material and must load");
}

/// The kubelet publishes projected volume roots as `drwxrwxrwt`, so a
/// world-writable root with the sticky bit has to stay acceptable; the same
/// mode without the sticky bit does not.
#[cfg(unix)]
#[test]
fn a_world_writable_material_directory_is_accepted_only_with_the_sticky_bit() {
    let material = MaterialDir::new();
    write_default_identity(&material);

    set_directory_permissions(&material.root, 0o1777);
    InboundTlsBindings::load(&tls_config(&material))
        .expect("a sticky world-writable root is what every Kubernetes secret mount looks like");

    set_directory_permissions(&material.root, 0o777);
    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("without the sticky bit, any account could swap the mounted key"),
        InboundTlsError::MaterialDirectoryPermissions {
            setting: "TLS_CERT_FILE"
        }
    );

    set_directory_permissions(&material.root, 0o700);
}

/// Builds the shape a Kubernetes Secret volume actually publishes: the kubelet's
/// atomic writer never exposes the leaf directly, it writes
/// `tls.key -> ..data/tls.key`.
#[cfg(unix)]
fn write_projected_identity(material: &MaterialDir, key_mode: u32) {
    let identity = server_identity();
    let data = material.root.join("..data");
    fs::create_dir_all(&data).expect("projected data directory should create");
    fs::write(data.join("tls.crt"), &identity.certificate_pem)
        .expect("projected cert should write");
    fs::write(data.join("tls.key"), &identity.private_key_pem).expect("projected key should write");
    set_file_permissions(&data.join("tls.crt"), 0o644);
    set_file_permissions(&data.join("tls.key"), key_mode);
    std::os::unix::fs::symlink("..data/tls.crt", material.root.join("tls.crt"))
        .expect("projected cert symlink should create");
    std::os::unix::fs::symlink("..data/tls.key", material.root.join("tls.key"))
        .expect("projected key symlink should create");
}

/// Constraint: the symlinked leaf and the permission mask are separate rules,
/// and tightening the second must not quietly re-introduce a refusal of the
/// first.
///
/// Refusing a symlinked leaf would make the most common way to mount this
/// material unusable, so the projected shape loads -- with the key mounted as
/// `defaultMode: 0400` and the certificate left world-readable, which is
/// exactly the split the two policies encode.
#[cfg(unix)]
#[test]
fn a_kubelet_style_symlinked_leaf_still_loads() {
    let material = MaterialDir::new();
    write_projected_identity(&material, 0o400);

    InboundTlsBindings::load(&tls_config(&material))
        .expect("a kubelet-style projected TLS secret with a 0400 key must load");
}

/// Constraint: tolerating the projection does not mean tolerating its default
/// mode.
///
/// This is the same shape as the test above with the key left at the `0644`
/// Kubernetes publishes by default, and it must fail. The two axes -- may the
/// leaf be a symlink, and who may read it -- are independent, and a policy that
/// answered only the first is what let a world-readable key through.
#[cfg(unix)]
#[test]
fn a_kubelet_style_symlinked_leaf_is_still_refused_at_the_default_mode() {
    let material = MaterialDir::new();
    write_projected_identity(&material, 0o644);

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("a projected key at the default 0644 must not start the gateway"),
        InboundTlsError::PrivateKeyMaterialUnsafe {
            setting: "TLS_KEY_FILE"
        }
    );
}

/// Symlink resolution is confined beneath the capability root, so material
/// pointed outside the mounted directory fails rather than being followed.
///
/// The escape surfaces as a denial rather than as `MaterialUnsafe`, because
/// cap-std refuses to traverse out of the root with `PermissionDenied` and the
/// shared reader maps that to `SourceDenied` before its unsafe-source fallback.
/// The assertion names that outcome rather than "some error", so a future
/// change that started *following* the link would have to fail here.
#[cfg(unix)]
#[test]
fn a_symlink_escaping_the_material_directory_fails_startup() {
    let material = MaterialDir::new();
    let outside = MaterialDir::new();
    let identity = server_identity();
    material.write("tls.crt", &identity.certificate_pem);
    let escaped = outside.write("tls.key", &identity.private_key_pem);
    std::os::unix::fs::symlink(&escaped, material.root.join("tls.key"))
        .expect("escaping symlink should create");

    assert_eq!(
        InboundTlsBindings::load(&tls_config(&material))
            .expect_err("material reached through an escaping symlink must fail closed"),
        InboundTlsError::MaterialDenied {
            setting: "TLS_KEY_FILE"
        }
    );
}
