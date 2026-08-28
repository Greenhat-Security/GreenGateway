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

/// Completes a TLS handshake and reads one HTTP response, or reports why not.
async fn tls_request(addr: SocketAddr, config: ClientConfig) -> Result<String, String> {
    tls_exchange(
        addr,
        Arc::new(config),
        &format!("GET /scheme HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\n\r\n"),
    )
    .await
    .map(|exchange| exchange.body)
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
    config.admin_tls_cert_files = Some(vec![material.path("tls.crt")]);
    config.admin_tls_key_files = Some(vec![material.path("tls.key")]);
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
    config.tls_cert_files = Some(vec!["/".to_owned()]);
    config.tls_key_files = Some(vec!["/run/tls/tls.key".to_owned()]);

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

// --- client-certificate authentication --------------------------------------
//
// Everything below drives a real handshake against a real listener. That is the
// point: the properties being asserted -- that an untrusted, expired, revoked,
// or wrong-purpose certificate never produces an identity -- are properties of
// rustls' verifier as this gateway configures it, and a test that stubbed the
// verifier out would be asserting only that the stub was called.
//
// Every negative case asserts *which way* the decision went, not merely that
// something failed: either the handshake was refused, or a request was served
// and answered 401 with no principal. "The request errored" would pass against
// a listener that was simply broken.

use axum::{extract::Request, http::StatusCode, middleware::from_fn};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevocationReason, RevokedCertParams, SanType, SerialNumber,
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
const OTHER_SPIFFE_ID: &str = "spiffe://gateway.test/ns/payments/sa/batch";

/// A throwaway client CA, kept alive so it can sign leaves and CRLs.
struct ClientCa {
    certificate: rcgen::Certificate,
    key: KeyPair,
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
        certificate,
        key,
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
        .signed_by(&key, &ca.certificate, &ca.key)
        .expect("test client certificate should build");

    ClientIdentity {
        chain: vec![certificate.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        serial,
    }
}

/// A CRL naming `revoked`, valid for `[now + issued, now + expires]`.
///
/// Both bounds are parameters so a test can produce an already-expired CRL --
/// which is a well-formed CRL, not a malformed one, and is the fixture the
/// expiry-enforcement test needs.
fn client_crl(
    ca: &ClientCa,
    revoked: &[&SerialNumber],
    issued: TimeDuration,
    expires: TimeDuration,
) -> String {
    let now = OffsetDateTime::now_utc();
    CertificateRevocationListParams {
        this_update: now + issued,
        next_update: now + expires,
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: revoked
            .iter()
            .map(|serial| RevokedCertParams {
                serial_number: (*serial).clone(),
                revocation_time: now - TimeDuration::hours(1),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&ca.certificate, &ca.key)
    .expect("test CRL should build")
    .pem()
    .expect("test CRL should encode as PEM")
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

/// Asserts that a connection was torn down by the named TLS alert.
///
/// Naming the alert is what keeps this from being "the request errored": the
/// alert says which check refused the certificate, so a test for an expired
/// certificate cannot pass because the listener was broken, misconfigured, or
/// refusing for some entirely different reason.
fn assert_refused_with_alert(result: Result<String, String>, alert: &str, context: &str) {
    match result {
        Ok(response) => panic!("{context}: the request was served instead of refused: {response}"),
        Err(refusal) => assert!(
            refusal.contains(alert),
            "{context}: expected the connection to be refused with the {alert} alert, got: {refusal}"
        ),
    }
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

#[tokio::test]
async fn a_verified_client_certificate_authenticates_as_its_spiffe_id() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("a well-formed client certificate must complete the handshake");

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "a verified certificate must authenticate: {response}"
    );
    assert!(
        response.contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "the principal must be the certificate's SPIFFE ID: {response}"
    );
    // The same request carried four different mTLS assertion headers naming a
    // different SPIFFE ID. None of them reached the handler, and none of them
    // decided the principal.
    assert!(
        response.contains("asserted=none"),
        "client-supplied mTLS assertion headers must be stripped before any handler: {response}"
    );
    assert!(
        !response.contains("sa/admin"),
        "a header must never become an identity: {response}"
    );
    listener.stop().await;
}

/// The `optional` half of the mode, and the downgrade question.
///
/// A caller who brings no certificate is not partly authenticated: they reach
/// the auth chain with nothing, and are refused. Presenting nothing is
/// therefore never worth more than presenting something invalid, which is
/// refused at the handshake.
#[tokio::test]
async fn an_anonymous_caller_on_an_optional_listener_authenticates_as_nobody() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let response = whoami(
        listener.addr,
        client_config_with_identity(&server.ca_der, None),
    )
    .await
    .expect("optional mode must still complete a handshake with no client certificate");

    assert_unauthorized(&response, "a caller with no certificate");
    assert!(
        response.contains("principal=none") || response.contains("unauthorized"),
        "the request must be refused rather than served anonymously: {response}"
    );
    listener.stop().await;
}

#[tokio::test]
async fn required_mode_refuses_a_handshake_that_carries_no_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Required,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let refusal = whoami(
        listener.addr,
        client_config_with_identity(&server.ca_der, None),
    )
    .await
    .expect_err("required mode must not serve a caller with no certificate");
    assert!(
        refusal.starts_with("handshake failed") || refusal.starts_with("response read failed"),
        "the refusal must come from the handshake, not from the router: {refusal}"
    );

    // The listener is refusing that caller, not broken: a caller with a
    // certificate is still served.
    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("a caller with a certificate must still be served");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "required mode must serve a caller who brings a certificate: {response}"
    );
    listener.stop().await;
}

/// The trust anchors are the configured bundle and nothing else.
///
/// The impostor certificate here is signed by a perfectly well-formed CA that
/// simply is not the configured one -- which is the shape a platform trust
/// store would accept and this configuration must not.
#[tokio::test]
async fn a_certificate_from_an_unconfigured_ca_never_authenticates() {
    let material = MaterialDir::new();
    let ca = client_ca();
    // Two impostors. The first is an ordinary unrelated CA. The second names
    // itself exactly as the configured one, which is what an attacker who has
    // read the deployment's configuration would mint: path building finds the
    // configured anchor by subject name and then the signature check fails.
    let unrelated_ca = client_ca_named("Some Other Test CA");
    let same_name_ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    assert_refused_with_alert(
        whoami(
            listener.addr,
            client_config_with_identity(
                &server.ca_der,
                Some(issue_client_identity(
                    &unrelated_ca,
                    ClientIdentitySpec::default(),
                )),
            ),
        )
        .await,
        "UnknownCA",
        "a certificate from an unconfigured CA",
    );
    assert_refused_with_alert(
        whoami(
            listener.addr,
            client_config_with_identity(
                &server.ca_der,
                Some(issue_client_identity(
                    &same_name_ca,
                    ClientIdentitySpec::default(),
                )),
            ),
        )
        .await,
        "DecryptError",
        "a certificate from a CA that names itself as the configured one",
    );

    // The listener is refusing that certificate, not refusing everything: one
    // from the configured CA is still served.
    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("a certificate from the configured CA must still authenticate");
    assert!(
        response.contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "the configured CA must still authenticate its own certificates: {response}"
    );
    listener.stop().await;
}

/// Validity windows are enforced by the verifier -- confirmed, not assumed.
#[tokio::test]
async fn an_expired_client_certificate_never_authenticates() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let expired = issue_client_identity(
        &ca,
        ClientIdentitySpec {
            not_after: OffsetDateTime::now_utc() - TimeDuration::hours(1),
            ..ClientIdentitySpec::default()
        },
    );

    assert_refused_with_alert(
        whoami(
            listener.addr,
            client_config_with_identity(&server.ca_der, Some(expired)),
        )
        .await,
        "CertificateExpired",
        "a certificate whose validity window has passed",
    );

    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("an in-date certificate from the same CA must still authenticate");
    assert!(
        response.contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "only the expiry may be deciding this: {response}"
    );
    listener.stop().await;
}

/// A certificate valid for a different purpose is a different credential.
///
/// This one is a server certificate: correctly issued, correctly signed by the
/// configured CA, in date -- and marked for server authentication only.
#[tokio::test]
async fn a_certificate_issued_for_server_authentication_never_authenticates_a_client() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let wrong_purpose = issue_client_identity(
        &ca,
        ClientIdentitySpec {
            extended_key_usages: vec![ExtendedKeyUsagePurpose::ServerAuth],
            ..ClientIdentitySpec::default()
        },
    );

    assert_refused_with_alert(
        whoami(
            listener.addr,
            client_config_with_identity(&server.ca_der, Some(wrong_purpose)),
        )
        .await,
        "UnsupportedCertificate",
        "a certificate marked for server authentication only",
    );

    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("a client-authentication certificate from the same CA must still authenticate");
    assert!(
        response.contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "only the extended key usage may be deciding this: {response}"
    );
    listener.stop().await;
}

/// Revocation, both halves.
///
/// The same certificate is offered to two listeners that differ only in whether
/// a CRL is configured. Without one it authenticates; with one it is refused.
/// The second half is what makes the first half meaningful: it shows the
/// refusal is the CRL doing its job rather than the certificate being broken.
#[tokio::test]
async fn a_revoked_certificate_is_refused_only_when_a_crl_is_configured() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let revoked = issue_client_identity(&ca, ClientIdentitySpec::default());
    material.write(
        "client.crl",
        &client_crl(
            &ca,
            &[&revoked.serial],
            -TimeDuration::hours(1),
            TimeDuration::days(1),
        ),
    );

    let without_crl = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&without_crl).await;
    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("with no CRL configured, nothing checks revocation");
    assert!(
        response.starts_with("HTTP/1.1 200 OK") && response.contains(CLIENT_SPIFFE_ID),
        "a revoked certificate authenticates when no CRL is configured -- which is exactly why \
         the absence of one is documented rather than implied: {response}"
    );
    listener.stop().await;

    let with_crl = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        Some("client.crl"),
    ))
    .expect("client-auth material with a CRL should load");
    let listener = serve_authenticating(&with_crl).await;
    assert_refused_with_alert(
        whoami(
            listener.addr,
            client_config_with_identity(&server.ca_der, Some(revoked)),
        )
        .await,
        "CertificateRevoked",
        "a certificate named by the configured CRL",
    );
    listener.stop().await;
}

/// A stale CRL is not a valid one.
///
/// The certificate here is *not* revoked; the CRL has simply expired. Treating
/// an expired CRL as still authoritative would mean a deployment whose CRL
/// publishing broke keeps accepting certificates revoked after the last CRL it
/// managed to fetch, with nothing to indicate it. Fail closed instead, and make
/// the failure loud.
#[tokio::test]
async fn an_expired_crl_refuses_certificates_it_does_not_even_list() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    // Well formed, correctly signed, listing nothing -- and out of date.
    material.write(
        "client.crl",
        &client_crl(&ca, &[], -TimeDuration::days(2), -TimeDuration::hours(1)),
    );

    let without_crl = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&without_crl).await;
    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("the certificate itself is perfectly valid");
    assert!(
        response.contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "the control: this certificate authenticates when no CRL is configured: {response}"
    );
    listener.stop().await;

    let with_expired_crl = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        Some("client.crl"),
    ))
    .expect("client-auth material with a CRL should load");
    let listener = serve_authenticating(&with_expired_crl).await;
    assert_refused_with_alert(
        whoami(
            listener.addr,
            client_config_with_identity(
                &server.ca_der,
                Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
            ),
        )
        .await,
        "UnknownCA",
        "a certificate whose revocation status cannot be determined from a stale CRL",
    );
    listener.stop().await;
}

/// A verified certificate with nothing to read is a caller with no identity,
/// not a caller with a blank one.
#[tokio::test]
async fn a_verified_certificate_with_no_identity_field_authenticates_as_nobody() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let no_identity = issue_client_identity(
        &ca,
        ClientIdentitySpec {
            sans: vec![SanType::DnsName(
                Ia5String::try_from("api.gateway.test").expect("test DNS SAN should be IA5"),
            )],
            ..ClientIdentitySpec::default()
        },
    );

    let response = whoami(
        listener.addr,
        client_config_with_identity(&server.ca_der, Some(no_identity)),
    )
    .await
    .expect("the certificate verifies, so the handshake completes");

    assert_unauthorized(&response, "a certificate with no SPIFFE ID");
    listener.stop().await;
}

/// The exactly-one rule, over a real handshake.
///
/// Both SPIFFE IDs here are issued by the configured CA, so this is not a
/// verification failure: it is the gateway refusing to choose which of two
/// identities a caller is.
#[tokio::test]
async fn a_verified_certificate_with_two_identities_authenticates_as_nobody() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let ambiguous = issue_client_identity(
        &ca,
        ClientIdentitySpec {
            sans: vec![uri_san(CLIENT_SPIFFE_ID), uri_san(OTHER_SPIFFE_ID)],
            ..ClientIdentitySpec::default()
        },
    );

    let response = whoami(
        listener.addr,
        client_config_with_identity(&server.ca_der, Some(ambiguous)),
    )
    .await
    .expect("the certificate verifies, so the handshake completes");

    assert_unauthorized(&response, "a certificate carrying two SPIFFE IDs");
    assert!(
        !response.contains("sa/batch"),
        "neither identity may be chosen: {response}"
    );
    listener.stop().await;
}

/// A listener that was never configured for client certificates cannot produce
/// a certificate identity, no matter what the caller claims in headers.
#[tokio::test]
async fn assertion_headers_cannot_authenticate_on_a_listener_without_client_auth() {
    let material = MaterialDir::new();
    let server = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let listener = serve_authenticating(&bindings).await;

    let response = whoami(
        listener.addr,
        client_config_with_identity(&server.ca_der, None),
    )
    .await
    .expect("a listener with no client auth still serves TLS");

    assert_unauthorized(&response, "four mTLS assertion headers and no certificate");
    assert_eq!(
        bindings.data_identity_source(),
        None,
        "a listener with no client auth configured must have no identity source to read with"
    );
    listener.stop().await;
}

/// The two ways the verifier can refuse to build name two different files.
///
/// Both fixtures are well-formed PEM -- the base64 decodes -- so neither is
/// caught by the reader, and both reach `build()`. An operator sent to the
/// wrong file by a misattributed error is an operator who cannot fix their
/// deployment.
#[test]
fn a_failed_verifier_build_names_the_file_that_caused_it() {
    let material = MaterialDir::new();
    let ca = client_ca();
    write_client_auth_material(&material, &ca);
    material.write(
        "not-a-crl.crl",
        "-----BEGIN X509 CRL-----\nZm9vYmFy\n-----END X509 CRL-----\n",
    );

    assert_eq!(
        InboundTlsBindings::load(&client_auth_config(
            &material,
            ClientCertRequirement::Optional,
            Some("not-a-crl.crl"),
        ))
        .expect_err("a PEM block that is not a CRL must not start the gateway"),
        InboundTlsError::RevocationListUnusable {
            setting: "CLIENT_CERT_CRL_FILE"
        }
    );

    // A well-formed PEM CERTIFICATE block whose contents are not a certificate.
    // `pem_slice_iter` decodes the base64 and stops there, so this is the shape
    // that reaches the trust store and fails there.
    //
    // A leaf certificate, by contrast, IS accepted as a trust anchor and is not
    // tested here: pinning one certificate as its own anchor is narrow but
    // coherent, and refusing it would be inventing a rule.
    material.write(
        "client-ca.crt",
        &pem_encode("CERTIFICATE", b"this is not a certificate"),
    );

    assert_eq!(
        InboundTlsBindings::load(&client_auth_config(
            &material,
            ClientCertRequirement::Optional,
            None,
        ))
        .expect_err("a bundle with no usable trust anchor must not start the gateway"),
        InboundTlsError::ClientTrustAnchorsUnusable {
            setting: "CLIENT_CERT_CA_FILE"
        }
    );
}

/// A CA bundle with a private key concatenated onto it is refused for the same
/// reason the server certificate file is: the key inherits the permissions of a
/// file mounted for public material.
#[test]
fn a_ca_bundle_containing_a_private_key_is_refused() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    material.write(
        "client-ca.crt",
        &format!("{}{}", ca.pem, server.private_key_pem),
    );

    assert_eq!(
        InboundTlsBindings::load(&client_auth_config(
            &material,
            ClientCertRequirement::Optional,
            None,
        ))
        .expect_err("a CA bundle carrying a private key must not start the gateway"),
        InboundTlsError::CertificateContainsPrivateKey {
            setting: "CLIENT_CERT_CA_FILE"
        }
    );
}

// --- failure classification ------------------------------------------------
//
// `classify_client_certificate_failure` is the only evidence an operator has
// that revocation is being consulted, and `docs/configuration.md` names two of
// its labels as things to alert on. Those are promises about exact strings, and
// the function reached this branch with none of its arms covered.

/// Every label the classifier can return, over the error shapes rustls actually
/// produces.
///
/// The `*Context` variants are exercised separately from their bare forms
/// because they are the ones `rustls::webpki::pki_error` really emits: a genuine
/// expiry arrives as `ExpiredContext`, never as `Expired`, and a stale CRL
/// arrives as `ExpiredRevocationListContext`. A classifier that matched only
/// the bare forms would answer `rejected_other` for every real expiry and every
/// real stale CRL -- silently, on the two counters the documentation tells
/// operators to watch. That is what this table exists to catch.
#[test]
fn every_client_certificate_failure_is_classified_as_its_documented_label() {
    use tokio_rustls::rustls::{pki_types::UnixTime, Error as TlsError};

    let epoch = UnixTime::since_unix_epoch(Duration::from_secs(0));
    let later = UnixTime::since_unix_epoch(Duration::from_secs(1));

    let cases: Vec<(TlsError, &'static str)> = vec![
        (TlsError::NoCertificatesPresented, "rejected_absent"),
        (
            TlsError::InvalidCertificate(CertificateError::Revoked),
            "rejected_revoked",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::Expired),
            "rejected_expired",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::ExpiredContext {
                time: later,
                not_after: epoch,
            }),
            "rejected_expired",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::NotValidYet),
            "rejected_not_yet_valid",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::NotValidYetContext {
                time: epoch,
                not_before: later,
            }),
            "rejected_not_yet_valid",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::UnknownIssuer),
            "rejected_untrusted",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::UnknownRevocationStatus),
            "rejected_unknown_revocation_status",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::ExpiredRevocationList),
            "rejected_expired_revocation_list",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::ExpiredRevocationListContext {
                time: later,
                next_update: epoch,
            }),
            "rejected_expired_revocation_list",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::InvalidPurpose),
            "rejected_wrong_purpose",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::BadEncoding),
            "rejected_bad_encoding",
        ),
        (
            TlsError::InvalidCertificate(CertificateError::BadSignature),
            "rejected_bad_signature",
        ),
        // A certificate error this classifier deliberately does not name. It
        // must land on the catch-all rather than on any of the labels above.
        (
            TlsError::InvalidCertificate(CertificateError::UnhandledCriticalExtension),
            "rejected_other",
        ),
        // A rustls error that is not about a certificate at all.
        (TlsError::DecryptError, "rejected_other"),
    ];

    for (error, expected) in cases {
        // Wrapped the way `tokio_rustls` wraps a handshake failure, so this
        // tests the downcast as well as the match.
        let wrapped = io::Error::new(io::ErrorKind::InvalidData, error);
        assert_eq!(
            classify_client_certificate_failure(&wrapped),
            expected,
            "wrong label for {wrapped:?}"
        );
    }

    // An I/O error carrying no rustls error at all -- a peer that went away
    // mid-handshake. It must not be reported as a certificate verdict.
    assert_eq!(
        classify_client_certificate_failure(&io::Error::from(io::ErrorKind::ConnectionReset)),
        "rejected_other",
        "an I/O failure with no TLS error inside must fall to the catch-all"
    );
}

/// The classifier is actually wired to the counter it is documented on.
///
/// The table above is a test of a pure function; it cannot show that a real
/// refused handshake reaches the metric. This drives a genuinely revoked
/// certificate through a genuinely configured CRL and reads the counter
/// `docs/configuration.md` tells operators is their evidence that revocation is
/// being consulted.
#[test]
fn a_revoked_certificate_is_counted_under_its_documented_outcome_label() {
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");

    // Same reasoning as `a_shed_connection_is_counted_on_the_handshake_outcome_metric`:
    // `metrics` resolves a thread-local recorder first, and a current-thread
    // runtime polls the accept loop's tasks on this thread.
    ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let material = MaterialDir::new();
            let ca = client_ca();
            let server = write_client_auth_material(&material, &ca);
            let revoked = issue_client_identity(&ca, ClientIdentitySpec::default());
            material.write(
                "client-crl.pem",
                &client_crl(
                    &ca,
                    &[&revoked.serial],
                    -TimeDuration::hours(1),
                    TimeDuration::days(1),
                ),
            );
            let bindings = InboundTlsBindings::load(&client_auth_config(
                &material,
                ClientCertRequirement::Optional,
                Some("client-crl.pem"),
            ))
            .expect("client-auth material should load");
            let listener = serve_authenticating(&bindings).await;

            let before = client_certificate_count(&recorder, "data", "rejected_revoked");
            assert_refused_with_alert(
                whoami(
                    listener.addr,
                    client_config_with_identity(&server.ca_der, Some(revoked)),
                )
                .await,
                "CertificateRevoked",
                "a revoked certificate against a configured CRL",
            );

            assert_eq!(
                client_certificate_count(&recorder, "data", "rejected_revoked") - before,
                1,
                "a refused revoked certificate must land on inbound_client_certificates_total{{outcome=\"rejected_revoked\"}}, which is what docs/configuration.md tells operators to read"
            );
            listener.stop().await;
        });
    });
}

fn client_certificate_count(
    recorder: &crate::audit::sink::tests::CountingRecorder,
    listener: &str,
    outcome: &str,
) -> u64 {
    recorder.count(
        crate::metrics::INBOUND_CLIENT_CERTIFICATES_TOTAL,
        &[("listener", listener), ("outcome", outcome)],
    )
}

// --- session resumption ----------------------------------------------------
//
// Resumption is the one path on which rustls hands back a client certificate it
// did not verify on *this* connection. `rustls::server::tls13` restores
// `peer_certificates` from the stored session, `rustls::server::tls12` does the
// same for the abbreviated handshake, and `can_resume` compares the cipher
// suite, the extended-master-secret state and the SNI -- nothing about the
// certificate. There is no hook that re-runs the client verifier, because in
// both protocol versions a resumed handshake carries no Certificate and no
// CertificateVerify at all: the peer proves it holds the resumption secret, not
// the certificate's private key.
//
// So a listener that asks for client certificates does not resume. These tests
// pin that from three directions: the config carries no resumption state, no
// second connection is ever resumed, and an expired certificate cannot come
// back to life on one.

/// The listener asks for certificates, so it keeps nothing to resume from.
///
/// Asserted on the built `ServerConfig` rather than only over the wire, because
/// the wire test can only prove that *this* client did not resume. This proves
/// the server has nothing to offer any client.
#[test]
fn a_client_certificate_listener_keeps_no_resumption_state() {
    let material = MaterialDir::new();
    let ca = client_ca();
    write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");

    let listener = bindings
        .data
        .as_ref()
        .expect("the data listener terminates TLS in this configuration");
    assert!(
        !listener.server_config.session_storage.can_cache(),
        "a listener that asks for client certificates must hold no session cache"
    );
    assert_eq!(
        listener.server_config.send_tls13_tickets, 0,
        "a listener that asks for client certificates must issue no TLS 1.3 tickets"
    );
    // Not something `disable_session_resumption` sets -- it is rustls' default,
    // and setting it would be a line no test could falsify. Asserted because a
    // real ticketer would make tickets self-contained, stop them resolving
    // through the emptied store, and bring TLS 1.2 stateless resumption back on
    // its own. This is the assertion that notices if one is ever installed.
    assert!(
        !listener.server_config.ticketer.enabled(),
        "a listener that asks for client certificates must have no ticketer that could resume a session without the store"
    );
}

/// The same listener with `CLIENT_CERT_MODE=off` is untouched.
///
/// Without this the previous test would be satisfied by disabling resumption
/// everywhere, which is a behaviour change for every deployment that has never
/// heard of client certificates.
#[test]
fn a_listener_without_client_certificates_keeps_its_resumption_state() {
    let material = MaterialDir::new();
    write_default_identity(&material);
    let bindings =
        InboundTlsBindings::load(&tls_config(&material)).expect("TLS material should load");

    let listener = bindings
        .data
        .as_ref()
        .expect("the data listener terminates TLS in this configuration");
    assert!(
        listener.server_config.session_storage.can_cache(),
        "a listener with no client-certificate authentication must keep rustls' session cache"
    );
    assert_eq!(
        listener.server_config.send_tls13_tickets, 2,
        "a listener with no client-certificate authentication must keep rustls' ticket count"
    );
}

/// 0-RTT is off on every inbound listener, with or without client certificates.
///
/// Early data is the same class of defect one layer down: a replayed early-data
/// request rides a resumed connection, so it inherits whatever the resumed
/// connection was trusted for. rustls defaults `max_early_data_size` to zero and
/// nothing here raises it; this is the assertion that notices if that changes.
#[test]
fn no_inbound_listener_offers_0_rtt_early_data() {
    let material = MaterialDir::new();
    let ca = client_ca();
    write_client_auth_material(&material, &ca);

    for (label, config) in [
        ("without client certificates", tls_config(&material)),
        (
            "with client certificates",
            client_auth_config(&material, ClientCertRequirement::Required, None),
        ),
    ] {
        let bindings = InboundTlsBindings::load(&config).expect("TLS material should load");
        let listener = bindings
            .data
            .as_ref()
            .expect("the data listener terminates TLS in this configuration");
        assert_eq!(
            listener.server_config.max_early_data_size, 0,
            "a listener {label} must not accept 0-RTT early data"
        );
    }
}

/// No second connection to a client-certificate listener is ever resumed.
///
/// Run over both protocol versions, because TLS 1.2 and TLS 1.3 restore the
/// chain through entirely separate code -- an abbreviated handshake keyed on a
/// session id, and a PSK keyed on a session ticket -- and `TLS_MIN_VERSION`
/// defaults to 1.2, so both are live.
#[tokio::test]
async fn a_client_certificate_listener_never_resumes_a_session() {
    assert_never_resumes(&[&version::TLS13], "TLS 1.3").await;
    assert_never_resumes(&[&version::TLS12], "TLS 1.2").await;
}

async fn assert_never_resumes(
    protocol_versions: &[&'static SupportedProtocolVersion],
    label: &str,
) {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Required,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let config = Arc::new(client_config_with_identity_at(
        &server.ca_der,
        Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        protocol_versions,
    ));

    let first = whoami_request(listener.addr, Arc::clone(&config), "")
        .await
        .unwrap_or_else(|error| panic!("{label}: the first handshake must succeed: {error}"));
    assert!(
        first
            .body
            .contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "{label}: the first connection must authenticate: {}",
        first.body
    );

    // The same client configuration, so the client is offering back whatever
    // the server gave it to resume with.
    let second = whoami_request(listener.addr, Arc::clone(&config), "")
        .await
        .unwrap_or_else(|error| panic!("{label}: the second handshake must succeed: {error}"));
    assert_eq!(
        second.handshake_kind,
        Some(HandshakeKind::Full),
        "{label}: a listener that asks for client certificates must make every connection prove possession of the key again"
    );
    assert!(
        second
            .body
            .contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "{label}: the listener must still serve the second connection, not merely refuse it: {}",
        second.body
    );
    listener.stop().await;
}

/// The control: the same client harness resumes happily against a listener that
/// does not ask for certificates.
///
/// Without this, `a_client_certificate_listener_never_resumes_a_session` could
/// pass because the test client never attempts resumption at all -- which is
/// exactly the blind spot that let the defect through. This also pins the
/// targeting: `CLIENT_CERT_MODE=off` behaves as it did before this change.
#[tokio::test]
async fn a_listener_without_client_certificates_still_resumes() {
    let material = MaterialDir::new();
    let server = write_default_identity(&material);
    let bindings =
        InboundTlsBindings::load(&tls_config(&material)).expect("TLS material should load");
    let listener = serve(&bindings).await;

    let config = Arc::new(default_client_config(&server.ca_der));
    let request =
        format!("GET /scheme HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: close\r\n\r\n");

    let first = tls_exchange(listener.addr, Arc::clone(&config), &request)
        .await
        .expect("the first handshake must succeed");
    assert_eq!(
        first.handshake_kind,
        Some(HandshakeKind::Full),
        "the first connection cannot be a resumption"
    );

    let second = tls_exchange(listener.addr, Arc::clone(&config), &request)
        .await
        .expect("the second handshake must succeed");
    assert_eq!(
        second.handshake_kind,
        Some(HandshakeKind::Resumed),
        "a listener that does not ask for client certificates must still resume, or this suite cannot tell a disabled resumption from a client that never tried"
    );
    listener.stop().await;
}

/// The property the whole section exists for.
///
/// A certificate is used inside its validity window, and then used again after
/// it has expired, on a connection built from the same client configuration --
/// which is the state a long-lived caller is in when its certificate lapses
/// mid-day. Expiry must apply to the second connection.
///
/// Timing: the certificate is issued as late as possible, immediately before
/// the first handshake, so the only work inside its validity window is one
/// localhost handshake. The wait is then computed from the certificate's own
/// `not_after` rather than being a fixed sleep, so a slow machine waits longer
/// rather than testing the wrong thing.
#[tokio::test]
async fn a_resumed_connection_cannot_revive_an_expired_client_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Required,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_authenticating(&bindings).await;

    let not_after = OffsetDateTime::now_utc() + TimeDuration::seconds(6);
    let config = Arc::new(client_config_with_identity(
        &server.ca_der,
        Some(issue_client_identity(
            &ca,
            ClientIdentitySpec {
                not_after,
                ..ClientIdentitySpec::default()
            },
        )),
    ));

    let first = whoami_request(listener.addr, Arc::clone(&config), "")
        .await
        .expect("a certificate inside its validity window must complete the handshake");
    assert!(
        first
            .body
            .contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "the premise of this test is that the certificate works while it is valid: {}",
        first.body
    );

    // Wait until the certificate is unambiguously outside its window.
    let remaining = (not_after - OffsetDateTime::now_utc()) + TimeDuration::seconds(2);
    if remaining.is_positive() {
        tokio::time::sleep(Duration::from_millis(
            u64::try_from(remaining.whole_milliseconds()).expect("a short wait fits in u64"),
        ))
        .await;
    }

    // The same client configuration, so the client offers back the ticket or
    // session id the first connection earned. Nothing about that ticket may
    // outlive the certificate that was verified to create it.
    match whoami_request(listener.addr, Arc::clone(&config), "").await {
        Ok(second) => {
            assert_ne!(
                second.handshake_kind,
                Some(HandshakeKind::Resumed),
                "an expired certificate must not be restored from a resumed session: {}",
                second.body
            );
            assert_unauthorized(&second.body, "an expired certificate on a later connection");
        }
        // The expected outcome once resumption is off: a full handshake, which
        // re-runs the verifier, which refuses the expired certificate.
        Err(refusal) => assert!(
            refusal.contains("CertificateExpired"),
            "the second connection must be refused for expiry specifically, not for some other reason: {refusal}"
        ),
    }
    listener.stop().await;
}

// --- credential precedence -------------------------------------------------
//
// `crate::middleware::auth::request_credential` documents that a credential the
// caller SENT wins over the certificate their connection was established with.
// That rule shipped with no test: inverting the function to certificate-first
// left the entire suite green, while turning any `optional` or `required`
// listener into one where a valid certificate silently launders an expired,
// revoked or unknown bearer token.
//
// These tests need a chain that actually judges bearer and cookie credentials.
// With only `ClientCertificateValidator` in the chain the middleware
// short-circuits a bearer credential as `bearer_auth_unsupported` before any
// validator sees it, and a test built on that would be asserting about a
// routing hint rather than about which credential won.

const GOOD_BEARER_TOKEN: &str = "test-bearer-token-the-chain-accepts";
const GOOD_SESSION_COOKIE: &str = "test-session-cookie-the-chain-accepts";
const TOKEN_SUBJECT: &str = "token-subject";

/// A validator that judges bearer and cookie credentials and knows exactly one
/// of each.
///
/// Knowing a good credential as well as rejecting bad ones is what lets these
/// tests distinguish three outcomes rather than two: authenticated as the
/// token's subject, authenticated as the certificate's subject, or refused. A
/// chain that could only refuse would collapse the first two.
struct StaticTokenValidator;

#[async_trait::async_trait]
impl SessionValidator for StaticTokenValidator {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        let accepted = match credential {
            SessionCredential::Bearer(token) => token == GOOD_BEARER_TOKEN,
            SessionCredential::Cookie(cookie) => cookie == GOOD_SESSION_COOKIE,
            SessionCredential::ClientCertificate(_) => false,
        };
        if !accepted {
            return Err(AuthError::InvalidSession(
                "the static test validator does not know this credential".to_owned(),
            ));
        }

        Ok(Principal {
            user_id: TOKEN_SUBJECT.to_owned(),
            issuer: None,
            email: None,
            org_id: None,
            roles: Vec::new(),
            session_id: "static-test-session".to_owned(),
            auth_method: AuthMethod::Bearer,
        })
    }
}

/// A validator that would happily authenticate anything, including a
/// certificate credential, while never having opted into being asked about one.
///
/// This is the shape `SessionValidator::supports_client_certificate` exists to
/// protect against and its doc comment describes: a validator that predates
/// certificates, has not been told about them, and whose `validate_session`
/// does not discriminate. Nothing else in the suite can exercise the
/// middleware's `client_certificate_auth_unsupported` branch, because every
/// real validator that declines the channel also rejects the credential -- so
/// deleting the branch would change no outcome and no test would notice.
struct PermissiveLegacyValidator;

#[async_trait::async_trait]
impl SessionValidator for PermissiveLegacyValidator {
    async fn validate_session(
        &self,
        _credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        Ok(Principal {
            user_id: "legacy-validator-subject".to_owned(),
            issuer: None,
            email: None,
            org_id: None,
            roles: Vec::new(),
            session_id: "legacy-test-session".to_owned(),
            auth_method: AuthMethod::Bearer,
        })
    }

    // `supports_client_certificate` is deliberately left at its default of
    // `false`. That is the whole fixture.
}

/// A certificate credential is never handed to a validator that did not opt in.
///
/// The routing hint defaults to `false` so that a validator written before
/// certificates existed is not silently asked to judge one. Without the
/// middleware's guard this request is served as `legacy-validator-subject`: a
/// validator that never agreed to judge certificates deciding who a certificate
/// caller is.
#[tokio::test]
async fn a_certificate_credential_is_refused_by_a_validator_that_never_opted_in() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_router(
        &bindings,
        authenticating_router_over(vec![
            Arc::new(PermissiveLegacyValidator) as Arc<dyn SessionValidator>
        ]),
    )
    .await;

    let response = whoami(
        listener.addr,
        client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        ),
    )
    .await
    .expect("the handshake must succeed; the refusal belongs to the router");

    assert_unauthorized(
        &response,
        "a certificate offered to a chain that never opted into certificates",
    );
    assert!(
        !response.contains("legacy-validator-subject"),
        "a validator that did not opt into the certificate channel must never be asked to judge one: {response}"
    );
    listener.stop().await;
}

/// A listener whose chain accepts tokens, cookies and certificates -- the shape
/// an `optional` deployment migrating onto certificates actually runs.
async fn serve_mixed_credentials(bindings: &InboundTlsBindings) -> RunningListener {
    serve_router(
        bindings,
        authenticating_router_over(vec![
            Arc::new(StaticTokenValidator) as Arc<dyn SessionValidator>,
            Arc::new(ClientCertificateValidator) as Arc<dyn SessionValidator>,
        ]),
    )
    .await
}

/// The control, on the same listener and the same chain as the tests below: a
/// caller who sends no credential is judged on the certificate.
///
/// Without this the three tests that follow would be satisfied by a listener
/// that had simply stopped accepting certificates.
#[tokio::test]
async fn a_connection_certificate_authenticates_when_no_credential_was_sent() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        "",
    )
    .await
    .expect("a well-formed client certificate must complete the handshake");

    assert!(
        response
            .body
            .contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "with nothing else sent, the certificate is the credential: {}",
        response.body
    );
    listener.stop().await;
}

/// A bearer token the chain rejects is a 401, even over a certificate the chain
/// would have accepted.
///
/// This is the rule `request_credential` documents. Under the inverted order the
/// token is never evaluated and the caller is served as the certificate's
/// subject -- an expired or revoked token silently succeeding as somebody else.
#[tokio::test]
async fn a_rejected_bearer_token_is_not_rescued_by_the_connection_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        "Authorization: Bearer not-a-token-this-chain-knows\r\n",
    )
    .await
    .expect("the handshake must still succeed; the refusal belongs to the router");

    assert_unauthorized(
        &response.body,
        "a rejected bearer token sent over a valid client certificate",
    );
    assert!(
        !response
            .body
            .contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "the certificate must not authenticate a caller who sent a credential that failed: {}",
        response.body
    );
    listener.stop().await;
}

/// The same rule in the direction that produces a principal: a token the chain
/// accepts wins, and the caller is the *token's* subject rather than the
/// certificate's.
///
/// This is the assertion that names the wrong value. Under the inverted order
/// this request is served as `principal=spiffe://gateway.test/ns/payments/sa/api`
/// instead of `principal=token-subject`, which is a silent identity swap rather
/// than a visible failure.
#[tokio::test]
async fn an_accepted_bearer_token_outranks_the_connection_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        &format!("Authorization: Bearer {GOOD_BEARER_TOKEN}\r\n"),
    )
    .await
    .expect("an accepted token over a valid certificate must be served");

    assert!(
        response
            .body
            .contains(&format!("principal={TOKEN_SUBJECT}")),
        "the caller asked to be judged as the token's subject: {}",
        response.body
    );
    assert!(
        !response.body.contains(CLIENT_SPIFFE_ID),
        "the connection's certificate must not decide the identity of a caller who sent a token: {}",
        response.body
    );
    listener.stop().await;
}

/// The cookie half of the same rule.
///
/// `request_credential` prefers a bearer token, then a session cookie, then the
/// certificate. A rejected cookie must therefore be a 401 too, not a fallthrough
/// to the connection's certificate.
#[tokio::test]
async fn a_rejected_session_cookie_is_not_rescued_by_the_connection_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        "Cookie: session=not-a-cookie-this-chain-knows\r\n",
    )
    .await
    .expect("the handshake must still succeed; the refusal belongs to the router");

    assert_unauthorized(
        &response.body,
        "a rejected session cookie sent over a valid client certificate",
    );
    listener.stop().await;
}

/// And the cookie in the accepting direction, so the cookie test above is not
/// passing because cookies never authenticate on this listener at all.
#[tokio::test]
async fn an_accepted_session_cookie_outranks_the_connection_certificate() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let listener = serve_mixed_credentials(&bindings).await;

    let response = whoami_request(
        listener.addr,
        Arc::new(client_config_with_identity(
            &server.ca_der,
            Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
        )),
        &format!("Cookie: session={GOOD_SESSION_COOKIE}\r\n"),
    )
    .await
    .expect("an accepted cookie over a valid certificate must be served");

    assert!(
        response
            .body
            .contains(&format!("principal={TOKEN_SUBJECT}")),
        "the caller asked to be judged as the cookie's subject: {}",
        response.body
    );
    assert!(
        !response.body.contains(CLIENT_SPIFFE_ID),
        "the connection's certificate must not decide the identity of a caller who sent a cookie: {}",
        response.body
    );
    listener.stop().await;
}

// --- SNI: more than one certificate per listener ----------------------------
//
// The selection rule under test, stated once here: the DNS SANs of each
// configured chain are the names it answers to, an exact name beats a wildcard,
// a wildcard matches exactly one label, and everything else -- no server name,
// an unclaimed name, a name nothing wildcard-matches -- gets the *first*
// configured chain.
//
// Every wire test below observes selection through the leaf the server
// actually served, read from a client that verifies normally. That shape is
// deliberate: a wrong selection does not go unnoticed, because a chain that
// does not claim the probed name fails the client's own verification loudly
// rather than silently succeeding. The default chains in the negative tests
// therefore deliberately claim the probe names, so the *correct* behaviour is
// the verifiable one and every regression is a loud failure either way.

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
        .signed_by(&key, &ca_certificate, &ca_key)
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

/// The named chain is the one that serves, and only that chain.
#[tokio::test]
async fn sni_selects_the_named_chain() {
    let material = MaterialDir::new();
    let alpha = server_identity_named(&["a.example.test"], &[]);
    let beta = server_identity_named(&["b.example.test"], &[]);
    let config = write_chains(&material, &[alpha.clone(), beta.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("two named chains should load");
    let listener = serve(&bindings).await;

    for (name, expected) in [("a.example.test", &alpha), ("b.example.test", &beta)] {
        let served = served_leaf(listener.addr, &[&alpha, &beta], dns_name(name))
            .await
            .unwrap_or_else(|error| {
                panic!("SNI {name} must complete a verifiable handshake: {error}")
            });
        assert_eq!(
            served,
            leaf_der(expected),
            "SNI {name} must be served by the chain that claims it"
        );
    }
    listener.stop().await;
}

/// `*.wild.example.test` serves `x.wild.example.test`, and neither
/// `y.x.wild.example.test` (two labels) nor `wild.example.test` (no label) --
/// both of which the default chain claims, so correct behaviour verifies and
/// every wrong one fails the client's name check loudly.
///
/// A note on what the negative probes can and cannot pin: the caller's own
/// certificate verification enforces one-label wildcard semantics too, so a
/// hypothetically over-broad *server-side* wildcard match could only ever end
/// in the same `NotValidForName` refusal the correct behaviour produces for an
/// unclaimed name -- there is no client-observable difference to assert. What
/// *is* observable and pinned here is the positive selection (the one
/// label-deeper name is served by the wildcard chain and verifies) and that
/// the exact-claimed probes land on the default chain rather than the
/// wildcard; `an_exact_name_beats_a_wildcard` pins the ordering that makes
/// that true. The suffix map's construction -- a wildcard is keyed on the
/// literal remainder after `*.`, and two distinct wildcards cannot share one
/// remainder -- is what makes over-broad matching unreachable rather than
/// merely untested.
#[tokio::test]
async fn a_wildcard_serves_exactly_one_label() {
    let material = MaterialDir::new();
    let default = server_identity_named(
        &[
            "fallback.example.test",
            "wild.example.test",
            "y.x.wild.example.test",
        ],
        &[],
    );
    let wildcard = server_identity_named(&["*.wild.example.test"], &[]);
    let config = write_chains(&material, &[default.clone(), wildcard.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("a wildcard chain should load");
    let listener = serve(&bindings).await;

    let served = served_leaf(
        listener.addr,
        &[&default, &wildcard],
        dns_name("x.wild.example.test"),
    )
    .await
    .expect("the wildcard must serve a one-label-deeper name");
    assert_eq!(
        served,
        leaf_der(&wildcard),
        "a wildcard must serve the name one label below it"
    );

    for name in ["wild.example.test", "y.x.wild.example.test"] {
        let served = served_leaf(listener.addr, &[&default, &wildcard], dns_name(name))
            .await
            .unwrap_or_else(|error| {
                panic!("{name} must reach the default chain it claims: {error}")
            });
        assert_eq!(
            served,
            leaf_der(&default),
            "{name} is more or less than the one label a wildcard matches, so the first chain must serve it"
        );
    }
    listener.stop().await;
}

/// An exact claim beats a wildcard that would also cover the name. Both chains
/// would verify for the name, so the served leaf is the only honest signal.
#[tokio::test]
async fn an_exact_name_beats_a_wildcard() {
    let material = MaterialDir::new();
    let default = server_identity_named(&["fallback.example.test"], &[]);
    let wildcard = server_identity_named(&["*.sub.example.test"], &[]);
    let exact = server_identity_named(&["exact.sub.example.test"], &[]);
    let config = write_chains(
        &material,
        &[default.clone(), wildcard.clone(), exact.clone()],
    );
    let bindings =
        InboundTlsBindings::load(&config).expect("exact and wildcard chains should load");
    let listener = serve(&bindings).await;

    let served = served_leaf(
        listener.addr,
        &[&default, &wildcard, &exact],
        dns_name("exact.sub.example.test"),
    )
    .await
    .expect("the exact chain must serve a name it claims outright");
    assert_eq!(
        served,
        leaf_der(&exact),
        "an exact claim must win over a wildcard that also covers the name"
    );
    listener.stop().await;
}

/// A name nothing claims lands on the first chain, which claims it here so the
/// correct behaviour is the verifiable one.
#[tokio::test]
async fn a_caller_that_names_no_recognised_server_gets_the_first_chain() {
    let material = MaterialDir::new();
    let default = server_identity_named(&["fallback.example.test", "nobody.example.test"], &[]);
    let beta = server_identity_named(&["b.example.test"], &[]);
    let config = write_chains(&material, &[default.clone(), beta.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("an unclaimed name is not an error");
    let listener = serve(&bindings).await;

    let served = served_leaf(
        listener.addr,
        &[&default, &beta],
        dns_name("nobody.example.test"),
    )
    .await
    .expect("the first chain claims the probe name, so it must verify");
    assert_eq!(
        served,
        leaf_der(&default),
        "a name no chain claims must be served by the first chain"
    );
    listener.stop().await;
}

/// A name no chain claims anywhere lands on the first chain too, and the
/// evidence is the *kind* of failure: the default chain is served and the
/// client -- which does not recognise it for a name it never claimed --
/// refuses with "certificate not valid for name". A resolver that answered
/// nothing for an unclaimed name would abort the handshake instead, which
/// arrives as a fatal alert, and those are different failures.
#[tokio::test]
async fn an_unclaimed_name_is_served_by_the_first_chain_not_refused() {
    let material = MaterialDir::new();
    let default = server_identity_named(&["fallback.example.test"], &[]);
    let beta = server_identity_named(&["b.example.test"], &[]);
    let config = write_chains(&material, &[default.clone(), beta.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("an unclaimed name is not an error");
    let listener = serve(&bindings).await;

    let refusal = served_leaf(
        listener.addr,
        &[&default, &beta],
        dns_name("unclaimed.example.test"),
    )
    .await
    .expect_err("a chain the client does not recognise for this name cannot verify");
    assert!(
        refusal.contains("not valid for name"),
        "the first chain must be served for an unclaimed name -- failing the client's own name check, not the handshake: {refusal}"
    );
    listener.stop().await;
}

/// A client that sends no server name at all -- reachable with an address in
/// place of a name, which sends no SNI extension -- gets the first chain. The
/// first chain carries the matching IP SAN, so the outcome verifies.
#[tokio::test]
async fn a_caller_that_sends_no_server_name_gets_the_first_chain() {
    let material = MaterialDir::new();
    let default = server_identity_named(
        &["fallback.example.test"],
        &[std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
    );
    let beta = server_identity_named(&["b.example.test"], &[]);
    let config = write_chains(&material, &[default.clone(), beta.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("an unnamed caller is not an error");
    let listener = serve(&bindings).await;

    let served = served_leaf(
        listener.addr,
        &[&default, &beta],
        ServerName::IpAddress(PkiIpAddr::V4(PkiIpv4Addr::from([127, 0, 0, 1]))),
    )
    .await
    .expect("the first chain claims the peer address, so it must verify");
    assert_eq!(
        served,
        leaf_der(&default),
        "a caller that names no server must be served by the first chain"
    );
    listener.stop().await;
}

/// Matching is ASCII-case-insensitive on the certificate's side too: a SAN
/// stored in upper case is claimed by the lower-case name on the wire.
#[tokio::test]
async fn sni_matching_ignores_ascii_case() {
    let material = MaterialDir::new();
    let default = server_identity_named(&["fallback.example.test"], &[]);
    let upper = server_identity_named(&["UPPER.Example.TEST"], &[]);
    let config = write_chains(&material, &[default.clone(), upper.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("an upper-case SAN should load");
    let listener = serve(&bindings).await;

    let served = served_leaf(
        listener.addr,
        &[&default, &upper],
        dns_name("upper.example.test"),
    )
    .await
    .expect("DNS names are case-insensitive, so the upper-case SAN must verify");
    assert_eq!(
        served,
        leaf_der(&upper),
        "a SAN stored in upper case must be claimed by the lower-case wire name"
    );
    listener.stop().await;
}

/// The whole point: a normal verifying client, trusting only the CA of the
/// chain that should serve it, completes a request end to end.
#[tokio::test]
async fn sni_selection_serves_a_verifying_client_end_to_end() {
    let material = MaterialDir::new();
    let alpha = server_identity_named(&["a.example.test"], &[]);
    let beta = server_identity_named(&["b.example.test"], &[]);
    let config = write_chains(&material, &[alpha.clone(), beta]);
    let bindings = InboundTlsBindings::load(&config).expect("two named chains should load");
    let listener = serve(&bindings).await;

    let tcp = TcpStream::connect(listener.addr)
        .await
        .expect("connect should succeed");
    let mut stream = TlsConnector::from(Arc::new(default_client_config(&alpha.ca_der.clone())))
        .connect(dns_name("a.example.test"), tcp)
        .await
        .expect("a client trusting only the named chain's CA must be served");
    stream
        .write_all(b"GET /scheme HTTP/1.1\r\nHost: a.example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("request write should succeed");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response read should succeed");
    let served = String::from_utf8_lossy(&response).into_owned();
    assert!(
        served.contains("200 OK"),
        "the request must complete over the selected chain: {served}"
    );
    listener.stop().await;
}

/// Selection and client-certificate authentication compose: the caller's chain
/// is chosen by SNI while the caller is authenticated by certificate.
#[tokio::test]
async fn sni_and_client_certificates_combine() {
    let material = MaterialDir::new();
    let alpha = server_identity_named(&["a.example.test"], &[]);
    let beta = server_identity_named(&["b.example.test"], &[]);
    let mut config = write_chains(&material, &[alpha.clone(), beta]);
    let ca = client_ca();
    material.write("client-ca.crt", &ca.pem);
    config.client_cert_auth = Some(crate::config::InboundClientAuthConfig {
        mode_setting: "CLIENT_CERT_MODE",
        requirement: ClientCertRequirement::Required,
        ca_setting: "CLIENT_CERT_CA_FILE",
        ca_file: material.path("client-ca.crt"),
        crl_setting: "CLIENT_CERT_CRL_FILE",
        crl_file: None,
        identity_source: ClientCertIdentitySource::Spiffe,
    });
    let bindings =
        InboundTlsBindings::load(&config).expect("SNI with client certificates should load");
    let listener = serve_authenticating(&bindings).await;

    let mut client_config = client_config_with_identity(
        &alpha.ca_der,
        Some(issue_client_identity(&ca, ClientIdentitySpec::default())),
    );
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(listener.addr)
        .await
        .expect("connect should succeed");
    let mut stream = TlsConnector::from(Arc::new(client_config))
        .connect(dns_name("a.example.test"), tcp)
        .await
        .expect("a client certificate over the selected chain must complete the handshake");
    stream
        .write_all(b"GET /whoami HTTP/1.1\r\nHost: a.example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("request write should succeed");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response read should succeed");
    let body = String::from_utf8_lossy(&response).into_owned();
    assert!(
        body.contains(&format!("principal={CLIENT_SPIFFE_ID}")),
        "the caller must be authenticated by its certificate over the selected chain: {body}"
    );
    listener.stop().await;
}

/// The same name twice in one chain is one claim, not two. Without the dedup
/// this is a false `ServerNameClaimedTwice` at startup.
#[tokio::test]
async fn the_same_name_twice_in_one_chain_is_one_claim() {
    let material = MaterialDir::new();
    let chain = server_identity_named(&["same.example.test", "SAME.example.test"], &[]);
    let config = write_chains(&material, std::slice::from_ref(&chain));
    let bindings = InboundTlsBindings::load(&config)
        .expect("a chain repeating its own name is one claim, not a collision");
    let listener = serve(&bindings).await;

    let served = served_leaf(listener.addr, &[&chain], dns_name("same.example.test"))
        .await
        .expect("the repeated name still names this chain");
    assert_eq!(served, leaf_der(&chain));
    listener.stop().await;
}

/// Two chains claiming one name is a configuration whose selection could never
/// be honest, so it is a startup failure that names the name.
#[test]
fn two_chains_claiming_one_name_fail_startup() {
    let material = MaterialDir::new();
    let first = server_identity_named(&["dup.example.test"], &[]);
    let second = server_identity_named(&["other.example.test", "dup.example.test"], &[]);
    let config = write_chains(&material, &[first, second]);

    let error = InboundTlsBindings::load(&config)
        .expect_err("a name claimed by two chains must fail startup");
    assert_eq!(
        error,
        InboundTlsError::ServerNameClaimedTwice {
            setting: "TLS_CERT_FILE",
            name: "dup.example.test".to_owned(),
        }
    );
    assert!(
        error.to_string().contains("dup.example.test"),
        "the error must name the name an operator has to fix: {error}"
    );
}

/// Two chains claiming the same *wildcard* is the same defect one step
/// removed, and the error names the whole pattern -- an operator resolving a
/// collision on `*.dup.example.test` should not have to guess which of two
/// patterns shares a suffix.
#[test]
fn two_chains_claiming_one_wildcard_fail_startup() {
    let material = MaterialDir::new();
    let first = server_identity_named(&["*.dup.example.test"], &[]);
    let second = server_identity_named(&["*.dup.example.test", "other.example.test"], &[]);
    let config = write_chains(&material, &[first, second]);

    assert_eq!(
        InboundTlsBindings::load(&config)
            .expect_err("a wildcard claimed by two chains must fail startup"),
        InboundTlsError::ServerNameClaimedTwice {
            setting: "TLS_CERT_FILE",
            name: "*.dup.example.test".to_owned(),
        }
    );
}

/// A mixed-case *wire* name selects a lower-case claim. The other case test
/// folds the certificate's side; this one exercises the wire side, which
/// arrives pre-folded by rustls (pki-types lower-cases the SNI it parses) --
/// defence in depth in the resolver covers it, but nothing in this suite
/// noticed when that resolver-side fold was deleted, because the pre-fold made
/// it unreachable. This pins the end-to-end path: if either fold ever stops
/// happening, a mixed-case caller stops matching a name it should, and this is
/// the test that fails.
#[tokio::test]
async fn a_mixed_case_wire_name_selects_the_lower_case_claim() {
    let material = MaterialDir::new();
    let default = server_identity_named(&["fallback.example.test"], &[]);
    let lower = server_identity_named(&["mixed.example.test"], &[]);
    let config = write_chains(&material, &[default.clone(), lower.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("a lower-case claim should load");
    let listener = serve(&bindings).await;

    let served = served_leaf(
        listener.addr,
        &[&default, &lower],
        ServerName::try_from("MiXeD.eXaMpLe.TeSt".to_owned())
            .expect("a mixed-case server name should parse"),
    )
    .await
    .expect("a mixed-case wire name must verify against the chain claiming its lower-case form");
    assert_eq!(
        served,
        leaf_der(&lower),
        "a mixed-case wire name must select the chain claiming its lower-case form"
    );
    listener.stop().await;
}

/// A later chain with no DNS names can never be selected -- SNI carries DNS
/// names only -- so it is a configuration error. The *first* chain is exempt:
/// it is the default, and a chain that serves only unnamed or by-address
/// callers is a legitimate default.
#[test]
fn a_later_chain_with_no_dns_names_fails_startup() {
    let material = MaterialDir::new();
    let default = server_identity_named(&["fallback.example.test"], &[]);
    let nameless =
        server_identity_named(&[], &[std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    let config = write_chains(&material, &[default, nameless]);

    let error = InboundTlsBindings::load(&config)
        .expect_err("a chain no name can select must fail startup");
    assert_eq!(
        error,
        InboundTlsError::ServerNameUnselectable {
            setting: "TLS_CERT_FILE",
            chain: 1,
        }
    );
    assert!(
        error.to_string().contains("position 2"),
        "the error must say which chain an operator has to fix: {error}"
    );
}

/// The exemption, pinned: a first chain with no DNS names loads and serves as
/// the default (observed over an address, the only name it can verify).
#[tokio::test]
async fn a_first_chain_with_no_dns_names_serves_as_the_default() {
    let material = MaterialDir::new();
    let nameless =
        server_identity_named(&[], &[std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    let beta = server_identity_named(&["b.example.test"], &[]);
    let config = write_chains(&material, &[nameless.clone(), beta.clone()]);
    let bindings =
        InboundTlsBindings::load(&config).expect("a nameless first chain is a legitimate default");
    let listener = serve(&bindings).await;

    let served = served_leaf(
        listener.addr,
        &[&nameless, &beta],
        ServerName::IpAddress(PkiIpAddr::V4(PkiIpv4Addr::from([127, 0, 0, 1]))),
    )
    .await
    .expect("the nameless default claims the peer address, so it must verify");
    assert_eq!(
        served,
        leaf_der(&nameless),
        "a caller that names no server must land on the nameless first chain"
    );
    listener.stop().await;
}

/// A wildcard that is not the whole first label -- `a.*.b`, `*foo.b`, a bare
/// `*` -- is not a name the SAN reader can even classify, so it claims nothing
/// rather than being matched by something looser than it says. Pinned as the
/// second-chain failure: a chain whose only SAN is such a name is nameless,
/// and only the first chain may be nameless.
#[test]
fn a_wildcard_that_is_not_a_whole_label_claims_nothing() {
    for name in ["a.*.b.example.test", "*foo.b.example.test", "*"] {
        let material = MaterialDir::new();
        let default = server_identity_named(&["fallback.example.test"], &[]);
        let unmatchable = server_identity_named(&[name], &[]);
        let config = write_chains(&material, &[default, unmatchable]);

        let error = InboundTlsBindings::load(&config).expect_err(&format!(
            "a later chain whose only SAN is '{name}' is nameless and must fail startup"
        ));
        assert_eq!(
            error,
            InboundTlsError::ServerNameUnselectable {
                setting: "TLS_CERT_FILE",
                chain: 1,
            },
            "'{name}' must not be claimable in any shape: {error}"
        );
    }
}

/// A trailing root dot would make an exact claim that no wire name ever
/// equals, so it is refused rather than silently never matching.
#[test]
fn a_trailing_dot_name_is_refused() {
    let material = MaterialDir::new();
    let chain = server_identity_named(&["dot.example.test."], &[]);
    let config = write_chains(&material, &[chain]);

    assert_eq!(
        InboundTlsBindings::load(&config)
            .expect_err("a trailing-dot SAN must be refused at startup"),
        InboundTlsError::ServerNameMalformed {
            setting: "TLS_CERT_FILE",
            name: "dot.example.test.".to_owned(),
        }
    );
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut encoded = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        encoded.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        encoded.push('\n');
    }
    encoded.push_str(&format!("-----END {label}-----\n"));
    encoded
}

// --- material reload ----------------------------------------------------------
//
// Certificates are the one piece of gateway configuration with a validity
// window, so they are also the one piece that must change while the gateway
// serves. The properties below are the contract of the reload, and each is
// pinned by at least one test: new connections see the new chains, old
// connections are untouched, invalid material changes nothing and says so,
// the client-certificate decisions a reload must not revisit (verifier,
// resumption) are the startup ones, the whole SNI set moves as a unit, and
// the two listeners reload independently.

/// The audit events of one type for one listener, in emission order.
fn audit_events(
    capture: &crate::audit::sink::tests::CaptureSink,
    event_type: &str,
    listener: &str,
) -> Vec<AuditEvent> {
    capture
        .events()
        .into_iter()
        .filter(|event| {
            event.event_type == event_type
                && event
                    .payload
                    .get("listener")
                    .and_then(|value| value.as_str())
                    == Some(listener)
        })
        .collect()
}

async fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
    let started = Instant::now();

    while started.elapsed() < timeout {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    assert!(
        condition(),
        "condition did not become true within {timeout:?}"
    );
}

/// Rewrites one listener's material to a new identity.
fn rotate_material(material: &MaterialDir, identity: &ServerIdentity) {
    material.write("tls.crt", &identity.certificate_pem);
    material.write("tls.key", &identity.private_key_pem);
}

/// One HTTP response off a keep-alive connection, without closing it.
///
/// Reads the status line and headers, then exactly `content-length` body
/// bytes, so the stream is left mid-connection and a second request can be
/// sent on it. This is how a test holds the same TLS connection across a
/// reload.
async fn read_one_http_response(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> String {
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(header_end) = find_header_end(&response) {
            let headers = String::from_utf8_lossy(&response[..header_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if response.len() >= header_end + content_length {
                return String::from_utf8_lossy(&response[..header_end + content_length])
                    .into_owned();
            }
        }
        let read = stream
            .read(&mut chunk)
            .await
            .expect("the established connection should keep reading");
        assert!(
            read > 0,
            "the established connection was closed mid-response"
        );
        response.extend_from_slice(&chunk[..read]);
    }
}

fn find_header_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

/// A router whose one route answers only when released, so a request can be
/// left in flight across a reload.
fn held_router(release: tokio::sync::watch::Receiver<bool>) -> Router {
    Router::new().route(
        "/held",
        get(move || {
            let mut release = release.clone();
            async move {
                loop {
                    if *release.borrow() {
                        break;
                    }
                    if release.changed().await.is_err() {
                        break;
                    }
                }
                "held-response"
            }
        }),
    )
}

/// A client that trusts several servers' CAs and presents a client
/// certificate: what a reload test on a client-certificate listener needs,
/// because the client must verify whichever chain is served, before or after
/// the swap.
fn client_config_trusting_identities_with_client_cert(
    servers: &[&ServerIdentity],
    identity: ClientIdentity,
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    for server in servers {
        roots
            .add(CertificateDer::from(server.ca_der.clone()))
            .expect("test CA should be accepted as a root");
    }
    let mut config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&version::TLS12, &version::TLS13])
        .expect("test client protocol versions should be supported")
        .with_root_certificates(roots)
        .with_client_auth_cert(identity.chain, identity.key)
        .expect("test client identity should load");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// A material change is served to new connections.
#[tokio::test]
async fn a_material_reload_swaps_the_certificate_served_to_new_connections() {
    let material = MaterialDir::new();
    let first = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve(&bindings).await;

    let second = server_identity();
    rotate_material(&material, &second);

    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
    })
    .await;

    let served = served_leaf(listener.addr, &[&first, &second], dns_name(SERVER_NAME))
        .await
        .expect("a new connection after the reload must complete a handshake");
    assert_eq!(
        served,
        leaf_der(&second),
        "a new connection must be served the reloaded leaf, not the startup one"
    );
    assert!(
        audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").is_empty(),
        "a valid reload must not report failures"
    );
    listener.stop().await;
}

/// The headline property: a connection established before a reload keeps
/// serving on it after the swap, including a response that was in flight
/// while the reload landed and a further request afterwards.
#[tokio::test]
async fn an_established_connection_keeps_serving_through_a_reload() {
    let material = MaterialDir::new();
    let first = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let (release, release_waiter) = tokio::sync::watch::channel(false);
    let listener = serve_router(&bindings, held_router(release_waiter)).await;

    // Established and requested BEFORE any reload, and held.
    let tcp = TcpStream::connect(listener.addr)
        .await
        .expect("connect before reload should succeed");
    let mut established = TlsConnector::from(Arc::new(default_client_config(&first.ca_der)))
        .connect(dns_name(SERVER_NAME), tcp)
        .await
        .expect("handshake before reload should complete");
    established
        .write_all(format!("GET /held HTTP/1.1\r\nHost: {SERVER_NAME}\r\n\r\n").as_bytes())
        .await
        .expect("request before reload should write");

    // The reload lands while that response is in flight.
    let second = server_identity();
    rotate_material(&material, &second);
    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
    })
    .await;
    let served = served_leaf(listener.addr, &[&first, &second], dns_name(SERVER_NAME))
        .await
        .expect("a new connection after the reload must complete a handshake");
    assert_eq!(
        served,
        leaf_der(&second),
        "the reload must genuinely have swapped what new connections are served"
    );

    // The pre-reload connection completes its in-flight response...
    release.send_replace(true);
    let response = read_one_http_response(&mut established).await;
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "the established connection must complete its in-flight response: {response}"
    );
    assert!(
        response.ends_with("held-response"),
        "the established connection must deliver the body: {response}"
    );

    // ...and keeps serving further requests on the same connection.
    established
        .write_all(format!("GET /held HTTP/1.1\r\nHost: {SERVER_NAME}\r\n\r\n").as_bytes())
        .await
        .expect("the follow-up request on the established connection should write");
    let second_response = read_one_http_response(&mut established).await;
    assert!(
        second_response.starts_with("HTTP/1.1 200 OK"),
        "the established connection must keep serving after the reload: {second_response}"
    );
    listener.stop().await;
}

/// Invalid new material changes nothing and says so: the last good chains keep
/// serving, the failure is audited with the setting to fix, no key material
/// rides along, and a later valid update is still accepted.
#[tokio::test]
async fn an_invalid_reload_keeps_the_previous_chains_and_is_audited() {
    let material = MaterialDir::new();
    let first = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve(&bindings).await;

    material.write("tls.crt", "this is not a PEM certificate");
    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").is_empty()
    })
    .await;

    let served = served_leaf(listener.addr, &[&first], dns_name(SERVER_NAME))
        .await
        .expect("the listener must keep serving after a rejected reload");
    assert_eq!(
        served,
        leaf_der(&first),
        "a rejected reload must leave the last good chains serving"
    );

    let failures = audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data");
    assert_eq!(
        failures.len(),
        1,
        "one change is one reload attempt, not a retry loop"
    );
    assert_eq!(failures[0].payload["outcome"], serde_json::json!("failure"));
    assert_eq!(
        failures[0].payload["certificate_setting"],
        serde_json::json!("TLS_CERT_FILE")
    );
    let reason = failures[0].payload["reason"]
        .as_str()
        .expect("the failure event should carry a reason");
    assert!(
        reason.contains("TLS_CERT_FILE"),
        "the reason should name the setting to fix: {reason}"
    );
    let serialized = serde_json::to_string(&failures[0]).expect("the event should serialize");
    assert!(
        !serialized.contains("PRIVATE KEY"),
        "the failure event must not carry key material: {serialized}"
    );

    // And the listener is not wedged: a later valid update is accepted.
    let second = server_identity();
    rotate_material(&material, &second);
    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
    })
    .await;
    let served = served_leaf(listener.addr, &[&first, &second], dns_name(SERVER_NAME))
        .await
        .expect("a new connection must complete a handshake after the valid update");
    assert_eq!(served, leaf_der(&second));
    listener.stop().await;
}

/// The key-matches-leaf pairing is a reload check, not only a startup one:
/// a new certificate beside the old key is refused and the old chains keep
/// serving.
#[tokio::test]
async fn a_key_that_no_longer_matches_is_refused_by_a_reload() {
    let material = MaterialDir::new();
    let first = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve(&bindings).await;

    let second = server_identity();
    material.write("tls.crt", &second.certificate_pem);
    // Rewrite the unchanged key bytes so the watcher sees a change on the
    // pair; the content is still the first identity's key.
    material.write("tls.key", &first.private_key_pem);

    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").is_empty()
    })
    .await;

    let served = served_leaf(listener.addr, &[&first], dns_name(SERVER_NAME))
        .await
        .expect("the listener must keep serving");
    assert_eq!(
        served,
        leaf_der(&first),
        "a mismatched pair must not be swapped in"
    );
    let reason = audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data")[0].payload
        ["reason"]
        .as_str()
        .expect("the failure event should carry a reason")
        .to_owned();
    assert!(
        reason.contains("TLS_KEY_FILE") && reason.contains("TLS_CERT_FILE"),
        "the mismatch reason should name both settings: {reason}"
    );
    listener.stop().await;
}

/// The SNI rules are reload rules: a rewrite whose chains claim one name
/// twice is refused naming the name, and the previous set keeps selecting.
#[tokio::test]
async fn a_reload_breaking_the_sni_rules_is_refused_and_audited() {
    let material = MaterialDir::new();
    let alpha = server_identity_named(&["a.example.test"], &[]);
    let beta = server_identity_named(&["b.example.test"], &[]);
    let config = write_chains(&material, &[alpha.clone(), beta.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("two named chains should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve(&bindings).await;

    let broken_first = server_identity_named(&["dup.example.test"], &[]);
    let broken_second = server_identity_named(&["dup.example.test"], &[]);
    material.write("tls-1.crt", &broken_first.certificate_pem);
    material.write("tls-1.key", &broken_first.private_key_pem);
    material.write("tls-2.crt", &broken_second.certificate_pem);
    material.write("tls-2.key", &broken_second.private_key_pem);

    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").is_empty()
    })
    .await;
    let reason = audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data")[0].payload
        ["reason"]
        .as_str()
        .expect("the failure event should carry a reason")
        .to_owned();
    assert!(
        reason.contains("dup.example.test"),
        "the duplicate-name reason should name the duplicated name: {reason}"
    );

    let served = served_leaf(listener.addr, &[&alpha, &beta], dns_name("a.example.test"))
        .await
        .expect("the listener must keep serving");
    assert_eq!(
        served,
        leaf_der(&alpha),
        "a set that breaks the SNI rules must not be swapped in"
    );
    listener.stop().await;
}

/// The permission rules are reload rules: a key that becomes group-readable
/// in place is refused, and the last good chains keep serving.
#[cfg(unix)]
#[tokio::test]
async fn an_unsafe_permission_reload_is_refused_and_audited() {
    let material = MaterialDir::new();
    let first = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve(&bindings).await;

    // Same bytes, unsafe mode: the reload re-reads and re-checks rather than
    // trusting that the file it validated once is still the file here.
    let key_path = material.root.join("tls.key");
    fs::write(&key_path, &first.private_key_pem).expect("key rewrite should write");
    set_file_permissions(&key_path, 0o644);

    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").is_empty()
    })
    .await;
    let reason = audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data")[0].payload
        ["reason"]
        .as_str()
        .expect("the failure event should carry a reason")
        .to_owned();
    assert!(
        reason.contains("TLS_KEY_FILE"),
        "the unsafe-permission reason should name the key setting: {reason}"
    );

    let served = served_leaf(listener.addr, &[&first], dns_name(SERVER_NAME))
        .await
        .expect("the listener must keep serving");
    assert_eq!(
        served,
        leaf_der(&first),
        "material that fails the permission check must not be swapped in"
    );
    listener.stop().await;
}

/// The kubelet rotation shape: the leaves are relative symlinks through a
/// `..data` symlink, and rotation flips `..data` -- the leaves' own directory
/// entries never change. The watcher must notice the flip.
#[cfg(unix)]
fn write_timestamped_projection(material: &MaterialDir, version: &str, identity: &ServerIdentity) {
    let directory = material.root.join(format!("..{version}"));
    fs::create_dir_all(&directory).expect("timestamped data directory should create");
    fs::write(directory.join("tls.crt"), &identity.certificate_pem)
        .expect("projected cert should write");
    fs::write(directory.join("tls.key"), &identity.private_key_pem)
        .expect("projected key should write");
    set_file_permissions(&directory.join("tls.crt"), 0o644);
    set_file_permissions(&directory.join("tls.key"), 0o400);
}

#[cfg(unix)]
#[tokio::test]
async fn a_kubelet_style_symlink_flip_reloads_the_material() {
    let material = MaterialDir::new();
    let first = server_identity();
    write_timestamped_projection(&material, "v1", &first);
    std::os::unix::fs::symlink("..v1", material.root.join("..data"))
        .expect("data symlink should create");
    std::os::unix::fs::symlink("..data/tls.crt", material.root.join("tls.crt"))
        .expect("leaf cert symlink should create");
    std::os::unix::fs::symlink("..data/tls.key", material.root.join("tls.key"))
        .expect("leaf key symlink should create");

    let bindings =
        InboundTlsBindings::load(&tls_config(&material)).expect("projected material should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve(&bindings).await;

    // Rotate: a new timestamped directory, then flip ..data onto it the way
    // the kubelet's atomic writer does -- a symlink rename, never a write to
    // the leaves the settings name.
    let second = server_identity();
    write_timestamped_projection(&material, "v2", &second);
    std::os::unix::fs::symlink("..v2", material.root.join("..data.tmp"))
        .expect("staging data symlink should create");
    fs::rename(
        material.root.join("..data.tmp"),
        material.root.join("..data"),
    )
    .expect("data symlink flip should rename");

    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
    })
    .await;
    let served = served_leaf(listener.addr, &[&first, &second], dns_name(SERVER_NAME))
        .await
        .expect("a new connection after the flip must complete a handshake");
    assert_eq!(
        served,
        leaf_der(&second),
        "flipping ..data must reload the material the leaves resolve to"
    );
    listener.stop().await;
}

/// A reload swaps chains and nothing else: on a client-certificate listener
/// the `ServerConfig` is still the startup object afterwards, so the verifier,
/// the empty session store, and the absent ticket count cannot have been
/// rebuilt without them -- and over the wire every connection is still a full
/// handshake that still authenticates.
#[tokio::test]
async fn a_client_certificate_listener_keeps_resumption_disabled_across_a_reload() {
    let material = MaterialDir::new();
    let ca = client_ca();
    let server = write_client_auth_material(&material, &ca);
    let bindings = InboundTlsBindings::load(&client_auth_config(
        &material,
        ClientCertRequirement::Optional,
        None,
    ))
    .expect("client-auth material should load");
    let startup_config = bindings
        .data
        .as_ref()
        .expect("the data listener terminates TLS in this configuration")
        .server_config
        .clone();
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve_authenticating(&bindings).await;

    let second = server_identity();
    rotate_material(&material, &second);
    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
    })
    .await;

    let post_reload_config = bindings
        .data
        .as_ref()
        .expect("the data listener terminates TLS in this configuration")
        .server_config
        .clone();
    assert!(
        Arc::ptr_eq(&startup_config, &post_reload_config),
        "a reload must not replace the ServerConfig: the verifier, the resumption settings, and the ALPN list are startup decisions a certificate rotation has no business revisiting"
    );
    assert!(
        !post_reload_config.session_storage.can_cache(),
        "a client-certificate listener must still hold no session cache after a reload"
    );
    assert_eq!(
        post_reload_config.send_tls13_tickets, 0,
        "a client-certificate listener must still issue no TLS 1.3 tickets after a reload"
    );
    assert!(
        !post_reload_config.ticketer.enabled(),
        "a client-certificate listener must still have no ticketer after a reload"
    );

    // Over the wire: two connections over one shared client configuration, so
    // the second offers back anything resumption could have handed it -- and
    // both must be full handshakes that still authenticate the caller.
    let config = Arc::new(client_config_trusting_identities_with_client_cert(
        &[&server, &second],
        issue_client_identity(&ca, ClientIdentitySpec::default()),
    ));
    for attempt in ["first", "second"] {
        let exchange = whoami_request(listener.addr, Arc::clone(&config), "")
            .await
            .unwrap_or_else(|error| {
                panic!("the {attempt} post-reload handshake must succeed: {error}")
            });
        assert!(
            exchange
                .body
                .contains(&format!("principal={CLIENT_SPIFFE_ID}")),
            "the {attempt} post-reload connection must still authenticate the client: {}",
            exchange.body
        );
        assert_eq!(
            exchange.handshake_kind,
            Some(HandshakeKind::Full),
            "the {attempt} post-reload connection must be a full handshake"
        );
    }
    listener.stop().await;
}

/// The SNI set moves as a unit: after a rewrite, a name that appeared starts
/// selecting its chain and a name that disappeared falls back to the first
/// chain, exactly as the startup rules say.
#[tokio::test]
async fn an_sni_chain_set_reloads_as_a_whole() {
    let material = MaterialDir::new();
    let alpha = server_identity_named(&["a.example.test"], &[]);
    let beta = server_identity_named(&["b.example.test"], &[]);
    let config = write_chains(&material, &[alpha.clone(), beta.clone()]);
    let bindings = InboundTlsBindings::load(&config).expect("two named chains should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve(&bindings).await;

    let gamma = server_identity_named(&["c.example.test"], &[]);
    let delta = server_identity_named(&["d.example.test"], &[]);
    material.write("tls-1.crt", &gamma.certificate_pem);
    material.write("tls-1.key", &gamma.private_key_pem);
    material.write("tls-2.crt", &delta.certificate_pem);
    material.write("tls-2.key", &delta.private_key_pem);

    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
    })
    .await;
    let accepted = audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data");
    assert_eq!(
        accepted[0].payload["chain_count"],
        serde_json::json!(2),
        "the accepted event should report the size of the new set"
    );

    let identities = [&alpha, &beta, &gamma, &delta];
    let served = served_leaf(listener.addr, &identities, dns_name("c.example.test"))
        .await
        .expect("a name the new set claims must complete a handshake");
    assert_eq!(
        served,
        leaf_der(&gamma),
        "a name added by the reload must select the chain that now claims it"
    );

    // The removed name lands on the first chain of the new set, exactly as
    // the startup rule says. The first chain does not claim it, so the
    // outcome is observable the way the startup SNI tests observe it: the
    // handshake completes and the client's own name check names the chain it
    // was served -- gamma's -- rather than the handshake being refused.
    let refusal = served_leaf(listener.addr, &identities, dns_name("a.example.test"))
        .await
        .expect_err("a chain that does not claim the removed name cannot verify");
    assert!(
        refusal.contains("not valid for name") && refusal.contains("c.example.test"),
        "the removed name must be served by the new first chain, failing the client's own name check against it rather than the handshake: {refusal}"
    );
    listener.stop().await;
}

/// The two listeners reload independently: a change to one listener's
/// material reloads that listener and leaves the other on its current
/// chains, in both directions.
#[tokio::test]
async fn listeners_reload_independently() {
    let data_material = MaterialDir::new();
    let data_first = write_default_identity(&data_material);
    let admin_material = MaterialDir::new();
    let admin_first = write_default_identity(&admin_material);

    let mut config = Config::test_defaults();
    config.tls_cert_files = Some(vec![data_material.path("tls.crt")]);
    config.tls_key_files = Some(vec![data_material.path("tls.key")]);
    config.admin_tls_cert_files = Some(vec![admin_material.path("tls.crt")]);
    config.admin_tls_key_files = Some(vec![admin_material.path("tls.key")]);

    let bindings = InboundTlsBindings::load(&config).expect("material should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watchers should start");
    let data_listener = serve(&bindings).await;
    let admin_listener = serve_admin(&bindings).await;

    // Admin rotates; data must not notice.
    let admin_second = server_identity();
    rotate_material(&admin_material, &admin_second);
    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "admin").is_empty()
    })
    .await;
    let served = served_leaf(
        admin_listener.addr,
        &[&admin_first, &admin_second],
        dns_name(SERVER_NAME),
    )
    .await
    .expect("the admin listener must serve after its own reload");
    assert_eq!(
        served,
        leaf_der(&admin_second),
        "the admin listener must serve its reloaded leaf"
    );
    let served = served_leaf(data_listener.addr, &[&data_first], dns_name(SERVER_NAME))
        .await
        .expect("the data listener must keep serving");
    assert_eq!(
        served,
        leaf_der(&data_first),
        "an admin reload must not disturb the data listener's chains"
    );
    assert!(
        audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
            && audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").is_empty(),
        "an admin reload must not produce data-listener reload events"
    );

    // And the converse: data rotates; admin keeps its reloaded chains.
    let data_second = server_identity();
    rotate_material(&data_material, &data_second);
    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
    })
    .await;
    let served = served_leaf(
        data_listener.addr,
        &[&data_first, &data_second],
        dns_name(SERVER_NAME),
    )
    .await
    .expect("the data listener must serve after its own reload");
    assert_eq!(served, leaf_der(&data_second));
    let served = served_leaf(admin_listener.addr, &[&admin_second], dns_name(SERVER_NAME))
        .await
        .expect("the admin listener must keep serving");
    assert_eq!(
        served,
        leaf_der(&admin_second),
        "a data reload must not disturb the admin listener's chains"
    );

    data_listener.stop().await;
    admin_listener.stop().await;
}

/// Material that stays broken is attempted exactly once. The watcher is
/// event-driven with no retry schedule, so a rejected reload cannot become a
/// spin -- asserted by settling the clock well past every debounce and
/// counting attempts.
#[tokio::test]
async fn persistently_invalid_material_is_not_retried_in_a_loop() {
    let material = MaterialDir::new();
    let first = write_default_identity(&material);
    let bindings = InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
    let capture = crate::audit::sink::tests::CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    bindings
        .spawn_material_reload_tasks(audit)
        .expect("material watcher should start");
    let listener = serve(&bindings).await;

    material.write("tls.crt", "still not a PEM certificate");
    wait_until(Duration::from_secs(10), || {
        !audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").is_empty()
    })
    .await;

    // Five times the debounce, plus margin: long enough that any periodic
    // retry would have fired repeatedly.
    tokio::time::sleep(TLS_MATERIAL_RELOAD_DEBOUNCE * 5 + Duration::from_millis(500)).await;

    assert_eq!(
        audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").len(),
        1,
        "a rejected reload must not be retried on a schedule"
    );
    assert!(
        audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty(),
        "material that never became valid must never be accepted"
    );
    let served = served_leaf(listener.addr, &[&first], dns_name(SERVER_NAME))
        .await
        .expect("the listener must keep serving");
    assert_eq!(served, leaf_der(&first));
    listener.stop().await;
}

/// Both reload outcomes are counted on the counter the documentation names,
/// with the listener as a static label.
#[test]
fn reload_outcomes_are_counted_on_the_documented_metric() {
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");

    ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let material = MaterialDir::new();
            let _first = write_default_identity(&material);
            let bindings =
                InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
            let capture = crate::audit::sink::tests::CaptureSink::new();
            let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
            bindings
                .spawn_material_reload_tasks(audit)
                .expect("material watcher should start");
            let listener = serve(&bindings).await;

            material.write("tls.crt", "not a PEM certificate, metric edition");
            wait_until(Duration::from_secs(10), || {
                !audit_events(&capture, audit::event::INBOUND_TLS_RELOAD_FAILED, "data").is_empty()
            })
            .await;

            let second = server_identity();
            rotate_material(&material, &second);
            wait_until(Duration::from_secs(10), || {
                !audit_events(&capture, audit::event::INBOUND_TLS_RELOADED, "data").is_empty()
            })
            .await;

            listener.stop().await;
        })
    });

    let rejected = recorder.count(
        crate::metrics::INBOUND_TLS_RELOADS_TOTAL,
        &[("listener", "data"), ("outcome", "rejected")],
    );
    assert_eq!(rejected, 1, "the rejected reload must be counted once");
    let accepted = recorder.count(
        crate::metrics::INBOUND_TLS_RELOADS_TOTAL,
        &[("listener", "data"), ("outcome", "accepted")],
    );
    assert_eq!(accepted, 1, "the accepted reload must be counted once");
}

/// The material watcher announces liveness on the documented counter, so a
/// task that has died is distinguishable from quiet files.
///
/// Without this, a dead watcher looks exactly like an unchanging certificate:
/// no events, no reloads, no signal. The counter advancing -- here, at least
/// twice within the wait bound, which only a running loop can do -- is the
/// observable difference.
#[test]
fn the_material_watcher_heartbeat_is_counted_while_it_runs() {
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");

    ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let material = MaterialDir::new();
            let _first = write_default_identity(&material);
            let bindings =
                InboundTlsBindings::load(&tls_config(&material)).expect("material should load");
            let capture = crate::audit::sink::tests::CaptureSink::new();
            let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
            bindings
                .spawn_material_reload_tasks(audit)
                .expect("material watcher should start");
            let listener = serve(&bindings).await;

            wait_until(Duration::from_secs(15), || {
                recorder.count(
                    crate::metrics::INBOUND_TLS_WATCH_HEARTBEATS_TOTAL,
                    &[("listener", "data")],
                ) >= 2
            })
            .await;
            listener.stop().await;
            let beats = recorder.count(
                crate::metrics::INBOUND_TLS_WATCH_HEARTBEATS_TOTAL,
                &[("listener", "data")],
            );
            assert!(
                beats >= 2,
                "the heartbeat counter must advance while the watcher runs (saw {beats}); a flat counter is how a dead watcher is told apart from quiet files"
            );
        })
    });
}
