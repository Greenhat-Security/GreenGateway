//! The listener path (`TlsListener`, `accept_loop`, `HandshakeLimits`):
//! plaintext when TLS is not configured, a handshake served end to end,
//! handshakes kept off the accept path under their bound, saturation
//! shedding rather than stalling, and the negotiated protocol floor and
//! ALPN. Shared fixtures stay in `inbound_tls_tests.rs`.
use super::*;

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
