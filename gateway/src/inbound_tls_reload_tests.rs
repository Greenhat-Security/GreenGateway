//! Material reload (`reload_listener_material` and its file watcher): new
//! connections get the new chains, established ones are untouched, invalid
//! material changes nothing and is audited, and the two listeners reload
//! independently. Shared fixtures stay in `inbound_tls_tests.rs`.
use super::*;

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
