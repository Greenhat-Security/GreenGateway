//! Session resumption (`disable_session_resumption`): a listener that asks
//! for client certificates keeps nothing to resume from, one that does not
//! still resumes, and no listener offers 0-RTT. Shared fixtures stay in
//! `inbound_tls_tests.rs`.
use super::*;

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
