//! Client-certificate authentication (`load_client_verifier`,
//! `client_identity`, `classify_client_certificate_failure`): only a
//! certificate the configured CA, CRL and purpose verify yields an
//! identity, and every refusal is counted under its documented label.
//! Shared fixtures stay in `inbound_tls_tests.rs`.
use super::*;

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

const OTHER_SPIFFE_ID: &str = "spiffe://gateway.test/ns/payments/sa/batch";

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
    .signed_by(&ca.issuer)
    .expect("test CRL should build")
    .pem()
    .expect("test CRL should encode as PEM")
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
