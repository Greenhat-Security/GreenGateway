//! SNI (`SniServerCertResolver`, `load_certified_chains`,
//! `validate_server_name`): the chain a handshake is served, and the
//! startup refusal of chain sets whose names collide or claim nothing.
//! Shared fixtures stay in `inbound_tls_tests.rs`.
use super::*;

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
