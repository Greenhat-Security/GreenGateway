//! Tests for the shared outbound TLS configuration in [`super::tls`].
//!
//! Three parts, and they guard different things.
//!
//! # Part one: the differential trust cases
//!
//! [`super::tls`] builds one `rustls::ClientConfig` and hands it to reqwest. The
//! single decision inside it that is easy to get wrong, and impossible to
//! notice, is how a configured CA bundle relates to the platform trust store:
//!
//! * the production construction adds configured CAs as EXTRA roots on top of
//!   the platform store, and
//! * the obvious alternative, `with_root_certificates(roots)`, REPLACES the
//!   platform store with them.
//!
//! Cases (a) to (e) run both constructions against the same fixture and record
//! which way each one decided. Five of the six reach identical verdicts -- which
//! is the finding, not an oversight. A private-CA fixture cannot tell the two
//! apart, because everything the private CA signs is trusted either way.
//!
//! Case (e) is the only case that discriminates: a publicly signed host reached
//! by a client that ALSO has a private CA configured. It is accepted under the
//! extra-roots construction and refused under the roots-only one. It cannot be
//! simulated offline without lying, because a "public" CA is public precisely by
//! being in the platform trust store, and installing one there would be
//! manufacturing the result. So it talks to [`PUBLIC_TRUST_ANCHOR_HOST`] and
//! carries `#[ignore]`, which keeps it out of offline CI without inventing a
//! deployment setting to switch it on -- `gateway/tests/env_example.rs` treats
//! every environment read under `gateway/src` as configuration an operator must
//! be able to find documented, and a test knob is not that.
//!
//! **Run case (e) by hand on every reqwest upgrade.** It is the only test in
//! this repository that can catch reqwest changing how configured CAs relate to
//! the platform trust store, and a change in that direction narrows outbound
//! trust silently -- private-CA upstreams keep working, publicly signed ones
//! start failing at whichever deployment happens to have both:
//!
//! ```text
//! cargo test --bin gateway -- --ignored egress::tls_tests::case_e
//! ```
//!
//! # Part two: what the preconfigured backend turns off
//!
//! Handing reqwest a finished `ClientConfig` disables two things it otherwise
//! does, both silently. These tests observe both rather than trusting the
//! reading of reqwest's source: ALPN is no longer pinned by `.http1_only()`, and
//! `add_root_certificate` no longer contributes trust.
//!
//! # Part three: what the TLS stream reports when its transport fails
//!
//! An upstream response that ends with the connection, rather than with a
//! `Content-Length` or a final chunk, is complete only if the stream really
//! ended. tokio-rustls 0.26.5 dropped a transport error that arrived in the
//! same read as data, and turned a `ConnectionAborted` into a clean end of
//! stream, so such a body could be cut short and still read as whole. That
//! needs a transport that fails exactly once at a chosen point, which a real
//! socket cannot be made to do, so this part drives the shared config over an
//! in-memory one.

use std::{
    collections::HashSet,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use reqwest::Method;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
        server::WebPkiClientVerifier,
        ClientConfig, RootCertStore, ServerConfig,
    },
    TlsAcceptor, TlsConnector,
};

use super::{
    base_client_builder_for_profile,
    client_cache::{PinnedClientCache, ProtocolProfile},
    tls, DnsResolver, EgressClient, EgressConfig,
};

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// The only thing these tests compare: was the peer trusted?
///
/// Recorded with the failure detail attached so an assertion can say which way
/// the decision went and why, rather than only that something errored -- a TLS
/// test that asserts "a request failed" passes just as happily when it failed
/// for an unrelated reason.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Accept,
    Reject,
}

impl Verdict {
    fn of<T, E: std::fmt::Debug>(result: Result<T, E>) -> (Self, String) {
        match result {
            Ok(_) => (Self::Accept, String::new()),
            Err(error) => (Self::Reject, format!("{error:?}")),
        }
    }
}

/// Which of the two trust constructions a hand-built leg uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Construction {
    /// `ClientConfig::builder().with_root_certificates(roots)` -- the obvious
    /// alternative, which drops every platform trust anchor.
    RootsOnly,
    /// What [`super::tls::client_config`] actually builds.
    Production,
}

/// The publicly signed host case (e) reaches.
///
/// Any host with a certificate chaining to a public CA works; this one is
/// reserved by IANA for exactly this kind of use. Edit it if a network reaches
/// the internet only through a proxy that terminates TLS with its own CA -- in
/// that environment case (e) cannot say anything, because the "public" anchor
/// would be the proxy's.
const PUBLIC_TRUST_ANCHOR_HOST: &str = "example.com";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

struct Ca {
    certificate: rcgen::Certificate,
    /// The CA's subject, key-identifier method, key usages and signing key:
    /// everything rcgen needs to issue a leaf under this CA.
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl Ca {
    fn pem(&self) -> String {
        self.certificate.pem()
    }

    fn der(&self) -> Vec<u8> {
        self.certificate.der().as_ref().to_vec()
    }
}

fn certificate_authority(common_name: &str) -> Ca {
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().expect("test CA key should generate");
    let certificate = params
        .self_signed(&key)
        .expect("test CA certificate should build");
    Ca {
        certificate,
        issuer: rcgen::Issuer::new(params, key),
    }
}

struct Leaf {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    /// Certificate followed by its private key: the shape
    /// `apply_tls_client_identity_pem` accepts.
    identity_pem: String,
}

fn leaf(ca: &Ca, san: &str, purpose: rcgen::ExtendedKeyUsagePurpose) -> Leaf {
    let mut params = rcgen::CertificateParams::new(vec![san.to_owned()])
        .expect("test leaf parameters should build");
    params.extended_key_usages = vec![purpose];
    let key = rcgen::KeyPair::generate().expect("test leaf key should generate");
    let certificate = params
        .signed_by(&key, &ca.issuer)
        .expect("test leaf certificate should build");

    Leaf {
        certificate_der: certificate.der().as_ref().to_vec(),
        private_key_der: key.serialize_der(),
        identity_pem: format!("{}{}", certificate.pem(), key.serialize_pem()),
    }
}

struct StaticResolver {
    address: SocketAddr,
}

#[async_trait]
impl DnsResolver for StaticResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        Ok(vec![self.address])
    }
}

// ---------------------------------------------------------------------------
// Fixture server
// ---------------------------------------------------------------------------

struct TestServer {
    address: SocketAddr,
    handshakes: Arc<AtomicUsize>,
    /// DER of the leaf certificate the client presented, if any.
    observed_client_leaf: Arc<Mutex<Option<Vec<u8>>>>,
    /// The protocol ALPN selected on the most recent handshake, if any. `None`
    /// after a handshake where the client offered no ALPN extension at all.
    negotiated_alpn: Arc<Mutex<Option<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A TLS server speaking just enough HTTP/1.1 that both legs agree on what "the
/// request worked" means.
async fn spawn_server(leaf: &Leaf, required_client_ca_der: Option<Vec<u8>>) -> TestServer {
    spawn_server_offering_alpn(leaf, required_client_ca_der, &[]).await
}

/// As [`spawn_server`], but advertising an ALPN list of its own.
///
/// A server that offers nothing selects nothing, which is what the trust cases
/// want; a server that offers `h2` and `http/1.1` is what makes the client's own
/// ALPN list observable.
async fn spawn_server_offering_alpn(
    leaf: &Leaf,
    required_client_ca_der: Option<Vec<u8>>,
    server_alpn: &[&[u8]],
) -> TestServer {
    install_test_provider();

    let builder = ServerConfig::builder();
    let mut server_config = match required_client_ca_der {
        Some(ca_der) => {
            let mut client_roots = RootCertStore::empty();
            client_roots
                .add(CertificateDer::from(ca_der))
                .expect("test client CA should be accepted");
            let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .expect("test client verifier should build");
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(
        vec![CertificateDer::from(leaf.certificate_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.private_key_der.clone())),
    )
    .expect("test server config should build");
    server_config.alpn_protocols = server_alpn
        .iter()
        .map(|protocol| protocol.to_vec())
        .collect();

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test server should bind");
    let address = listener
        .local_addr()
        .expect("test server address should be available");

    let handshakes = Arc::new(AtomicUsize::new(0));
    let observed_client_leaf: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let negotiated_alpn: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let handshake_count = Arc::clone(&handshakes);
    let observed = Arc::clone(&observed_client_leaf);
    let alpn_slot = Arc::clone(&negotiated_alpn);

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let handshake_count = Arc::clone(&handshake_count);
            let observed = Arc::clone(&observed);
            let alpn_slot = Arc::clone(&alpn_slot);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                handshake_count.fetch_add(1, Ordering::SeqCst);
                *alpn_slot.lock().expect("test lock") =
                    stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                if let Some(leaf) = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(<[CertificateDer<'static>]>::first)
                {
                    *observed.lock().expect("test lock") = Some(leaf.as_ref().to_vec());
                }
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
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.flush().await;
            });
        }
    });

    TestServer {
        address,
        handshakes,
        observed_client_leaf,
        negotiated_alpn,
        task,
    }
}

/// The rest of this crate's suite installs `ring` process-wide before standing
/// up a TLS fixture, so do the same here rather than letting the process default
/// depend on which test wins the race.
fn install_test_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ---------------------------------------------------------------------------
// Production leg: the real EgressClient
// ---------------------------------------------------------------------------

fn egress_config(host: &str, ca_pem: Option<&str>, identity_pem: Option<&str>) -> EgressConfig {
    let mut config = EgressConfig {
        allowed_hosts: HashSet::from([host.to_owned()]),
        deny_private_ips: false,
        max_response_bytes: 2,
        ..EgressConfig::default()
    };
    if let Some(pem) = ca_pem {
        config
            .apply_tls_ca_bundle_pem(pem.as_bytes())
            .expect("test CA bundle should apply");
    }
    if let Some(pem) = identity_pem {
        config
            .apply_tls_client_identity_pem(pem.as_bytes())
            .expect("test client identity should apply");
    }
    config
}

#[tokio::test]
async fn approved_mutation_egress_uses_a_fresh_socket_and_never_retries_an_ambiguous_send() {
    use futures_util::StreamExt;
    use http::HeaderMap;
    use hyper_util::rt::TokioIo;
    const HOST: &str = "mutations.example.test";
    install_test_provider();
    let ca = certificate_authority("GreenGateway Mutation Test CA");
    let leaf = leaf(&ca, HOST, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf.certificate_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.private_key_der)),
        )
        .unwrap();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let sockets = Arc::new(AtomicUsize::new(0));
    let mutations = Arc::new(AtomicUsize::new(0));
    let accepted = sockets.clone();
    let received = mutations.clone();
    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        while let Ok((socket, _)) = listener.accept().await {
            accepted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let received = received.clone();
            tokio::spawn(async move {
                let stream = acceptor.accept(socket).await.unwrap();
                let service = hyper::service::service_fn(
                    move |request: http::Request<hyper::body::Incoming>| {
                        let received = received.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            if parts.method == Method::POST {
                                let bytes = axum::body::to_bytes(axum::body::Body::new(body), 16)
                                    .await
                                    .unwrap();
                                assert_eq!(bytes.as_ref(), b"body");
                                received.fetch_add(1, Ordering::SeqCst);
                                if parts.uri.path() == "/ambiguous" {
                                    return Err(std::io::Error::other("close after receipt"));
                                }
                            }
                            Ok(http::Response::new(axum::body::Body::empty()))
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let client = EgressClient::new_with_resolver(
        egress_config(HOST, Some(&ca.pem()), None),
        Arc::new(StaticResolver { address }),
    )
    .unwrap();
    let url = format!("https://{HOST}:{}/mutation", address.port());
    let destination = client.checked_destination(&url).await.unwrap();
    // The server supports persistent connections. Ordinary traffic demonstrably reuses them.
    for _ in 0..6 {
        client.request(Method::GET, &url).await.unwrap();
    }
    let ordinary_sockets = sockets.load(Ordering::SeqCst);
    assert!(ordinary_sockets < 6);
    for occurrence in 1..=2 {
        let mut response = client
            .stream_approved_mutation_at_checked_destination(
                &destination,
                Method::POST,
                &url,
                HeaderMap::new(),
                Some(b"body".to_vec()),
            )
            .await
            .unwrap();
        assert!(response.body.next().await.is_none());
        assert_eq!(mutations.load(Ordering::SeqCst), occurrence);
        assert_eq!(
            sockets.load(Ordering::SeqCst),
            ordinary_sockets + occurrence
        );
    }
    let ambiguous = format!("https://{HOST}:{}/ambiguous", address.port());
    assert!(client
        .stream_approved_mutation_at_checked_destination(
            &destination,
            Method::POST,
            &ambiguous,
            HeaderMap::new(),
            Some(b"body".to_vec())
        )
        .await
        .is_err());
    assert_eq!(mutations.load(Ordering::SeqCst), 3);
    assert_eq!(sockets.load(Ordering::SeqCst), ordinary_sockets + 3);
    server.abort();
}

/// Drives the whole production path -- allowlist, DNS pinning, the pinned client
/// cache, and the shared TLS config -- and reports only the trust verdict.
async fn production_verdict(
    host: &str,
    address: SocketAddr,
    ca_pem: Option<&str>,
    identity_pem: Option<&str>,
) -> (Verdict, String) {
    let config = egress_config(host, ca_pem, identity_pem);
    let client = match EgressClient::new_with_resolver_and_cache(
        config,
        Arc::new(StaticResolver { address }),
        Arc::new(PinnedClientCache::new()),
    ) {
        Ok(client) => client,
        Err(error) => return (Verdict::Reject, format!("builder: {error:?}")),
    };

    let url = format!("https://{host}:{}/resource", address.port());
    Verdict::of(client.request(Method::GET, &url).await)
}

// ---------------------------------------------------------------------------
// Comparison leg: the same material through each construction
// ---------------------------------------------------------------------------

fn hand_built_config(
    ca_pem: Option<&str>,
    identity_pem: Option<&str>,
    construction: Construction,
) -> Result<ClientConfig, String> {
    let roots = match ca_pem {
        Some(pem) => tls::parse_ca_bundle_pem(pem.as_bytes())
            .map_err(|error| format!("ca bundle: {error:?}"))?,
        None => Vec::new(),
    };
    let identity = match identity_pem {
        Some(pem) => Some(
            tls::parse_client_identity_pem(pem.as_bytes())
                .map_err(|error| format!("identity: {error:?}"))?,
        ),
        None => None,
    };

    match construction {
        // Not a reimplementation: this is the configuration production hands to
        // reqwest, reached through the same function.
        Construction::Production => {
            tls::client_config(&roots, identity.as_ref(), ProtocolProfile::Http1AndHttp2)
                .map_err(|error| format!("production config: {error:?}"))
        }
        Construction::RootsOnly => {
            // Same provider and same protocol versions as production, so the
            // only thing this leg varies is the trust construction. A second
            // difference here would make a disagreement ambiguous.
            let builder = ClientConfig::builder_with_provider(tls::crypto_provider())
                .with_protocol_versions(rustls::ALL_VERSIONS)
                .map_err(|error| format!("versions: {error:?}"))?;
            let mut store = RootCertStore::empty();
            for root in roots {
                store
                    .add(root)
                    .map_err(|error| format!("root store: {error:?}"))?;
            }
            let builder = builder.with_root_certificates(store);
            let mut config = match identity {
                Some(identity) => {
                    // `TlsClientIdentity` does not lend out its private key, so
                    // the alternative construction takes the parsed identity
                    // apart rather than the production type growing an accessor
                    // for it.
                    let (certificates, private_key) = identity.into_parts();
                    builder
                        .with_client_auth_cert(certificates, private_key)
                        .map_err(|error| format!("client auth: {error:?}"))?
                }
                None => builder.with_no_client_auth(),
            };
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Ok(config)
        }
    }
}

async fn hand_built_verdict(
    host: &str,
    address: SocketAddr,
    ca_pem: Option<&str>,
    identity_pem: Option<&str>,
    construction: Construction,
) -> (Verdict, String) {
    let config = match hand_built_config(ca_pem, identity_pem, construction) {
        Ok(config) => config,
        Err(error) => return (Verdict::Reject, format!("builder: {error}")),
    };

    let result = async {
        let tcp = TcpStream::connect(address)
            .await
            .map_err(|error| format!("tcp: {error}"))?;
        let name = ServerName::try_from(host.to_owned())
            .map_err(|error| format!("server name: {error:?}"))?;
        let mut stream = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|error| format!("handshake: {error}"))?;
        // The exchange has to complete, not just the handshake: under TLS 1.3 a
        // client finishes its side before the server has validated the client
        // certificate, so a refused mTLS identity surfaces as an alert on the
        // first read rather than as a handshake error.
        let request =
            format!("GET /resource HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("write: {error}"))?;
        let mut response = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(read) => {
                    response.extend_from_slice(&chunk[..read]);
                    if response.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(error) => {
                    // The fixture closes without `close_notify`, which rustls
                    // reports as an error. Bytes already read still count, so an
                    // unclean EOF after a complete status line is not a trust
                    // failure.
                    if response.is_empty() {
                        return Err(format!("read: {error}"));
                    }
                    break;
                }
            }
        }
        if !response.starts_with(b"HTTP/1.1 200") {
            return Err(format!(
                "unexpected response: {}",
                String::from_utf8_lossy(&response)
            ));
        }
        Ok::<(), String>(())
    }
    .await;

    Verdict::of(result)
}

/// Runs one offline case through every leg and reports what each decided.
async fn assert_all_legs_agree(
    case: &str,
    expected: Verdict,
    host: &str,
    address: SocketAddr,
    ca_pem: Option<&str>,
    identity_pem: Option<&str>,
) {
    let (production, production_detail) =
        production_verdict(host, address, ca_pem, identity_pem).await;
    let (shared, shared_detail) = hand_built_verdict(
        host,
        address,
        ca_pem,
        identity_pem,
        Construction::Production,
    )
    .await;
    let (roots_only, roots_only_detail) =
        hand_built_verdict(host, address, ca_pem, identity_pem, Construction::RootsOnly).await;

    eprintln!(
        "[egress-trust] {case}\n  \
         egress client   = {production:?} {production_detail}\n  \
         shared config   = {shared:?} {shared_detail}\n  \
         roots-only      = {roots_only:?} {roots_only_detail}"
    );

    assert_eq!(
        production, expected,
        "{case}: the egress client reached the wrong verdict ({production_detail})"
    );
    assert_eq!(
        shared, expected,
        "{case}: the shared TLS config disagreed with the egress client ({shared_detail})"
    );
    assert_eq!(
        roots_only, expected,
        "{case}: the roots-only construction disagreed here, which no offline fixture should \
         be able to show -- if this fires, the case has started discriminating and case (e) \
         is no longer the only guard ({roots_only_detail})"
    );
}

// ---------------------------------------------------------------------------
// (a)-(d2): offline. None of these can distinguish the two constructions.
// ---------------------------------------------------------------------------

/// (a) The configured CA signed the server: trusted.
#[tokio::test]
async fn case_a_a_configured_ca_is_trusted() {
    let host = "trust-a.example.test";
    let ca = certificate_authority("GreenGateway Trust Test CA A");
    let server_leaf = leaf(&ca, host, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let server = spawn_server(&server_leaf, None).await;

    assert_all_legs_agree(
        "case (a) configured CA",
        Verdict::Accept,
        host,
        server.address,
        Some(&ca.pem()),
        None,
    )
    .await;
    assert!(
        server.handshakes.load(Ordering::SeqCst) >= 3,
        "every leg should have reached the fixture server"
    );
}

/// (b) A CA the deployment did not configure: refused.
#[tokio::test]
async fn case_b_an_unconfigured_ca_is_refused() {
    let host = "trust-b.example.test";
    let serving_ca = certificate_authority("GreenGateway Trust Test Serving CA B");
    let other_ca = certificate_authority("GreenGateway Trust Test Unrelated CA B");
    let server_leaf = leaf(
        &serving_ca,
        host,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    );
    let server = spawn_server(&server_leaf, None).await;

    assert_all_legs_agree(
        "case (b) unconfigured CA",
        Verdict::Reject,
        host,
        server.address,
        Some(&other_ca.pem()),
        None,
    )
    .await;
}

/// (c) The right CA for the wrong name: refused. Hostname verification is not
/// something the shared config may quietly drop.
#[tokio::test]
async fn case_c_a_trusted_certificate_for_another_hostname_is_refused() {
    let served_host = "trust-c.example.test";
    let requested_host = "trust-c-other.example.test";
    let ca = certificate_authority("GreenGateway Trust Test CA C");
    let server_leaf = leaf(&ca, served_host, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let server = spawn_server(&server_leaf, None).await;

    assert_all_legs_agree(
        "case (c) wrong hostname",
        Verdict::Reject,
        requested_host,
        server.address,
        Some(&ca.pem()),
        None,
    )
    .await;
}

/// (d) Mutual TLS: accepted, and the server sees the identity that was
/// configured rather than some other one.
#[tokio::test]
async fn case_d_the_configured_client_identity_is_the_one_presented() {
    let host = "trust-d.example.test";
    let server_ca = certificate_authority("GreenGateway Trust Test Server CA D");
    let client_ca = certificate_authority("GreenGateway Trust Test Client CA D");
    let server_leaf = leaf(&server_ca, host, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let client_leaf = leaf(
        &client_ca,
        "trust-client-d.example.test",
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    );
    let server = spawn_server(&server_leaf, Some(client_ca.der())).await;

    let (verdict, detail) = production_verdict(
        host,
        server.address,
        Some(&server_ca.pem()),
        Some(&client_leaf.identity_pem),
    )
    .await;
    eprintln!("[egress-trust] case (d) egress client = {verdict:?} {detail}");
    assert_eq!(
        verdict,
        Verdict::Accept,
        "the egress client failed its mTLS leg: {detail}"
    );
    assert_eq!(
        server
            .observed_client_leaf
            .lock()
            .expect("test lock")
            .as_deref(),
        Some(client_leaf.certificate_der.as_slice()),
        "the server did not observe the configured client certificate"
    );

    for construction in [Construction::Production, Construction::RootsOnly] {
        *server.observed_client_leaf.lock().expect("test lock") = None;
        let (verdict, detail) = hand_built_verdict(
            host,
            server.address,
            Some(&server_ca.pem()),
            Some(&client_leaf.identity_pem),
            construction,
        )
        .await;
        eprintln!("[egress-trust] case (d) {construction:?} = {verdict:?} {detail}");
        assert_eq!(
            verdict,
            Verdict::Accept,
            "{construction:?} failed its mTLS leg: {detail}"
        );
        assert_eq!(
            server
                .observed_client_leaf
                .lock()
                .expect("test lock")
                .as_deref(),
            Some(client_leaf.certificate_der.as_slice()),
            "{construction:?} presented a different client certificate"
        );
    }
}

/// (d2) The negative control for (d). Without it, (d) would still pass if the
/// server had stopped checking client certificates at all.
#[tokio::test]
async fn case_d2_a_client_identity_from_an_untrusted_ca_is_refused() {
    let host = "trust-d2.example.test";
    let server_ca = certificate_authority("GreenGateway Trust Test Server CA D2");
    let accepted_client_ca = certificate_authority("GreenGateway Trust Test Accepted Client CA D2");
    let rogue_client_ca = certificate_authority("GreenGateway Trust Test Rogue Client CA D2");
    let server_leaf = leaf(&server_ca, host, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let rogue_leaf = leaf(
        &rogue_client_ca,
        "trust-rogue-d2.example.test",
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    );
    let server = spawn_server(&server_leaf, Some(accepted_client_ca.der())).await;

    assert_all_legs_agree(
        "case (d2) rogue client identity",
        Verdict::Reject,
        host,
        server.address,
        Some(&server_ca.pem()),
        Some(&rogue_leaf.identity_pem),
    )
    .await;
}

// ---------------------------------------------------------------------------
// (e): the only discriminating case, and the only one that needs a network.
// ---------------------------------------------------------------------------

/// (e) A publicly signed host, reached by a client that ALSO configures a
/// private CA.
///
/// This is the regression the shared config exists to make impossible, and the
/// only test that can observe it:
///
/// ```text
///   egress client -> Accept    configured CAs are extra roots
///   shared config -> Accept    the construction production uses
///   roots-only    -> Reject    the platform trust store was replaced
/// ```
///
/// `#[ignore]`d because it needs a real public trust anchor, not because it is
/// optional. Run it by hand whenever reqwest is upgraded. If `egress client`
/// ever comes back `Reject`, reqwest no longer layers configured CAs on top of
/// the platform store and [`super::tls`] must be re-read against the new source
/// before it is trusted again.
#[tokio::test]
#[ignore = "needs a real publicly signed host; run on every reqwest upgrade with --ignored"]
async fn case_e_a_public_host_stays_trusted_when_a_private_ca_is_also_configured() {
    install_test_provider();

    let host = PUBLIC_TRUST_ANCHOR_HOST.to_owned();
    let private_ca = certificate_authority("GreenGateway Trust Test Unrelated Private CA");
    let ca_pem = private_ca.pem();
    let url = format!("https://{host}/");

    let public_config = |ca_pem: Option<&str>| {
        let mut config = EgressConfig {
            allowed_hosts: HashSet::from([host.clone()]),
            ..EgressConfig::default()
        };
        if let Some(pem) = ca_pem {
            config
                .apply_tls_ca_bundle_pem(pem.as_bytes())
                .expect("test CA bundle should apply");
        }
        config
    };

    let baseline = match EgressClient::new(public_config(None)) {
        Ok(client) => Verdict::of(client.request(Method::GET, &url).await),
        Err(error) => (Verdict::Reject, format!("builder: {error:?}")),
    };
    let with_private_ca = match EgressClient::new(public_config(Some(&ca_pem))) {
        Ok(client) => Verdict::of(client.request(Method::GET, &url).await),
        Err(error) => (Verdict::Reject, format!("builder: {error:?}")),
    };
    let shared = public_handshake_verdict(&host, Some(&ca_pem), Construction::Production).await;
    let roots_only = public_handshake_verdict(&host, Some(&ca_pem), Construction::RootsOnly).await;

    eprintln!(
        "[egress-trust] case (e) against {host}\n  \
         egress client, no private CA = {:?} {}\n  \
         egress client, private CA    = {:?} {}\n  \
         shared config                = {:?} {}\n  \
         roots-only                   = {:?} {}",
        baseline.0,
        baseline.1,
        with_private_ca.0,
        with_private_ca.1,
        shared.0,
        shared.1,
        roots_only.0,
        roots_only.1
    );

    assert_eq!(
        baseline.0,
        Verdict::Accept,
        "{host} was not reached with no custom CA configured. An `UnknownIssuer` here is NOT a \
         network problem: it means the platform trust store is no longer consulted at all, \
         which is the regression this case exists to catch. Anything else is a network \
         precondition failure ({})",
        baseline.1
    );
    assert_eq!(
        with_private_ca.0,
        Verdict::Accept,
        "adding a private CA narrowed outbound trust. Configured CAs are no longer EXTRA \
         roots, and every publicly signed upstream in a deployment with a private CA is now \
         unreachable ({})",
        with_private_ca.1
    );
    assert_eq!(
        shared.0,
        Verdict::Accept,
        "the shared TLS config disagreed with the egress client ({})",
        shared.1
    );
    assert_eq!(
        roots_only.0,
        Verdict::Reject,
        "the roots-only construction accepted a public CA it was never given, so this case is \
         no longer discriminating and nothing in this suite guards the extra-roots property \
         ({})",
        roots_only.1
    );
}

/// The trust decision against a real host: the handshake alone, with no request.
async fn public_handshake_verdict(
    host: &str,
    ca_pem: Option<&str>,
    construction: Construction,
) -> (Verdict, String) {
    let config = match hand_built_config(ca_pem, None, construction) {
        Ok(config) => config,
        Err(error) => return (Verdict::Reject, format!("builder: {error}")),
    };

    let result = async {
        let tcp = TcpStream::connect((host, 443))
            .await
            .map_err(|error| format!("tcp: {error}"))?;
        let name = ServerName::try_from(host.to_owned())
            .map_err(|error| format!("server name: {error:?}"))?;
        TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await
            .map_err(|error| format!("handshake: {error}"))?;
        Ok::<(), String>(())
    }
    .await;

    Verdict::of(result)
}

// ---------------------------------------------------------------------------
// Part two: what a preconfigured backend turns off
//
// Both of the properties below are consequences of reqwest's `BuiltRustls` arm
// (`reqwest-0.13.4/src/async_impl/client.rs:642-685`) doing nothing but pass the
// config to the connector. They are observed here rather than taken from that
// reading, because getting either one wrong is silent: the wrong ALPN panics
// deep inside hyper-util, and lost trust material shows up only against a
// private-CA upstream.
// ---------------------------------------------------------------------------

/// The client's ALPN list has to be set on the shared config, because
/// `.http1_only()` no longer reaches it.
///
/// The server offers `h2` and `http/1.1`, so what it selects is decided by what
/// the client offered. Deleting the `alpn_protocols` assignment in
/// `tls::client_config` makes this observe `None` -- no ALPN extension sent at
/// all -- which this fixture would still serve over HTTP/1.1. That is exactly
/// why the assertion is on the negotiated protocol and not on the request
/// succeeding.
#[tokio::test]
async fn the_shared_config_offers_http1_to_a_server_that_would_have_taken_h2() {
    let host = "alpn.example.test";
    let ca = certificate_authority("GreenGateway ALPN Test CA");
    let server_leaf = leaf(&ca, host, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let server = spawn_server_offering_alpn(&server_leaf, None, &[b"h2", b"http/1.1"]).await;

    let (verdict, detail) = production_verdict(host, server.address, Some(&ca.pem()), None).await;
    assert_eq!(
        verdict,
        Verdict::Accept,
        "the request should succeed: {detail}"
    );

    let negotiated = server.negotiated_alpn.lock().expect("test lock").clone();
    assert_eq!(
        negotiated.as_deref(),
        Some(b"http/1.1".as_slice()),
        "the shared config must offer http/1.1; `None` means no ALPN extension was sent, \
         which leaves the protocol up to the upstream"
    );
}

/// `add_root_certificate` on the reqwest builder is inert once a config is
/// preconfigured, which is why the loop that used to call it was deleted rather
/// than left in place.
///
/// The CA reaches the builder through reqwest's own API and nothing else, and
/// the connection must still be refused. If this ever starts passing, reqwest
/// has begun merging its own trust material into a preconfigured backend and
/// `base_client_builder_for_profile` should be re-read against the new source.
#[tokio::test]
async fn a_ca_given_only_to_the_reqwest_builder_does_not_establish_trust() {
    let host = "dead-roots.example.test";
    let ca = certificate_authority("GreenGateway Dead Roots Test CA");
    let server_leaf = leaf(&ca, host, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let server = spawn_server(&server_leaf, None).await;
    let url = format!("https://{host}:{}/resource", server.address.port());

    // Positive control: the same CA through `EgressConfig` -- the only route
    // that now exists -- is trusted.
    let (verdict, detail) = production_verdict(host, server.address, Some(&ca.pem()), None).await;
    assert_eq!(
        verdict,
        Verdict::Accept,
        "the CA must work when it goes through the shared config: {detail}"
    );

    // The same CA, handed to reqwest instead. The shared config this builder
    // carries has no trust material at all.
    let certificate = reqwest::Certificate::from_pem(ca.pem().as_bytes())
        .expect("test CA should parse as a reqwest certificate");
    let client = base_client_builder_for_profile(
        &egress_config(host, None, None),
        ProtocolProfile::Http1AndHttp2,
    )
    .expect("a builder with no trust material should still build")
    .add_root_certificate(certificate)
    .resolve(host, server.address)
    .build()
    .expect("the reqwest client should build");

    let (verdict, detail) = Verdict::of(client.get(&url).send().await);
    eprintln!(
        "[egress-tls] add_root_certificate under a preconfigured backend = {verdict:?} {detail}"
    );
    assert_eq!(
        verdict,
        Verdict::Reject,
        "reqwest honoured `add_root_certificate` under a preconfigured backend; the shared \
         config is no longer the only source of outbound trust"
    );
    assert!(
        detail.contains("UnknownIssuer"),
        "the refusal must be a trust decision rather than an unrelated failure: {detail}"
    );
}

/// The cost of getting the ALPN list wrong, observed rather than assumed.
///
/// `scripts/check-egress-only.sh` keeps `hyper-util/http2` off, and without that
/// feature hyper-util does not report an h2-negotiated connection as an error --
/// it panics (`hyper-util-0.1.20/src/client/legacy/client.rs:563`). So an ALPN
/// list carrying `h2` is not a degraded mode, it is a crash on the first request
/// to any upstream that accepts h2. This is why `tls::client_config` states the
/// ALPN list per profile instead of leaving it to be inherited.
///
/// The panic below is expected. It is raised in a spawned task and observed
/// through the `JoinHandle`, so the panic message in the test output is part of
/// the test passing.
#[tokio::test]
async fn an_h2_alpn_list_panics_hyper_util_rather_than_erroring() {
    let host = "alpn-h2.example.test";
    let ca = certificate_authority("GreenGateway ALPN h2 Test CA");
    let server_leaf = leaf(&ca, host, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let server = spawn_server_offering_alpn(&server_leaf, None, &[b"h2", b"http/1.1"]).await;

    let mut config = hand_built_config(Some(&ca.pem()), None, Construction::Production)
        .expect("the shared config should build");
    config.alpn_protocols = vec![b"h2".to_vec()];

    let client = base_client_builder_for_profile(
        &egress_config(host, Some(&ca.pem()), None),
        ProtocolProfile::Http1AndHttp2,
    )
    .expect("the builder should build")
    .tls_backend_preconfigured(config)
    .resolve(host, server.address)
    .build()
    .expect("the reqwest client should build");

    let url = format!("https://{host}:{}/resource", server.address.port());
    eprintln!("[egress-tls] the panic that follows is the assertion of this test, not a failure");
    let outcome = tokio::spawn(async move { client.get(url).send().await.is_ok() }).await;

    assert!(
        outcome
            .as_ref()
            .err()
            .is_some_and(tokio::task::JoinError::is_panic),
        "an h2-negotiated connection was expected to panic hyper-util in a build without its \
         http2 feature; got {outcome:?}"
    );
    assert_eq!(
        wait_for_negotiated_alpn(&server).await.as_deref(),
        Some(b"h2".as_slice()),
        "the preconfigured ALPN list must have reached the handshake; `.http1_only()` was in \
         effect on this builder and did not override it"
    );
}

/// Waits for the fixture server to record a negotiated protocol.
///
/// The client panics as soon as the handshake reports `h2`, without sending a
/// request, so it can be gone before the server's accept task has resumed. The
/// wait is bounded, and a timeout returns `None` so the assertion that called it
/// fails rather than the test hanging.
async fn wait_for_negotiated_alpn(server: &TestServer) -> Option<Vec<u8>> {
    for _ in 0..200 {
        if let Some(protocol) = server.negotiated_alpn.lock().expect("test lock").clone() {
            return Some(protocol);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    None
}

// ---------------------------------------------------------------------------
// Part three: what the TLS stream reports when its transport fails
// ---------------------------------------------------------------------------

/// An in-memory transport that, once armed, fails with `ConnectionAborted`
/// where it would otherwise wait for more bytes.
///
/// Bytes already in the pipe are read first, so the failure lands strictly
/// after them: inside the read that returns the last of them, when that read
/// still has room for more.
struct AbortsWhenDrained {
    inner: DuplexStream,
    armed: Arc<AtomicBool>,
}

impl AsyncRead for AbortsWhenDrained {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Pending if self.armed.load(Ordering::SeqCst) => Poll::Ready(Err(
                std::io::Error::from(std::io::ErrorKind::ConnectionAborted),
            )),
            other => other,
        }
    }
}

impl AsyncWrite for AbortsWhenDrained {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A transport error that follows data is reported, not folded into a clean
/// end of stream.
///
/// The fixture writes one record and stays connected, and then the transport
/// fails. The first read must return the record and the second the
/// transport's error. tokio-rustls 0.26.5 answered the second read with
/// `Ok(0)`, which is also how an upstream that finished a close-delimited
/// response ends it, so hyper would have taken a body cut off here as
/// complete. 0.26.6 keeps the error for the next read.
#[tokio::test]
async fn a_transport_abort_after_data_is_an_error_not_the_end_of_the_stream() {
    const BODY: &[u8] = b"the first part of a close-delimited body";

    install_test_provider();
    let host = "abort.example.test";
    let ca = certificate_authority("GreenGateway Transport Abort Test CA");
    let server_leaf = leaf(&ca, host, rcgen::ExtendedKeyUsagePurpose::ServerAuth);
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_leaf.certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                server_leaf.private_key_der.clone(),
            )),
        )
        .expect("test server config should build");
    let client_config = hand_built_config(Some(&ca.pem()), None, Construction::Production)
        .expect("the shared config should build");

    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let (written, wait_for_written) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut stream = TlsAcceptor::from(Arc::new(server_config))
            .accept(server_io)
            .await
            .expect("the fixture handshake should complete");
        stream
            .write_all(BODY)
            .await
            .expect("the fixture should write");
        stream.flush().await.expect("the fixture should flush");
        let _ = written.send(());
        // Stay connected: closing here would be an end of stream, another case.
        std::future::pending::<()>().await;
    });

    let armed = Arc::new(AtomicBool::new(false));
    let transport = AbortsWhenDrained {
        inner: client_io,
        armed: Arc::clone(&armed),
    };
    let name = ServerName::try_from(host.to_owned()).expect("test host should be a server name");
    let mut stream = TlsConnector::from(Arc::new(client_config))
        .connect(name, transport)
        .await
        .expect("the client handshake should complete");

    // Armed only once the record is in the pipe, so one read takes the record
    // and then, with room to spare, meets the failed transport.
    wait_for_written
        .await
        .expect("the fixture should have written");
    armed.store(true, Ordering::SeqCst);

    let mut buffer = [0_u8; 1024];
    let read = stream
        .read(&mut buffer)
        .await
        .expect("the record should be read before the failure");
    assert_eq!(&buffer[..read], BODY);

    let outcome = stream.read(&mut buffer).await;
    server.abort();
    let error = outcome.expect_err(
        "a transport abort after data must be an error; `Ok(0)` is how a finished \
         close-delimited response ends",
    );
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted,
        "the transport's own error should reach the reader: {error}"
    );
}
