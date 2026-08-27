//! Transport tests for the outbound gRPC (HTTP/2) client.
//!
//! Everything here is about the TLS half, which nothing else covers: the
//! proxy-level tests in `proxy::grpc::tests` drive plaintext h2c so they can
//! stand up an upstream cheaply, and that leaves ALPN, trust, and the shared
//! TLS configuration untested. The cases below stand up a real TLS server and
//! observe what the transport does with it.

use std::{
    collections::HashSet,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use hyper::body::{Body as HttpBody, Frame};
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

use super::{
    client_cache::ProtocolProfile, grpc::GrpcRequestBody, DnsResolver, EgressClient, EgressConfig,
    EgressError, GrpcFailure,
};

const HOST: &str = "grpc-upstream.example.test";

struct StaticResolver {
    address: SocketAddr,
}

#[async_trait]
impl DnsResolver for StaticResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        Ok(vec![self.address])
    }
}

/// An empty request body: these tests are about the connection, not the payload.
struct EmptyBody;

impl HttpBody for EmptyBody {
    type Data = Bytes;
    type Error = EgressError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, EgressError>>> {
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        true
    }
}

struct ServerFixture {
    ca_pem: String,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

fn server_fixture() -> ServerFixture {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GreenGateway gRPC Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
    let ca_certificate = ca_params
        .self_signed(&ca_key)
        .expect("test CA certificate should build");

    let mut params = rcgen::CertificateParams::new(vec![HOST.to_owned()])
        .expect("test server certificate parameters should build");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("test server key should generate");
    let certificate = params
        .signed_by(&key, &ca_certificate, &ca_key)
        .expect("test server certificate should build");

    ServerFixture {
        ca_pem: ca_certificate.pem(),
        certificate_der: certificate.der().as_ref().to_vec(),
        private_key_der: key.serialize_der(),
    }
}

/// Stands up an HTTPS server with the given ALPN list.
///
/// An EMPTY list is the interesting case, not an oversight: rustls skips ALPN
/// selection entirely when either side offers nothing
/// (`rustls-0.23.41/src/server/hs.rs:100-119`), so the handshake succeeds with
/// no protocol negotiated. That is the shape a fail-closed client has to catch
/// on its own, because TLS will not fail it.
async fn spawn_tls_upstream(fixture: &ServerFixture, alpn: &[&[u8]]) -> SocketAddr {
    spawn_counted_tls_upstream(fixture, alpn).await.0
}

/// The same server, with a count of the connections it accepted.
///
/// One accepted connection is one HTTP/2 handshake, so the count is how the
/// pool's partitioning is observed: two calls that share a pooled connection
/// produce one, two that must not share produce two.
async fn spawn_counted_tls_upstream(
    fixture: &ServerFixture,
    alpn: &[&[u8]],
) -> (SocketAddr, Arc<AtomicUsize>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fixture.certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture.private_key_der.clone())),
        )
        .expect("test TLS server config should build");
    server_config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("TLS upstream should bind");
    let address = listener
        .local_addr()
        .expect("TLS upstream address should be available");
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&connections);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    |_: hyper::Request<hyper::body::Incoming>| async move {
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                        trailers.insert("grpc-message", http::HeaderValue::from_static("tls-ok"));
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(TrailersOnlyBody {
                                    trailers: Some(trailers),
                                })
                                .expect("TLS upstream response should build"),
                        )
                    },
                );
                crate::proxy::grpc::listen::test_support::serve_one(stream, service).await;
            });
        }
    });

    (address, connections)
}

struct TrailersOnlyBody {
    trailers: Option<http::HeaderMap>,
}

impl HttpBody for TrailersOnlyBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(
            self.trailers
                .take()
                .map(|trailers| Ok(Frame::trailers(trailers))),
        )
    }
}

fn egress_client(address: SocketAddr, ca_pem: Option<&str>) -> EgressClient {
    let mut config = EgressConfig {
        allowed_hosts: HashSet::from([HOST.to_owned()]),
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        response_idle_timeout: Duration::from_secs(5),
        deny_private_ips: false,
        ..EgressConfig::default()
    };
    if let Some(ca_pem) = ca_pem {
        config
            .apply_tls_ca_bundle_pem(ca_pem.as_bytes())
            .expect("test CA bundle should apply");
    }

    EgressClient::new_with_resolver(config, Arc::new(StaticResolver { address }))
        .expect("test egress client should build")
}

async fn call(
    client: &EgressClient,
    address: SocketAddr,
) -> Result<super::grpc::GrpcResponse, EgressError> {
    let url = format!("https://{HOST}:{}/pkg.Service/Method", address.port());
    let destination = client.checked_destination(&url).await?;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    headers.insert(http::header::TE, http::HeaderValue::from_static("trailers"));

    client
        .grpc_call_at_checked_destination(
            &destination,
            &url,
            headers,
            GrpcRequestBody::new(EmptyBody),
            Duration::from_secs(2),
        )
        .await
}

/// The positive control for every fail-closed case below: with the private CA
/// configured and the server selecting `h2`, a call completes over TLS.
#[tokio::test]
async fn a_tls_endpoint_that_selects_h2_carries_a_call() {
    let fixture = server_fixture();
    let address = spawn_tls_upstream(&fixture, &[b"h2"]).await;
    let client = egress_client(address, Some(&fixture.ca_pem));

    let response = call(&client, address)
        .await
        .expect("a TLS endpoint that speaks h2 should carry the call");
    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(
        response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
}

/// A server that completes the handshake without selecting `h2` is refused.
///
/// This is the case TLS itself will NOT catch. rustls skips ALPN selection
/// entirely when the server offers no list, so the handshake succeeds and the
/// connection is simply not h2 — and the transport is about to speak HTTP/2 at
/// it. Refusing here rather than discovering the consequences in production is
/// the whole reason the check exists.
#[tokio::test]
async fn a_tls_endpoint_that_does_not_select_h2_is_refused_after_the_handshake() {
    let fixture = server_fixture();
    let address = spawn_tls_upstream(&fixture, &[]).await;
    let client = egress_client(address, Some(&fixture.ca_pem));

    let error = call(&client, address)
        .await
        .expect_err("a connection that negotiated no protocol must be refused");
    assert!(
        matches!(error, EgressError::Grpc(GrpcFailure::AlpnNotH2)),
        "expected an ALPN refusal, got {}",
        error.safe_category()
    );
}

/// An endpoint whose certificate does not chain to a configured or platform
/// trust anchor is refused, exactly as it is on every other outbound path.
#[tokio::test]
async fn an_untrusted_tls_endpoint_is_refused() {
    let fixture = server_fixture();
    let address = spawn_tls_upstream(&fixture, &[b"h2"]).await;
    // Same server, no CA configured: the private CA is not in the platform
    // store, so the chain does not verify.
    let client = egress_client(address, None);

    let error = call(&client, address)
        .await
        .expect_err("an untrusted certificate must be refused");
    assert!(
        matches!(error, EgressError::Grpc(GrpcFailure::Tls)),
        "expected a TLS refusal, got {}",
        error.safe_category()
    );
}

/// The gRPC protocol profile has no reqwest transport, and asking for one is an
/// error rather than a panic.
///
/// Without this the builder succeeds and hands reqwest a TLS configuration
/// whose ALPN list is `h2`. In a build without `hyper-util/http2` that does not
/// error at construction; it PANICS at request time, inside hyper-util
/// (`hyper-util-0.1.20/src/client/legacy/client.rs:562-563`), on whatever task
/// happened to make the call.
#[tokio::test]
async fn the_grpc_profile_has_no_reqwest_transport() {
    let config = EgressConfig::default();

    // `let ... else` rather than `expect_err`, because `reqwest::ClientBuilder`
    // is not `Debug` and so cannot be unwrapped out of the `Ok` side.
    let Err(error) = super::base_client_builder_for_profile(&config, ProtocolProfile::Grpc) else {
        panic!("the gRPC profile must not build a reqwest client");
    };
    assert!(
        matches!(error, EgressError::InvalidPolicy(ref message)
            if message.contains("gRPC protocol profile")),
        "expected an explicit refusal, got {}",
        error.safe_category()
    );

    // The control: every other profile still builds, so the refusal is about
    // the gRPC profile and not about the builder being broken.
    for profile in [
        ProtocolProfile::Http1AndHttp2,
        ProtocolProfile::Sse,
        ProtocolProfile::UpgradeHttp1,
    ] {
        assert!(
            super::base_client_builder_for_profile(&config, profile).is_ok(),
            "{profile:?} must still build a reqwest client"
        );
    }
}

/// Two clients whose TLS material differs never share a pooled connection.
///
/// This is what makes custom-CA isolation and per-endpoint mutual-TLS isolation
/// properties of the pool KEY rather than of a check somewhere: the key carries
/// the trust-anchor fingerprint, the client-identity fingerprint, and the opaque
/// transport partition, so material that differs cannot reach the same socket.
///
/// Both halves are asserted. Without the first -- two calls from one client
/// reusing one connection -- the second would prove nothing, because a
/// transport that never pooled at all would also open two.
#[tokio::test]
async fn upstream_connections_are_partitioned_by_tls_material() {
    let fixture = server_fixture();
    let (address, connections) = spawn_counted_tls_upstream(&fixture, &[b"h2"]).await;

    let client = egress_client(address, Some(&fixture.ca_pem));
    for attempt in 0..2 {
        call(&client, address)
            .await
            .unwrap_or_else(|error| panic!("call {attempt} should succeed: {error}"));
    }
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "two calls from one client must share one pooled HTTP/2 connection"
    );

    // A second client trusting a DIFFERENT set of anchors, to the same address.
    let other = server_fixture();
    let widened = format!("{}{}", fixture.ca_pem, other.ca_pem);
    let widened_client = egress_client(address, Some(&widened));
    call(&widened_client, address)
        .await
        .expect("the widened-trust client should also reach the endpoint");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        2,
        "a client with different trust material shared a pooled connection with one that \
         has different trust material"
    );

    // And it keeps its own connection rather than opening a new one each time.
    call(&widened_client, address)
        .await
        .expect("the widened-trust client should reuse its own connection");
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

/// A certificate that does not name the host being connected to is refused.
///
/// The gRPC transport does not implement hostname verification of its own; it
/// gets it from the one shared `rustls::ClientConfig` that `egress::tls` builds
/// for every outbound transport. This asserts that it really is getting it,
/// rather than having quietly opted out by constructing its own connector.
#[tokio::test]
async fn a_certificate_for_another_host_is_refused() {
    let fixture = server_fixture();
    let address = spawn_tls_upstream(&fixture, &[b"h2"]).await;

    // Trust the CA, then ask for a different name than the leaf certifies.
    let mut config = EgressConfig {
        allowed_hosts: HashSet::from(["other.example.test".to_owned()]),
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        response_idle_timeout: Duration::from_secs(5),
        deny_private_ips: false,
        ..EgressConfig::default()
    };
    config
        .apply_tls_ca_bundle_pem(fixture.ca_pem.as_bytes())
        .expect("test CA bundle should apply");
    let client = EgressClient::new_with_resolver(config, Arc::new(StaticResolver { address }))
        .expect("test egress client should build");

    let url = format!(
        "https://other.example.test:{}/pkg.Service/Method",
        address.port()
    );
    let destination = client
        .checked_destination(&url)
        .await
        .expect("the destination should pass the egress policy");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/grpc"),
    );
    headers.insert(http::header::TE, http::HeaderValue::from_static("trailers"));

    let error = client
        .grpc_call_at_checked_destination(
            &destination,
            &url,
            headers,
            GrpcRequestBody::new(EmptyBody),
            Duration::from_secs(2),
        )
        .await
        .expect_err("a certificate for another host must be refused");
    assert!(
        matches!(error, EgressError::Grpc(GrpcFailure::Tls)),
        "expected a TLS refusal, got {}",
        error.safe_category()
    );
}
