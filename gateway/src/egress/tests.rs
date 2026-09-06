use std::{
    collections::{HashMap, VecDeque},
    io::{self, ErrorKind},
    net::IpAddr,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
    time::Duration,
};

use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing_subscriber::fmt::MakeWriter;

use super::*;

#[tokio::test]
async fn request_phase_disconnect_is_a_retryable_transport_failure() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener should bind");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("test connection");
        let mut request = vec![0_u8; 4096];
        let _ = stream.read(&mut request).await;
        // Close without response headers, modelling a pooled upstream that
        // disappears while an otherwise replay-safe request is in flight.
    });

    let error = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("test client")
        .get(format!("http://{address}/disconnect"))
        .send()
        .await
        .expect_err("closed upstream should fail before response headers");
    server.await.expect("test server should finish");

    assert!(error.is_request());
    assert!(!error.is_connect());
    assert!(EgressError::Http(error).is_retryable_transport_failure());
}

#[tokio::test]
async fn counted_stream_allows_exact_limit_with_backpressure() {
    let source_polls = Arc::new(AtomicUsize::new(0));
    let polls = Arc::clone(&source_polls);
    let source = stream::iter([Bytes::from_static(b"ab"), Bytes::from_static(b"cd")])
        .inspect(move |_| {
            polls.fetch_add(1, Ordering::SeqCst);
        })
        .map(Ok);
    let failure = Arc::new(AtomicU8::new(REQUEST_BODY_OK));
    let counted = counted_request_body_stream(Box::pin(source), 4, Arc::clone(&failure));
    futures_util::pin_mut!(counted);

    assert_eq!(
        counted.next().await.expect("first chunk").expect("success"),
        Bytes::from_static(b"ab")
    );
    assert_eq!(source_polls.load(Ordering::SeqCst), 1);
    assert_eq!(
        counted
            .next()
            .await
            .expect("second chunk")
            .expect("success"),
        Bytes::from_static(b"cd")
    );
    assert!(counted.next().await.is_none());
    assert_eq!(failure.load(Ordering::Acquire), REQUEST_BODY_OK);
}

#[tokio::test]
async fn counted_stream_caps_underdeclared_or_chunked_body_before_error() {
    let source = stream::iter([
        Ok(Bytes::from_static(b"abc")),
        Ok(Bytes::from_static(b"def")),
    ]);
    let failure = Arc::new(AtomicU8::new(REQUEST_BODY_OK));
    let counted = counted_request_body_stream(Box::pin(source), 4, Arc::clone(&failure));
    futures_util::pin_mut!(counted);

    assert_eq!(
        counted.next().await.expect("first chunk").expect("success"),
        Bytes::from_static(b"abc")
    );
    assert_eq!(
        counted
            .next()
            .await
            .expect("bounded partial chunk")
            .expect("success"),
        Bytes::from_static(b"d")
    );
    assert!(counted.next().await.expect("overflow marker").is_err());
    assert_eq!(failure.load(Ordering::Acquire), REQUEST_BODY_TOO_LARGE);
}

#[tokio::test]
async fn known_stream_length_over_limit_fails_before_dns_or_dial() {
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket(
        "93.184.216.34:80",
    )]));
    let mut config = egress_config_for_host("api.example.test");
    config.max_request_body_bytes = 3;
    let client =
        EgressClient::new_with_resolver(config, resolver.clone()).expect("client should build");
    let body = EgressRequestBody::streaming(Box::pin(stream::empty()), Some(4));

    let result = client
        .stream_request_with_body(
            Method::POST,
            "http://api.example.test/",
            HeaderMap::new(),
            body,
        )
        .await;

    assert!(matches!(
        result,
        Err(EgressError::RequestBodyTooLarge { size: 4, max: 3 })
    ));
    assert!(resolver.calls().is_empty());
}

#[tokio::test]
async fn dropping_counted_stream_cancels_and_drops_its_source() {
    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropSignal(Arc::clone(&dropped));
    let source = stream::unfold(Some(guard), |state| async move {
        let _state = state;
        std::future::pending::<
            Option<(
                Result<Bytes, EgressRequestBodySourceError>,
                Option<DropSignal>,
            )>,
        >()
        .await
    });
    let failure = Arc::new(AtomicU8::new(REQUEST_BODY_OK));
    let counted = counted_request_body_stream(Box::pin(source), 4, failure);

    drop(counted);

    assert!(dropped.load(Ordering::SeqCst));
}

#[derive(Clone)]
enum FakeResolution {
    Addresses(Vec<SocketAddr>),
    Error(ErrorKind),
}

struct FakeDnsResolver {
    resolution: FakeResolution,
    calls: Mutex<Vec<(String, u16)>>,
}

impl FakeDnsResolver {
    fn with_addresses(addresses: Vec<SocketAddr>) -> Self {
        Self {
            resolution: FakeResolution::Addresses(addresses),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn with_error(kind: ErrorKind) -> Self {
        Self {
            resolution: FakeResolution::Error(kind),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(String, u16)> {
        self.calls
            .lock()
            .expect("fake resolver calls lock should not be poisoned")
            .clone()
    }
}

#[async_trait]
impl DnsResolver for FakeDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        self.calls
            .lock()
            .expect("fake resolver calls lock should not be poisoned")
            .push((host.to_owned(), port));

        match &self.resolution {
            FakeResolution::Addresses(addresses) => Ok(addresses.clone()),
            FakeResolution::Error(kind) => Err(std::io::Error::new(*kind, "synthetic DNS failure")),
        }
    }
}

struct SequencedDnsResolver {
    resolutions: Mutex<VecDeque<FakeResolution>>,
    calls: AtomicUsize,
}

impl SequencedDnsResolver {
    fn new(resolutions: impl IntoIterator<Item = FakeResolution>) -> Self {
        Self {
            resolutions: Mutex::new(resolutions.into_iter().collect()),
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl DnsResolver for SequencedDnsResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let resolution = self
            .resolutions
            .lock()
            .expect("sequenced resolver lock should not be poisoned")
            .pop_front()
            .expect("test resolver should have one resolution per call");
        match resolution {
            FakeResolution::Addresses(addresses) => Ok(addresses),
            FakeResolution::Error(kind) => Err(std::io::Error::new(kind, "synthetic DNS failure")),
        }
    }
}

fn egress_config_for_host(host: &str) -> EgressConfig {
    EgressConfig {
        allowed_hosts: HashSet::from([host.to_owned()]),
        ..EgressConfig::default()
    }
}

#[test]
fn egress_generation_is_order_independent_and_change_sensitive() {
    let mut first = EgressConfig {
        allowed_hosts: HashSet::from(["a.example.test".to_owned(), "b.example.test".to_owned()]),
        allowed_host_globs: vec!["*.one.example".to_owned(), "*.two.example".to_owned()],
        private_ip_allow_cidrs: vec![
            "10.0.0.0/8".parse().expect("first CIDR should parse"),
            "192.168.0.0/16".parse().expect("second CIDR should parse"),
        ],
        allowed_ports: HashSet::from([443, 8443]),
        nat64_prefixes: vec![
            "64:ff9b:1::/48"
                .parse()
                .expect("first NAT64 prefix should parse"),
            "2001:db8:64::/96"
                .parse()
                .expect("second NAT64 prefix should parse"),
        ],
        ..EgressConfig::default()
    };
    let mut second = first.clone();
    second.allowed_host_globs.reverse();
    second.private_ip_allow_cidrs.reverse();
    second.nat64_prefixes.reverse();

    assert_eq!(
        egress_config_generation(&first),
        egress_config_generation(&second),
        "semantically unordered policy collections should hash identically"
    );

    first.connect_timeout += Duration::from_millis(1);
    assert_ne!(
        egress_config_generation(&first),
        egress_config_generation(&second),
        "transport-relevant changes must produce another generation"
    );

    first = second.clone();
    first.client_identity_fingerprint = Some([7; 32]);
    assert_ne!(
        egress_config_generation(&first),
        egress_config_generation(&second),
        "client identity changes must produce another egress generation"
    );
}

#[test]
fn in_memory_tls_material_is_validated_without_retaining_or_rendering_input() {
    let certified =
        rcgen::generate_simple_self_signed(vec!["tls-material.example.test".to_owned()])
            .expect("test certificate should generate");
    let ca_pem = certified.cert.pem();
    let identity_pem = format!("{}{}", ca_pem, certified.key_pair.serialize_pem());

    let mut config = EgressConfig {
        tls_ca_bundle_path: Some(PathBuf::from("old-locator-canary.pem")),
        ..EgressConfig::default()
    };
    config
        .apply_tls_ca_bundle_pem(ca_pem.as_bytes())
        .expect("in-memory CA bundle should be accepted");
    config
        .apply_tls_client_identity_pem(identity_pem.as_bytes())
        .expect("in-memory combined identity should be accepted");

    assert!(config.tls_ca_bundle_path.is_none());
    assert!(!config.tls_root_certificates.is_empty());
    assert!(config.client_identity.is_some());
    assert!(config.client_identity_fingerprint.is_some());
    let debug = format!("{config:?}");
    assert!(!debug.contains("old-locator-canary"));
    assert!(!debug.contains("BEGIN CERTIFICATE"));
    assert!(!debug.contains("BEGIN PRIVATE KEY"));
    assert!(!debug.contains("tls_root_set_fingerprint"));
    assert!(!debug.contains("client_identity_fingerprint"));

    let invalid_ca = b"TOP_SECRET_INVALID_CA_MATERIAL";
    let ca_error = EgressConfig::default()
        .apply_tls_ca_bundle_pem(invalid_ca)
        .expect_err("invalid in-memory CA material must fail");
    let rendered_ca_error = format!("{ca_error:?}\n{ca_error}");
    assert_eq!(ca_error.safe_category(), "invalid_tls_ca_bundle");
    assert!(!rendered_ca_error.contains(std::str::from_utf8(invalid_ca).expect("ASCII marker")));
    assert!(!rendered_ca_error.contains("memory"));

    let invalid_identity = b"TOP_SECRET_INVALID_IDENTITY_MATERIAL";
    let identity_error = EgressConfig::default()
        .apply_tls_client_identity_pem(invalid_identity)
        .expect_err("invalid in-memory identity material must fail");
    let rendered_identity_error = format!("{identity_error:?}\n{identity_error}");
    assert_eq!(
        identity_error.safe_category(),
        "invalid_tls_client_identity"
    );
    assert!(!rendered_identity_error
        .contains(std::str::from_utf8(invalid_identity).expect("ASCII marker")));

    let ca_path = std::env::temp_dir().join(format!(
        "greengateway-in-memory-ca-delegation-{}.pem",
        uuid::Uuid::new_v4()
    ));
    fs::write(&ca_path, ca_pem.as_bytes()).expect("test CA file should be written");
    let mut from_path = EgressConfig::default();
    from_path
        .apply_tls_ca_bundle_path(ca_path.clone())
        .expect("path CA setter should delegate to the PEM validator");
    assert_eq!(from_path.tls_ca_bundle_path.as_ref(), Some(&ca_path));
    assert_eq!(
        from_path.tls_root_set_fingerprint,
        config.tls_root_set_fingerprint
    );
    let _ = fs::remove_file(ca_path);
}

#[test]
fn opaque_transport_partition_changes_transport_but_not_policy_identity() {
    let base = egress_config_for_host("partition.example.test");
    let mut first = base.clone();
    first.apply_transport_partition(b"connection-partition-a-canary");
    let mut same = base.clone();
    same.apply_transport_partition(b"connection-partition-a-canary");
    let mut different = base.clone();
    different.apply_transport_partition(b"connection-partition-b-canary");

    assert_ne!(base, first);
    assert_eq!(first, same);
    assert_ne!(first, different);
    assert_eq!(
        egress_policy_generation(&first),
        egress_policy_generation(&different),
        "transport partitioning must not alter effective egress policy"
    );
    assert_eq!(
        egress_config_generation(&first),
        egress_config_generation(&same)
    );
    assert_ne!(
        egress_config_generation(&first),
        egress_config_generation(&different)
    );

    let debug = format!("{first:?}");
    assert!(debug.contains("transport_partitioned: true"));
    assert!(!debug.contains("transport_partition:"));
    assert!(!debug.contains("connection-partition-a-canary"));
}

#[tokio::test]
async fn rebind_adopts_only_same_policy_and_authority_without_dns() {
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket("8.8.8.8:443")]));
    let base_config = EgressConfig {
        allowed_hosts: HashSet::from([
            "rebind.example.test".to_owned(),
            "other.example.test".to_owned(),
        ]),
        ..EgressConfig::default()
    };
    let client = isolated_egress_client(base_config.clone(), resolver.clone());
    let url = "https://rebind.example.test/resource";
    let destination = client
        .checked_destination(url)
        .await
        .expect("initial egress policy and DNS check should succeed");

    let mut transport_config = base_config.clone();
    transport_config.timeout += Duration::from_secs(1);
    transport_config.apply_transport_partition(b"reconfigured-transport");
    let reconfigured = client
        .reconfigured(transport_config)
        .expect("transport-only reconfiguration should build");

    assert_eq!(
        destination.policy_generation,
        reconfigured.policy_generation
    );
    assert_ne!(
        destination.config_generation,
        reconfigured.config_generation
    );
    let rebound = reconfigured
        .rebind_checked_destination(&destination, url)
        .expect("same-policy exact destination should be rebound");
    assert_eq!(rebound.pinned_addr, destination.pinned_addr);
    assert_eq!(rebound.config_generation, reconfigured.config_generation);
    assert_eq!(
        resolver.calls(),
        vec![("rebind.example.test".to_owned(), 443)],
        "rebind must not perform DNS"
    );

    reconfigured
        .mcp_reqwest_client_at_checked_destination(&rebound, url)
        .expect("rebound destination should select an MCP-safe pinned client");
    reconfigured
        .mcp_reqwest_client_at_checked_destination(&rebound, url)
        .expect("identical MCP transport should reuse the pinned client");
    assert_eq!(reconfigured.client_cache.len(), 1);
    assert_eq!(
        resolver.calls().len(),
        1,
        "cached MCP client selection must not perform DNS"
    );

    let old_generation_error = reconfigured
        .mcp_reqwest_client_at_checked_destination(&destination, url)
        .expect_err("an un-rebound destination must not cross configurations");
    assert!(matches!(
        old_generation_error,
        EgressError::InvalidPolicy(_)
    ));

    let authority_error = reconfigured
        .rebind_checked_destination(&destination, "https://other.example.test/resource")
        .expect_err("rebind must not authorize another authority");
    assert!(matches!(authority_error, EgressError::InvalidPolicy(_)));

    let mut changed_policy = base_config;
    changed_policy
        .allowed_hosts
        .insert("policy-change.example.test".to_owned());
    let changed_policy_client = client
        .reconfigured(changed_policy)
        .expect("changed-policy client should build");
    let policy_error = changed_policy_client
        .rebind_checked_destination(&destination, url)
        .expect_err("destination must not cross effective egress policies");
    assert!(matches!(policy_error, EgressError::InvalidPolicy(_)));

    let mut tampered_destination = destination;
    tampered_destination.pinned_addr = socket("10.0.0.1:443");
    let socket_error = reconfigured
        .rebind_checked_destination(&tampered_destination, url)
        .expect_err("pinned socket must be revalidated without DNS");
    assert!(matches!(
        socket_error,
        EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("10.0.0.1")
    ));
    assert_eq!(resolver.calls().len(), 1);

    let destination_debug = format!("{rebound:?}");
    assert!(!destination_debug.contains("generation"));
    assert!(!destination_debug.contains("transport_partition"));
}

fn isolated_egress_client(config: EgressConfig, resolver: Arc<dyn DnsResolver>) -> EgressClient {
    EgressClient::new_with_resolver_and_cache(
        config,
        resolver,
        Arc::new(client_cache::PinnedClientCache::new()),
    )
    .expect("isolated test client should build")
}

#[test]
fn egress_error_safe_categories_are_bounded_constants() {
    let errors = vec![
        (
            EgressError::HostNotAllowed("secret-host".to_owned()),
            "host_not_allowed",
        ),
        (EgressError::PortNotAllowed(1234), "port_not_allowed"),
        (
            EgressError::NonGlobalIpBlocked(ip("127.0.0.1")),
            "non_global_ip_blocked",
        ),
        (
            EgressError::InvalidPolicy("secret-policy".to_owned()),
            "invalid_policy",
        ),
        (
            EgressError::DnsResolutionFailed("secret-dns-detail".to_owned()),
            "dns_resolution_failed",
        ),
        (
            EgressError::InvalidUrl("secret-url".to_owned()),
            "invalid_url",
        ),
        (
            EgressError::SchemeNotAllowed("secret-scheme".to_owned()),
            "scheme_not_allowed",
        ),
        (
            EgressError::RequestBodyTooLarge { size: 2, max: 1 },
            "request_body_too_large",
        ),
        (
            EgressError::ResponseTooLarge { size: 2, max: 1 },
            "response_too_large",
        ),
        (
            EgressError::ResponseIdleTimeout {
                timeout: Duration::from_millis(1),
            },
            "response_idle_timeout",
        ),
        (
            EgressError::InvalidTlsCaBundle {
                path: PathBuf::from("secret-ca-path").into(),
                message: "secret-ca-error".to_owned(),
            },
            "invalid_tls_ca_bundle",
        ),
        (
            EgressError::InvalidTlsClientIdentity,
            "invalid_tls_client_identity",
        ),
    ];

    for (error, expected) in errors {
        let category = error.safe_category();
        assert_eq!(category, expected);
        assert!(category.len() <= 32);
        assert!(
            category
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "unsafe category characters in {category}"
        );
        assert!(!category.contains("secret"));
    }

    let http_error = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("test client should build")
        .get("http://[")
        .build()
        .expect_err("invalid URL should create a reqwest error");
    let http_category = EgressError::Http(http_error).safe_category();
    assert!(matches!(
        http_category,
        "http_timeout"
            | "http_connect"
            | "http_request"
            | "http_body"
            | "http_decode"
            | "http_status"
            | "http_other"
    ));
}

#[test]
fn a_certificate_without_a_trailing_newline_still_joins_into_a_parsable_identity() {
    let key = rcgen::KeyPair::generate().expect("test identity key should generate");
    let certificate = rcgen::CertificateParams::new(vec!["client.example.test".to_owned()])
        .expect("test identity parameters should build")
        .self_signed(&key)
        .expect("test identity certificate should build");
    let certificate_pem = certificate.pem();
    let key_pem = key.serialize_pem();

    // Both certificate shapes must yield a parsable identity. The preflight
    // check and the request path build this document from the same helper,
    // so the bytes a write validates are the bytes the transport later
    // sends; while they had separate assemblers only newline-terminated
    // fixtures were ever exercised, so a divergence could not be caught.
    let unterminated = certificate_pem.trim_end_matches('\n');
    assert!(!unterminated.ends_with('\n'));
    let joined = join_tls_client_identity_pem(unterminated.as_bytes(), key_pem.as_bytes())
        .expect("joining a bounded pair should succeed");
    assert!(tls_client_identity_pem_is_valid(joined.as_slice()));
    assert_eq!(joined.len(), unterminated.len() + 1 + key_pem.len());

    // A certificate that already ends in a newline gains no second one.
    let already_terminated =
        join_tls_client_identity_pem(certificate_pem.as_bytes(), key_pem.as_bytes())
            .expect("joining a bounded pair should succeed");
    assert!(tls_client_identity_pem_is_valid(
        already_terminated.as_slice()
    ));
    assert_eq!(
        already_terminated.len(),
        certificate_pem.len() + key_pem.len()
    );
}

#[test]
fn a_half_validator_rejects_material_of_the_wrong_kind_or_a_corrupt_body() {
    let key = rcgen::KeyPair::generate().expect("test identity key should generate");
    let certificate = rcgen::CertificateParams::new(vec!["client.example.test".to_owned()])
        .expect("test identity parameters should build")
        .self_signed(&key)
        .expect("test identity certificate should build");
    let certificate_pem = certificate.pem();
    let key_pem = key.serialize_pem();

    assert!(tls_client_identity_half_is_valid(
        certificate_pem.as_bytes(),
        true
    ));
    assert!(tls_client_identity_half_is_valid(key_pem.as_bytes(), false));

    // Each half must reject the other's material, so a rotation cannot put
    // a certificate where a key belongs.
    assert!(!tls_client_identity_half_is_valid(key_pem.as_bytes(), true));
    assert!(!tls_client_identity_half_is_valid(
        certificate_pem.as_bytes(),
        false
    ));

    // Garbage, and a key whose markers are intact but whose body is
    // truncated or corrupt — marker counting alone accepted the latter.
    assert!(!tls_client_identity_half_is_valid(
        b"not-a-private-key",
        false
    ));
    let corrupt = key_pem.replace("-----END", "!!!!!\n-----END");
    assert!(!tls_client_identity_half_is_valid(
        corrupt.as_bytes(),
        false
    ));
    let unterminated = key_pem.replace("-----END PRIVATE KEY-----", "");
    assert!(!tls_client_identity_half_is_valid(
        unterminated.as_bytes(),
        false
    ));
}

#[test]
fn mounted_tls_client_identity_is_validated_and_redacted() {
    let key = rcgen::KeyPair::generate().expect("test identity key should generate");
    let certificate = rcgen::CertificateParams::new(vec!["client.example.test".to_owned()])
        .expect("test identity parameters should build")
        .self_signed(&key)
        .expect("test identity certificate should build");
    let valid_pem = format!("{}{}", certificate.pem(), key.serialize_pem());
    let valid_path = std::env::temp_dir().join(format!(
        "greengateway-valid-client-identity-{}.pem",
        uuid::Uuid::new_v4()
    ));
    fs::write(&valid_path, valid_pem.as_bytes()).expect("valid test identity should be written");

    let mut config = EgressConfig::default();
    config
        .apply_tls_client_identity_pem_path(valid_path.clone())
        .expect("matching certificate and key should be accepted");
    assert!(config.client_identity.is_some());
    assert!(config.client_identity_fingerprint.is_some());
    let debug = format!("{config:?}");
    assert!(debug.contains("client_identity_configured: true"));
    assert!(!debug.contains("BEGIN CERTIFICATE"));
    assert!(!debug.contains("BEGIN PRIVATE KEY"));

    let other_key =
        rcgen::KeyPair::generate().expect("mismatched test identity key should generate");
    let mismatched_pem = format!("{}{}", certificate.pem(), other_key.serialize_pem());
    let mismatched_path = std::env::temp_dir().join(format!(
        "greengateway-mismatched-client-identity-{}.pem",
        uuid::Uuid::new_v4()
    ));
    fs::write(&mismatched_path, mismatched_pem.as_bytes())
        .expect("mismatched test identity should be written");

    let error = EgressConfig::default()
        .apply_tls_client_identity_pem_path(mismatched_path.clone())
        .expect_err("a certificate and unrelated private key must fail startup validation");
    assert_eq!(error.safe_category(), "invalid_tls_client_identity");
    let rendered = format!("{error:?}\n{error}");
    assert!(!rendered.contains("BEGIN CERTIFICATE"));
    assert!(!rendered.contains("BEGIN PRIVATE KEY"));
    assert!(!rendered.contains(&other_key.serialize_pem()));

    let duplicate_key_pem = format!("{valid_pem}{}", key.serialize_pem());
    let duplicate_key_path = std::env::temp_dir().join(format!(
        "greengateway-duplicate-client-key-{}.pem",
        uuid::Uuid::new_v4()
    ));
    fs::write(&duplicate_key_path, duplicate_key_pem.as_bytes())
        .expect("duplicate-key test identity should be written");
    EgressConfig::default()
        .apply_tls_client_identity_pem_path(duplicate_key_path.clone())
        .expect_err("an identity PEM with multiple private keys must fail validation");

    let secret_marker = "TOP_SECRET_CLIENT_IDENTITY_BYTES";
    let invalid_path = std::env::temp_dir().join(format!(
        "greengateway-invalid-client-identity-{}.pem",
        uuid::Uuid::new_v4()
    ));
    fs::write(&invalid_path, secret_marker).expect("invalid test identity should be written");
    let error = EgressConfig::default()
        .apply_tls_client_identity_pem_path(invalid_path.clone())
        .expect_err("non-PEM identity bytes must fail startup validation");
    assert!(!format!("{error:?}\n{error}").contains(secret_marker));

    let oversized_path = std::env::temp_dir().join(format!(
        "greengateway-oversized-client-identity-{}.pem",
        uuid::Uuid::new_v4()
    ));
    fs::write(
        &oversized_path,
        vec![b'x'; MAX_TLS_CLIENT_IDENTITY_PEM_BYTES + 1],
    )
    .expect("oversized test identity should be written");
    let error = EgressConfig::default()
        .apply_tls_client_identity_pem_path(oversized_path.clone())
        .expect_err("an oversized identity PEM must fail bounded startup validation");
    assert_eq!(error.safe_category(), "invalid_tls_client_identity");
    assert!(!format!("{error:?}\n{error}").contains(
        oversized_path
            .file_name()
            .expect("oversized test file should have a name")
            .to_string_lossy()
            .as_ref()
    ));

    let _ = fs::remove_file(valid_path);
    let _ = fs::remove_file(mismatched_path);
    let _ = fs::remove_file(duplicate_key_path);
    let _ = fs::remove_file(invalid_path);
    let _ = fs::remove_file(oversized_path);
}

#[test]
fn rejected_scheme_log_exposes_only_a_bounded_category() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(logs.clone())
        .finish();
    let _guard = crate::tracing_test_guard(subscriber);
    let client =
        EgressClient::new(EgressConfig::default()).expect("scheme log test client should build");

    // Touch the rejection callsite once while our subscriber is installed,
    // then re-evaluate the interest cache.
    //
    // `rebuild_interest_cache` only revisits callsites that have already
    // registered, and this one is reached by many other egress tests. Those
    // tests do not take `TRACING_TEST_LOCK`, so one of them can register the
    // callsite -- on its own subscriber-less thread, which caches
    // `Interest::never` process-wide -- at any point, including after the
    // rebuild `tracing_test_guard` performs on entry. The warmup alone does
    // not repair that: registration happens once per process, so a callsite
    // another thread already stamped `never` stays `never` and the warmup is
    // a no-op. Warming up first *and then* rebuilding covers both orders:
    // the warmup guarantees the callsite is registered, and the rebuild --
    // still under the lock, with our subscriber installed on this thread --
    // guarantees its cached interest reflects our subscriber rather than
    // whichever thread happened to reach it first.
    let _ = client.checked_url("warmup-scheme://warmup.invalid/warmup");
    tracing::callsite::rebuild_interest_cache();
    logs.clear();

    let error = client
        .checked_url("secret-scheme://secret-host.example/private?token=secret-query")
        .expect_err("unsupported URL scheme should fail closed");
    assert!(matches!(error, EgressError::SchemeNotAllowed(_)));
    drop(_guard);

    let output = logs.contents();
    assert!(output.contains("scheme_not_allowed"));
    for secret in ["secret-scheme", "secret-host", "private", "secret-query"] {
        assert!(
            !output.contains(secret),
            "scheme rejection log leaked {secret}: {output}"
        );
    }
}

#[test]
fn sensitive_response_debug_redacts_headers_and_body() {
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::WWW_AUTHENTICATE,
        reqwest::header::HeaderValue::from_static("Bearer realm=\"challenge-canary\""),
    );
    let response = SensitiveEgressResponse {
        status: StatusCode::UNAUTHORIZED,
        headers,
        body: Zeroizing::new(b"access-token-canary".to_vec()),
    };

    let rendered = format!("{response:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("challenge-canary"));
    assert!(!rendered.contains("access-token-canary"));
}

#[tokio::test]
async fn injected_resolver_preserves_answer_order_and_records_host_and_port() {
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![
        socket("8.8.8.8:8443"),
        socket("1.1.1.1:8443"),
    ]));
    let client = EgressClient::new_with_resolver(
        egress_config_for_host("api.example.test"),
        resolver.clone(),
    )
    .expect("client should build");

    let destination = client
        .checked_destination("https://api.example.test:8443/resource")
        .await
        .expect("public answer set should be accepted");

    assert_eq!(destination.host, "api.example.test");
    assert_eq!(destination.pinned_addr, socket("8.8.8.8:8443"));
    assert_eq!(
        resolver.calls(),
        vec![("api.example.test".to_owned(), 8443)]
    );
}

#[tokio::test]
async fn every_dns_path_rejects_a_mixed_public_and_private_answer_set() {
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![
        socket("8.8.8.8:443"),
        socket("10.0.0.8:443"),
    ]));
    let client = EgressClient::new_with_resolver(
        egress_config_for_host("api.example.test"),
        resolver.clone(),
    )
    .expect("client should build");

    let destination_error = client
        .checked_destination("https://api.example.test/resource")
        .await
        .expect_err("destination check should reject a mixed answer set");
    let request_error = client
        .request_with_headers(
            Method::GET,
            "https://api.example.test/resource",
            HeaderMap::new(),
            None,
        )
        .await
        .expect_err("buffered request should reject a mixed answer set");
    let stream_error = client
        .stream_request_with_headers(
            Method::GET,
            "https://api.example.test/resource",
            HeaderMap::new(),
            None,
        )
        .await
        .expect_err("streaming request should reject a mixed answer set");

    for error in [destination_error, request_error, stream_error] {
        assert!(matches!(
            error,
            EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("10.0.0.8")
        ));
    }
    assert_eq!(
        resolver.calls(),
        vec![("api.example.test".to_owned(), 443); 3]
    );
}

#[tokio::test]
async fn injected_resolver_empty_answer_fails_closed() {
    let resolver = Arc::new(FakeDnsResolver::with_addresses(Vec::new()));
    let client =
        EgressClient::new_with_resolver(egress_config_for_host("empty.example.test"), resolver)
            .expect("client should build");

    let error = client
        .checked_destination("https://empty.example.test/resource")
        .await
        .expect_err("empty DNS answers should deny");

    assert!(matches!(
        error,
        EgressError::DnsResolutionFailed(message)
            if message == "empty.example.test:443"
    ));
}

#[tokio::test]
async fn injected_resolver_error_fails_closed() {
    let resolver = Arc::new(FakeDnsResolver::with_error(ErrorKind::TimedOut));
    let client =
        EgressClient::new_with_resolver(egress_config_for_host("error.example.test"), resolver)
            .expect("client should build");

    let error = client
        .checked_destination("https://error.example.test:8443/resource")
        .await
        .expect_err("resolver errors should deny");

    assert!(matches!(
        error,
        EgressError::DnsResolutionFailed(message)
            if message.starts_with("error.example.test:8443:")
    ));
}

#[tokio::test]
async fn injected_resolver_wrong_port_fails_closed() {
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket(
        "8.8.8.8:9443",
    )]));
    let client =
        EgressClient::new_with_resolver(egress_config_for_host("port.example.test"), resolver)
            .expect("client should build");

    let error = client
        .checked_destination("https://port.example.test:8443/resource")
        .await
        .expect_err("resolver answers for a different port should deny");

    assert!(matches!(
        error,
        EgressError::DnsResolutionFailed(message)
            if message.starts_with("port.example.test:8443:")
    ));
}

#[tokio::test]
async fn reconfigured_client_preserves_injected_resolver() {
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket("8.8.8.8:443")]));
    let client = EgressClient::new_with_resolver(
        egress_config_for_host("first.example.test"),
        resolver.clone(),
    )
    .expect("client should build");
    client
        .checked_destination("https://first.example.test/resource")
        .await
        .expect("original client should use injected resolver");

    let reconfigured = client
        .reconfigured(egress_config_for_host("second.example.test"))
        .expect("reconfigured client should build");
    reconfigured
        .checked_destination("https://second.example.test/resource")
        .await
        .expect("reconfigured client should retain injected resolver");

    assert_eq!(
        resolver.calls(),
        vec![
            ("first.example.test".to_owned(), 443),
            ("second.example.test".to_owned(), 443),
        ]
    );
}

#[tokio::test]
async fn egress_client_sends_directly_with_proxy_discovery_disabled() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("direct test listener should bind");
    let addr = listener
        .local_addr()
        .expect("direct listener address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("direct server should accept one connection");
        read_one_request(&stream).await;
        write_all(
            &stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect",
        )
        .await;
    });
    let client = EgressClient::new(EgressConfig {
        allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
        deny_private_ips: false,
        timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_millis(500),
        max_response_bytes: 6,
        ..EgressConfig::default()
    })
    .expect("client should build");

    let response = client
        .request(Method::GET, &format!("http://{addr}/"))
        .await
        .expect("ambient proxy settings must not intercept egress");

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, b"direct");
    server.await.expect("direct server should finish");
}

#[tokio::test]
async fn an_upgrade_response_yields_a_bidirectional_stream_through_the_pinned_destination() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("upgrade listener should bind");
    let addr = listener
        .local_addr()
        .expect("upgrade address should be available");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("upgrade server should accept one connection");
        read_one_request(&stream).await;
        write_all(
                &stream,
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .await;
        // Prove the socket is genuinely bidirectional after the switch.
        let mut received = [0u8; 4];
        stream
            .read_exact(&mut received)
            .await
            .expect("upgraded server should read bytes from the gateway");
        assert_eq!(&received, b"ping");
        stream
            .write_all(b"pong")
            .await
            .expect("upgraded server should write");
    });

    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![addr]));
    let config = EgressConfig {
        allowed_hosts: HashSet::from(["upgrade.example.test".to_owned()]),
        deny_private_ips: false,
        timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_millis(500),
        ..EgressConfig::default()
    };
    let client = EgressClient::new_with_resolver(config, resolver.clone())
        .expect("upgrade client should build");
    let url = format!("http://upgrade.example.test:{}/socket", addr.port());
    let destination = client
        .checked_destination(&url)
        .await
        .expect("destination should pass policy");

    let response = client
        .upgrade_request_at_checked_destination(&destination, &url, HeaderMap::new())
        .await
        .expect("upgrade request should reach the pinned destination");
    assert_eq!(response.status, StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        response
            .headers
            .get("upgrade")
            .and_then(|value| value.to_str().ok()),
        Some("websocket")
    );

    let mut upgraded = response
        .into_upgraded()
        .await
        .expect("a 101 response should yield the raw stream");
    upgraded
        .write_all(b"ping")
        .await
        .expect("upgraded stream should be writable");
    let mut echoed = [0u8; 4];
    upgraded
        .read_exact(&mut echoed)
        .await
        .expect("upgraded stream should be readable");
    assert_eq!(&echoed, b"pong");

    // The whole exchange used exactly the one DNS decision already made.
    assert_eq!(
        resolver.calls(),
        vec![("upgrade.example.test".to_owned(), addr.port())]
    );
    server.await.expect("upgrade server should finish");
}

#[tokio::test]
async fn a_response_that_did_not_switch_protocols_never_yields_a_stream() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("refusing listener should bind");
    let addr = listener
        .local_addr()
        .expect("refusing address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("refusing server should accept one connection");
        read_one_request(&stream).await;
        // An upstream that answers an upgrade with an ordinary response,
        // body and all. None of it may become a tunnel.
        write_all(
            &stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nrefused",
        )
        .await;
    });

    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![addr]));
    let config = EgressConfig {
        allowed_hosts: HashSet::from(["refuse.example.test".to_owned()]),
        deny_private_ips: false,
        timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_millis(500),
        ..EgressConfig::default()
    };
    let client =
        EgressClient::new_with_resolver(config, resolver).expect("refusing client should build");
    let url = format!("http://refuse.example.test:{}/socket", addr.port());
    let destination = client
        .checked_destination(&url)
        .await
        .expect("destination should pass policy");

    let response = client
        .upgrade_request_at_checked_destination(&destination, &url, HeaderMap::new())
        .await
        .expect("the request itself succeeds; the upgrade is what failed");
    assert_eq!(response.status, StatusCode::OK);
    let error = response
        .into_upgraded()
        .await
        .expect_err("a non-101 response must not yield a stream");
    assert!(matches!(error, EgressError::InvalidPolicy(_)));
    server.await.expect("refusing server should finish");
}

#[test]
fn the_protocol_profile_partitions_the_pinned_client_cache_key() {
    // The pinned client cache is process-wide, so entry counts race with
    // every other test. What actually has to hold is that the profile is
    // part of the cache key: an upgraded connection must never be handed a
    // pooled client that ALPN-negotiated h2, and long-lived upgraded
    // sockets must not share a pool with ordinary requests.
    let key_for = |profile| client_cache::PinnedClientCacheKey {
        scheme: "http".to_owned(),
        host: "profiles.example.test".to_owned(),
        port: 8080,
        pinned_addr: "127.0.0.1:8080"
            .parse::<SocketAddr>()
            .expect("pinned address should parse"),
        egress_generation: [7u8; 32],
        request_timeout: Duration::from_secs(5),
        response_idle_timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(1),
        tls_root_set_fingerprint: [9u8; 32],
        client_identity_fingerprint: None,
        transport_partition: None,
        protocol_profile: profile,
        outbound_proxy_policy: client_cache::OutboundProxyPolicy::Disabled,
    };

    let ordinary = key_for(client_cache::ProtocolProfile::Http1AndHttp2);
    let sse = key_for(client_cache::ProtocolProfile::Sse);
    let upgrade = key_for(client_cache::ProtocolProfile::UpgradeHttp1);

    assert_ne!(upgrade, ordinary);
    assert_ne!(upgrade, sse);
    assert_ne!(ordinary, sse);
    assert_eq!(
        upgrade,
        key_for(client_cache::ProtocolProfile::UpgradeHttp1),
        "one destination and profile must resolve to a single cache entry"
    );
}

#[tokio::test]
async fn checked_destination_send_reuses_one_dns_decision_and_rejects_mismatches() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("checked-destination listener should bind");
    let addr = listener
        .local_addr()
        .expect("checked-destination address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("checked-destination server should accept one connection");
        read_one_request(&stream).await;
        write_all(
            &stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        .await;
    });
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![addr]));
    let config = EgressConfig {
        allowed_hosts: HashSet::from([
            "checked.example.test".to_owned(),
            "other.example.test".to_owned(),
        ]),
        deny_private_ips: false,
        timeout: Duration::from_secs(2),
        connect_timeout: Duration::from_millis(500),
        ..EgressConfig::default()
    };
    let client = EgressClient::new_with_resolver(config.clone(), resolver.clone())
        .expect("checked-destination client should build");
    let url = format!("http://checked.example.test:{}/resource", addr.port());
    let destination = client
        .checked_destination(&url)
        .await
        .expect("destination should pass one DNS and policy check");

    let response = client
        .request_with_headers_at_checked_destination(
            &destination,
            Method::GET,
            &url,
            HeaderMap::new(),
            None,
        )
        .await
        .expect("checked destination should send without another DNS lookup");
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        resolver.calls(),
        vec![("checked.example.test".to_owned(), addr.port())]
    );
    server
        .await
        .expect("checked-destination server should finish");

    let authority_error = client
        .request_with_headers_at_checked_destination(
            &destination,
            Method::GET,
            &format!("http://other.example.test:{}/resource", addr.port()),
            HeaderMap::new(),
            None,
        )
        .await
        .expect_err("a checked destination must not authorize another authority");
    assert!(matches!(authority_error, EgressError::InvalidPolicy(_)));

    let scheme_error = client
        .request_with_headers_at_checked_destination(
            &destination,
            Method::GET,
            &format!("https://checked.example.test:{}/resource", addr.port()),
            HeaderMap::new(),
            None,
        )
        .await
        .expect_err("a checked destination must not authorize a scheme change");
    assert!(matches!(scheme_error, EgressError::InvalidPolicy(_)));

    let mut changed_config = config;
    changed_config.timeout = Duration::from_secs(3);
    let changed_client = client
        .reconfigured(changed_config)
        .expect("changed egress client should build");
    let generation_error = changed_client
        .request_with_headers_at_checked_destination(
            &destination,
            Method::GET,
            &url,
            HeaderMap::new(),
            None,
        )
        .await
        .expect_err("a checked destination must not cross egress configurations");
    assert!(matches!(generation_error, EgressError::InvalidPolicy(_)));
}

#[test]
fn egress_client_ignores_ambient_proxy_environment() {
    let proxy_listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("ambient proxy sentinel listener should bind");
    let proxy_addr = proxy_listener
        .local_addr()
        .expect("ambient proxy sentinel address should be available");
    let proxy_url = format!("http://{proxy_addr}");
    let output = Command::new(std::env::current_exe().expect("test executable should exist"))
        .args([
            "--exact",
            "egress::tests::egress_client_sends_directly_with_proxy_discovery_disabled",
            "--nocapture",
        ])
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("all_proxy", &proxy_url)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .expect("proxy-isolation child test should start");

    assert!(
        output.status.success(),
        "proxy-isolation child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("running 1 test"),
        "proxy-isolation child must execute exactly one helper test: {stdout}"
    );
    proxy_listener
        .set_nonblocking(true)
        .expect("proxy sentinel should become nonblocking");
    assert!(
        matches!(proxy_listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
        "ambient proxy sentinel must receive zero connections"
    );
}

#[test]
fn non_global_ipv4_matches_registry_snapshot_and_multicast_policy() {
    for (address, expected_non_global) in [
        ("0.0.0.0", true),
        ("0.255.255.255", true),
        ("1.0.0.0", false),
        ("10.0.0.0", true),
        ("10.255.255.255", true),
        ("100.63.255.255", false),
        ("100.64.0.0", true),
        ("100.127.255.255", true),
        ("100.128.0.0", false),
        ("127.0.0.0", true),
        ("127.255.255.255", true),
        ("169.254.0.0", true),
        ("169.254.255.255", true),
        ("172.15.255.255", false),
        ("172.16.0.0", true),
        ("172.31.255.255", true),
        ("172.32.0.0", false),
        ("192.0.0.8", true),
        ("192.0.0.9", false),
        ("192.0.0.10", false),
        ("192.0.0.11", true),
        ("192.0.2.1", true),
        ("192.31.196.1", false),
        ("192.88.99.1", true),
        ("192.168.0.0", true),
        ("192.168.255.255", true),
        ("192.175.48.1", false),
        ("198.18.0.0", true),
        ("198.19.255.255", true),
        ("198.51.100.1", true),
        ("203.0.113.1", true),
        ("223.255.255.255", false),
        ("224.0.0.0", true),
        ("239.255.255.255", true),
        ("240.0.0.0", true),
        ("255.255.255.255", true),
        ("8.8.8.8", false),
    ] {
        assert_eq!(
            is_non_global_ip(ip(address), &[]),
            expected_non_global,
            "unexpected classification for {address}"
        );
    }
}

#[test]
fn non_global_ipv6_matches_registry_snapshot_and_global_unicast_policy() {
    for (address, expected_non_global) in [
        ("::", true),
        ("::1", true),
        ("::2", true),
        ("::ffff:127.0.0.1", true),
        ("::ffff:8.8.8.8", false),
        ("100::1", true),
        ("100:0:0:1::1", true),
        ("2001::1", true),
        ("2001:1::1", false),
        ("2001:1::2", false),
        ("2001:1::3", false),
        ("2001:2::1", true),
        ("2001:3::1", false),
        ("2001:4:112::1", false),
        ("2001:10::1", true),
        ("2001:20::1", false),
        ("2001:30::1", false),
        ("2001:db8::1", true),
        ("2002::1", true),
        ("2620:4f:8000::1", false),
        ("3fff::1", true),
        ("5f00::1", true),
        ("fc00::1", true),
        ("fe80::1", true),
        ("fec0::1", true),
        ("ff02::1", true),
        ("2606:4700:4700::1111", false),
        ("4000::1", true),
    ] {
        assert_eq!(
            is_non_global_ip(ip(address), &[]),
            expected_non_global,
            "unexpected classification for {address}"
        );
    }
}

#[test]
fn nat64_classification_uses_embedded_ipv4_and_requires_configured_local_prefixes() {
    assert!(is_non_global_ip(ip("64:ff9b::a9fe:a9fe"), &[]));
    assert!(!is_non_global_ip(ip("64:ff9b::808:808"), &[]));

    let local_use_public = ip("64:ff9b:1:808:8:800::");
    let local_use_private = ip("64:ff9b:1:a9fe:a9:fe00::");
    assert!(is_non_global_ip(local_use_public, &[]));

    let configured = vec!["64:ff9b:1::/48"
        .parse::<IpNet>()
        .expect("test NAT64 prefix should parse")];
    assert!(!is_non_global_ip(local_use_public, &configured));
    assert!(is_non_global_ip(local_use_private, &configured));
    assert!(is_non_global_ip(ip("64:ff9b:1:808:108:800::"), &configured));
}

#[test]
fn rfc6052_extraction_supports_every_standard_prefix_length() {
    let expected = Ipv4Addr::new(192, 0, 2, 33);
    for (prefix, address) in [
        ("2001:db8::/32", "2001:db8:c000:221::"),
        ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
        ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
        ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
        ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
        ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
    ] {
        let prefix = prefix
            .parse::<IpNet>()
            .expect("RFC 6052 example prefix should parse");
        let address = address
            .parse::<Ipv6Addr>()
            .expect("RFC 6052 example address should parse");
        assert!(prefix.contains(&IpAddr::V6(address)));
        assert_eq!(
            extract_rfc6052_ipv4(address, prefix.prefix_len()),
            Some(expected),
            "unexpected extraction for {prefix}"
        );
    }
}

#[test]
fn rfc6052_extraction_rejects_nonzero_u_octet_for_96_prefixes() {
    let prefix = "2001:db8:122:344:100::/96"
        .parse::<IpNet>()
        .expect("test prefix should parse");
    let address = "2001:db8:122:344:100:0:808:808"
        .parse::<Ipv6Addr>()
        .expect("test address should parse");

    assert!(prefix.contains(&IpAddr::V6(address)));
    assert_eq!(address.octets()[8], 1);
    assert_eq!(extract_rfc6052_ipv4(address, 96), None);
    assert!(is_non_global_ip(IpAddr::V6(address), &[prefix]));
}

#[test]
fn host_glob_matching_supports_exact_and_leading_wildcard_patterns() {
    assert!(host_glob_matches("api.example.test", "api.example.test"));
    assert!(host_glob_matches("API.EXAMPLE.TEST", "api.example.test"));
    assert!(!host_glob_matches("api.example.test", "other.example.test"));

    assert!(host_glob_matches("*.example.test", "api.example.test"));
    assert!(host_glob_matches("*.example.test", "v1.api.example.test"));
    assert!(!host_glob_matches("*.example.test", "example.test"));
    assert!(!host_glob_matches("*.example.test", "badexample.test"));
}

#[test]
fn policy_host_globs_extend_exact_env_allowlist() {
    let allowed_hosts = HashSet::from(["api.example.test".to_owned()]);
    let allowed_host_globs = vec!["*.svc.example.test".to_owned()];

    for url in [
        "https://api.example.test/resource",
        "https://worker.svc.example.test/resource",
        "https://v1.worker.svc.example.test/resource",
    ] {
        let url = Url::parse(url).expect("URL should parse");
        checked_host(&url, &allowed_hosts, &allowed_host_globs)
            .expect("exact env host or policy glob should allow");
    }

    let url = Url::parse("https://svc.example.test/resource").expect("URL should parse");
    let error = checked_host(&url, &allowed_hosts, &allowed_host_globs)
        .expect_err("wildcard should not match the suffix itself");

    assert!(matches!(
        error,
        EgressError::HostNotAllowed(host) if host == "svc.example.test"
    ));
}

#[test]
fn cidr_matching_covers_ipv4_edges() {
    let cidrs = vec!["192.168.1.0/24".parse().expect("CIDR should parse")];

    assert!(ip_matches_policy_cidr(ip("192.168.1.0"), &cidrs));
    assert!(ip_matches_policy_cidr(ip("192.168.1.255"), &cidrs));
    assert!(!ip_matches_policy_cidr(ip("192.168.0.255"), &cidrs));
    assert!(!ip_matches_policy_cidr(ip("192.168.2.0"), &cidrs));
}

#[test]
fn cidr_matching_covers_ipv6_edges() {
    let cidrs = vec!["2001:db8:abcd::/48".parse().expect("CIDR should parse")];

    assert!(ip_matches_policy_cidr(ip("2001:db8:abcd::"), &cidrs));
    assert!(ip_matches_policy_cidr(
        ip("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff"),
        &cidrs
    ));
    assert!(!ip_matches_policy_cidr(
        ip("2001:db8:abcc:ffff:ffff:ffff:ffff:ffff"),
        &cidrs
    ));
    assert!(!ip_matches_policy_cidr(ip("2001:db8:abce::"), &cidrs));
}

#[test]
fn policy_ports_restrict_only_when_non_empty() {
    checked_policy_port(8080, &HashSet::new())
        .expect("empty policy port set should preserve prior behavior");

    let allowed_ports = HashSet::from([443, 8443]);
    checked_policy_port(443, &allowed_ports).expect("listed port should be allowed");
    let error =
        checked_policy_port(8080, &allowed_ports).expect_err("unlisted port should be denied");

    assert!(matches!(error, EgressError::PortNotAllowed(8080)));
}

#[tokio::test]
async fn request_to_disallowed_policy_port_is_blocked() {
    let client = EgressClient::new(EgressConfig {
        allowed_hosts: HashSet::from(["api.example.test".to_owned()]),
        allowed_ports: HashSet::from([443]),
        ..EgressConfig::default()
    })
    .expect("client should build");

    let error = client
        .request(Method::GET, "https://api.example.test:8443/resource")
        .await
        .expect_err("unlisted destination port should be denied");

    assert!(matches!(error, EgressError::PortNotAllowed(8443)));
}

#[tokio::test]
async fn request_to_any_port_is_allowed_when_policy_ports_are_empty() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one connection");
        read_one_request(&stream).await;
        write_all(
            &stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        .await;
    });
    let client = EgressClient::new(EgressConfig {
        allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
        deny_private_ips: false,
        max_response_bytes: 2,
        ..EgressConfig::default()
    })
    .expect("client should build");

    let response = client
        .request(Method::GET, &format!("http://127.0.0.1:{}/", addr.port()))
        .await
        .expect("empty policy ports should not restrict the request port");

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, b"ok");
    server.await.expect("test server task should finish");
}

#[test]
fn policy_cidr_exempts_only_matching_private_resolved_ips() {
    let allowed_cidrs = vec!["10.0.0.0/8".parse().expect("CIDR should parse")];
    let resolved = vec![socket("10.1.2.3:443")];
    let pinned = checked_socket_addr(
        "internal.example.test",
        &resolved,
        true,
        &[],
        &allowed_cidrs,
    )
    .expect("private IP covered by policy CIDR should be allowed");

    assert_eq!(pinned, socket("10.1.2.3:443"));

    let resolved = vec![socket("192.168.1.10:443")];
    let error = checked_socket_addr(
        "internal.example.test",
        &resolved,
        true,
        &[],
        &allowed_cidrs,
    )
    .expect_err("private IP outside policy CIDR should still be blocked");

    assert!(matches!(
        error,
        EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("192.168.1.10")
    ));
}

#[test]
fn no_policy_egress_section_preserves_env_only_config() {
    let mut config = test_config();
    config.egress_allowed_hosts = vec!["API.EXAMPLE.TEST".to_owned()];
    config.egress_nat64_prefixes = vec!["64:ff9b:1::/48"
        .parse()
        .expect("test NAT64 prefix should parse")];

    let env_only = EgressConfig::from_config(&config);
    let no_policy = EgressConfig::from_config_and_policy(&config, None)
        .expect("no policy should build egress config");
    let empty_policy =
        EgressConfig::from_config_and_policy(&config, Some(&EgressPolicy::default()))
            .expect("empty policy should build egress config");

    assert_eq!(env_only, no_policy);
    assert_eq!(env_only, empty_policy);
    assert_eq!(
        env_only.allowed_hosts,
        HashSet::from(["api.example.test".to_owned()])
    );
    assert!(env_only.allowed_host_globs.is_empty());
    assert!(env_only.private_ip_allow_cidrs.is_empty());
    assert!(env_only.allowed_ports.is_empty());
    assert_eq!(env_only.nat64_prefixes, config.egress_nat64_prefixes);
}

#[test]
fn policy_egress_is_startup_snapshot_until_config_is_rebuilt() {
    let config = test_config();
    let initial_policy = EgressPolicy {
        hosts: vec!["*.initial.example.test".to_owned()],
        cidrs: vec!["10.0.0.0/8".to_owned()],
        ports: vec![443],
    };
    let updated_policy = EgressPolicy {
        hosts: vec!["*.updated.example.test".to_owned()],
        cidrs: vec!["192.168.0.0/16".to_owned()],
        ports: vec![8443],
    };

    let startup_config = EgressConfig::from_config_and_policy(&config, Some(&initial_policy))
        .expect("initial policy should build egress config");

    assert!(host_glob_matches(
        &startup_config.allowed_host_globs[0],
        "api.initial.example.test"
    ));
    assert!(!startup_config
        .allowed_host_globs
        .iter()
        .any(|pattern| host_glob_matches(pattern, "api.updated.example.test")));
    assert!(startup_config.allowed_ports.contains(&443));
    assert!(!startup_config.allowed_ports.contains(&8443));
    assert!(ip_matches_policy_cidr(
        ip("10.1.2.3"),
        &startup_config.private_ip_allow_cidrs
    ));
    assert!(!ip_matches_policy_cidr(
        ip("192.168.1.10"),
        &startup_config.private_ip_allow_cidrs
    ));

    let rebuilt_config = EgressConfig::from_config_and_policy(&config, Some(&updated_policy))
        .expect("updated policy should build egress config");

    assert!(rebuilt_config
        .allowed_host_globs
        .iter()
        .any(|pattern| host_glob_matches(pattern, "api.updated.example.test")));
    assert!(rebuilt_config.allowed_ports.contains(&8443));
    assert!(ip_matches_policy_cidr(
        ip("192.168.1.10"),
        &rebuilt_config.private_ip_allow_cidrs
    ));
}

#[test]
fn empty_allowlist_denies_everything() {
    let client = EgressClient::new(EgressConfig::default()).expect("client should build");
    let url = client
        .checked_url("https://api.example.test/resource")
        .expect("URL should parse");

    let error = checked_host(
        &url,
        &client.config.allowed_hosts,
        &client.config.allowed_host_globs,
    )
    .expect_err("empty allowlist should deny");

    assert!(matches!(
        error,
        EgressError::HostNotAllowed(host) if host == "api.example.test"
    ));
}

#[test]
fn from_config_auto_seeds_jwks_host_into_allowlist() {
    let mut config = test_config();
    config.jwt_jwks_url = Some("https://idp.example.test/.well-known/jwks.json".to_owned());

    let egress = EgressConfig::from_config(&config);

    assert!(egress.allowed_hosts.contains("idp.example.test"));
}

#[test]
fn from_config_auto_seeds_auth_provider_hosts_into_allowlist() {
    let mut config = test_config();
    config.auth_providers = vec![crate::config::AuthProviderConfig {
        name: "primary".to_owned(),
        provider_type: crate::config::AuthProviderType::Jwt,
        jwks_url: Some("https://idp.example.test/.well-known/jwks.json".to_owned()),
        issuer: Some("https://issuer.example.test/".to_owned()),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: crate::config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: crate::config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];

    let egress = EgressConfig::from_config(&config);

    assert!(egress.allowed_hosts.contains("idp.example.test"));
    assert!(egress.allowed_hosts.contains("issuer.example.test"));
}

#[test]
fn from_config_auto_seeds_cookie_session_introspection_host_into_allowlist() {
    let mut config = test_config();
    config.auth_providers = vec![crate::config::AuthProviderConfig {
        name: "app-session".to_owned(),
        provider_type: crate::config::AuthProviderType::CookieSession,
        jwks_url: None,
        issuer: None,
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: Some("https://sessions.example.test/introspect".to_owned()),
        introspection_timeout_ms: crate::config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: crate::config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: Some("user_id".to_owned()),
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];

    let egress = EgressConfig::from_config(&config);

    assert!(egress.allowed_hosts.contains("sessions.example.test"));
}

#[test]
fn from_config_auto_seeds_upstream_host_into_allowlist() {
    let mut config = test_config();
    config.upstream_url = Some("https://upstream.example.test:8443/base".to_owned());

    let egress = EgressConfig::from_config(&config);

    assert!(egress.allowed_hosts.contains("upstream.example.test"));
    assert!(config.egress_allowed_hosts.is_empty());
}

#[test]
fn from_config_auto_seeds_all_route_upstream_hosts_into_allowlist() {
    let mut config = test_config();
    config.upstream_routes = vec![
        crate::config::UpstreamRouteConfig {
            id: None,
            connection_id: None,
            path_prefix: Some("/api".to_owned()),
            host: None,
            upstream_url: "https://api-upstream.example.test/base".to_owned(),
            upstreams: Vec::new(),
            load_balancing: crate::config::UpstreamLoadBalancingConfig::default(),
            request_body: crate::config::UpstreamRequestBodyConfig::default(),
            sse: None,
            websocket: None,
            grpc: None,
            limits: crate::config::UpstreamPoolLimitsConfig::default(),
            health_check: None,
            retry: None,
            circuit_breaker: None,
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
            add_request_headers: HashMap::new(),
            strip_request_headers: Vec::new(),
            tls_ca_bundle_path: None,
            openapi_spec_path: None,
        },
        crate::config::UpstreamRouteConfig {
            id: None,
            connection_id: None,
            path_prefix: Some("/assets".to_owned()),
            host: None,
            upstream_url: "http://assets-upstream.example.test".to_owned(),
            upstreams: Vec::new(),
            load_balancing: crate::config::UpstreamLoadBalancingConfig::default(),
            request_body: crate::config::UpstreamRequestBodyConfig::default(),
            sse: None,
            websocket: None,
            grpc: None,
            limits: crate::config::UpstreamPoolLimitsConfig::default(),
            health_check: None,
            retry: None,
            circuit_breaker: None,
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
            add_request_headers: HashMap::new(),
            strip_request_headers: Vec::new(),
            tls_ca_bundle_path: None,
            openapi_spec_path: None,
        },
        crate::config::UpstreamRouteConfig {
            id: Some("payments".to_owned()),
            connection_id: None,
            path_prefix: Some("/payments".to_owned()),
            host: None,
            upstream_url: String::new(),
            upstreams: vec![
                crate::config::UpstreamEndpointConfig {
                    id: "payments-a".to_owned(),
                    url: "https://payments-a.example.test".to_owned(),
                    weight: 3,
                    tls_ca_bundle_path: None,
                    client_identity_pem_path: None,
                },
                crate::config::UpstreamEndpointConfig {
                    id: "payments-b".to_owned(),
                    url: "https://payments-b.example.test".to_owned(),
                    weight: 1,
                    tls_ca_bundle_path: None,
                    client_identity_pem_path: None,
                },
            ],
            load_balancing: crate::config::UpstreamLoadBalancingConfig::default(),
            request_body: crate::config::UpstreamRequestBodyConfig::default(),
            sse: None,
            websocket: None,
            grpc: None,
            limits: crate::config::UpstreamPoolLimitsConfig::default(),
            health_check: None,
            retry: None,
            circuit_breaker: None,
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
            add_request_headers: HashMap::new(),
            strip_request_headers: Vec::new(),
            tls_ca_bundle_path: None,
            openapi_spec_path: None,
        },
    ];

    let egress = EgressConfig::from_config(&config);

    assert!(egress.allowed_hosts.contains("api-upstream.example.test"));
    assert!(egress
        .allowed_hosts
        .contains("assets-upstream.example.test"));
    assert!(egress.allowed_hosts.contains("payments-a.example.test"));
    assert!(egress.allowed_hosts.contains("payments-b.example.test"));
}

#[test]
fn from_config_merges_explicit_and_auto_seeded_upstream_hosts() {
    let mut config = test_config();
    config.egress_allowed_hosts = vec!["api.example.test".to_owned()];
    config.upstream_url = Some("https://upstream.example.test/base".to_owned());

    let egress = EgressConfig::from_config(&config);

    assert_eq!(egress.allowed_hosts.len(), 2);
    assert!(egress.allowed_hosts.contains("api.example.test"));
    assert!(egress.allowed_hosts.contains("upstream.example.test"));
}

#[test]
fn upstream_timeout_overrides_only_replace_timeout_fields() {
    let mut config = test_config();
    config.egress_allowed_hosts = vec!["api.example.test".to_owned()];
    config.upstream_timeout_ms = Some(1500);
    config.upstream_response_idle_timeout_ms = Some(400);
    config.upstream_connect_timeout_ms = Some(300);

    let mut egress = EgressConfig::from_config(&config);
    egress.apply_upstream_timeout_overrides(&config);

    assert_eq!(egress.timeout, Duration::from_millis(1500));
    assert_eq!(egress.response_idle_timeout, Duration::from_millis(400));
    assert_eq!(egress.connect_timeout, Duration::from_millis(300));
    assert_eq!(
        egress.allowed_hosts,
        HashSet::from(["api.example.test".to_owned()])
    );
    assert_eq!(egress.max_response_bytes, config.egress_max_response_bytes);
    assert_eq!(
        egress.max_request_body_bytes,
        config.egress_max_request_body_bytes
    );
    assert!(egress.deny_private_ips);
}

#[tokio::test]
async fn auto_seeded_upstream_host_still_blocks_private_ips_by_default() {
    let mut config = test_config();
    config.upstream_url = Some("http://127.0.0.1:1/".to_owned());
    let egress_config = EgressConfig::from_config(&config);
    assert!(egress_config.allowed_hosts.contains("127.0.0.1"));
    assert!(egress_config.deny_private_ips);
    let client = EgressClient::new(egress_config).expect("client should build");

    let error = client
        .stream_request_with_headers(Method::GET, "http://127.0.0.1:1/", HeaderMap::new(), None)
        .await
        .expect_err("auto-seeded private upstream should still be blocked");

    assert!(matches!(
        error,
        EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("127.0.0.1")
    ));
}

#[test]
fn host_not_in_allowlist_is_denied() {
    let allowed_hosts = HashSet::from(["api.example.test".to_owned()]);
    let url = Url::parse("https://other.example.test/resource").expect("URL should parse");
    let error =
        checked_host(&url, &allowed_hosts, &[]).expect_err("non-allowlisted host should deny");

    assert!(matches!(
        error,
        EgressError::HostNotAllowed(host) if host == "other.example.test"
    ));
}

#[test]
fn scheme_other_than_http_or_https_is_denied() {
    let client = EgressClient::new(EgressConfig::default()).expect("client should build");
    let error = client
        .checked_url("ftp://api.example.test/resource")
        .expect_err("ftp scheme should deny");

    assert!(matches!(
        error,
        EgressError::SchemeNotAllowed(scheme) if scheme == "ftp"
    ));
}

#[test]
fn url_without_host_is_invalid() {
    let client = EgressClient::new(EgressConfig::default()).expect("client should build");
    let error = client
        .checked_url("data:text/plain,hello")
        .expect_err("URL without host should be invalid");

    assert!(matches!(error, EgressError::InvalidUrl(_)));
}

#[test]
fn url_userinfo_and_fragments_are_invalid() {
    let client = EgressClient::new(EgressConfig::default()).expect("client should build");
    for unsafe_url in [
        "https://operator:credential-canary@api.example.test/resource",
        "https://api.example.test/resource#fragment",
    ] {
        let error = client
            .checked_url(unsafe_url)
            .expect_err("unsafe URL components should be rejected");
        assert!(matches!(error, EgressError::InvalidUrl(_)));
        assert!(!error.to_string().contains("credential-canary"));
    }
}

#[tokio::test]
async fn ipv6_literal_url_is_denied() {
    let config = EgressConfig {
        allowed_hosts: HashSet::from(["[::1]".to_owned()]),
        ..EgressConfig::default()
    };
    let client = EgressClient::new(config).expect("client should build");

    let result = client.request(Method::GET, "http://[::1]/").await;

    assert!(result.is_err(), "IPv6 literal URL should be denied");
}

#[test]
fn any_non_global_resolved_ip_blocks_the_host() {
    let resolved = vec![
        socket("93.184.216.34:443"),
        socket("198.18.0.1:443"),
        socket("1.1.1.1:443"),
    ];
    let error = checked_socket_addr("api.example.test", &resolved, true, &[], &[])
        .expect_err("mixed public and non-global answers should deny");

    assert!(matches!(
        error,
        EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("198.18.0.1")
    ));
}

#[test]
fn configured_nat64_prefix_is_applied_before_address_pinning() {
    let prefixes = vec!["64:ff9b:1::/48"
        .parse::<IpNet>()
        .expect("test NAT64 prefix should parse")];
    let public = vec![socket("[64:ff9b:1:808:8:800::]:443")];
    let pinned = checked_socket_addr("api.example.test", &public, true, &prefixes, &[])
        .expect("public embedded IPv4 should be allowed");
    assert_eq!(pinned, public[0]);

    let private = vec![socket("[64:ff9b:1:a9fe:a9:fe00::]:443")];
    let error = checked_socket_addr("api.example.test", &private, true, &prefixes, &[])
        .expect_err("private embedded IPv4 should be blocked");
    assert!(matches!(
        error,
        EgressError::NonGlobalIpBlocked(blocked)
            if blocked == ip("64:ff9b:1:a9fe:a9:fe00::")
    ));
}

#[test]
fn all_public_resolved_ips_select_exact_pinned_addr() {
    let resolved = vec![socket("93.184.216.34:443"), socket("1.1.1.1:443")];
    let pinned = checked_socket_addr("api.example.test", &resolved, true, &[], &[])
        .expect("public resolved addresses should be allowed");

    assert_eq!(pinned, socket("93.184.216.34:443"));
}

#[test]
fn private_resolved_ip_is_allowed_when_private_deny_is_disabled() {
    let resolved = vec![socket("10.0.0.1:443")];
    let pinned = checked_socket_addr("internal.example.test", &resolved, false, &[], &[])
        .expect("private address should be allowed when private deny is disabled");

    assert_eq!(pinned, socket("10.0.0.1:443"));
}

#[test]
fn empty_resolution_fails_closed() {
    let error = checked_socket_addr("api.example.test", &[], true, &[], &[])
        .expect_err("empty resolution should deny");

    assert!(matches!(
        error,
        EgressError::DnsResolutionFailed(host) if host == "api.example.test"
    ));
}

#[test]
fn request_body_size_is_enforced_before_send() {
    let error = enforce_request_body_size(4, 3).expect_err("oversized body should deny");

    assert!(matches!(
        error,
        EgressError::RequestBodyTooLarge { size: 4, max: 3 }
    ));
    enforce_request_body_size(3, 3).expect("body at limit should be allowed");
}

#[tokio::test]
async fn oversized_request_bodies_are_rejected_before_dns_resolution() {
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket("8.8.8.8:443")]));
    let client = EgressClient::new_with_resolver(
        EgressConfig {
            max_request_body_bytes: 3,
            ..egress_config_for_host("oversized.example.test")
        },
        resolver.clone(),
    )
    .expect("client should build");

    let buffered_error = client
        .request_with_headers(
            Method::POST,
            "https://oversized.example.test/resource",
            HeaderMap::new(),
            Some(vec![0; 4]),
        )
        .await
        .expect_err("oversized buffered request should fail");
    let streaming_error = client
        .stream_request_with_headers(
            Method::POST,
            "https://oversized.example.test/resource",
            HeaderMap::new(),
            Some(vec![0; 4]),
        )
        .await
        .expect_err("oversized streaming request should fail");

    for error in [buffered_error, streaming_error] {
        assert!(matches!(
            error,
            EgressError::RequestBodyTooLarge { size: 4, max: 3 }
        ));
    }
    assert!(
        resolver.calls().is_empty(),
        "oversized request denial must not resolve DNS"
    );
}

#[tokio::test]
async fn pinned_client_uses_checked_socket_addr_for_connection() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one connection");
        read_one_request(&stream).await;
        write_all(
            &stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\npinned",
        )
        .await;
    });
    let mut config = EgressConfig {
        allowed_hosts: HashSet::from(["egress-pinned.test".to_owned()]),
        deny_private_ips: false,
        ..EgressConfig::default()
    };
    config.max_response_bytes = 6;
    let client = EgressClient::new(config).expect("client should build");
    let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
        .expect("test URL should parse");
    let pinned_client = client
        .pinned_client(&url, "egress-pinned.test", addr)
        .expect("pinned client should build");

    let response = client
        .send_with_client(pinned_client, Method::GET, url, HeaderMap::new(), None)
        .await
        .expect("pinned request should reach the test server");

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, b"pinned");
    server.await.expect("test server task should finish");
}

#[tokio::test]
async fn pinned_client_uses_checked_socket_addr_with_custom_tls_roots() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one connection");
        read_one_request(&stream).await;
        write_all(
            &stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ncustom tls",
        )
        .await;
    });
    let certified = rcgen::generate_simple_self_signed(vec!["egress-pinned.test".to_owned()])
        .expect("test root certificate should generate");
    let tls_root_certificates = tls::parse_ca_bundle_pem(certified.cert.pem().as_bytes())
        .expect("test root certificate should parse");
    let config = EgressConfig {
        allowed_hosts: HashSet::from(["egress-pinned.test".to_owned()]),
        max_response_bytes: 10,
        deny_private_ips: false,
        tls_ca_bundle_path: Some(PathBuf::from("test-ca.pem")),
        tls_root_certificates,
        tls_root_set_fingerprint: tls_root_set_fingerprint(certified.cert.pem().as_bytes()),
        ..EgressConfig::default()
    };
    let client = EgressClient::new(config).expect("client should build");
    let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
        .expect("test URL should parse");
    let pinned_client = client
        .pinned_client(&url, "egress-pinned.test", addr)
        .expect("pinned client should build");

    let response = client
        .send_with_client(pinned_client, Method::GET, url, HeaderMap::new(), None)
        .await
        .expect("pinned request should reach the test server");

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, b"custom tls");
    server.await.expect("test server task should finish");
}

#[tokio::test]
async fn sequential_requests_reuse_connections_but_revalidate_dns() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let accepted_connections = Arc::new(AtomicUsize::new(0));
    let served_requests = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(serve_keep_alive(
        listener,
        Arc::clone(&accepted_connections),
        Arc::clone(&served_requests),
    ));
    let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![addr]));
    let client = isolated_egress_client(
        EgressConfig {
            allowed_hosts: HashSet::from(["reuse.example.test".to_owned()]),
            deny_private_ips: false,
            max_response_bytes: 2,
            ..EgressConfig::default()
        },
        resolver.clone(),
    );
    let url = format!("http://reuse.example.test:{}/", addr.port());

    for _ in 0..100 {
        let response = client
            .request(Method::GET, &url)
            .await
            .expect("sequential request should succeed");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"ok");
    }

    assert_eq!(
        resolver.calls().len(),
        100,
        "DNS must be checked every time"
    );
    assert_eq!(served_requests.load(Ordering::SeqCst), 100);
    assert!(
        accepted_connections.load(Ordering::SeqCst) <= 2,
        "100 sequential requests should reuse a bounded number of TCP connections"
    );
    assert_eq!(client.client_cache.len(), 1);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn safe_to_private_dns_change_never_reuses_cached_destination() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one connection");
        read_one_request(&stream).await;
        write_all(
            &stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        )
        .await;
    });
    let resolver = Arc::new(SequencedDnsResolver::new([
        FakeResolution::Addresses(vec![addr]),
        FakeResolution::Addresses(vec![SocketAddr::from(([10, 0, 0, 1], addr.port()))]),
    ]));
    let client = isolated_egress_client(
        EgressConfig {
            allowed_hosts: HashSet::from(["rebind.example.test".to_owned()]),
            private_ip_allow_cidrs: vec!["127.0.0.0/8".parse().expect("test CIDR should parse")],
            deny_private_ips: true,
            max_response_bytes: 2,
            ..EgressConfig::default()
        },
        resolver.clone(),
    );
    let url = format!("http://rebind.example.test:{}/", addr.port());

    let first = client
        .request(Method::GET, &url)
        .await
        .expect("first validated destination should succeed");
    assert_eq!(first.body, b"ok");
    let error = client
        .request(Method::GET, &url)
        .await
        .expect_err("private rebound destination must fail closed");

    assert!(matches!(
        error,
        EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("10.0.0.1")
    ));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        client.client_cache.len(),
        1,
        "the old client may remain idle but must not be selected after failed validation"
    );
    server.await.expect("test server task should finish");
}

#[test]
fn cache_partitions_address_timeout_trust_identity_and_egress_generations() {
    let base_config = EgressConfig {
        allowed_hosts: HashSet::from(["partition.example.test".to_owned()]),
        deny_private_ips: false,
        ..EgressConfig::default()
    };
    let client = isolated_egress_client(base_config.clone(), Arc::new(SystemDnsResolver));
    let url = Url::parse("https://partition.example.test/").expect("test URL should parse");
    let first_addr = socket("8.8.8.8:443");
    client
        .pinned_client(&url, "partition.example.test", first_addr)
        .expect("first client should build");
    client
        .pinned_client(&url, "partition.example.test", first_addr)
        .expect("identical profile should reuse");
    assert_eq!(client.client_cache.len(), 1);

    client
        .pinned_client(&url, "partition.example.test", socket("1.1.1.1:443"))
        .expect("a new exact address should build a separate client");
    assert_eq!(client.client_cache.len(), 2);

    let mut timeout_config = base_config.clone();
    timeout_config.timeout += Duration::from_secs(1);
    let timeout_client = client
        .reconfigured(timeout_config)
        .expect("timeout client should build");
    timeout_client
        .pinned_client(&url, "partition.example.test", first_addr)
        .expect("a new timeout profile should build a separate client");
    assert_eq!(client.client_cache.len(), 3);

    let certified = rcgen::generate_simple_self_signed(vec!["partition.example.test".to_owned()])
        .expect("test root certificate should generate");
    let pem = certified.cert.pem();
    let mut trust_config = base_config.clone();
    trust_config.tls_root_certificates =
        tls::parse_ca_bundle_pem(pem.as_bytes()).expect("test root certificate should parse");
    trust_config.tls_root_set_fingerprint = tls_root_set_fingerprint(pem.as_bytes());
    let trust_client = client
        .reconfigured(trust_config)
        .expect("trust-profile client should build");
    trust_client
        .pinned_client(&url, "partition.example.test", first_addr)
        .expect("a new trust profile should build a separate client");
    assert_eq!(client.client_cache.len(), 4);

    let mut first_identity_config = base_config.clone();
    let first_identity =
        rcgen::generate_simple_self_signed(vec!["client-a.example.test".to_owned()])
            .expect("first test identity should generate");
    let first_identity_pem = format!(
        "{}{}",
        first_identity.cert.pem(),
        first_identity.key_pair.serialize_pem()
    );
    first_identity_config.client_identity = Some(
        tls::parse_client_identity_pem(first_identity_pem.as_bytes())
            .expect("first test identity should parse"),
    );
    first_identity_config.client_identity_fingerprint = Some(tls_client_identity_fingerprint(
        first_identity_pem.as_bytes(),
    ));
    let first_identity_client = client
        .reconfigured(first_identity_config)
        .expect("first identity client should build");
    first_identity_client
        .pinned_client(&url, "partition.example.test", first_addr)
        .expect("a client identity should build a separate client");
    assert_eq!(client.client_cache.len(), 5);

    let mut second_identity_config = base_config.clone();
    let second_identity =
        rcgen::generate_simple_self_signed(vec!["client-b.example.test".to_owned()])
            .expect("second test identity should generate");
    let second_identity_pem = format!(
        "{}{}",
        second_identity.cert.pem(),
        second_identity.key_pair.serialize_pem()
    );
    second_identity_config.client_identity = Some(
        tls::parse_client_identity_pem(second_identity_pem.as_bytes())
            .expect("second test identity should parse"),
    );
    second_identity_config.client_identity_fingerprint = Some(tls_client_identity_fingerprint(
        second_identity_pem.as_bytes(),
    ));
    let second_identity_client = client
        .reconfigured(second_identity_config)
        .expect("second identity client should build");
    second_identity_client
        .pinned_client(&url, "partition.example.test", first_addr)
        .expect("another client identity should build a separate client");
    assert_eq!(client.client_cache.len(), 6);

    let mut egress_config = base_config;
    egress_config
        .allowed_hosts
        .insert("additional.example.test".to_owned());
    let egress_client = client
        .reconfigured(egress_config)
        .expect("egress-generation client should build");
    egress_client
        .pinned_client(&url, "partition.example.test", first_addr)
        .expect("a new egress generation should build a separate client");
    assert_eq!(client.client_cache.len(), 7);
}

#[tokio::test]
async fn response_body_size_is_enforced_while_streaming() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one connection");
        read_one_request(&stream).await;
        write_all(
            &stream,
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ntoo-big",
        )
        .await;
    });
    let config = EgressConfig {
        allowed_hosts: HashSet::from(["egress-pinned.test".to_owned()]),
        max_response_bytes: 6,
        deny_private_ips: false,
        ..EgressConfig::default()
    };
    let client = EgressClient::new(config).expect("client should build");
    let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
        .expect("test URL should parse");
    let pinned_client = client
        .pinned_client(&url, "egress-pinned.test", addr)
        .expect("pinned client should build");

    let error = client
        .send_with_client(pinned_client, Method::GET, url, HeaderMap::new(), None)
        .await
        .expect_err("oversized response should deny");

    assert!(matches!(
        error,
        EgressError::ResponseTooLarge { size: 7, max: 6 }
    ));
    server.await.expect("test server task should finish");
}

#[tokio::test]
async fn stream_request_returns_after_headers_before_full_body() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one connection");
        read_one_request(&stream).await;
        write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n",
            )
            .await;
        tokio::time::sleep(Duration::from_millis(700)).await;
        write_all(&stream, b"5\r\nworld\r\n0\r\n\r\n").await;
    });
    let client = EgressClient::new(EgressConfig {
        allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
        max_response_bytes: 10,
        deny_private_ips: false,
        ..EgressConfig::default()
    })
    .expect("client should build");
    let url = format!("http://127.0.0.1:{}/stream", addr.port());

    let response = tokio::time::timeout(
        Duration::from_millis(500),
        client.stream_request_with_headers(Method::GET, &url, HeaderMap::new(), None),
    )
    .await
    .expect("streaming response should return before full body is sent")
    .expect("streaming request should succeed");

    assert_eq!(response.status, StatusCode::OK);

    let mut body = response.body;
    let first = tokio::time::timeout(Duration::from_millis(200), body.next())
        .await
        .expect("first chunk should be available")
        .expect("stream should yield a first chunk")
        .expect("first chunk should be ok");
    assert_eq!(&first[..], b"hello");

    assert!(
        tokio::time::timeout(Duration::from_millis(100), body.next())
            .await
            .is_err(),
        "second chunk should not be buffered before the upstream sends it"
    );

    let second = tokio::time::timeout(Duration::from_secs(1), body.next())
        .await
        .expect("second chunk should arrive")
        .expect("stream should yield a second chunk")
        .expect("second chunk should be ok");
    assert_eq!(&second[..], b"world");

    assert!(
        tokio::time::timeout(Duration::from_millis(200), body.next())
            .await
            .expect("stream end should arrive")
            .is_none()
    );
    server.await.expect("test server task should finish");
}

#[tokio::test]
async fn stream_response_body_size_is_enforced_while_consuming() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one connection");
        read_one_request(&stream).await;
        write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n",
            )
            .await;
    });
    let client = EgressClient::new(EgressConfig {
        allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
        max_response_bytes: 5,
        deny_private_ips: false,
        ..EgressConfig::default()
    })
    .expect("client should build");
    let url = format!("http://127.0.0.1:{}/stream", addr.port());
    let response = client
        .stream_request_with_headers(Method::GET, &url, HeaderMap::new(), None)
        .await
        .expect("headers should be returned before oversized body is consumed");

    let mut body = response.body;
    let mut saw_limit_error = false;
    while let Some(chunk) = body.next().await {
        match chunk {
            Ok(_) => {}
            Err(EgressError::ResponseTooLarge { size, max }) => {
                assert_eq!(size, 6);
                assert_eq!(max, 5);
                saw_limit_error = true;
                break;
            }
            Err(err) => panic!("unexpected stream error: {err}"),
        }
    }

    assert!(
        saw_limit_error,
        "stream should fail once the cap is exceeded"
    );
    server.await.expect("test server task should finish");
}

#[tokio::test]
async fn stream_response_body_idle_timeout_is_enforced_while_consuming() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let server = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one connection");
        read_one_request(&stream).await;
        write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhi\r\n",
            )
            .await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let client = EgressClient::new(EgressConfig {
        allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
        timeout: Duration::from_secs(5),
        response_idle_timeout: Duration::from_millis(100),
        max_response_bytes: 10,
        deny_private_ips: false,
        ..EgressConfig::default()
    })
    .expect("client should build");
    let url = format!("http://127.0.0.1:{}/stream", addr.port());
    let response = client
        .stream_request_with_headers(Method::GET, &url, HeaderMap::new(), None)
        .await
        .expect("headers should be returned before stalled body is consumed");

    let mut body = response.body;
    let first = tokio::time::timeout(Duration::from_millis(200), body.next())
        .await
        .expect("first chunk should arrive")
        .expect("stream should yield a first chunk")
        .expect("first chunk should be ok");
    assert_eq!(&first[..], b"hi");

    let error = tokio::time::timeout(Duration::from_millis(500), body.next())
        .await
        .expect("idle timeout error should arrive before the outer test timeout")
        .expect("stream should yield an idle timeout error")
        .expect_err("stalled stream should fail");
    assert!(matches!(
        error,
        EgressError::ResponseIdleTimeout { timeout }
            if timeout == Duration::from_millis(100)
    ));
    server.abort();
}

#[tokio::test]
async fn stream_request_reuses_allowlist_and_private_ip_checks() {
    let client = EgressClient::new(EgressConfig::default()).expect("client should build");
    let error = client
        .stream_request_with_headers(Method::GET, "http://127.0.0.1:1/", HeaderMap::new(), None)
        .await
        .expect_err("non-allowlisted stream host should deny");

    assert!(matches!(
        error,
        EgressError::HostNotAllowed(host) if host == "127.0.0.1"
    ));

    let client = EgressClient::new(EgressConfig {
        allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
        deny_private_ips: true,
        ..EgressConfig::default()
    })
    .expect("client should build");
    let error = client
        .stream_request_with_headers(Method::GET, "http://127.0.0.1:1/", HeaderMap::new(), None)
        .await
        .expect_err("private stream host should deny");

    assert!(matches!(
        error,
        EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("127.0.0.1")
    ));
}

async fn read_one_request(stream: &TcpStream) {
    let mut buffer = [0; 1024];

    loop {
        stream
            .readable()
            .await
            .expect("test stream should become readable");

        match stream.try_read(&mut buffer) {
            Ok(_) => return,
            Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
            Err(err) => panic!("failed to read test request: {err}"),
        }
    }
}

async fn serve_keep_alive(
    listener: TcpListener,
    accepted_connections: Arc<AtomicUsize>,
    served_requests: Arc<AtomicUsize>,
) {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .expect("keep-alive test server should accept connections");
        accepted_connections.fetch_add(1, Ordering::SeqCst);
        let served_requests = Arc::clone(&served_requests);
        tokio::spawn(async move {
            serve_keep_alive_connection(stream, served_requests).await;
        });
    }
}

async fn serve_keep_alive_connection(mut stream: TcpStream, served_requests: Arc<AtomicUsize>) {
    let mut pending = Vec::new();
    loop {
        let header_end = loop {
            if let Some(position) = pending.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }

            let mut buffer = [0_u8; 1024];
            let read = stream
                .read(&mut buffer)
                .await
                .expect("keep-alive test request should read");
            if read == 0 {
                return;
            }
            pending.extend_from_slice(&buffer[..read]);
        };
        pending.drain(..header_end);

        served_requests.fetch_add(1, Ordering::SeqCst);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok")
            .await
            .expect("keep-alive test response should write");
    }
}

async fn write_all(stream: &TcpStream, bytes: &[u8]) {
    let mut written = 0;

    while written < bytes.len() {
        stream
            .writable()
            .await
            .expect("test stream should become writable");

        match stream.try_write(&bytes[written..]) {
            Ok(0) => panic!("test stream closed before response was written"),
            Ok(count) => written += count,
            Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
            Err(err) => panic!("failed to write test response: {err}"),
        }
    }
}

fn ip(value: &str) -> IpAddr {
    value.parse().expect("test IP should parse")
}

fn socket(value: &str) -> SocketAddr {
    value.parse().expect("test socket address should parse")
}

#[derive(Clone, Default)]
struct CapturedLogs {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl CapturedLogs {
    fn clear(&self) {
        self.buffer
            .lock()
            .expect("captured logs should not be poisoned")
            .clear();
    }

    fn contents(&self) -> String {
        String::from_utf8(
            self.buffer
                .lock()
                .expect("captured logs should not be poisoned")
                .clone(),
        )
        .expect("captured logs should be UTF-8")
    }
}

impl<'a> MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CapturedLogWriter {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

struct CapturedLogWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for CapturedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.buffer
            .lock()
            .map_err(|_| io::Error::other("captured logs lock poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn test_config() -> Config {
    Config {
        listen_addr: "127.0.0.1:0"
            .parse()
            .expect("test listen address should parse"),
        admin_listen_addr: None,
        grpc_listen_addr: None,
        grpc_max_concurrent_streams: crate::config::DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
        grpc_max_metadata_bytes: crate::config::DEFAULT_GRPC_MAX_METADATA_BYTES,
        tls_cert_files: None,
        tls_key_files: None,
        admin_tls_cert_files: None,
        admin_tls_key_files: None,
        tls_min_version: crate::config::DEFAULT_TLS_MIN_VERSION,
        tls_handshake_timeout_ms: crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
        tls_max_concurrent_handshakes: crate::config::DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
        client_cert_auth: None,
        admin_client_cert_auth: None,
        admin_prefix: "/admin".to_owned(),
        admin_login_provider: None,
        admin_login_pending_ttl_secs: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
        admin_login_pending_max_entries: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
        admin_login_pending_max_per_ip: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
        admin_login_keyring: Vec::new(),
        rate_limit_keyring: Vec::new(),
        gateway_public_url: None,
        audit_log_file: None,
        audit_sqlite_path: None,
        audit_sqlite_retention_days: None,
        shutdown_drain_delay_ms: crate::config::DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
        shutdown_timeout_ms: crate::config::DEFAULT_SHUTDOWN_TIMEOUT_MS,
        audit_drain_timeout_ms: crate::config::DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
        discovery_sqlite_path: None,
        discovery_endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
        discovery_projector_lease_ttl_ms: crate::config::DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS,
        discovery_projector_poll_ms: crate::config::DEFAULT_DISCOVERY_PROJECTOR_POLL_MS,
        discovery_projector_batch: crate::config::DEFAULT_DISCOVERY_PROJECTOR_BATCH,
        principal_sqlite_path: None,
        connections_sqlite_path: None,
        connection_local_secret_keyring: Vec::new(),
        connection_vault_provider: crate::connections::vault_secret::VaultProviderConfig::default(),
        connection_gcp_provider: crate::connections::gcp_secret::GcpProviderConfig::default(),
        connection_azure_provider: crate::connections::azure_secret::AzureProviderConfig::default(),
        connection_aws_provider: crate::connections::aws_secret::AwsProviderConfig::default(),
        connection_kubernetes_provider:
            crate::connections::kubernetes_secret::KubernetesProviderConfig::default(),
        connection_secret_aliases: Vec::new(),
        connection_secrets_root: None,
        payload_capture_enabled: false,
        payload_capture_sample_rate: crate::config::DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
        schema_mismatch_signal_threshold:
            crate::discovery::signals::DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
        error_rate_spike_signal_threshold:
            crate::discovery::signals::DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
        principal_new_to_endpoint_signal_threshold:
            crate::discovery::signals::DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
        volume_outlier_signal_threshold:
            crate::discovery::signals::DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
        rule_suggestion_baseline_window_hours:
            crate::discovery::suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
        openapi_spec_path: None,
        policy_file: None,
        tools_file: None,
        policy_history_sqlite_path: None,
        cors_allow_origins: Vec::new(),
        max_body_size: 1_048_576,
        rate_limit_read_rps: 50.0,
        rate_limit_read_burst: 100,
        rate_limit_write_rps: 10.0,
        rate_limit_write_burst: 20,
        rate_limit_max_buckets: crate::config::DEFAULT_RATE_LIMIT_MAX_BUCKETS,
        rate_limit_bucket_ttl_ms: crate::config::DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
        trust_proxy_headers: false,
        trusted_proxy_cidrs: Vec::new(),
        rbac_exempt_paths: vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
        ],
        validation_allowed_content_types: vec!["application/json".to_owned()],
        auth_enabled: true,
        auth_mode: crate::config::AuthMode::Required,
        auth_cookie_name: "session".to_owned(),
        auth_exempt_paths: vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
        ],
        auth_providers: Vec::new(),
        jwt_jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        jwt_jwks_timeout_ms: 2000,
        jwt_jwks_max_key_age_secs: 300,
        jwt_require_jti: false,
        roles_claim: "roles".to_owned(),
        service_token_sqlite_path: None,
        service_token_cache_ttl_ms: crate::config::DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
        tool_runtime_queue_depth: crate::config::DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
        tool_runtime_global_concurrency: crate::config::DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
        tool_runtime_queue_timeout_ms: crate::config::DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
        tool_lease_ttl_ms: crate::config::DEFAULT_TOOL_LEASE_TTL_MS,
        cluster_heartbeat_ms: crate::config::DEFAULT_CLUSTER_HEARTBEAT_MS,
        cluster_member_stale_ms: crate::config::DEFAULT_CLUSTER_MEMBER_STALE_MS,
        cluster_maintenance_interval_ms: crate::config::DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS,
        cluster_maintenance_lease_ttl_ms: crate::config::DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS,
        readiness_probe_cache_ms: crate::config::DEFAULT_READINESS_PROBE_CACHE_MS,
        cluster_status_expose_hostnames: false,
        audit_postgres_retention_days: None,
        tool_runtime_default_timeout_ms: crate::config::DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
        csrf_enabled: true,
        csrf_cookie_name: "csrf_token".to_owned(),
        csrf_header_name: "x-csrf-token".to_owned(),
        csrf_cookie_domain: None,
        csrf_exempt_paths: vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
        ],
        upstream_url: None,
        upstream_routes: Vec::new(),
        mcp_upstream_servers: Vec::new(),
        upstream_timeout_ms: None,
        upstream_response_idle_timeout_ms: None,
        upstream_connect_timeout_ms: None,
        egress_allowed_hosts: Vec::new(),
        egress_timeout_ms: 30_000,
        egress_response_idle_timeout_ms: 30_000,
        egress_connect_timeout_ms: 10_000,
        egress_max_response_bytes: 5_242_880,
        egress_max_request_body_bytes: 1_048_576,
        egress_nat64_prefixes: Vec::new(),
        egress_deny_private_ips: true,
        state_backend: crate::config::StateBackend::Sqlite,
        deployment_id: None,
        database: crate::config::DatabaseSettings::default(),
    }
}
