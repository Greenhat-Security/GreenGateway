use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use reqwest::Method;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        server::WebPkiClientVerifier,
        RootCertStore, ServerConfig,
    },
    TlsAcceptor,
};

use super::{
    client_cache::PinnedClientCache, DnsResolver, EgressClient, EgressConfig, EgressError,
};

struct StaticResolver {
    address: SocketAddr,
}

#[async_trait]
impl DnsResolver for StaticResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        Ok(vec![self.address])
    }
}

struct SecretFile {
    path: PathBuf,
}

impl SecretFile {
    fn new(name: &str, contents: &[u8]) -> Self {
        let path =
            std::env::temp_dir().join(format!("greengateway-{name}-{}.pem", uuid::Uuid::new_v4()));
        fs::write(&path, contents).expect("test secret file should be written");
        Self { path }
    }
}

impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct CertificateAuthority {
    certificate: rcgen::Certificate,
    key: rcgen::KeyPair,
}

fn certificate_authority(common_name: &str) -> CertificateAuthority {
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
    CertificateAuthority { certificate, key }
}

struct ServerIdentity {
    ca_pem: String,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
}

fn server_identity(host: &str) -> ServerIdentity {
    let ca = certificate_authority("GreenGateway mTLS Test Server CA");
    let mut params = rcgen::CertificateParams::new(vec![host.to_owned()])
        .expect("test server certificate parameters should build");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("test server key should generate");
    let certificate = params
        .signed_by(&key, &ca.certificate, &ca.key)
        .expect("test server certificate should build");

    ServerIdentity {
        ca_pem: ca.certificate.pem(),
        certificate_der: certificate.der().as_ref().to_vec(),
        private_key_der: key.serialize_der(),
    }
}

struct ClientIdentity {
    ca_der: Vec<u8>,
    pem: String,
}

fn client_identity(name: &str) -> ClientIdentity {
    let ca = certificate_authority(&format!("GreenGateway {name} Test Client CA"));
    let mut params = rcgen::CertificateParams::new(vec![format!("{name}.example.test")])
        .expect("test client certificate parameters should build");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().expect("test client key should generate");
    let certificate = params
        .signed_by(&key, &ca.certificate, &ca.key)
        .expect("test client certificate should build");

    ClientIdentity {
        ca_der: ca.certificate.der().as_ref().to_vec(),
        pem: format!("{}{}", certificate.pem(), key.serialize_pem()),
    }
}

struct MtlsServer {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for MtlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_mtls_server(server: &ServerIdentity, trusted_client_ca_der: Vec<u8>) -> MtlsServer {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut client_roots = RootCertStore::empty();
    client_roots
        .add(CertificateDer::from(trusted_client_ca_der))
        .expect("test client CA should be accepted");
    let verifier = WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .expect("test client certificate verifier should build");
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server.certificate_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.private_key_der.clone())),
        )
        .expect("test mTLS server config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test mTLS server should bind");
    let address = listener
        .local_addr()
        .expect("test mTLS server address should be available");
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = Arc::clone(&requests);

    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let request_count = Arc::clone(&request_count);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
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
                request_count.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });

    MtlsServer {
        address,
        requests,
        task,
    }
}

fn configured_client(
    host: &str,
    address: SocketAddr,
    server_ca_pem: Option<&str>,
    identity_pem: Option<&str>,
    cache: Arc<PinnedClientCache>,
) -> Result<EgressClient, EgressError> {
    let mut config = EgressConfig {
        allowed_hosts: HashSet::from([host.to_owned()]),
        deny_private_ips: false,
        max_response_bytes: 2,
        ..EgressConfig::default()
    };
    let ca_file = server_ca_pem.map(|pem| SecretFile::new("mtls-server-ca", pem.as_bytes()));
    if let Some(file) = &ca_file {
        config.apply_tls_ca_bundle_path(file.path.clone())?;
    }
    let identity_file =
        identity_pem.map(|pem| SecretFile::new("mtls-client-identity", pem.as_bytes()));
    if let Some(file) = &identity_file {
        config.apply_tls_client_identity_pem_path(file.path.clone())?;
    }

    EgressClient::new_with_resolver_and_cache(config, Arc::new(StaticResolver { address }), cache)
}

#[tokio::test]
async fn mutual_tls_preserves_pinned_dns_sni_and_strict_verification() {
    let host = "mtls.example.test";
    let server_identity = server_identity(host);
    let client_identity = client_identity("accepted-client");
    let server = spawn_mtls_server(&server_identity, client_identity.ca_der.clone()).await;
    let cache = Arc::new(PinnedClientCache::new());
    let client = configured_client(
        host,
        server.address,
        Some(&server_identity.ca_pem),
        Some(&client_identity.pem),
        Arc::clone(&cache),
    )
    .expect("valid mTLS client should build");
    let url = format!("https://{host}:{}/resource", server.address.port());

    let response = client
        .request(Method::GET, &url)
        .await
        .expect("pinned DNS, hostname verification, custom CA, and mTLS should succeed");
    assert_eq!(response.body, b"ok");
    assert_eq!(server.requests.load(Ordering::SeqCst), 1);

    let wrong_host = "wrong-name.example.test";
    let wrong_name_client = configured_client(
        wrong_host,
        server.address,
        Some(&server_identity.ca_pem),
        Some(&client_identity.pem),
        Arc::clone(&cache),
    )
    .expect("wrong-host test client should build");
    let error = wrong_name_client
        .request(
            Method::GET,
            &format!("https://{wrong_host}:{}/resource", server.address.port()),
        )
        .await
        .expect_err("a trusted certificate for another hostname must fail");
    assert!(matches!(error, EgressError::Http(_)));

    let anonymous_client = configured_client(
        host,
        server.address,
        Some(&server_identity.ca_pem),
        None,
        Arc::clone(&cache),
    )
    .expect("anonymous test client should build");
    let error = anonymous_client
        .request(Method::GET, &url)
        .await
        .expect_err("the mTLS server must reject a missing client identity");
    assert!(matches!(error, EgressError::Http(_)));

    let untrusted_server_client = configured_client(
        host,
        server.address,
        None,
        Some(&client_identity.pem),
        cache,
    )
    .expect("untrusted-server test client should build");
    let error = untrusted_server_client
        .request(Method::GET, &url)
        .await
        .expect_err("the server certificate must remain strictly verified");
    assert!(matches!(error, EgressError::Http(_)));
    assert_eq!(
        server.requests.load(Ordering::SeqCst),
        1,
        "failed TLS handshakes must not deliver HTTP requests"
    );
}

#[tokio::test]
async fn distinct_client_identities_do_not_cross_endpoint_boundaries() {
    let host = "identity-isolation.example.test";
    let server_identity = server_identity(host);
    let first_identity = client_identity("first-client");
    let second_identity = client_identity("second-client");
    let first_server = spawn_mtls_server(&server_identity, first_identity.ca_der.clone()).await;
    let second_server = spawn_mtls_server(&server_identity, second_identity.ca_der.clone()).await;
    let cache = Arc::new(PinnedClientCache::new());

    let first_client = configured_client(
        host,
        first_server.address,
        Some(&server_identity.ca_pem),
        Some(&first_identity.pem),
        Arc::clone(&cache),
    )
    .expect("first endpoint client should build");
    let second_client = configured_client(
        host,
        second_server.address,
        Some(&server_identity.ca_pem),
        Some(&second_identity.pem),
        Arc::clone(&cache),
    )
    .expect("second endpoint client should build");

    first_client
        .request(
            Method::GET,
            &format!("https://{host}:{}/first", first_server.address.port()),
        )
        .await
        .expect("first endpoint should receive only its accepted identity");
    second_client
        .request(
            Method::GET,
            &format!("https://{host}:{}/second", second_server.address.port()),
        )
        .await
        .expect("second endpoint should receive only its accepted identity");

    let crossed_client = configured_client(
        host,
        second_server.address,
        Some(&server_identity.ca_pem),
        Some(&first_identity.pem),
        cache,
    )
    .expect("crossed-identity test client should build");
    let error = crossed_client
        .request(
            Method::GET,
            &format!("https://{host}:{}/crossed", second_server.address.port()),
        )
        .await
        .expect_err("the first endpoint identity must not authenticate to the second endpoint");
    assert!(matches!(error, EgressError::Http(_)));
    assert_eq!(first_server.requests.load(Ordering::SeqCst), 1);
    assert_eq!(second_server.requests.load(Ordering::SeqCst), 1);
}
