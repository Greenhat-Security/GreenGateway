use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use gateway_config::capabilities::GatewayCapabilities;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

use super::*;

const CANARY: &str = "gg-canary-remote-7f3a9c";

#[test]
fn server_urls_must_be_an_exact_admin_base() {
    for (text, expected) in [
        (
            "https://gateway.example.test/v1/admin",
            "https://gateway.example.test/v1/admin",
        ),
        (
            "https://gateway.example.test/v1/admin/",
            "https://gateway.example.test/v1/admin",
        ),
        (
            "https://gateway.example.test:8443/v1/ops/admin",
            "https://gateway.example.test:8443/v1/ops/admin",
        ),
        (
            "https://[2001:db8::1]/v1/admin",
            "https://[2001:db8::1]/v1/admin",
        ),
        (
            "http://127.0.0.1:9090/v1/admin",
            "http://127.0.0.1:9090/v1/admin",
        ),
        (
            "http://127.8.9.10/v1/a.b-c_d~e",
            "http://127.8.9.10/v1/a.b-c_d~e",
        ),
        ("http://[::1]:9090/v1/admin", "http://[::1]:9090/v1/admin"),
    ] {
        let server = ServerUrl::parse(text).unwrap_or_else(|code| panic!("{text}: {code:?}"));
        assert_eq!(server.0.as_str(), expected);
        assert_eq!(
            server.endpoint(CAPABILITIES_PATH).as_str(),
            format!("{expected}/config/capabilities")
        );
    }
    for (text, code) in [
        (
            "http://gateway.example.test/v1/admin",
            Code::PlaintextRefused,
        ),
        ("http://localhost:9090/v1/admin", Code::PlaintextRefused),
        ("http://10.0.0.1/v1/admin", Code::PlaintextRefused),
        ("http://[::ffff:127.0.0.1]/v1/admin", Code::PlaintextRefused),
        (
            "https://operator@gateway.example.test/v1/admin",
            Code::UserinfoRefused,
        ),
        (
            "https://gateway.example.test/v1/admin?debug=1",
            Code::QueryOrFragmentRefused,
        ),
        (
            "https://gateway.example.test/v1/admin#top",
            Code::QueryOrFragmentRefused,
        ),
        ("https://gateway.example.test", Code::InvalidServerUrl),
        ("https://gateway.example.test/", Code::InvalidServerUrl),
        ("https://gateway.example.test/v1", Code::InvalidServerUrl),
        ("https://gateway.example.test/v1/", Code::InvalidServerUrl),
        (
            "https://gateway.example.test/v2/admin",
            Code::InvalidServerUrl,
        ),
        ("https://gateway.example.test/admin", Code::InvalidServerUrl),
        (
            "https://gateway.example.test/v1//admin",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test/v1/admin//",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test/v1/./admin",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test/v1/x/../admin",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test/v1/ad%6Din",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test/v1/ad min",
            Code::InvalidServerUrl,
        ),
        // The URL parser would drop these and use a base nobody typed.
        (
            "https://gateway.example.test/v1/ad\tmin",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test/v1/ad\nmin",
            Code::InvalidServerUrl,
        ),
        (
            " https://gateway.example.test/v1/admin",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test/v1/admin\r\n",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test/v1/admin\u{0}",
            Code::InvalidServerUrl,
        ),
        (
            "https://gateway.example.test\\v1\\admin",
            Code::InvalidServerUrl,
        ),
        (
            "ftp://gateway.example.test/v1/admin",
            Code::InvalidServerUrl,
        ),
        ("gateway.example.test/v1/admin", Code::InvalidServerUrl),
        ("", Code::InvalidServerUrl),
    ] {
        assert_eq!(ServerUrl::parse(text).map(|_| ()), Err(code), "{text}");
    }
    // Assembled at run time so the source holds no credential-shaped URL.
    let with_password = [
        "https://operator",
        "placeholder@gateway.example.test/v1/admin",
    ]
    .join(":");
    assert_eq!(
        ServerUrl::parse(&with_password).map(|_| ()),
        Err(Code::UserinfoRefused)
    );
}

fn remote_arguments(words: &[&str]) -> Option<RemoteArguments> {
    let arguments: Vec<std::ffi::OsString> = words.iter().map(Into::into).collect();
    match crate::cli::parse(&arguments) {
        Ok(crate::cli::Parsed::Run(invocation)) => {
            RemoteArguments::from_invocation(&invocation).expect("valid remote options")
        }
        other => panic!("{words:?} should run, got {other:?}"),
    }
}

#[test]
fn remote_options_are_taken_as_given_and_default_when_absent() {
    assert!(remote_arguments(&["version"]).is_none());

    let remote = remote_arguments(&[
        "version",
        "--server",
        "https://gateway.example.test/v1/admin",
        "--ca-file",
        "ca.pem",
        "--token-file",
        "token",
        "--timeout",
        "300",
    ])
    .expect("a server");
    assert_eq!(
        remote.server.0.as_str(),
        "https://gateway.example.test/v1/admin"
    );
    assert_eq!(remote.ca_file.as_deref(), Some(Path::new("ca.pem")));
    assert!(matches!(&remote.token, TokenSource::File(path) if path == Path::new("token")));
    assert_eq!(remote.timeout, Duration::from_secs(MAX_TIMEOUT_SECONDS));

    let remote = remote_arguments(&[
        "version",
        "--server",
        "http://127.0.0.1:9090/v1/admin",
        "--token-stdin",
        "--timeout=1",
    ])
    .expect("a server");
    assert!(matches!(remote.token, TokenSource::Stdin));
    assert_eq!(remote.ca_file, None);
    assert_eq!(remote.timeout, Duration::from_secs(1));

    let remote =
        remote_arguments(&["version", "--server", "http://[::1]/v1/admin"]).expect("a server");
    assert!(matches!(remote.token, TokenSource::None));
    assert_eq!(remote.timeout, DEFAULT_TIMEOUT);
}

/// What a fake server saw.
#[derive(Clone, Default)]
struct Seen {
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Seen {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("lock").clone()
    }
}

/// Answers every connection on 127.0.0.1 with `response`, recording the
/// request head. `None` holds the connection open without answering.
async fn serve(response: Option<Vec<u8>>, tls: Option<TlsAcceptor>) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let seen = Seen::default();
    let recorder = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            recorder.connections.fetch_add(1, Ordering::SeqCst);
            let response = response.clone();
            let recorder = recorder.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(stream).await {
                            answer(stream, response, recorder).await;
                        }
                    }
                    None => answer(stream, response, recorder).await,
                }
            });
        }
    });
    (address, seen)
}

async fn answer<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    response: Option<Vec<u8>>,
    seen: Seen,
) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        match stream.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    seen.requests
        .lock()
        .expect("lock")
        .push(String::from_utf8_lossy(&head).into_owned());
    match response {
        Some(response) => {
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        }
        None => tokio::time::sleep(Duration::from_secs(30)).await,
    }
}

fn http_response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn capabilities_body() -> String {
    serde_json::to_string(&GatewayCapabilities::environment("1.0.1")).expect("serializes")
}

fn token() -> Token {
    credential::from_stdin(false, &mut CANARY.as_bytes()).expect("valid token")
}

fn client(base: &str, roots: TrustAnchors, timeout: Duration) -> AdminClient {
    AdminClient::new(Target {
        server: ServerUrl::parse(base).expect("valid base"),
        roots,
        token: Some(token()),
        timeout,
    })
    .expect("client builds")
}

fn plain_client(address: SocketAddr) -> AdminClient {
    client(
        &format!("http://{address}/v1/admin"),
        Vec::new(),
        Duration::from_secs(10),
    )
}

#[tokio::test]
async fn the_handshake_reads_the_capability_document_with_the_bearer_token_only() {
    let (address, seen) = serve(
        Some(http_response(
            "200 OK",
            "application/json; charset=utf-8",
            &capabilities_body(),
        )),
        None,
    )
    .await;
    let outcome = handshake(&plain_client(address)).await;
    assert_eq!(
        outcome,
        Ok(Handshake::Compatible(GatewayCapabilities::environment(
            "1.0.1"
        )))
    );
    let requests = seen.requests();
    assert_eq!(requests.len(), 1);
    let request = requests[0].to_ascii_lowercase();
    assert!(
        request.starts_with("get /v1/admin/config/capabilities http/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains(&format!(
        "authorization: bearer {}",
        CANARY.to_ascii_lowercase()
    )));
    assert!(request.contains("accept: application/json\r\n"));
    assert!(request.contains(&format!(
        "user-agent: ggctl/{}\r\n",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(!request.contains("referer"));
    assert!(!request.contains("proxy"));
    assert!(!request.contains("cookie"));
}

#[tokio::test]
async fn statuses_map_to_stable_codes_and_a_redirect_is_never_followed() {
    let (target, target_seen) = serve(
        Some(http_response(
            "200 OK",
            "application/json",
            &capabilities_body(),
        )),
        None,
    )
    .await;
    let redirect = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target}/v1/admin/config/capabilities\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    for (response, code) in [
        (redirect, Code::RedirectRefused),
        (
            http_response("301 Moved Permanently", "text/plain", ""),
            Code::RedirectRefused,
        ),
        (
            http_response("401 Unauthorized", "application/json", "{}"),
            Code::Unauthenticated,
        ),
        (
            http_response("403 Forbidden", "application/json", "{}"),
            Code::Forbidden,
        ),
        (
            http_response("404 Not Found", "application/json", "{}"),
            Code::CapabilitiesUnavailable,
        ),
        (
            http_response("503 Service Unavailable", "application/json", "{}"),
            Code::ServerUnavailable,
        ),
        (
            http_response("500 Internal Server Error", "application/json", "{}"),
            Code::UnexpectedStatus,
        ),
        (
            http_response("204 No Content", "application/json", ""),
            Code::UnexpectedStatus,
        ),
        (
            http_response("200 OK", "text/html", &capabilities_body()),
            Code::UnexpectedContentType,
        ),
        (
            http_response("200 OK", "application/jsonx", &capabilities_body()),
            Code::UnexpectedContentType,
        ),
    ] {
        let (address, _) = serve(Some(response), None).await;
        assert_eq!(handshake(&plain_client(address)).await, Err(code));
    }
    assert_eq!(
        target_seen.connections.load(Ordering::SeqCst),
        0,
        "the redirect target was contacted"
    );
}

#[tokio::test]
async fn an_unreadable_document_is_an_incompatible_server_not_a_partial_read() {
    let mut newer: serde_json::Value = serde_json::from_str(&capabilities_body()).expect("JSON");
    newer["apiVersion"] = "greengateway.dev/v1beta1".into();
    newer["gatewayVersion"] = "2.0.0".into();
    let mut invalid: serde_json::Value = serde_json::from_str(&capabilities_body()).expect("JSON");
    invalid["sourceMode"] = "bundle".into();
    for (body, expected) in [
        (
            newer.to_string(),
            Handshake::Incompatible {
                gateway_version: Some("2.0.0".to_owned()),
                reason: Code::UnsupportedCapabilitiesVersion,
            },
        ),
        (
            invalid.to_string(),
            Handshake::Incompatible {
                gateway_version: Some("1.0.1".to_owned()),
                reason: Code::CapabilitiesInvalid,
            },
        ),
        (
            "not json".to_owned(),
            Handshake::Incompatible {
                gateway_version: None,
                reason: Code::CapabilitiesInvalid,
            },
        ),
    ] {
        let (address, _) = serve(
            Some(http_response("200 OK", "application/json", &body)),
            None,
        )
        .await;
        assert_eq!(handshake(&plain_client(address)).await, Ok(expected));
    }
}

#[tokio::test]
async fn responses_are_bounded_with_or_without_a_length() {
    let large = "x".repeat(MAX_CAPABILITIES_BYTES + 1);
    let (address, _) = serve(
        Some(http_response("200 OK", "application/json", &large)),
        None,
    )
    .await;
    assert_eq!(
        handshake(&plain_client(address)).await,
        Err(Code::ResponseTooLarge)
    );

    let chunked = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{large}\r\n0\r\n\r\n",
        large.len()
    )
    .into_bytes();
    let (address, _) = serve(Some(chunked), None).await;
    assert_eq!(
        handshake(&plain_client(address)).await,
        Err(Code::ResponseTooLarge)
    );
}

#[tokio::test]
async fn a_request_that_reached_the_server_is_never_resent() {
    // The server accepts, reads the request and closes without answering.
    let (address, seen) = serve(Some(Vec::new()), None).await;
    assert_eq!(
        handshake(&plain_client(address)).await,
        Err(Code::TransportFailed)
    );
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
    assert_eq!(seen.requests().len(), 1);
}

#[tokio::test]
async fn a_refused_connection_is_unavailable_and_a_silent_server_times_out() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let closed = listener.local_addr().expect("address");
    drop(listener);
    assert_eq!(
        handshake(&plain_client(closed)).await,
        Err(Code::ConnectFailed)
    );

    let (address, seen) = serve(None, None).await;
    let client = client(
        &format!("http://{address}/v1/admin"),
        Vec::new(),
        Duration::from_secs(1),
    );
    assert_eq!(handshake(&client).await, Err(Code::Timeout));
    assert_eq!(
        seen.connections.load(Ordering::SeqCst),
        1,
        "a timed-out read is not retried"
    );
}

struct Pki {
    ca_pem: String,
    acceptor: TlsAcceptor,
}

/// A CA and a server certificate for `san`, generated at test runtime.
fn pki(san: IpAddr) -> Pki {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ggctl test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let ca = ca_params.self_signed(&ca_key).expect("CA certificate");
    let mut server_params = rcgen::CertificateParams::default();
    server_params.distinguished_name = rcgen::DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ggctl test server");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(san));
    // macOS requires the server-authentication purpose on a TLS leaf.
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = rcgen::KeyPair::generate().expect("server key");
    let server = server_params
        .signed_by(
            &server_key,
            &rcgen::Issuer::from_params(&ca_params, &ca_key),
        )
        .expect("server certificate");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(server.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
    )
    .expect("server config");
    Pki {
        ca_pem: ca.pem(),
        acceptor: TlsAcceptor::from(Arc::new(config)),
    }
}

#[tokio::test]
async fn https_verifies_the_certificate_and_the_hostname() {
    let body = http_response("200 OK", "application/json", &capabilities_body());
    let pki_for_loopback = pki(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let (address, _) = serve(Some(body.clone()), Some(pki_for_loopback.acceptor.clone())).await;
    let base = format!("https://{address}/v1/admin");
    let roots = roots_from_pem(pki_for_loopback.ca_pem.as_bytes()).expect("PEM");
    assert_eq!(
        handshake(&client(&base, roots, Duration::from_secs(10))).await,
        Ok(Handshake::Compatible(GatewayCapabilities::environment(
            "1.0.1"
        )))
    );
    // Without the CA the platform roots do not trust the server.
    assert_eq!(
        handshake(&client(&base, Vec::new(), Duration::from_secs(10))).await,
        Err(Code::ConnectFailed)
    );
    // A trusted certificate for another address fails hostname verification.
    let other = pki(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    let (address, seen) = serve(Some(body), Some(other.acceptor.clone())).await;
    let roots = roots_from_pem(other.ca_pem.as_bytes()).expect("PEM");
    assert_eq!(
        handshake(&client(
            &format!("https://{address}/v1/admin"),
            roots,
            Duration::from_secs(10)
        ))
        .await,
        Err(Code::ConnectFailed)
    );
    assert!(
        seen.requests().is_empty(),
        "no request was sent over an unverified connection"
    );
}

/// A directory of CA files, removed on drop. On Unix it and every file
/// written into it get explicit modes, so the runner's umask cannot decide
/// whether the permission rules pass.
struct CaDirectory(PathBuf);

impl CaDirectory {
    fn new(name: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("ggctl-ca-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("directory");
        let directory = Self(directory);
        set_mode(&directory.0, 0o700);
        directory
    }

    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write");
        set_mode(&path, 0o644);
        path
    }
}

impl Drop for CaDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

#[test]
fn a_ca_file_must_hold_a_pem_certificate() {
    let directory = CaDirectory::new("contents");
    let pem = pki(IpAddr::V4(Ipv4Addr::LOCALHOST)).ca_pem;
    let valid = directory.write("ca.pem", pem.as_bytes());
    assert_eq!(load_roots(&valid).map(|roots| roots.len()), Ok(1));
    let empty = directory.write("empty.pem", b"no certificate here\n");
    assert_eq!(load_roots(&empty).map(|_| ()), Err(Code::CaFileInvalid));
    let large = directory.write("large.pem", &vec![b'a'; MAX_CA_FILE_BYTES + 1]);
    assert_eq!(load_roots(&large).map(|_| ()), Err(Code::CaFileTooLarge));
    assert_eq!(
        load_roots(&directory.0).map(|_| ()),
        Err(Code::CaFileNotRegularFile)
    );
    assert_eq!(
        load_roots(&directory.0.join("missing.pem")).map(|_| ()),
        Err(Code::CaFileUnreadable)
    );
}

/// The trust anchors decide where the token goes, so another account must
/// not be able to add one: world-readable is fine, writable is not.
#[cfg(unix)]
#[test]
fn a_ca_file_writable_by_group_or_other_is_refused() {
    let directory = CaDirectory::new("modes");
    let pem = pki(IpAddr::V4(Ipv4Addr::LOCALHOST)).ca_pem;
    for mode in [0o644, 0o444, 0o640, 0o600] {
        let path = directory.write(&format!("ca-{mode:o}.pem"), pem.as_bytes());
        set_mode(&path, mode);
        assert_eq!(
            load_roots(&path).map(|roots| roots.len()),
            Ok(1),
            "{mode:o}"
        );
    }
    for mode in [0o664, 0o666, 0o646, 0o620, 0o602] {
        let path = directory.write(&format!("ca-{mode:o}.pem"), pem.as_bytes());
        set_mode(&path, mode);
        assert_eq!(
            load_roots(&path).map(|_| ()),
            Err(Code::CaFileUnsafePermissions),
            "{mode:o}"
        );
    }
}

/// Whoever can write a directory can replace a `0644` file in it; the sticky
/// bit stops an account doing that to a file it does not own.
#[cfg(unix)]
#[test]
fn a_ca_file_in_a_directory_writable_by_group_or_other_is_refused() {
    use std::os::unix::fs::symlink;

    let pem = pki(IpAddr::V4(Ipv4Addr::LOCALHOST)).ca_pem;
    for mode in [0o770, 0o775, 0o707, 0o777] {
        let directory = CaDirectory::new(&format!("directory-{mode:o}"));
        let path = directory.write("ca.pem", pem.as_bytes());
        set_mode(&directory.0, mode);
        assert_eq!(
            load_roots(&path).map(|_| ()),
            Err(Code::CaFileUnsafePermissions),
            "{mode:o}"
        );
    }
    for mode in [0o755, 0o750, 0o1777, 0o1775] {
        let directory = CaDirectory::new(&format!("directory-{mode:o}"));
        let path = directory.write("ca.pem", pem.as_bytes());
        set_mode(&directory.0, mode);
        assert_eq!(
            load_roots(&path).map(|roots| roots.len()),
            Ok(1),
            "{mode:o}"
        );
    }

    // A link is judged by the directory holding the file it points to too.
    let shared = CaDirectory::new("link-target");
    shared.write("ca.pem", pem.as_bytes());
    set_mode(&shared.0, 0o775);
    let private = CaDirectory::new("link");
    let link = private.0.join("ca.pem");
    symlink(shared.0.join("ca.pem"), &link).expect("symlink");
    assert_eq!(
        load_roots(&link).map(|_| ()),
        Err(Code::CaFileUnsafePermissions)
    );
    set_mode(&shared.0, 0o755);
    assert_eq!(load_roots(&link).map(|roots| roots.len()), Ok(1));
    // And a link in a writable directory can be repointed, wherever it points.
    set_mode(&private.0, 0o777);
    assert_eq!(
        load_roots(&link).map(|_| ()),
        Err(Code::CaFileUnsafePermissions)
    );
}
