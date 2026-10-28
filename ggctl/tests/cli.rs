//! The `ggctl` binary end to end: real processes, real standard streams and
//! exit codes, and loopback-only fake gateways. Nothing here reaches the
//! public network.

use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
};

use serde_json::{json, Value};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};

const CANARY: &str = "gg-canary-cli-0d1e2f3a";

fn ggctl(arguments: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ggctl"));
    command
        .args(arguments)
        // Ambient proxy variables are ignored: were they honored, every
        // request below would go to a closed port instead.
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().expect("ggctl should start");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("stdin accepts the token");
    }
    child.wait_with_output().expect("ggctl should finish")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("UTF-8 output")
}

fn assert_no_canary(output: &Output) {
    let all = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(!all.contains(CANARY), "the token reached the output: {all}");
}

fn schema(file: &str) -> jsonschema::Validator {
    let path = format!("{}/../docs/schemas/{file}", env!("CARGO_MANIFEST_DIR"));
    let value: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("schema")).expect("JSON");
    jsonschema::validator_for(&value).expect("schema compiles")
}

/// Parses a `--format json` report and holds it to the published schemas.
fn report(output: &Output) -> Value {
    let report: Value = serde_json::from_slice(&output.stdout).expect("exactly one JSON document");
    let errors: Vec<_> = schema("ggctl-report.v1alpha1.schema.json")
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{report:#}");
    if let Some(capabilities) = report["result"]["server"].get("capabilities") {
        assert!(schema("gateway-capabilities.v1alpha1.schema.json").is_valid(capabilities));
    }
    assert_eq!(
        Some(report["exitCode"].as_i64().expect("exit code")),
        output.status.code().map(i64::from)
    );
    report
}

/// A loopback HTTP server answering every request with one response.
struct FakeGateway {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
}

impl FakeGateway {
    fn start(response: Vec<u8>, tls: Option<Arc<rustls::ServerConfig>>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (recorded, counted) = (requests.clone(), connections.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                counted.fetch_add(1, Ordering::SeqCst);
                let (response, recorded, tls) = (response.clone(), recorded.clone(), tls.clone());
                thread::spawn(move || match tls {
                    Some(config) => {
                        let Ok(connection) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        answer(
                            rustls::StreamOwned::new(connection, stream),
                            &response,
                            &recorded,
                        );
                    }
                    None => answer(stream, &response, &recorded),
                });
            }
        });
        Self {
            address,
            requests,
            connections,
        }
    }

    fn base(&self, scheme: &str) -> String {
        format!("{scheme}://{}/v1/admin", self.address)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("lock").clone()
    }
}

fn answer<S: Read + Write>(mut stream: S, response: &[u8], recorded: &Mutex<Vec<String>>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < 16 * 1024 {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    recorded
        .lock()
        .expect("lock")
        .push(String::from_utf8_lossy(&head).into_owned());
    let _ = stream.write_all(response);
    let _ = stream.flush();
}

fn http_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn capabilities(version: &str) -> String {
    json!({
        "apiVersion": "greengateway.dev/v1alpha1",
        "kind": "GatewayCapabilities",
        "gatewayVersion": version,
        "sourceMode": "environment",
        "documents": [],
        "operations": []
    })
    .to_string()
}

#[test]
fn help_completion_and_schema_are_artifacts_on_standard_output() {
    let output = ggctl(&["--help"], None);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).contains("Exit codes:"));
    assert!(output.stderr.is_empty());

    let output = ggctl(&["completion", "bash"], None);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout).ends_with("complete -F _ggctl ggctl\n"));

    let output = ggctl(&["schema", "GgctlReport"], None);
    assert_eq!(output.status.code(), Some(0));
    let committed = std::fs::read_to_string(format!(
        "{}/../docs/schemas/ggctl-report.v1alpha1.schema.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("schema");
    assert_eq!(text(&output.stdout), committed.replace("\r\n", "\n"));

    let output = ggctl(&["version", "--format", "json"], None);
    assert_eq!(output.status.code(), Some(0));
    let report = report(&output);
    assert_eq!(report["outcome"], "success");
    assert_eq!(
        report["result"]["client"]["version"],
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn argument_errors_exit_2_and_never_echo_the_argument() {
    for arguments in [
        vec!["version".to_owned(), format!("--token={CANARY}")],
        vec![
            "version".to_owned(),
            "--token".to_owned(),
            CANARY.to_owned(),
        ],
        vec!["version".to_owned(), format!("--{CANARY}")],
        vec![CANARY.to_owned()],
        vec!["version".to_owned(), CANARY.to_owned()],
        vec!["version".to_owned(), "--insecure".to_owned()],
        // Assembled at run time so the source holds no credential-shaped URL.
        vec![
            "version".to_owned(),
            "--server".to_owned(),
            [
                "https://operator",
                &format!("{CANARY}@gateway.example.test/v1/admin"),
            ]
            .join(":"),
        ],
        vec![
            "version".to_owned(),
            "--server".to_owned(),
            format!("https://gateway.example.test/v1/admin?token={CANARY}"),
        ],
        vec!["db".to_owned(), "migrate".to_owned()],
    ] {
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        let output = ggctl(&arguments, None);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert!(
            text(&output.stderr).starts_with("ggctl: error: "),
            "{arguments:?}"
        );
        assert_no_canary(&output);
    }
}

#[test]
fn the_handshake_uses_the_piped_token_and_reports_a_compatible_gateway() {
    let gateway = FakeGateway::start(http_response("200 OK", &capabilities("1.0.1")), None);
    let token = format!("{CANARY}\n");
    let output = ggctl(
        &[
            "version",
            "--server",
            &gateway.base("http"),
            "--token-stdin",
            "--format",
            "json",
        ],
        Some(token.as_bytes()),
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(output.stderr.is_empty());
    assert_no_canary(&output);
    let report = report(&output);
    assert_eq!(report["result"]["server"]["compatible"], true);
    assert_eq!(report["result"]["server"]["gatewayVersion"], "1.0.1");
    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /v1/admin/config/capabilities HTTP/1.1\r\n"));
    assert!(requests[0].contains(&format!("authorization: Bearer {CANARY}\r\n")));

    let output = ggctl(
        &[
            "version",
            "--server",
            &gateway.base("http"),
            "--token-stdin",
        ],
        Some(token.as_bytes()),
    );
    assert_eq!(output.status.code(), Some(0));
    let stdout = text(&output.stdout);
    assert!(stdout.contains("server: compatible\ngateway: 1.0.1\nsource mode: environment\n"));
    assert!(stdout.contains("configuration operations: none\n"));
}

#[test]
fn every_failure_has_its_documented_exit_code_and_no_retry_after_contact() {
    let newer = capabilities("2.0.0").replace("v1alpha1", "v1beta1");
    for (response, exit, code) in [
        (http_response("401 Unauthorized", "{}"), 8, "remote.unauthenticated"),
        (http_response("403 Forbidden", "{}"), 8, "remote.forbidden"),
        (http_response("404 Not Found", "{}"), 3, "compat.capabilities_unavailable"),
        (http_response("503 Service Unavailable", "{}"), 6, "remote.server_unavailable"),
        (http_response("500 Internal Server Error", "{}"), 1, "remote.unexpected_status"),
        (http_response("200 OK", &newer), 3, "compat.unsupported_capabilities_version"),
        (
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
            1,
            "remote.redirect_refused",
        ),
    ] {
        let gateway = FakeGateway::start(response, None);
        let output = ggctl(
            &["version", "--server", &gateway.base("http"), "--token-stdin", "--format", "json"],
            Some(CANARY.as_bytes()),
        );
        assert_eq!(output.status.code(), Some(exit), "{code}");
        assert_no_canary(&output);
        let report = report(&output);
        assert_eq!(report["diagnostics"][0]["code"], code);
        assert_eq!(report["result"]["server"]["compatible"], false);
        assert_eq!(gateway.connections.load(Ordering::SeqCst), 1, "{code}");
    }
    // The newer server's version is still reported, and human output names
    // the incompatibility on standard error.
    let gateway = FakeGateway::start(http_response("200 OK", &newer), None);
    let output = ggctl(&["version", "--server", &gateway.base("http")], None);
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stdout).contains("server: incompatible\ngateway: 2.0.0\n"));
    assert!(text(&output.stderr).contains("compat.unsupported_capabilities_version"));
}

#[test]
fn an_unreachable_server_is_retryable_and_names_nothing_about_it() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let base = format!("http://{address}/v1/admin");
    let output = ggctl(&["version", "--server", &base], None);
    assert_eq!(output.status.code(), Some(6));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("remote.connect_failed"));
    assert!(!stderr.contains(&address.port().to_string()), "{stderr}");
    assert!(text(&output.stdout).contains("server: not verified\n"));
}

fn tls_config() -> (String, Arc<rustls::ServerConfig>) {
    // Distinct subject names: a leaf whose subject equals its issuer's looks
    // self-issued, and platform verifiers refuse to chain it.
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ggctl test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let ca = ca_params.self_signed(&ca_key).expect("CA");
    let mut server_params = rcgen::CertificateParams::default();
    server_params.distinguished_name = rcgen::DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ggctl test server");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
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
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(server.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
    )
    .expect("config");
    (ca.pem(), Arc::new(config))
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("ggctl-cli-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temp directory");
        // An explicit mode, so the runner's umask cannot decide whether the
        // CA file's directory passes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("mode");
        }
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn https_with_an_added_trust_anchor_and_a_token_file() {
    let (ca_pem, config) = tls_config();
    let gateway = FakeGateway::start(
        http_response("200 OK", &capabilities("1.0.1")),
        Some(config),
    );
    let directory = TempDirectory::new("https");
    let ca_file = directory.0.join("ca.pem");
    std::fs::write(&ca_file, ca_pem).expect("CA file");
    let token_file = directory.0.join("token");
    std::fs::write(&token_file, CANARY).expect("token file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))
            .expect("mode");
        // A trust anchor may be world-readable.
        std::fs::set_permissions(&ca_file, std::fs::Permissions::from_mode(0o644)).expect("mode");
    }
    let base = gateway.base("https");
    let ca = ca_file.to_str().expect("UTF-8 path");
    let token = token_file.to_str().expect("UTF-8 path");

    let output = ggctl(
        &[
            "version",
            "--server",
            &base,
            "--ca-file",
            ca,
            "--token-file",
            token,
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(report(&output)["result"]["server"]["compatible"], true);
    assert_no_canary(&output);

    // Without the added anchor the certificate is not trusted, and nothing
    // was sent over the unverified connection.
    let before = gateway.requests().len();
    let output = ggctl(&["version", "--server", &base, "--token-file", token], None);
    assert_eq!(output.status.code(), Some(6));
    assert!(text(&output.stderr).contains("remote.connect_failed"));
    assert_eq!(gateway.requests().len(), before);
    assert_no_canary(&output);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644))
            .expect("mode");
        let output = ggctl(
            &[
                "version",
                "--server",
                &base,
                "--ca-file",
                ca,
                "--token-file",
                token,
            ],
            None,
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(text(&output.stderr).contains("credential.unsafe_permissions"));
        assert_eq!(gateway.requests().len(), before);

        // A CA file another account can write could add the anchor that
        // receives the token: refused before any connection is made.
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))
            .expect("mode");
        std::fs::set_permissions(&ca_file, std::fs::Permissions::from_mode(0o664)).expect("mode");
        let output = ggctl(
            &[
                "version",
                "--server",
                &base,
                "--ca-file",
                ca,
                "--token-file",
                token,
            ],
            None,
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(text(&output.stderr).contains("trust.ca_file_unsafe_permissions"));
        assert_eq!(gateway.requests().len(), before);
        assert_no_canary(&output);
    }
}
