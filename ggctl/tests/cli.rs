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

use gateway_config::mcp_client_configs::{
    Auth, ClientKind, Format, McpClientConfigs, McpUrl, ServerName,
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

/// A configuration bundle under the system temporary directory, removed on
/// drop.
struct Bundle(std::path::PathBuf);

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Bundle {
    /// A production bundle pinning `policy`, the empty tools document and a
    /// deployment document.
    fn new(policy: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "ggctl-cli-bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the bundle directory should create");
        let bundle = Self(root);
        bundle.write(
            "deployment.yaml",
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n",
        );
        bundle.write("policy.json", policy);
        bundle.write(
            "tools.json",
            "{\"schema_version\": \"0.1.0\", \"tools\": []}\n",
        );
        let pin = |name: &str| {
            gateway_config::bundle::sha256_pin(
                &std::fs::read(bundle.0.join(name)).expect("the bundle file should read"),
            )
        };
        let manifest = format!(
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayBundle\nmetadata:\n  name: payments-production\nspec:\n  deployment:\n    path: deployment.yaml\n    sha256: \"{}\"\n  resources:\n    policy:\n      source: bundle\n      path: policy.json\n      schema_version: \"0.1.0\"\n      sha256: \"{}\"\n    tools:\n      source: bundle\n      path: tools.json\n      schema_version: \"0.1.0\"\n      sha256: \"{}\"\n",
            pin("deployment.yaml"),
            pin("policy.json"),
            pin("tools.json"),
        );
        bundle.write("bundle.yaml", &manifest);
        bundle
    }

    fn write(&self, name: &str, contents: &str) {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("the bundle file should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for (path, mode) in [(&self.0, 0o755), (&path, 0o644)] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                    .expect("permissions should set");
            }
        }
    }

    fn path(&self) -> &str {
        self.0
            .to_str()
            .expect("the temporary directory should be UTF-8")
    }
}

fn assert_path_not_echoed(output: &Output, path: &str) {
    let all = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(
        !all.contains(path),
        "the bundle path reached the output: {all}"
    );
}

#[test]
fn validate_and_doctor_read_a_bundle_offline_with_their_exit_codes() {
    let bundle = Bundle::new("{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\"}\n");

    let output = ggctl(&["validate", bundle.path()], None);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout)
        .starts_with("bundle payments-production (greengateway.dev/v1alpha1): valid\n"));
    assert!(
        text(&output.stderr).starts_with("ggctl: info: validate.production_validators_not_run: ")
    );
    assert_path_not_echoed(&output, bundle.path());

    for command in ["validate", "doctor"] {
        let output = ggctl(&[command, bundle.path(), "--format", "json"], None);
        assert_eq!(output.status.code(), Some(0), "{command}");
        let report = report(&output);
        assert_eq!(report["command"], command);
        assert!(output.stderr.is_empty(), "{command}");
        assert_path_not_echoed(&output, bundle.path());
    }

    let output = ggctl(&["validate", bundle.path(), "--format", "sarif"], None);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let log: Value = serde_json::from_slice(&output.stdout).expect("one SARIF log");
    assert_eq!(log["version"], "2.1.0");
    assert_eq!(
        log["runs"][0]["results"][0]["ruleId"],
        "validate.production_validators_not_run"
    );

    // A production bundle with an allow-by-default policy is invalid, and
    // the policy's values never reach the output.
    let allow = Bundle::new(&format!(
        "{{\"schema_version\": \"0.1.0\", \"id\": \"{CANARY}\", \"default_action\": \"allow\"}}\n"
    ));
    for command in ["validate", "doctor"] {
        let output = ggctl(&[command, allow.path(), "--format", "json"], None);
        assert_eq!(output.status.code(), Some(3), "{command}");
        let report = report(&output);
        assert_eq!(
            report["diagnostics"][0]["code"],
            "profile.policy_default_allow"
        );
        assert_eq!(
            report["diagnostics"][0]["location"],
            json!({"file": "policy.json", "pointer": "/default_action", "line": 1, "column": 79})
        );
        assert_no_canary(&output);
    }

    // A bundle that cannot be read at all is an I/O failure.
    let missing = bundle.0.join("missing");
    let missing = missing.to_str().expect("UTF-8");
    for command in ["validate", "doctor"] {
        let output = ggctl(&[command, missing], None);
        assert_eq!(output.status.code(), Some(1), "{command}");
        assert!(text(&output.stderr).contains("bundle.root_unavailable"));
        assert_path_not_echoed(&output, missing);
    }
}

/// `--env` end to end: real processes, the published report schema, the
/// exit codes, and a secret in the file that never reaches either stream.
#[test]
fn environment_files_are_validated_diagnosed_and_compared_without_echoing_a_value() {
    let bundle = Bundle::new("{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\"}\n");
    bundle.write(
        "base.env",
        &format!(
            "AUTH_ENABLED=true\nTLS_CERT_FILE=/run/tls/a.crt\nTLS_KEY_FILE=/run/{CANARY}/a.key\n"
        ),
    );
    bundle.write(
        "candidate.env",
        &format!(
            "# reviewed\nexport AUTH_ENABLED=false\nTLS_CERT_FILE=/run/tls/a.crt\nTLS_KEY_FILE=/run/{CANARY}/b.key\n{CANARY}={CANARY}\n"
        ),
    );
    bundle.write(
        "refused.env",
        &format!("AUTH_MODE={CANARY}\nAUTH_MODE={CANARY}\n"),
    );
    let path = |name: &str| bundle.0.join(name).to_str().expect("UTF-8").to_owned();
    let (base, candidate, refused) = (path("base.env"), path("candidate.env"), path("refused.env"));

    for command in ["validate", "doctor"] {
        let output = ggctl(&[command, "--env", &candidate, "--format", "json"], None);
        assert_eq!(output.status.code(), Some(0), "{command}");
        let found = report(&output);
        assert_eq!(found["command"], command);
        assert_no_canary(&output);
        assert_path_not_echoed(&output, &candidate);

        let output = ggctl(&[command, "--env", &refused, "--format", "json"], None);
        assert_eq!(output.status.code(), Some(3), "{command}");
        let found = report(&output);
        let codes: Vec<_> = found["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .map(|diagnostic| diagnostic["code"].as_str().expect("code").to_owned())
            .collect();
        assert_eq!(
            codes[..2],
            ["env.duplicate_key", "config.refused"],
            "{command}"
        );
        assert_no_canary(&output);

        let output = ggctl(&[command, "--env", &refused], None);
        assert_eq!(output.status.code(), Some(3), "{command}");
        assert!(text(&output.stderr).contains("  at: argument 2, line 2\n  setting: AUTH_MODE\n"));
        assert_no_canary(&output);
        assert_path_not_echoed(&output, &refused);
    }

    let output = ggctl(
        &[
            "validate", "--env", &refused, "--strict", "--format", "sarif",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    let log: Value = serde_json::from_slice(&output.stdout).expect("one SARIF log");
    assert_eq!(log["runs"][0]["results"][0]["ruleId"], "env.duplicate_key");
    assert_eq!(log["runs"][0]["results"][0]["level"], "error");
    assert_no_canary(&output);

    let output = ggctl(
        &[
            "diff",
            "--env",
            &candidate,
            "--against-env",
            &base,
            "--check",
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(4));
    let report = report(&output);
    assert!(report["result"]["diff"]["riskCodes"]
        .as_array()
        .expect("risk codes")
        .contains(&json!("risk.auth_disabled")));
    assert_no_canary(&output);

    let output = ggctl(
        &["diff", "--env", &candidate, "--against", bundle.path()],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stderr).contains("diff.not_comparable"));

    let missing = path("missing.env");
    let output = ggctl(&["validate", "--env", &missing], None);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).starts_with("ggctl: error: env.unreadable: "));
    assert_path_not_echoed(&output, &missing);

    let output = ggctl(&["validate", bundle.path(), "--env", &candidate], None);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(text(&output.stderr).starts_with("ggctl: error: usage.conflicting_options: "));
}

#[test]
fn pin_repins_an_edited_file_and_never_one_that_is_invalid() {
    let bundle = Bundle::new("{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\"}\n");
    bundle.write(
        "policy.json",
        "{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\", \"enforcement_mode\": \"enforce\"}\n",
    );
    let output = ggctl(&["validate", bundle.path()], None);
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stderr).contains("bundle.digest_mismatch"));

    let output = ggctl(&["pin", bundle.path(), "--format", "json"], None);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let found = report(&output);
    assert_eq!(found["command"], "pin");
    assert_eq!(found["result"]["written"], true);
    assert_path_not_echoed(&output, bundle.path());
    let output = ggctl(&["validate", bundle.path(), "--strict"], None);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    // An allow-by-default policy is refused, and the manifest is untouched.
    let manifest = std::fs::read(bundle.0.join("bundle.yaml")).expect("the manifest");
    bundle.write(
        "policy.json",
        &format!("{{\"schema_version\": \"0.1.0\", \"id\": \"{CANARY}\", \"default_action\": \"allow\"}}\n"),
    );
    let output = ggctl(&["pin", bundle.path()], None);
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stderr).contains("profile.policy_default_allow"));
    assert_no_canary(&output);
    assert_eq!(
        std::fs::read(bundle.0.join("bundle.yaml")).expect("the manifest"),
        manifest
    );
}

#[test]
fn init_writes_a_bundle_that_validates_strictly_and_converts_to_itself() {
    // An empty parent: init creates the bundle directory in it.
    let parent = Bundle::new("{\"schema_version\": \"0.1.0\"}\n");
    let output_directory = parent.0.join("generated");
    let generated = output_directory.to_str().expect("UTF-8");

    let output = ggctl(
        &[
            "init",
            "--profile",
            "production",
            "--output",
            generated,
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let found = report(&output);
    assert_eq!(found["command"], "init");
    assert_eq!(found["result"]["created"], true);
    assert_eq!(
        found["result"]["bundle"]["deployment"]["profile"],
        "production"
    );
    assert_path_not_echoed(&output, generated);

    let output = ggctl(
        &["validate", generated, "--strict", "--warnings-as-errors"],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    // A second init into the same directory is refused and changes nothing.
    let before = std::fs::read(output_directory.join("bundle.yaml")).expect("the manifest");
    let output = ggctl(
        &["init", "--profile", "development", "--output", generated],
        None,
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(text(&output.stderr).contains("output.destination_exists"));
    assert_eq!(
        std::fs::read(output_directory.join("bundle.yaml")).expect("the manifest"),
        before
    );

    let copy = parent.0.join("copy");
    let output = ggctl(
        &[
            "convert",
            generated,
            "--to",
            "greengateway.dev/v1alpha1",
            "--output",
            copy.to_str().expect("UTF-8"),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(
        std::fs::read(copy.join("bundle.yaml")).expect("the copied manifest"),
        before
    );
    let output = ggctl(
        &[
            "convert",
            generated,
            "--to",
            "greengateway.dev/v1alpha0",
            "--in-place",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stderr).contains("convert.unsupported_version"));
}

fn mcp_document(name: &str, oauth: bool) -> McpClientConfigs {
    McpClientConfigs::render(
        &McpUrl::new("https://gateway.example.test/base/mcp").expect("valid URL"),
        &ServerName::new(name).expect("valid name"),
        oauth,
    )
    .expect("renders")
}

/// Runs `ggctl mcp-config` in `directory`, with the canary token piped in.
fn mcp_config(directory: &std::path::Path, base: &str, extra: &[&str]) -> Output {
    let mut arguments = vec!["mcp-config", "--server", base, "--token-stdin"];
    arguments.extend_from_slice(extra);
    let mut child = Command::new(env!("CARGO_BIN_EXE_ggctl"))
        .args(&arguments)
        .current_dir(directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ggctl should start");
    // A command refused before it reads the token may already have closed
    // its standard input.
    let _ = child
        .stdin
        .take()
        .expect("stdin")
        .write_all(CANARY.as_bytes());
    child.wait_with_output().expect("ggctl should finish")
}

#[test]
fn mcp_config_writes_exactly_the_served_template_and_never_a_client_file_or_the_token() {
    let document = mcp_document("greengateway", true);
    let body = serde_json::to_string(&document).expect("serializes");
    let gateway = FakeGateway::start(http_response("200 OK", &body), None);
    // Client files ggctl must never open, edit or replace.
    let directory = TempDirectory::new("mcp-config");
    for file in [".cursor/mcp.json", ".vscode/mcp.json"] {
        let path = directory.0.join(file);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("client directory");
        std::fs::write(&path, "{\"sentinel\": true}\n").expect("client file");
    }
    let mut requests = 0;
    for client in ClientKind::ALL {
        for auth in Auth::ALL {
            if !client.supports(auth) {
                continue;
            }
            let output = mcp_config(
                &directory.0,
                &gateway.base("http"),
                &["--client", client.as_str(), "--auth", auth.as_str()],
            );
            requests += 1;
            assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
            assert!(output.stderr.is_empty());
            assert_no_canary(&output);
            let stdout = text(&output.stdout);
            let template = document.template(client, auth).expect("served");
            assert_eq!(stdout, template.content);
            match template.format {
                Format::Json => {
                    let parsed: Value = serde_json::from_str(&stdout).expect("JSON template");
                    assert!(parsed
                        .to_string()
                        .contains("https://gateway.example.test/base/mcp"));
                }
                Format::Url => assert_eq!(
                    url::Url::parse(stdout.trim_end()).expect("URL").as_str(),
                    "https://gateway.example.test/base/mcp"
                ),
            }
            assert_eq!(
                stdout.contains("GREENGATEWAY_MCP_TOKEN"),
                auth == Auth::Token
            );
        }
    }
    let seen = gateway.requests();
    assert_eq!(seen.len(), requests);
    for request in &seen {
        assert!(
            request.starts_with("GET /v1/admin/mcp/client-configs HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains(&format!("authorization: Bearer {CANARY}\r\n")));
    }
    for file in [".cursor/mcp.json", ".vscode/mcp.json"] {
        assert_eq!(
            std::fs::read_to_string(directory.0.join(file)).expect("client file"),
            "{\"sentinel\": true}\n"
        );
    }
    let mut left: Vec<_> = std::fs::read_dir(&directory.0)
        .expect("directory")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    left.sort();
    assert_eq!(left, [".cursor", ".vscode"]);
}

#[test]
fn mcp_config_names_the_server_entry_and_refuses_a_hostile_name_unsent() {
    let named = serde_json::to_string(&mcp_document("prod-gw", true)).expect("serializes");
    let gateway = FakeGateway::start(http_response("200 OK", &named), None);
    let directory = TempDirectory::new("mcp-config-name");
    let output = mcp_config(
        &directory.0,
        &gateway.base("http"),
        &["--client", "vscode", "--name", "prod-gw"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        parsed["servers"]["prod-gw"]["url"],
        "https://gateway.example.test/base/mcp"
    );
    assert!(gateway.requests()[0]
        .starts_with("GET /v1/admin/mcp/client-configs?name=prod-gw HTTP/1.1\r\n"));

    // A server that answers with another name is not trusted with this one.
    let output = mcp_config(&directory.0, &gateway.base("http"), &["--client", "vscode"]);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(text(&output.stderr).contains("mcp.client_configs_invalid"));

    for hostile in ["a\"b", "${env:HOME}", "__proto__", "a b", "-x"] {
        let output = mcp_config(
            &directory.0,
            &gateway.base("http"),
            &["--client", "cursor", "--name", hostile],
        );
        assert_eq!(output.status.code(), Some(2), "{hostile}");
        assert!(output.stdout.is_empty());
        assert!(!text(&output.stderr).contains(hostile), "{hostile}");
    }
    assert_eq!(gateway.requests().len(), 2);
}

#[test]
fn mcp_config_failures_write_nothing_and_have_their_documented_exit_codes() {
    let mut tampered = serde_json::to_value(mcp_document("greengateway", true)).expect("JSON");
    tampered["templates"][4]["content"] = format!("Bearer {CANARY}\n").into();
    let mut newer = serde_json::to_value(mcp_document("greengateway", true)).expect("JSON");
    newer["apiVersion"] = "greengateway.dev/v1beta1".into();
    let no_oauth = serde_json::to_string(&mcp_document("greengateway", false)).expect("JSON");
    let directory = TempDirectory::new("mcp-config-failures");
    for (response, client, exit, code) in [
        (
            http_response(
                "409 Conflict",
                r#"{"error":"MCP client configuration templates require GATEWAY_PUBLIC_URL","reason":"public_url_not_configured"}"#,
            ),
            "cursor",
            3,
            "mcp.public_url_unusable",
        ),
        (
            http_response("404 Not Found", "{}"),
            "cursor",
            3,
            "mcp.client_configs_unavailable",
        ),
        (
            http_response("403 Forbidden", "{}"),
            "cursor",
            8,
            "remote.forbidden",
        ),
        (
            http_response("401 Unauthorized", "{}"),
            "cursor",
            8,
            "remote.unauthenticated",
        ),
        (
            http_response("200 OK", &tampered.to_string()),
            "cursor",
            3,
            "mcp.client_configs_invalid",
        ),
        (
            http_response("200 OK", &newer.to_string()),
            "cursor",
            3,
            "mcp.unsupported_version",
        ),
        (
            http_response("200 OK", &no_oauth),
            "claude-desktop",
            3,
            "mcp.oauth_unavailable",
        ),
    ] {
        let gateway = FakeGateway::start(response, None);
        let output = mcp_config(&directory.0, &gateway.base("http"), &["--client", client]);
        assert_eq!(output.status.code(), Some(exit), "{code}");
        assert!(output.stdout.is_empty(), "{code}");
        assert!(
            text(&output.stderr).contains(code),
            "{code}: {}",
            text(&output.stderr)
        );
        assert_no_canary(&output);
        assert_eq!(gateway.connections.load(Ordering::SeqCst), 1, "{code}");
    }

    // Refused before anything is read or sent.
    let gateway = FakeGateway::start(http_response("200 OK", &no_oauth), None);
    for (extra, code) in [
        (
            &["--client", "claude-desktop", "--auth", "token"][..],
            "mcp.no_token_template",
        ),
        (
            &["--client", "cursor", "--format", "json"],
            "usage.unknown_option",
        ),
        (&["--client", "zed"], "usage.invalid_value"),
        (&[], "usage.missing_argument"),
    ] {
        let output = mcp_config(&directory.0, &gateway.base("http"), extra);
        assert_eq!(output.status.code(), Some(2), "{code}");
        assert!(output.stdout.is_empty());
        assert!(
            text(&output.stderr).contains(code),
            "{code}: {}",
            text(&output.stderr)
        );
    }
    assert_eq!(gateway.connections.load(Ordering::SeqCst), 0);
    let output = ggctl(&["mcp-config", "--client", "cursor"], None);
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output.stderr).contains("usage.missing_argument"));
}

/// A standalone state directory under the system temporary directory,
/// removed on drop.
struct StateDir(std::path::PathBuf);

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl StateDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "ggctl-cli-state-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the state directory should create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("permissions should set");
        }
        Self(root)
    }

    fn path(&self) -> &str {
        self.0
            .to_str()
            .expect("the temporary directory should be UTF-8")
    }

    fn revisions(&self) -> u64 {
        let held = gateway_config::state_dir::StateDirectory::acquire(&self.0)
            .expect("the state directory locks");
        gateway_config::ledger::RevisionLedger::inspect(&held)
            .expect("the ledger verifies")
            .revisions
    }
}

/// A role name that must never reach the output.
const ROLE_CANARY: &str = "zqcanaryrole";

/// A deny-by-default policy granting each of `roles` one permission.
fn roles_policy(roles: &[&str]) -> String {
    let roles: Vec<String> = roles
        .iter()
        .map(|role| format!("\"{role}\": {{\"permissions\": [\"admin:policy:read\"]}}"))
        .collect();
    format!(
        "{{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\", \"roles\": {{{}}}}}\n",
        roles.join(", ")
    )
}

/// Starts `ggctl` without waiting for it.
fn spawn(arguments: &[&str]) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_ggctl"))
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ggctl should start")
}

/// Appends a revision `bundle` as a gateway applying it online would, by a
/// principal whose subject is the canary.
fn apply_online(state: &StateDir, bundle: &Bundle) -> String {
    use gateway_config::ledger::{
        ActivationClass, AuthMode, LedgerActor, Operation, Proposal, RevisionCodes, RevisionLedger,
    };
    let held = gateway_config::state_dir::StateDirectory::acquire(&state.0)
        .expect("the state directory locks");
    let mut ledger = RevisionLedger::open(&held).expect("the ledger opens");
    let read = gateway_config::bundle::read_bundle(
        &bundle.0,
        gateway_config::bundle::ReadOptions { strict: true },
        &gateway_config::bundle::PublishedSchemasOnly,
    );
    let candidate = read.bundle.expect("the bundle reads");
    let head = ledger.state().expect("state").desired.revision;
    let actor = LedgerActor::principal(CANARY, Some("provider:corp"), AuthMode::BearerToken)
        .expect("recordable");
    ledger
        .append(
            &head,
            Proposal {
                bundle: &candidate,
                actor,
                operation: Operation::Apply,
                activation: ActivationClass::Live,
                codes: RevisionCodes::none(),
                request: None,
                recorded_at: std::time::SystemTime::now(),
            },
        )
        .expect("the revision appends")
        .revision
        .as_str()
        .to_owned()
}

#[test]
fn the_ledger_commands_seed_verify_and_roll_back_offline_without_echoing_anything() {
    let wide = Bundle::new(&roles_policy(&["auditor", ROLE_CANARY]));
    let state = StateDir::new();
    let output = ggctl(
        &[
            "ledger",
            "seed",
            wide.path(),
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stdout));
    let seeded = report(&output);
    assert_eq!(seeded["command"], "ledger seed");
    assert_eq!(seeded["result"]["seeded"], true);
    assert!(output.stderr.is_empty());
    let seed = seeded["result"]["ledger"]["desired"]["revision"]
        .as_str()
        .expect("the seed's ID")
        .to_owned();
    assert_no_canary(&output);
    assert!(!text(&output.stdout).contains(ROLE_CANARY));
    assert_path_not_echoed(&output, wide.path());
    assert_path_not_echoed(&output, state.path());

    // Seeding again, or over a leftover journal, is refused.
    let output = ggctl(
        &["ledger", "seed", wide.path(), "--state-dir", state.path()],
        None,
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(text(&output.stderr).contains("ggctl: error: ledger.exists: "));
    let leftover = StateDir::new();
    std::fs::write(leftover.0.join("config-ledger.sqlite3-journal"), b"journal")
        .expect("the leftover should write");
    let output = ggctl(
        &[
            "ledger",
            "seed",
            wide.path(),
            "--state-dir",
            leftover.path(),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(5));
    assert!(text(&output.stderr).contains("ggctl: error: ledger.exists: "));
    assert!(!leftover.0.join("config-ledger.sqlite3").exists());

    let narrow = Bundle::new(&roles_policy(&["auditor"]));
    let second = apply_online(&state, &narrow);

    // The rollback restores a role: nothing is written until its risk code
    // is named.
    let output = ggctl(
        &[
            "ledger",
            "rollback",
            &seed,
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    let refused = report(&output);
    assert_eq!(
        refused["result"]["plan"]["unacknowledged"],
        json!(["risk.policy_broadened"])
    );
    assert_eq!(state.revisions(), 2);
    let output = ggctl(
        &[
            "ledger",
            "rollback",
            &seed,
            "--state-dir",
            state.path(),
            "--acknowledge",
            "risk.policy_broadened",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(text(&output.stdout)
        .starts_with(&format!("rollback of {second} to the content of {seed}:\n")));
    assert!(text(&output.stderr).contains("ggctl: info: ledger.gateway_recompiles_at_start: "));
    assert_no_canary(&output);
    assert!(!text(&output.stdout).contains(ROLE_CANARY));
    assert_path_not_echoed(&output, state.path());

    let output = ggctl(
        &[
            "ledger",
            "verify",
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0));
    let verified = report(&output);
    let desired = &verified["result"]["ledger"]["desired"];
    assert_eq!(verified["result"]["ledger"]["revisions"], 3);
    assert_eq!(desired["operation"], "rollback");
    assert_eq!(desired["rollbackOf"], seed.as_str());
    assert_eq!(desired["actorKind"], "system");
    assert_eq!(desired["appliedOnline"], false);
    assert_no_canary(&output);

    // An edit outside the gateway is caught, and its class reported.
    let ledger = state.0.join("config-ledger.sqlite3");
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", ledger.display()));
    }
    let mut bytes = std::fs::read(&ledger).expect("the ledger");
    let found: Vec<usize> = bytes
        .windows(ROLE_CANARY.len())
        .enumerate()
        .filter(|(_, window)| *window == ROLE_CANARY.as_bytes())
        .map(|(index, _)| index)
        .collect();
    // The role is in the seed's policy, which the rollback shares: one
    // stored document. Changing it breaks its pin.
    assert_eq!(found.len(), 1, "the role's copies in the ledger");
    bytes[found[0]] = b'Z';
    std::fs::write(&ledger, &bytes).expect("the edit should write");
    let output = ggctl(
        &[
            "ledger",
            "verify",
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    let corrupt = report(&output);
    assert_eq!(
        corrupt["result"],
        json!({"verified": false, "corruption": "document"})
    );
    assert_eq!(corrupt["diagnostics"][0]["code"], "ledger.corrupt");
    assert_eq!(std::fs::read(&ledger).expect("the ledger"), bytes);
}

#[test]
fn a_held_state_directory_exits_5_and_two_ggctl_processes_have_one_winner() {
    let bundle = Bundle::new(&roles_policy(&["auditor"]));
    let state = StateDir::new();
    let held = gateway_config::state_dir::StateDirectory::acquire(&state.0)
        .expect("the test holds the lock");
    for arguments in [
        &["ledger", "seed", bundle.path(), "--state-dir", state.path()][..],
        &["ledger", "verify", "--state-dir", state.path()],
    ] {
        let output = ggctl(arguments, None);
        assert_eq!(output.status.code(), Some(5), "{arguments:?}");
        assert!(text(&output.stderr).contains("ggctl: error: state_dir.locked: "));
    }
    assert!(!state.0.join("config-ledger.sqlite3").exists());
    drop(held);

    // Two seeds at once: exactly one creates the ledger. The other finds the
    // directory locked or, if it came second, the ledger there; both exit 5.
    let children: Vec<_> = (0..2)
        .map(|_| spawn(&["ledger", "seed", bundle.path(), "--state-dir", state.path()]))
        .collect();
    let mut exits: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().expect("ggctl should finish"))
        .map(|output| output.status.code())
        .collect();
    exits.sort();
    assert_eq!(exits, [Some(0), Some(5)]);
    assert_eq!(state.revisions(), 1);

    // Two rollbacks at once: exactly one appends a revision.
    let output = ggctl(
        &[
            "ledger",
            "verify",
            "--state-dir",
            state.path(),
            "--format",
            "json",
        ],
        None,
    );
    let seed = report(&output)["result"]["ledger"]["desired"]["revision"]
        .as_str()
        .expect("the seed's ID")
        .to_owned();
    apply_online(
        &state,
        &Bundle::new(&roles_policy(&["auditor", "operator"])),
    );
    let children: Vec<_> = (0..2)
        .map(|_| spawn(&["ledger", "rollback", &seed, "--state-dir", state.path()]))
        .collect();
    let outcomes: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().expect("ggctl should finish"))
        .map(|output| (output.status.code(), text(&output.stderr)))
        .collect();
    let winners = outcomes.iter().filter(|(code, _)| *code == Some(0)).count();
    assert_eq!(winners, 1, "{outcomes:?}");
    // The loser found the lock held, or the rollback already made.
    assert!(
        outcomes.iter().any(|(code, stderr)| {
            (*code == Some(5) && stderr.contains("state_dir.locked"))
                || (*code == Some(3) && stderr.contains("ledger.no_change"))
        }),
        "{outcomes:?}"
    );
    assert_eq!(state.revisions(), 3);
}

/// A loopback HTTP server that answers the n-th request with the n-th
/// response (the last one again after that), recording each request's head
/// and body.
struct ScriptedGateway {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
}

impl ScriptedGateway {
    fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let address = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        thread::spawn(move || {
            for (index, stream) in listener.incoming().enumerate() {
                let Ok(mut stream) = stream else { break };
                let response = responses
                    .get(index)
                    .or(responses.last())
                    .cloned()
                    .unwrap_or_default();
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                recorded.lock().expect("lock").push(request);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        Self { address, requests }
    }

    fn base(&self) -> String {
        format!("http://{}/v1/admin", self.address)
    }

    fn requests(&self) -> Vec<(String, Vec<u8>)> {
        self.requests.lock().expect("lock").clone()
    }
}

/// One request's head and its `Content-Length` body.
fn read_request(stream: &mut std::net::TcpStream) -> Option<(String, Vec<u8>)> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 || stream.read(&mut byte).ok()? != 1 {
            return None;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let length = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).ok()?;
    Some((head, body))
}

fn json_response(status: &str, headers: &str, body: &Value) -> Vec<u8> {
    let body = body.to_string();
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A request document under the system temporary directory, removed on drop.
struct Document(PathBuf);

impl Document {
    fn new(name: &str, contents: &[u8]) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ggctl-cli-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("the document should write");
        Self(path)
    }

    fn path(&self) -> &str {
        self.0
            .to_str()
            .expect("the temporary directory should be UTF-8")
    }
}

impl Drop for Document {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Asserts the request line and the bearer token of a recorded request,
/// and that a body is sent as JSON.
fn assert_request(request: &(String, Vec<u8>), line: &str) {
    let head = request.0.to_ascii_lowercase();
    assert!(
        head.starts_with(&format!("{} http/1.1\r\n", line.to_ascii_lowercase())),
        "{head}"
    );
    assert!(head.contains(&format!(
        "authorization: bearer {}",
        CANARY.to_ascii_lowercase()
    )));
    if !request.1.is_empty() {
        assert!(
            head.contains("content-type: application/json\r\n"),
            "{head}"
        );
    }
}

const POLICY_ETAG: &str = "\"sha256:5f2c\"";
const REPLAY_JOB: &str = "rpl_00112233445566778899aabbccddeeff";

#[test]
fn policy_lint_sends_the_exact_bytes_and_reports_the_validators_findings() {
    let policy = b"{ \"schema_version\": \"1.0.0\",\n  \"default_action\": \"allow\" }\n";
    let document = Document::new("policy.json", policy);
    let digest = format!("sha256:{}", "a".repeat(64));
    let inspection = json!({
        "valid": false,
        "errors": [format!("rules must not be empty near {CANARY}")],
        "schema_version": "1.0.0",
        "diagnostics": [
            {"code": "required_member_missing", "severity": "error", "pointer": "/rules",
             "message": "a required member is missing", "remediation": "add the member",
             "blocks": {"simulation": true, "tests": true, "publication": true, "evidence": true}},
            {"code": "default_action_allow", "severity": "risk", "pointer": "/default_action",
             "message": "the default action allows", "remediation": "deny by default",
             "blocks": {"simulation": false, "tests": false, "publication": false, "evidence": false}}
        ],
        "source_digest": digest,
        "resource_snapshot": {"digest": digest, "complete": true}
    });
    let gateway = ScriptedGateway::start(vec![json_response("400 Bad Request", "", &inspection)]);
    let output = ggctl(
        &[
            "policy",
            "lint",
            document.path(),
            "--server",
            &gateway.base(),
            "--token-stdin",
            "--format",
            "json",
        ],
        Some(CANARY.as_bytes()),
    );
    assert_eq!(output.status.code(), Some(3), "{}", text(&output.stdout));
    let reported = report(&output);
    assert_eq!(reported["command"], "policy lint");
    assert_eq!(reported["diagnostics"][0]["code"], "policy.invalid");
    assert_eq!(reported["result"]["valid"], false);
    assert_eq!(reported["result"]["diagnostics"][1]["severity"], "risk");
    assert_eq!(reported["result"]["resourceSnapshot"]["complete"], true);
    assert!(output.stderr.is_empty());
    assert_no_canary(&output);
    assert_path_not_echoed(&output, document.path());
    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "POST /v1/admin/policy/validate");
    assert_eq!(
        requests[0].1, policy,
        "the document is sent as its exact bytes"
    );

    // SARIF: one result per finding, located by JSON Pointer only.
    let output = ggctl(
        &[
            "policy",
            "lint",
            document.path(),
            "--server",
            &gateway.base(),
            "--token-stdin",
            "--format",
            "sarif",
        ],
        Some(CANARY.as_bytes()),
    );
    assert_eq!(output.status.code(), Some(3));
    let log: Value = serde_json::from_slice(&output.stdout).expect("one SARIF log");
    let results = log["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results.len(), 3);
    assert_eq!(results[1]["ruleId"], "required_member_missing");
    assert_eq!(
        results[2]["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
        "/default_action"
    );
    assert!(output.stderr.is_empty());
    assert_no_canary(&output);
    assert_path_not_echoed(&output, document.path());

    // A valid document exits 0, unless a risk is an error by request.
    let valid = json!({"valid": true, "diagnostics": [inspection["diagnostics"][1].clone()]});
    let gateway = ScriptedGateway::start(vec![json_response("200 OK", "", &valid)]);
    let output = ggctl(
        &[
            "policy",
            "lint",
            document.path(),
            "--server",
            &gateway.base(),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        text(&output.stdout),
        "policy: valid, 1 risk\nrisk default_action_allow at /default_action: the default action allows\n"
    );
    let output = ggctl(
        &[
            "policy",
            "lint",
            document.path(),
            "--server",
            &gateway.base(),
            "--warnings-as-errors",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stderr).contains("validate.warnings_as_errors"));
}

#[test]
fn policy_test_splices_the_suite_and_candidate_and_gates_on_the_status() {
    let suite = b"{\"schema_version\": \"policy-tests.v1\", \"cases\": []}\n";
    let candidate = b"{ \"schema_version\": \"1.0.0\", \"rules\": [] }";
    let suite_file = Document::new("suite.json", suite);
    let candidate_file = Document::new("candidate.json", candidate);
    let results = json!({
        "schema_version": "policy-test-results.v1",
        "status": "failed",
        "mode": "test",
        "suite": {"schema_version": "policy-tests.v1", "digest": "sha256:d"},
        "policy": {"source": "inline_candidate", "etag": POLICY_ETAG},
        "summary": {"total": 1, "passed": 0, "failed": 1, "incomplete": 0, "errors": 0},
        "cases": [{"id": "orders-blocked", "kind": "http", "status": "failed", "mismatches": ["effect"]}],
        "not_evaluated": ["authentication"]
    });
    let gateway = ScriptedGateway::start(vec![json_response(
        "200 OK",
        "X-GreenGateway-Policy-Tests-Status: failed\r\n",
        &results,
    )]);
    let output = ggctl(
        &[
            "policy",
            "test",
            suite_file.path(),
            "--candidate",
            candidate_file.path(),
            "--server",
            &gateway.base(),
            "--token-stdin",
            "--format",
            "json",
        ],
        Some(CANARY.as_bytes()),
    );
    assert_eq!(output.status.code(), Some(3), "{}", text(&output.stdout));
    let reported = report(&output);
    assert_eq!(
        reported["diagnostics"][0]["code"],
        "policy.tests_not_passed"
    );
    assert_eq!(reported["result"]["status"], "failed");
    assert_eq!(reported["result"]["results"], results);
    let requests = gateway.requests();
    assert_eq!(requests.len(), 1);
    assert_request(&requests[0], "POST /v1/admin/policy/tests/runs");
    let mut expected = b"{\"suite\":".to_vec();
    expected.extend_from_slice(suite);
    expected.extend_from_slice(b",\"format\":\"json\",\"policy\":");
    expected.extend_from_slice(candidate);
    expected.push(b'}');
    assert_eq!(requests[0].1, expected);
    assert_no_canary(&output);
    assert_path_not_echoed(&output, suite_file.path());
    assert_path_not_echoed(&output, candidate_file.path());

    // JUnit is the gateway's own report, on standard output as answered.
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"policy-tests.v1\" tests=\"1\"></testsuite>\n";
    let gateway = ScriptedGateway::start(vec![format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/xml; charset=utf-8\r\nX-GreenGateway-Policy-Tests-Status: passed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}",
        xml.len()
    )
    .into_bytes()]);
    let output = ggctl(
        &[
            "policy",
            "test",
            suite_file.path(),
            "--draft",
            "pd_0123456789abcdef0123456789abcdef",
            "--draft-etag",
            POLICY_ETAG,
            "--server",
            &gateway.base(),
            "--format",
            "junit",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), xml);
    assert!(output.stderr.is_empty());
    let body: Value =
        serde_json::from_slice(&gateway.requests()[0].1).expect("the request is JSON");
    assert_eq!(body["format"], "junit");
    assert_eq!(
        body["candidate"],
        json!({"source": "draft", "draft_id": "pd_0123456789abcdef0123456789abcdef", "draft_etag": POLICY_ETAG})
    );

    // A JUnit report without its status header is not trusted.
    let gateway = ScriptedGateway::start(vec![format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}",
        xml.len()
    )
    .into_bytes()]);
    let output = ggctl(
        &[
            "policy",
            "test",
            suite_file.path(),
            "--server",
            &gateway.base(),
            "--format",
            "junit",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(text(&output.stderr).contains("policy.response_invalid"));
}

#[test]
fn policy_explain_sends_the_request_as_written_and_reports_refusals_by_code() {
    let request = b"{\"schema_version\": \"policy-simulation.v1\", \"base_etag\": \"\\\"sha256:5f2c\\\"\",\n \"candidate\": {\"source\": \"active\"}, \"cases\": [{\"id\": \"reader\", \"kind\": \"http\", \"request\": {\"method\": \"GET\", \"path\": \"/orders/1\"}}]}";
    let cases = Document::new("cases.json", request);
    let results = json!({
        "schema_version": "policy-simulation-results.v1",
        "mode": "synthetic",
        "trace": {"level": "terminal"},
        "base": {"source": "active", "etag": POLICY_ETAG},
        "candidate": {"source": "active", "etag": POLICY_ETAG},
        "cases": [{"id": "reader", "kind": "http", "results": [{"projection": "as_authored",
            "candidate": {"lane": "http", "logical": "deny", "enforcement": "shadowed",
                          "effective_action": "would_forward", "reason": "matched_rule"}}]}],
        "not_evaluated": ["authentication"]
    });
    let gateway = ScriptedGateway::start(vec![json_response("200 OK", "", &results)]);
    let output = ggctl(
        &[
            "policy",
            "explain",
            cases.path(),
            "--server",
            &gateway.base(),
            "--token-stdin",
        ],
        Some(CANARY.as_bytes()),
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(
        text(&output.stdout),
        format!(
            "simulation: 1 case, trace terminal\n  base       active {POLICY_ETAG}\n  candidate  active {POLICY_ETAG}\ncase reader (http)\n  as_authored: http deny shadowed would_forward matched_rule\nnot evaluated: authentication\n"
        )
    );
    let requests = gateway.requests();
    assert_request(&requests[0], "POST /v1/admin/policy/simulations");
    assert_eq!(requests[0].1, request);
    assert_no_canary(&output);

    // A stale base is a precondition conflict, reported by its stable reason.
    let gateway = ScriptedGateway::start(vec![json_response(
        "412 Precondition Failed",
        "",
        &json!({
            "error": format!("the active policy changed near {CANARY}"),
            "reason": "policy_simulation_base_stale",
            "current_etag": "\"sha256:9a\""
        }),
    )]);
    let output = ggctl(
        &[
            "policy",
            "explain",
            cases.path(),
            "--server",
            &gateway.base(),
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(5));
    let reported = report(&output);
    assert_eq!(
        reported["diagnostics"][0]["code"],
        "policy.precondition_failed"
    );
    assert_eq!(
        reported["result"]["refusal"],
        json!({"status": 412, "reason": "policy_simulation_base_stale"})
    );
    assert_no_canary(&output);

    // A document that is not JSON is refused before anything is sent.
    let broken = Document::new("broken.json", b"{\"cases\": [");
    let gateway = ScriptedGateway::start(vec![json_response("200 OK", "", &results)]);
    let output = ggctl(
        &[
            "policy",
            "explain",
            broken.path(),
            "--server",
            &gateway.base(),
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stderr).contains("input.not_json"));
    assert!(gateway.requests().is_empty());
    assert_path_not_echoed(&output, broken.path());
}

fn replay_job(state: &str) -> Value {
    let mut job = json!({
        "schema_version": "policy-replay-job.v1",
        "job_id": REPLAY_JOB,
        "state": state,
        "cancel_requested": false,
        "base": {"source": "active", "etag": POLICY_ETAG, "current": true},
        "freshness": {"state": "current"},
        "candidate": {"source": "active", "etag": POLICY_ETAG},
        "window": {"from": "2026-10-27T00:00:00Z", "to": "2026-10-28T00:00:00Z"},
        "cutoff": {"high_water": 41, "selected_records": 3}
    });
    if state == "completed" {
        job["result_digest"] = json!(format!("sha256:{}", "b".repeat(64)));
        job["result"] = json!({
            "schema_version": "policy-replay-results.v1",
            "complete": true,
            "limitations": [],
            "records": {"selected": 3, "scanned": 3, "replayable": 3}
        });
    }
    job
}

#[test]
fn policy_replay_starts_waits_reads_and_cancels_without_resending() {
    let gateway = ScriptedGateway::start(vec![
        json_response("202 Accepted", "", &replay_job("queued")),
        json_response("200 OK", "", &replay_job("running")),
        json_response("200 OK", "", &replay_job("completed")),
    ]);
    let output = ggctl(
        &[
            "policy",
            "replay",
            "--server",
            &gateway.base(),
            "--base-etag",
            POLICY_ETAG,
            "--window",
            "2026-10-27T00:00:00Z/2026-10-28T00:00:00Z",
            "--idempotency-key",
            "nightly",
            "--wait",
            "--token-stdin",
            "--format",
            "json",
        ],
        Some(CANARY.as_bytes()),
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stdout));
    let reported = report(&output);
    assert_eq!(reported["command"], "policy replay");
    assert_eq!(reported["result"]["action"], "start");
    assert_eq!(reported["result"]["job"]["state"], "completed");
    let requests = gateway.requests();
    assert_eq!(requests.len(), 3);
    assert_request(&requests[0], "POST /v1/admin/policy/replays");
    for poll in &requests[1..] {
        assert_request(poll, &format!("GET /v1/admin/policy/replays/{REPLAY_JOB}"));
        assert!(poll.1.is_empty());
    }
    let body: Value = serde_json::from_slice(&requests[0].1).expect("JSON");
    assert_eq!(
        body,
        json!({
            "schema_version": "policy-replay.v1",
            "base_etag": POLICY_ETAG,
            "candidate": {"source": "active"},
            "window": {"from": "2026-10-27T00:00:00Z", "to": "2026-10-28T00:00:00Z"},
            "projections": ["as_authored"],
            "idempotency_key": "nightly"
        })
    );
    assert_no_canary(&output);

    // An incomplete result satisfies no gate.
    let mut incomplete = replay_job("completed_incomplete");
    incomplete["result"] = json!({"complete": false, "limitations": ["no_data"]});
    let gateway = ScriptedGateway::start(vec![json_response("200 OK", "", &incomplete)]);
    let output = ggctl(
        &[
            "policy",
            "replay",
            "--server",
            &gateway.base(),
            "--job",
            REPLAY_JOB,
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stdout)
        .starts_with(&format!("replay job {REPLAY_JOB}: completed_incomplete\n")));
    assert!(text(&output.stderr).contains("policy.replay_incomplete"));

    // Cancelling a finished job discards it.
    let gateway = ScriptedGateway::start(vec![
        b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec(),
    ]);
    let output = ggctl(
        &[
            "policy",
            "replay",
            "--server",
            &gateway.base(),
            "--cancel",
            REPLAY_JOB,
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), "replay job discarded\n");
    let requests = gateway.requests();
    assert!(requests[0].0.starts_with(&format!(
        "DELETE /v1/admin/policy/replays/{REPLAY_JOB} HTTP/1.1\r\n"
    )));

    // A start whose answer is lost is never resent, and the job may exist.
    let gateway = ScriptedGateway::start(vec![Vec::new()]);
    let candidate = Document::new("replay-candidate.json", b"{\"schema_version\": \"1.0.0\"}");
    let output = ggctl(
        &[
            "policy",
            "replay",
            "--server",
            &gateway.base(),
            "--base-etag",
            POLICY_ETAG,
            "--window",
            "2026-10-27T00:00:00Z",
            "--candidate",
            candidate.path(),
            "--format",
            "json",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(1));
    let reported = report(&output);
    let codes: Vec<_> = reported["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|diagnostic| diagnostic["code"].clone())
        .collect();
    assert_eq!(
        codes,
        [
            json!("remote.transport_failed"),
            json!("policy.outcome_unknown")
        ]
    );
    assert!(reported["diagnostics"][1]["hint"]
        .as_str()
        .is_some_and(|hint| hint.contains("--idempotency-key")));
    assert_eq!(gateway.requests().len(), 1, "a start is never resent");
    assert_path_not_echoed(&output, candidate.path());
}

#[test]
fn policy_commands_need_a_server_and_refuse_bad_values_before_any_request() {
    for words in [
        &["policy", "lint", "policy.json"][..],
        &["policy", "replay", "--job", REPLAY_JOB],
    ] {
        let output = ggctl(words, None);
        assert_eq!(output.status.code(), Some(2), "{words:?}");
        assert!(output.stdout.is_empty());
        assert!(text(&output.stderr).contains("usage.server_required"));
    }
    let gateway = ScriptedGateway::start(vec![json_response("200 OK", "", &json!({}))]);
    let base = gateway.base();
    for (words, code) in [
        (
            &["policy", "replay", "--job", "rpl_../../config"][..],
            "usage.invalid_value",
        ),
        (
            &["policy", "test", "suite.json", "--draft", "pd_1"],
            "usage.missing_option",
        ),
        (
            &[
                "policy",
                "replay",
                "--base-etag",
                "unquoted",
                "--window",
                "2026",
            ],
            "usage.invalid_value",
        ),
    ] {
        let mut arguments = words.to_vec();
        arguments.extend(["--server", base.as_str()]);
        let output = ggctl(&arguments, None);
        assert_eq!(output.status.code(), Some(2), "{words:?}");
        assert!(output.stdout.is_empty());
        assert!(text(&output.stderr).contains(code), "{words:?}");
    }
    assert!(gateway.requests().is_empty());
    for (words, code) in [
        (&["policy"][..], "usage.missing_command"),
        (&["policy", "frobnicate"], "usage.unknown_command"),
    ] {
        let output = ggctl(words, None);
        assert_eq!(output.status.code(), Some(2), "{words:?}");
        assert!(text(&output.stderr).contains(code), "{words:?}");
    }
    let output = ggctl(&["help", "policy"], None);
    assert_eq!(output.status.code(), Some(0));
    for command in ["lint", "test", "explain", "replay"] {
        assert!(
            text(&output.stdout).contains(&format!("\n  {command}  ")),
            "{command}"
        );
    }
}

/// A served evidence package: the report alone, built with the gateway's
/// digest code.
fn evidence_package() -> Vec<u8> {
    use gateway_config::canonical_json;
    let report = json!({
        "schema_version": "policy-evidence-report.v1",
        "completeness": "incomplete",
        "limitations": ["tests_not_included"],
        "trust": {"signed": false, "statement": "This package is unsigned."}
    });
    let media_type = "application/vnd.greengateway.policy-evidence-report+json";
    let package = json!({
        "schema_version": "policy-evidence.v1",
        "generated_at": "2026-10-28T12:00:00Z",
        "manifest": [{
            "name": "report",
            "media_type": media_type,
            "schema_version": "policy-evidence-report.v1",
            "digest": canonical_json::semantic_digest(media_type, "policy-evidence-report.v1", &report)
                .expect("digest"),
            "size": canonical_json::canonical_json_bytes(&report).expect("canonical").len(),
        }],
        "report": report,
    });
    canonical_json::canonical_json_bytes(&package).expect("canonical")
}

#[test]
fn evidence_verify_runs_offline_and_reports_integrity_never_trust() {
    let package = Document::new("policy-evidence.json", &evidence_package());
    // There is no server, and the proxy variables `ggctl` is run with point
    // at a closed port: nothing could be reached even if it were tried.
    let output = ggctl(
        &["evidence", "verify", package.path(), "--format", "json"],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stdout));
    let reported = report(&output);
    assert_eq!(reported["command"], "evidence verify");
    assert_eq!(reported["result"]["verdict"], "integrity_valid");
    assert_eq!(reported["result"]["signature"], "unsigned");
    assert_eq!(reported["result"]["trusted"], false);
    assert_eq!(reported["diagnostics"][0]["code"], "evidence.unsigned");
    assert_eq!(reported["diagnostics"][0]["severity"], "info");
    assert_path_not_echoed(&output, package.path());

    let output = ggctl(&["evidence", "verify", package.path()], None);
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stdout)
        .starts_with("evidence package: integrity_valid, unsigned (not trusted)\n"));
    assert!(text(&output.stderr).starts_with("ggctl: info: evidence.unsigned: "));
    assert_path_not_echoed(&output, package.path());

    // One changed byte of the report is an integrity failure.
    let tampered = String::from_utf8(evidence_package())
        .expect("UTF-8")
        .replacen("tests_not_included", "tests_not_includex", 1);
    let tampered = Document::new("tampered.json", tampered.as_bytes());
    let output = ggctl(
        &["evidence", "verify", tampered.path(), "--format", "json"],
        None,
    );
    assert_eq!(output.status.code(), Some(7));
    let reported = report(&output);
    assert_eq!(reported["result"]["verdict"], "integrity_invalid");
    assert_eq!(
        reported["diagnostics"][0]["code"],
        "evidence.digest_mismatch"
    );

    // There is no remote form.
    let output = ggctl(
        &[
            "evidence",
            "verify",
            package.path(),
            "--server",
            "http://127.0.0.1:9/v1/admin",
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(text(&output.stderr).contains("usage.unknown_option"));
}

#[test]
fn backup_create_refuses_a_locked_state_directory_and_verify_exits_7_on_damage() {
    use gateway_config::{
        bundle::{read_bundle, PublishedSchemasOnly, ReadOptions},
        ledger::{LedgerActor, RevisionLedger},
        state_dir::StateDirectory,
    };

    let bundle = Bundle::new("{\"schema_version\": \"0.1.0\", \"default_action\": \"deny\"}\n");
    let state = TempDirectory::new(&format!("backup-state-{CANARY}"));
    let out = TempDirectory::new(&format!("backup-out-{CANARY}"));
    let state_dir = state.0.to_str().expect("UTF-8");
    let archive = out.0.join("state.ggbk");
    let archive_path = archive.to_str().expect("UTF-8");
    {
        let read = read_bundle(&bundle.0, ReadOptions::default(), &PublishedSchemasOnly);
        let held = StateDirectory::acquire(&state.0).expect("the state directory locks");
        let actor = LedgerActor::system("ggctl-ledger-seed").expect("recordable");
        let seeded = RevisionLedger::seed(
            &held,
            read.bundle.as_ref().expect("the bundle reads"),
            actor,
            std::time::SystemTime::now(),
        );
        drop(seeded.expect("seed"));

        // While this process holds the lock, as a running gateway would, a
        // backup is refused and writes nothing.
        let output = ggctl(
            &[
                "backup",
                "create",
                "--state-dir",
                state_dir,
                "--output",
                archive_path,
                "--format",
                "json",
            ],
            None,
        );
        assert_eq!(output.status.code(), Some(5), "{}", text(&output.stdout));
        let refused = report(&output);
        assert_eq!(refused["diagnostics"][0]["code"], "state_dir.locked");
        assert!(!archive.exists());
        assert_no_canary(&output);
        drop(held);
    }

    let output = ggctl(
        &[
            "backup",
            "create",
            "--state-dir",
            state_dir,
            "--output",
            archive_path,
        ],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(text(&output.stdout).starts_with("created a backup of 1 stores\n"));
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
    assert_no_canary(&output);

    let output = ggctl(
        &["backup", "verify", archive_path, "--format", "json"],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stdout));
    assert_eq!(report(&output)["result"]["verified"], true);

    // Cut short, the archive is an integrity failure; nothing is left beside it.
    let bytes = std::fs::read(&archive).expect("the archive");
    std::fs::write(&archive, &bytes[..bytes.len() - 1]).expect("truncated");
    let output = ggctl(
        &["backup", "verify", archive_path, "--format", "json"],
        None,
    );
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(
        report(&output)["diagnostics"][0]["code"],
        "archive.truncated"
    );
    assert_no_canary(&output);
    let names: Vec<_> = std::fs::read_dir(&out.0)
        .expect("lists")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("UTF-8")
        })
        .collect();
    assert_eq!(names, ["state.ggbk"]);
}
