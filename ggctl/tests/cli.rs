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
