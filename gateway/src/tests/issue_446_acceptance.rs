//! Issue #446: Phase 8 acceptance through the composed router.
//!
//! The executor suites (`tools::executor_caller_assertion_tests`,
//! `tools::executor_delegated_token_tests`) prove each per-caller lane on its
//! own. These tests drive the whole gateway instead: Connections are created
//! through the admin API, the Gmail catalog is registered from the hermetic
//! Discovery golden through preview and register, and every call is a real
//! rmcp streamable-HTTP client authenticated to `/mcp` with a JWT from a
//! configured identity provider. One in-process TLS listener plays the
//! internal API, the delegated-token issuer and Gmail; the gateway reaches it
//! through its egress like any other host. Every key is generated per test.
//!
//! Domain-wide delegation is not driven here: the router has no seam to stand
//! in for Google's IAM `signJwt` and token endpoints, only the Connection
//! runtime does. Its evidence is executor-level:
//! `connections::google_delegation_tests::two_principals_are_signed_for_as_themselves_and_get_tokens_of_their_own`,
//! `connections::google_delegation_tests::a_domain_wide_delegation_serves_its_callers_own_lanes_and_no_other`
//! and
//! `tools::executor_delegated_token_tests::a_caller_a_domain_wide_delegation_cannot_act_as_is_refused_before_the_egress_preflight`.

use super::*;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
    DecodingKey, Validation,
};
use rmcp::{
    model::{CallToolResult, ErrorData},
    service::{RoleClient, RunningService, ServiceError},
};

use crate::connections::{
    caller_assertion::JWKS_PATH,
    secret::{OperatorSecretAliasConfig, SecretRootConfig},
    test_support::{generated_es256_pem, pem_body_lines, write_secret_file},
};

/// The identity provider alice and bob sign in with.
const CALLER_IDP: &str = "https://idp.example.test";
/// The issuer every assertion and subject token this gateway signs names.
const GATEWAY_ISSUER: &str = "https://gateway.example.test";
const ATTESTED_AUDIENCE: &str = "https://internal.example.test";
const SUBJECT_TOKEN_AUDIENCE: &str = "https://issuer.example.test";
const SUBJECT_TOKEN_TYPE: &str = "caller-assertion+jwt";
const ASSERTION_HEADER: &str = "x-caller-assertion";
const ATTESTED_KID: &str = "gw-internal-1";
const SUBJECT_KID: &str = "gw-gmail-1";
const GMAIL_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";
const GMAIL_DISCOVERY: &str = include_str!("../tools/testdata/discovery-golden/gmail-subset.json");

const ATTESTED_BASE_PATH: &str = "/internal/v1";
const EXCHANGE_PATH: &str = "/oauth2/token-exchange";
const GMAIL_PATH_PREFIX: &str = "/gmail/";

const SERVICE_BEARER_ALIAS: &str = "internal-service-bearer";
const ATTESTED_KEY_ALIAS: &str = "internal-assertion-key";
const EXCHANGE_SECRET_ALIAS: &str = "gmail-exchange-secret";
const SUBJECT_KEY_ALIAS: &str = "gmail-subject-key";
/// What the internal API knows the gateway by. Low-entropy and obviously fake.
const SERVICE_BEARER: &str = "internal-service-bearer-canary";
/// What the issuer knows the gateway by. Low-entropy and obviously fake.
const EXCHANGE_CLIENT_SECRET: &str = "gmail-exchange-client-canary";
/// What the stub issuer adds to every grant. It may never surface.
const REFRESH_TOKEN_CANARY: &str = "phase8-refresh-token-canary";

const ATTESTED_TOOL: &str = "record_note";
/// The read the delegated catalog registers and serves.
const GMAIL_PROFILE: &str = "gmail.users.getProfile";
/// What `gmail.readonly` grants, and so every tool the preview offers.
const GMAIL_READ_TOOLS: [&str; 5] = [
    "gmail.users.getProfile",
    "gmail.users.messages.get",
    "gmail.users.messages.list",
    "gmail.users.threads.get",
    "gmail.users.threads.list",
];
/// Every mutation the Discovery golden generates: none may be served.
const GMAIL_MUTATIONS: [&str; 7] = [
    "gmail.users.messages.delete",
    "gmail.users.messages.modify",
    "gmail.users.messages.trash",
    "gmail.users.threads.delete",
    "gmail.users.threads.modify",
    "gmail.users.threads.trash",
    "gmail.users.threads.untrash",
];

const ATTESTED_ALICE_REQUEST: &str = "issue-446-attested-alice";
const ATTESTED_BOB_REQUEST: &str = "issue-446-attested-bob";
const GMAIL_ALICE_REQUEST: &str = "issue-446-gmail-alice";
const GMAIL_BOB_REQUEST: &str = "issue-446-gmail-bob";
const SERVICE_REQUEST: &str = "issue-446-service-token";

/// One request the stub listener received, exactly as it arrived.
#[derive(Clone, Debug)]
struct StubRequest {
    method: String,
    target: String,
    /// Every header line in the order received, names lowercased.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl StubRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    fn header_count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(candidate, _)| candidate == name)
            .count()
    }

    fn form_field(&self, name: &str) -> Option<String> {
        url::form_urlencoded::parse(&self.body)
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.into_owned())
    }
}

/// The internal API, the delegated-token issuer and Gmail behind one TLS
/// listener, told apart by path.
struct Phase8Stub {
    addr: std::net::SocketAddr,
    ca_pem: String,
    requests: Arc<Mutex<Vec<StubRequest>>>,
    /// Every TCP connection accepted, whether or not a request followed: a
    /// refusal that leaves no byte on the wire leaves this unchanged.
    accepted: Arc<AtomicUsize>,
    stop: tokio_util::sync::CancellationToken,
}

impl Drop for Phase8Stub {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl Phase8Stub {
    async fn start() -> Self {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (ca_pem, certificate_der, key_der) = test_ca_signed_server_certificate();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .expect("stub TLS config should build");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("stub listener should bind");
        let addr = listener
            .local_addr()
            .expect("stub listener should have an address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let issued = Arc::new(AtomicUsize::new(0));
        let stop = tokio_util::sync::CancellationToken::new();
        let (server_requests, server_accepted, server_stop) =
            (Arc::clone(&requests), Arc::clone(&accepted), stop.clone());
        tokio::spawn(async move {
            loop {
                let (stream, _) = tokio::select! {
                    () = server_stop.cancelled() => return,
                    accepted = listener.accept() => match accepted {
                        Ok(accepted) => accepted,
                        Err(_) => return,
                    },
                };
                server_accepted.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let requests = Arc::clone(&server_requests);
                let issued = Arc::clone(&issued);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let Some(request) = read_stub_request(&mut stream).await else {
                        return;
                    };
                    let (status, body) = answer_stub_request(&request, &issued);
                    requests
                        .lock()
                        .expect("stub requests should not poison")
                        .push(request);
                    let body = body.to_string();
                    let reason = status.canonical_reason().unwrap_or("Response");
                    let head = format!(
                        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status.as_u16(),
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(body.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Self {
            addr,
            ca_pem,
            requests,
            accepted,
            stop,
        }
    }

    fn base_url(&self) -> String {
        format!("https://127.0.0.1:{}", self.addr.port())
    }

    fn requests(&self) -> Vec<StubRequest> {
        self.requests
            .lock()
            .expect("stub requests should not poison")
            .clone()
    }

    fn requests_under(&self, prefix: &str) -> Vec<StubRequest> {
        self.requests()
            .into_iter()
            .filter(|request| request.target.starts_with(prefix))
            .collect()
    }

    fn exchange_count(&self) -> usize {
        self.requests_under(EXCHANGE_PATH).len()
    }

    fn gmail_count(&self) -> usize {
        self.requests_under(GMAIL_PATH_PREFIX).len()
    }

    fn accepted_connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

async fn read_stub_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<StubRequest> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(head_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&bytes[..head_end]).ok()?.to_owned();
            let mut lines = head.split("\r\n");
            let mut request_line = lines.next()?.split_whitespace();
            let method = request_line.next()?.to_owned();
            let target = request_line.next()?.to_owned();
            let headers = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
                .collect::<Vec<_>>();
            let length = headers
                .iter()
                .find(|(name, _)| name == "content-length")
                .and_then(|(_, value)| value.parse::<usize>().ok())
                .unwrap_or(0);
            while bytes.len() < head_end + 4 + length {
                let read = stream.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                bytes.extend_from_slice(&chunk[..read]);
            }
            return Some(StubRequest {
                method,
                target,
                headers,
                body: bytes[head_end + 4..head_end + 4 + length].to_vec(),
            });
        }
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

/// The claims of a JWT, unverified: what the stub issuer reads to pick a
/// caller's grant. A real issuer verifies first; the test does that on the
/// gateway's behalf against the published JWKS.
fn unverified_claims(token: &str) -> Value {
    token
        .split('.')
        .nth(1)
        .and_then(|payload| URL_SAFE_NO_PAD.decode(payload).ok())
        .and_then(|payload| serde_json::from_slice(&payload).ok())
        .unwrap_or(Value::Null)
}

fn answer_stub_request(request: &StubRequest, issued: &AtomicUsize) -> (StatusCode, Value) {
    if request.target == EXCHANGE_PATH {
        // The issuer hands each caller named by the subject token a token of
        // their own.
        let Some(caller) = request.form_field("subject_token").and_then(|token| {
            unverified_claims(&token)["caller_sub"]
                .as_str()
                .map(str::to_owned)
        }) else {
            return (
                StatusCode::BAD_REQUEST,
                json!({ "error": "invalid_request" }),
            );
        };
        let serial = issued.fetch_add(1, Ordering::SeqCst) + 1;
        return (
            StatusCode::OK,
            json!({
                "access_token": format!("delegated-{caller}-{serial}"),
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": request.form_field("scope").unwrap_or_default(),
                "refresh_token": REFRESH_TOKEN_CANARY,
            }),
        );
    }
    if request.target.starts_with(ATTESTED_BASE_PATH) {
        return (StatusCode::CREATED, json!({ "recorded": true }));
    }
    if request.target.starts_with(GMAIL_PATH_PREFIX) {
        // Gmail knows its users only by their own tokens.
        let mailbox = request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer delegated-"))
            .and_then(|token| token.rsplit_once('-'))
            .map(|(caller, _)| caller.to_owned());
        return match mailbox {
            Some(mailbox) => (
                StatusCode::OK,
                json!({ "emailAddress": format!("{mailbox}@example.test"), "messagesTotal": 1 }),
            ),
            None => (StatusCode::UNAUTHORIZED, json!({})),
        };
    }
    (StatusCode::NOT_FOUND, json!({}))
}

/// A secrets root holding the files the operator aliases point at, and the
/// CA the gateway's egress trusts. Removed on drop.
struct SecretsRoot {
    root: PathBuf,
    aliases: Vec<OperatorSecretAliasConfig>,
    ca_bundle: PathBuf,
    attested_key_pem: String,
    subject_key_pem: String,
}

impl SecretsRoot {
    fn new(ca_pem: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-issue-446-secrets-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("secrets root should create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("secrets root permissions should set");
        }
        let attested_key_pem = generated_es256_pem();
        let subject_key_pem = generated_es256_pem();
        let aliases = vec![
            write_secret_file(&root, SERVICE_BEARER_ALIAS, SERVICE_BEARER.as_bytes()),
            write_secret_file(&root, ATTESTED_KEY_ALIAS, attested_key_pem.as_bytes()),
            write_secret_file(
                &root,
                EXCHANGE_SECRET_ALIAS,
                EXCHANGE_CLIENT_SECRET.as_bytes(),
            ),
            write_secret_file(&root, SUBJECT_KEY_ALIAS, subject_key_pem.as_bytes()),
        ];
        let ca_bundle = root.join("stub-ca.pem");
        fs::write(&ca_bundle, ca_pem).expect("stub CA should write");
        Self {
            root,
            aliases,
            ca_bundle,
            attested_key_pem,
            subject_key_pem,
        }
    }
}

impl Drop for SecretsRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Default)]
struct CapturedLogs {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl CapturedLogs {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.buffer.lock().expect("captured logs should not poison"))
            .into_owned()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
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

impl std::io::Write for CapturedLogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.buffer
            .lock()
            .map_err(|_| std::io::Error::other("captured logs lock poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Every level, so a debug line that carried a key or a token would show.
/// The tests run on the current-thread runtime, so the gateway, the stub and
/// the client all log on the thread this subscriber is installed on.
fn capture_all_logs() -> (CapturedLogs, impl Drop) {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(logs.clone())
        .finish();
    (logs, crate::tracing_test_guard(subscriber))
}

/// The acceptance policy; with `deny_bob`, a per-principal rule refuses bob
/// the Gmail read.
fn phase8_policy(deny_bob: bool) -> String {
    let tool = json!({
        "allowed_roles": ["mail-user"],
        "timeout_ms": 5000,
        "max_concurrent": 2
    });
    let mut tools = serde_json::Map::new();
    tools.insert(ATTESTED_TOOL.to_owned(), tool.clone());
    // The mutations have entries too, so their absence from tools/list is
    // the catalog's doing rather than the policy's.
    for name in GMAIL_READ_TOOLS.iter().chain(GMAIL_MUTATIONS.iter()) {
        tools.insert((*name).to_owned(), tool.clone());
    }
    json!({
        "schema_version": "0.1.0",
        "id": "issue-446-phase8-acceptance",
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": { "permissions": ["*"] },
            "mail-user": { "permissions": [ADMIN_MCP_USE_PERMISSION] }
        },
        "routes": [],
        "tools": tools,
        "rules": if deny_bob {
            json!([{
                "id": "bob-may-not-read-gmail",
                "tool_name": GMAIL_PROFILE,
                "principal": { "principal_ids": ["bob"] },
                "action": "deny"
            }])
        } else {
            json!([])
        }
    })
    .to_string()
}

fn attested_connection(stub: &Phase8Stub) -> Value {
    json!({
        "display_name": "Internal notes API",
        "enabled": true,
        "kind": "http_api",
        "endpoint": { "base_url": stub.base_url(), "base_path": ATTESTED_BASE_PATH },
        "authentication": { "type": "static_bearer", "secret_id": SERVICE_BEARER_ALIAS },
        "caller_assertion": {
            "signing_key_id": ATTESTED_KEY_ALIAS,
            "kid": ATTESTED_KID,
            "algorithm": "es256",
            "issuer": GATEWAY_ISSUER,
            "audience": ATTESTED_AUDIENCE,
            "token_type": "at+jwt",
            "header_name": ASSERTION_HEADER,
            "lifetime_seconds": 60,
            "bind_request": true
        }
    })
}

fn gmail_connection(stub: &Phase8Stub) -> Value {
    json!({
        "display_name": "Gmail as the caller",
        "enabled": true,
        "kind": "http_api",
        "endpoint": { "base_url": stub.base_url(), "base_path": "/" },
        "authentication": {
            "type": "delegated_issuer_token",
            "token_exchange_url": format!("{}{EXCHANGE_PATH}", stub.base_url()),
            "client_id": "greengateway",
            "client_secret_id": EXCHANGE_SECRET_ALIAS,
            "requested_scopes": [GMAIL_READONLY],
            "audience": "https://gmail.googleapis.com",
            "subject_token_source": "caller_assertion"
        },
        "caller_assertion": {
            "signing_key_id": SUBJECT_KEY_ALIAS,
            "kid": SUBJECT_KID,
            "algorithm": "es256",
            "issuer": GATEWAY_ISSUER,
            "audience": SUBJECT_TOKEN_AUDIENCE,
            "token_type": SUBJECT_TOKEN_TYPE,
            "header_name": ASSERTION_HEADER,
            "lifetime_seconds": 60,
            "claims": ["email"]
        },
        "discovery": { "type": "managed_openapi", "use_connection_authentication": false }
    })
}

/// The manual HTTP tool on the attested Connection: its body is bound into
/// each assertion.
fn attested_tools_document(connection_id: &str) -> String {
    let mapping = json!({
        "method": "POST",
        "path_template": "/notes",
        "body": { "mode": "body_args_json" }
    });
    json!({
        "schema_version": "0.1.0",
        "tools": [{
            "name": ATTESTED_TOOL,
            "description": "Records a note in the internal API as the calling user.",
            "input_json_schema": {
                "type": "object",
                "required": ["text"],
                "properties": { "text": { "type": "string" } },
                "additionalProperties": false
            },
            "target": { "type": "http", "connection_id": connection_id, "mapping": mapping },
            "source": { "type": "manual" },
            "upstream": mapping
        }]
    })
    .to_string()
}

struct Phase8Harness {
    router: Router,
    stub: Phase8Stub,
    capture: audit::sink::tests::CaptureSink,
    admin_token: String,
    service_token: String,
    secrets: SecretsRoot,
    _connection_db: TempDb,
    _token_db: TempDb,
    _policy: TempPolicyFile,
    _tools: TempToolsFile,
}

struct Phase8Parts<'a> {
    jwks_addr: std::net::SocketAddr,
    connection_db: &'a TempDb,
    token_db: &'a TempDb,
    policy: &'a TempPolicyFile,
    tools: &'a TempToolsFile,
    secrets: &'a SecretsRoot,
}

fn phase8_router(parts: &Phase8Parts<'_>, capture: &audit::sink::tests::CaptureSink) -> Router {
    let mut config = test_config(Vec::new());
    configure_test_jwt_provider(&mut config, parts.jwks_addr);
    // A provider-vouched issuer is what lets a principal be attested.
    config.auth_providers[0].issuer = Some(CALLER_IDP.to_owned());
    config.policy_file = Some(parts.policy.path.to_string_lossy().into_owned());
    config.tools_file = Some(parts.tools.path.to_string_lossy().into_owned());
    config.connections_sqlite_path = Some(parts.connection_db.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(parts.token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 20;
    config.connection_secrets_root = Some(SecretRootConfig::new(parts.secrets.root.clone()));
    config.connection_secret_aliases = parts.secrets.aliases.clone();
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    config.tool_runtime_default_timeout_ms = 5_000;
    config.rate_limit_write_rps = 1_000.0;
    config.rate_limit_write_burst = 1_000;
    let recorder = PrometheusBuilder::new().build_recorder();
    let apps = gateway_app_with_process_started_at_and_overrides(
        config,
        recorder.handle(),
        audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            egress_tls_ca_bundle_path: Some(parts.secrets.ca_bundle.clone()),
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("Phase 8 acceptance app should build");
    match apps.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("Phase 8 acceptance app should be unified"),
    }
}

fn admin_request(
    method: Method,
    uri: &str,
    token: &str,
    body: Option<Value>,
    if_match: Option<&str>,
) -> Request<Body> {
    let mut request = connection_admin_request(
        method,
        uri,
        None,
        body.map(|body| body.to_string()),
        if_match,
        false,
    );
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .expect("admin service token should be a header value"),
    );
    request
}

async fn admin_call(
    router: &Router,
    request: Request<Body>,
    expected: StatusCode,
    what: &str,
) -> (HeaderMap, Value) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .unwrap_or_else(|error| panic!("{what} should complete: {error}"));
    let status = response.status();
    let headers = response.headers().clone();
    let body = body_string(response).await;
    assert_eq!(status, expected, "{what}: {body}");
    let body = serde_json::from_str(&body).unwrap_or_else(|_| panic!("{what} answers JSON"));
    (headers, body)
}

fn header_text(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("response should carry {name}"))
        .to_owned()
}

/// Creates a Connection through the admin API; returns its ID and ETag.
async fn create_connection(router: &Router, token: &str, document: Value) -> (String, String) {
    let (headers, _) = admin_call(
        router,
        admin_request(Method::GET, CONNECTIONS_ADMIN_ROUTE, token, None, None),
        StatusCode::OK,
        "Connection list",
    )
    .await;
    let collection_etag = header_text(&headers, CONNECTION_COLLECTION_ETAG_HEADER);
    let (headers, created) = admin_call(
        router,
        admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            token,
            Some(document),
            Some(&collection_etag),
        ),
        StatusCode::CREATED,
        "Connection create",
    )
    .await;
    let id = created["id"]
        .as_str()
        .expect("a created Connection has an ID")
        .to_owned();
    (id, header_text(&headers, header::ETAG.as_str()))
}

/// Registers the GET tools the Gmail golden previews on `connection_id`, and
/// publishes an overlay that declares each of them read-only.
async fn register_gmail_catalog(router: &Router, token: &str, connection_id: &str, etag: &str) {
    let (_, preview) = admin_call(
        router,
        admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview"),
            token,
            Some(json!({ "spec": GMAIL_DISCOVERY })),
            None,
        ),
        StatusCode::OK,
        "Gmail Discovery preview",
    )
    .await;
    assert_eq!(
        preview["conversion"]["source_format"],
        json!("google_discovery_v1")
    );
    let tools = preview["tools"]
        .as_array()
        .expect("the preview lists tools");
    let mut offered = tools
        .iter()
        .map(|tool| {
            (
                tool["name"].as_str().expect("a previewed tool has a name"),
                tool["upstream"]["method"]
                    .as_str()
                    .expect("a previewed tool has a method"),
            )
        })
        .collect::<Vec<_>>();
    offered.sort_unstable();
    assert_eq!(offered, GMAIL_READ_TOOLS.map(|name| (name, "GET")));
    // A read-only scope binds reads alone; the preview says why each
    // mutation is left out rather than offering it.
    let incompatible = preview["incompatibilities"]
        .as_array()
        .expect("the preview lists incompatibilities")
        .iter()
        .filter_map(|incompatibility| incompatibility["tool_name"].as_str())
        .collect::<BTreeSet<_>>();
    for mutation in GMAIL_MUTATIONS {
        assert!(incompatible.contains(mutation), "{mutation}: {preview}");
    }
    let selected = GMAIL_READ_TOOLS;
    let confirmations = preview["security_confirmations"]
        .as_array()
        .expect("the preview lists security confirmations")
        .iter()
        .filter(|confirmation| {
            confirmation["tool_name"]
                .as_str()
                .is_some_and(|name| selected.contains(&name))
        })
        .cloned()
        .collect::<Vec<_>>();
    admin_call(
        router,
        admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/register"),
            token,
            Some(json!({
                "spec": GMAIL_DISCOVERY,
                "spec_digest": preview["spec_digest"],
                "expected_spec_revision": preview["spec_revision"],
                "expected_catalog_revision": preview["catalog_revision"],
                "selected_tool_names": selected,
                "security_confirmations": confirmations,
            })),
            Some(etag),
        ),
        StatusCode::CREATED,
        "Gmail catalog registration",
    )
    .await;

    let overlay_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/overlay");
    let (headers, _) = admin_call(
        router,
        admin_request(Method::GET, &overlay_uri, token, None, None),
        StatusCode::OK,
        "Gmail overlay read",
    )
    .await;
    let overlay_etag = header_text(&headers, header::ETAG.as_str());
    let read_only = selected
        .iter()
        .map(|name| {
            (
                (*name).to_owned(),
                json!({ "annotations": { "readOnlyHint": true } }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    admin_call(
        router,
        admin_request(
            Method::PUT,
            &overlay_uri,
            token,
            Some(json!({ "schema_version": "0.1.0", "tools": read_only })),
            Some(&overlay_etag),
        ),
        StatusCode::OK,
        "Gmail read-only overlay",
    )
    .await;
}

/// Both Connections created through the admin API, the Gmail catalog
/// registered, and the gateway restarted with the manual tool that names the
/// attested Connection -- its ID exists only once the Connection does.
async fn phase8_harness() -> Phase8Harness {
    let stub = Phase8Stub::start().await;
    let secrets = SecretsRoot::new(&stub.ca_pem);
    let jwks_addr = spawn_test_jwks_server().await;
    let connection_db = TempDb::new("issue-446-connections");
    let token_db = TempDb::new("issue-446-tokens");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let admin_token = create_service_token(&token_store, &["admin"]);
    let service_token = create_service_token(&token_store, &["mail-user"]);
    let policy = TempPolicyFile::new(&phase8_policy(true));
    let tools = TempToolsFile::new(&empty_tools_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let parts = Phase8Parts {
        jwks_addr,
        connection_db: &connection_db,
        token_db: &token_db,
        policy: &policy,
        tools: &tools,
        secrets: &secrets,
    };

    let router = phase8_router(&parts, &capture);
    let (attested_id, _) =
        create_connection(&router, &admin_token, attested_connection(&stub)).await;
    let (gmail_id, gmail_etag) =
        create_connection(&router, &admin_token, gmail_connection(&stub)).await;
    register_gmail_catalog(&router, &admin_token, &gmail_id, &gmail_etag).await;
    drop(router);

    fs::write(&tools.path, attested_tools_document(&attested_id))
        .expect("the manual tool should write");
    let router = phase8_router(&parts, &capture);

    Phase8Harness {
        router,
        stub,
        capture,
        admin_token,
        service_token,
        secrets,
        _connection_db: connection_db,
        _token_db: token_db,
        _policy: policy,
        _tools: tools,
    }
}

impl Phase8Harness {
    /// What an operator does to lift bob's rule: replace the live policy
    /// through the admin API.
    async fn lift_bobs_rule(&self) {
        let (headers, _) = admin_call(
            &self.router,
            admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                &self.admin_token,
                None,
                None,
            ),
            StatusCode::OK,
            "policy read",
        )
        .await;
        let etag = header_text(&headers, header::ETAG.as_str());
        let body: Value = serde_json::from_str(&phase8_policy(false)).expect("the policy is JSON");
        admin_call(
            &self.router,
            admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                &self.admin_token,
                Some(body),
                Some(&etag),
            ),
            StatusCode::OK,
            "policy replacement",
        )
        .await;
    }

    fn events(&self, event_type: &str, request_id: &str) -> Vec<audit::AuditEvent> {
        self.capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == event_type && event.request_id == request_id)
            .collect()
    }

    async fn wait_for(&self, event_type: &'static str, request_id: &str, count: usize) {
        wait_for_delivered_audit_events(&self.capture, event_type, |events| {
            events
                .iter()
                .filter(|event| event.event_type == event_type && event.request_id == request_id)
                .count()
                >= count
        })
        .await;
        assert_eq!(
            self.events(event_type, request_id).len(),
            count,
            "{event_type} for {request_id}"
        );
    }

    /// The published caller-assertion keys, fetched the way an upstream does:
    /// with no credential at all.
    async fn anonymous_jwks(&self) -> String {
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(JWKS_PATH)
                    .body(Body::empty())
                    .expect("JWKS request should build"),
            )
            .await
            .expect("JWKS request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        body_string(response).await
    }

    /// Everything that may never appear in an audit event or a log line: both
    /// signing keys, the service bearer, the issuer client secret, every
    /// token the issuer handed out with its refresh token, and every
    /// assertion and subject token the stub received with its signature.
    fn secret_material(&self) -> Vec<String> {
        let mut canaries = vec![
            SERVICE_BEARER.to_owned(),
            EXCHANGE_CLIENT_SECRET.to_owned(),
            base64::engine::general_purpose::STANDARD
                .encode(format!("greengateway:{EXCHANGE_CLIENT_SECRET}")),
            REFRESH_TOKEN_CANARY.to_owned(),
            "delegated-alice-".to_owned(),
            "delegated-bob-".to_owned(),
        ];
        for pem in [
            &self.secrets.attested_key_pem,
            &self.secrets.subject_key_pem,
        ] {
            canaries.extend(pem_body_lines(pem).into_iter().map(str::to_owned));
        }
        for request in self.stub.requests() {
            let tokens = request
                .header(ASSERTION_HEADER)
                .map(str::to_owned)
                .into_iter()
                .chain(request.form_field("subject_token"));
            for token in tokens {
                // The signature alone is as good as the token to a replayer.
                canaries.extend(token.rsplit('.').next().map(str::to_owned));
                canaries.push(token);
            }
        }
        canaries
    }

    fn assert_no_secret_material(&self, logs: &CapturedLogs) {
        let audit = serde_json::to_string(&self.capture.events()).expect("audit serializes");
        let logs = logs.contents();
        for canary in self.secret_material() {
            assert!(!audit.contains(&canary), "the audit leaked {canary:?}");
            assert!(!logs.contains(&canary), "the logs leaked {canary:?}");
        }
    }
}

fn caller_token(user: &str) -> String {
    signed_token_with_issuer(user, &["mail-user"], CALLER_IDP)
}

type McpClient = RunningService<RoleClient, ()>;

/// A real rmcp streamable-HTTP client authenticated to `/mcp` with `token`.
async fn mcp_client(
    gateway: std::net::SocketAddr,
    token: &str,
    request_id: &'static str,
) -> McpClient {
    let headers = HashMap::from([
        (
            HeaderName::from_static(REQUEST_ID_HEADER),
            HeaderValue::from_static(request_id),
        ),
        (
            header::COOKIE,
            HeaderValue::from_static("csrf_token=issue-446-acceptance"),
        ),
        (
            HeaderName::from_static("x-csrf-token"),
            HeaderValue::from_static("issue-446-acceptance"),
        ),
    ]);
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(format!("http://{gateway}{MCP_ROUTE}"))
            .auth_header(token.to_owned())
            .custom_headers(headers),
    );
    ().serve(transport)
        .await
        .expect("the rmcp client should initialize")
}

async fn call_tool(
    client: &McpClient,
    tool: &'static str,
    arguments: Value,
) -> Result<CallToolResult, ErrorData> {
    let arguments: RmcpJsonObject =
        serde_json::from_value(arguments).expect("tool arguments are an object");
    match client
        .call_tool(RmcpCallToolRequestParams::new(tool).with_arguments(arguments))
        .await
    {
        Ok(result) => Ok(result),
        Err(ServiceError::McpError(error)) => Err(error),
        Err(other) => panic!("{tool} failed outside JSON-RPC: {other}"),
    }
}

fn refusal_reason(error: &ErrorData) -> Value {
    error
        .data
        .as_ref()
        .map(|data| data["reason"].clone())
        .unwrap_or(Value::Null)
}

/// What an upstream does with a token it received: select the key by `kid`
/// from the published set, take the algorithm from that key rather than from
/// the token, and check the signature, `typ`, `iss`, `aud` and `exp`.
fn verify_with_published_set(token: &str, jwks: &str, audience: &str, token_type: &str) -> Value {
    let header = decode_header(token).expect("the token header decodes");
    assert_eq!(header.typ.as_deref(), Some(token_type));
    let set: JwkSet = serde_json::from_str(jwks).expect("the JWKS is a standard JWK Set");
    let jwk = set
        .find(&header.kid.expect("the token names its key"))
        .expect("the signing key is published");
    assert_eq!(jwk.common.key_algorithm, Some(KeyAlgorithm::ES256));
    let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
    validation.set_issuer(&[GATEWAY_ISSUER]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    decode::<Value>(
        token,
        &DecodingKey::from_jwk(jwk).expect("the published key loads"),
        &validation,
    )
    .expect("the token verifies against the published set")
    .claims
}

#[tokio::test]
async fn e2e_attested_internal_api_names_each_caller_beside_the_service_bearer() {
    let (logs, _logs_guard) = capture_all_logs();
    let harness = phase8_harness().await;
    let (gateway, server) = spawn_gateway_router(harness.router.clone()).await;

    let callers = [
        ("alice", ATTESTED_ALICE_REQUEST, "alice's note"),
        ("bob", ATTESTED_BOB_REQUEST, "bob's note"),
    ];
    for (user, request_id, text) in callers {
        let client = mcp_client(gateway, &caller_token(user), request_id).await;
        let result = call_tool(&client, ATTESTED_TOOL, json!({ "text": text }))
            .await
            .unwrap_or_else(|error| panic!("{user}'s attested call should succeed: {error:?}"));
        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            result.structured_content,
            Some(json!({ "status": 201, "body": { "recorded": true } }))
        );
        client.cancel().await.expect("the client should close");
    }

    let requests = harness.stub.requests_under(ATTESTED_BASE_PATH);
    assert_eq!(requests.len(), 2, "one upstream request per call");
    let jwks = harness.anonymous_jwks().await;
    let mut subjects = Vec::new();
    for (request, (user, request_id, text)) in requests.iter().zip(callers) {
        // The service credential and the assertion ride together: the bearer
        // says the gateway is calling, the assertion on whose behalf.
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {SERVICE_BEARER}").as_str())
        );
        assert_eq!(request.header_count(ASSERTION_HEADER), 1);
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, format!("{ATTESTED_BASE_PATH}/notes"));
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).expect("the body is JSON"),
            json!({ "text": text })
        );
        let claims = verify_with_published_set(
            request
                .header(ASSERTION_HEADER)
                .expect("the upstream receives the assertion"),
            &jwks,
            ATTESTED_AUDIENCE,
            "at+jwt",
        );
        assert_eq!(claims["caller_iss"], json!(CALLER_IDP));
        assert_eq!(claims["caller_sub"], json!(user));
        assert_eq!(claims["sub"], json!(format!("{CALLER_IDP}#{user}")));
        assert_eq!(claims["jti"], json!(request_id));
        // Bound to the request as the upstream received it: the request line
        // and a digest of the exact body bytes.
        assert_eq!(claims["method"], json!(request.method));
        assert_eq!(claims["path"], json!(request.target));
        assert_eq!(
            claims["request_sha256"],
            json!(hex::encode(Sha256::digest(&request.body)))
        );
        subjects.push(claims["sub"].clone());
    }
    assert_ne!(subjects[0], subjects[1]);
    // Only the internal API was called: no exchange, no Gmail.
    assert_eq!(harness.stub.exchange_count(), 0);
    assert_eq!(harness.stub.gmail_count(), 0);

    for (user, request_id, _) in callers {
        harness
            .wait_for(audit::event::TOOL_UPSTREAM_REQUEST, request_id, 1)
            .await;
        let upstream = &harness.events(audit::event::TOOL_UPSTREAM_REQUEST, request_id)[0];
        assert_eq!(upstream.payload["outcome"], json!("success"));
        assert_eq!(
            upstream.payload["caller_assertion"],
            json!({ "kid": ATTESTED_KID, "jti": request_id })
        );
        let actor = upstream.actor.as_ref().expect("the call names its actor");
        assert_eq!(actor.user_id, user);
        assert_eq!(actor.auth_mode, "bearer_token");
        harness
            .wait_for(audit::event::TOOL_INVOKE_SUCCESS, request_id, 1)
            .await;
    }

    harness.assert_no_secret_material(&logs);
    server.abort();
}

#[tokio::test]
async fn e2e_delegated_gmail_catalog_acts_as_each_caller_and_refuses_a_denied_one_first() {
    let (logs, _logs_guard) = capture_all_logs();
    let harness = phase8_harness().await;
    let (gateway, server) = spawn_gateway_router(harness.router.clone()).await;

    // The catalog serves the read, declared read-only by the overlay, and no
    // mutation at all.
    let alice = mcp_client(gateway, &caller_token("alice"), GMAIL_ALICE_REQUEST).await;
    let listed = alice
        .list_all_tools()
        .await
        .expect("alice should list tools");
    let listed = listed
        .iter()
        .map(|tool| {
            let rendered = serde_json::to_value(tool).expect("a tool serializes");
            (
                tool.name.to_string(),
                rendered["annotations"]["readOnlyHint"].clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for name in GMAIL_READ_TOOLS {
        assert_eq!(listed.get(name), Some(&json!(true)), "{name}: {listed:?}");
    }
    for mutation in GMAIL_MUTATIONS {
        assert!(!listed.contains_key(mutation), "{mutation} is served");
    }
    // A hint is only ever declared, never inferred from a method.
    assert_eq!(listed.get(ATTESTED_TOOL), Some(&Value::Null));

    // Bob's rule refuses him before his token is ever asked for.
    let bob = mcp_client(gateway, &caller_token("bob"), GMAIL_BOB_REQUEST).await;
    let refused = call_tool(&bob, GMAIL_PROFILE, json!({ "userId": "me" }))
        .await
        .expect_err("bob may not read Gmail");
    assert_eq!(refusal_reason(&refused), json!("matched_rule"));
    assert_eq!(harness.stub.exchange_count(), 0);
    assert_eq!(harness.stub.gmail_count(), 0);

    let read = call_tool(&alice, GMAIL_PROFILE, json!({ "userId": "me" }))
        .await
        .expect("alice reads her own profile");
    assert_eq!(read.is_error, Some(false));
    assert_eq!(
        read.structured_content
            .as_ref()
            .map(|content| content["body"]["emailAddress"].clone()),
        Some(json!("alice@example.test"))
    );
    assert_eq!(harness.stub.exchange_count(), 1);
    assert_eq!(harness.stub.gmail_count(), 1);

    // Alice's token does not move the rule either: nothing more is asked of
    // the issuer or sent to Gmail for bob.
    let refused = call_tool(&bob, GMAIL_PROFILE, json!({ "userId": "me" }))
        .await
        .expect_err("bob still may not read Gmail");
    assert_eq!(refusal_reason(&refused), json!("matched_rule"));
    assert_eq!(harness.stub.exchange_count(), 1);
    assert_eq!(harness.stub.gmail_count(), 1);

    // Once the operator lifts the rule, bob is served as himself.
    harness.lift_bobs_rule().await;
    let read = call_tool(&bob, GMAIL_PROFILE, json!({ "userId": "me" }))
        .await
        .expect("bob reads his own profile");
    assert_eq!(read.is_error, Some(false));
    assert_eq!(
        read.structured_content
            .as_ref()
            .map(|content| content["body"]["emailAddress"].clone()),
        Some(json!("bob@example.test"))
    );

    // One exchange per caller, and each reached Gmail with a token of their
    // own and nothing that names them in the gateway's terms.
    assert_eq!(harness.stub.exchange_count(), 2);
    let gmail = harness.stub.requests_under(GMAIL_PATH_PREFIX);
    assert_eq!(
        gmail
            .iter()
            .map(|request| (request.method.as_str(), request.target.as_str()))
            .collect::<Vec<_>>(),
        [
            ("GET", "/gmail/v1/users/me/profile"),
            ("GET", "/gmail/v1/users/me/profile")
        ]
    );
    assert_eq!(
        gmail
            .iter()
            .map(|request| request.header("authorization"))
            .collect::<Vec<_>>(),
        [
            Some("Bearer delegated-alice-1"),
            Some("Bearer delegated-bob-2")
        ]
    );
    assert!(gmail
        .iter()
        .all(|request| request.header_count(ASSERTION_HEADER) == 0));

    // The issuer is asked as the gateway, for the read-only scope, with a
    // subject token naming the caller that verifies against the same
    // anonymously fetched set.
    let jwks = harness.anonymous_jwks().await;
    let exchanges = harness.stub.requests_under(EXCHANGE_PATH);
    assert_eq!(exchanges.len(), 2);
    for (exchange, user) in exchanges.iter().zip(["alice", "bob"]) {
        assert_eq!(
            exchange.header("authorization"),
            Some(
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD
                        .encode(format!("greengateway:{EXCHANGE_CLIENT_SECRET}"))
                )
                .as_str()
            )
        );
        assert_eq!(
            exchange.form_field("scope").as_deref(),
            Some(GMAIL_READONLY)
        );
        let subject_token = exchange
            .form_field("subject_token")
            .expect("the exchange carries a subject token");
        let claims = verify_with_published_set(
            &subject_token,
            &jwks,
            SUBJECT_TOKEN_AUDIENCE,
            SUBJECT_TOKEN_TYPE,
        );
        assert_eq!(claims["caller_sub"], json!(user));
        assert_eq!(claims["email"], json!(format!("{user}@example.test")));
    }

    // An exchange is the Connection's own work rather than the call's, so
    // it carries its own request ID and names the caller as its actor.
    wait_for_delivered_audit_events(&harness.capture, "both exchanges", |events| {
        events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE)
            .count()
            >= 2
    })
    .await;
    let exchanges = harness
        .capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE)
        .collect::<Vec<_>>();
    assert_eq!(exchanges.len(), 2);
    for (exchange, user) in exchanges.iter().zip(["alice", "bob"]) {
        assert_eq!(exchange.payload["outcome"], json!("success"));
        assert_eq!(exchange.payload["reason"], json!("exchanged"));
        assert_eq!(exchange.payload["subject_token"]["kid"], json!(SUBJECT_KID));
        let actor = exchange
            .actor
            .as_ref()
            .expect("the exchange names its caller");
        assert_eq!(actor.user_id, user);
        assert_eq!(actor.auth_mode, "bearer_token");
    }
    harness
        .wait_for(audit::event::TOOL_INVOKE_REJECTED, GMAIL_BOB_REQUEST, 2)
        .await;
    for rejected in harness.events(audit::event::TOOL_INVOKE_REJECTED, GMAIL_BOB_REQUEST) {
        assert_eq!(rejected.payload["tool_name"], json!(GMAIL_PROFILE));
        assert_eq!(rejected.payload["reason"], json!("matched_rule"));
        assert_eq!(
            rejected.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("bob")
        );
    }

    let messages = call_tool(
        &alice,
        "gmail.users.messages.list",
        json!({ "userId": "me", "labelIds": ["INBOX", "a&b=c"] }),
    )
    .await
    .expect("a repeated label filter reaches Gmail");
    assert_eq!(messages.is_error, Some(false));
    let requests = harness.stub.requests_under(GMAIL_PATH_PREFIX);
    assert_eq!(
        requests
            .last()
            .expect("the filtered read reached Gmail")
            .target,
        "/gmail/v1/users/me/messages?labelIds=INBOX&labelIds=a%26b%3Dc"
    );

    harness.assert_no_secret_material(&logs);
    alice.cancel().await.expect("alice's client should close");
    bob.cancel().await.expect("bob's client should close");
    server.abort();
}

#[tokio::test]
async fn e2e_a_service_token_is_refused_on_both_lanes_before_any_byte_leaves() {
    let (logs, _logs_guard) = capture_all_logs();
    let harness = phase8_harness().await;
    let (gateway, server) = spawn_gateway_router(harness.router.clone()).await;
    let before = harness.stub.accepted_connections();

    // A service token is admitted to both tools, but names nobody a provider
    // vouched for: there is no one to attest and no one to exchange for.
    let service = mcp_client(gateway, &harness.service_token, SERVICE_REQUEST).await;
    let attested = call_tool(&service, ATTESTED_TOOL, json!({ "text": "from a service" }))
        .await
        .expect_err("a service token cannot be attested");
    assert_eq!(
        refusal_reason(&attested),
        json!("caller_assertion_no_principal")
    );
    let delegated = call_tool(&service, GMAIL_PROFILE, json!({ "userId": "me" }))
        .await
        .expect_err("a service token has no mailbox");
    assert_eq!(
        refusal_reason(&delegated),
        json!("delegated_token_no_principal")
    );

    // Not one connection to the issuer or either upstream, so not one byte.
    assert_eq!(harness.stub.accepted_connections(), before);
    assert!(harness.stub.requests().is_empty());

    harness
        .wait_for(audit::event::TOOL_INVOKE_FAILURE, SERVICE_REQUEST, 2)
        .await;
    let failures = harness.events(audit::event::TOOL_INVOKE_FAILURE, SERVICE_REQUEST);
    assert_eq!(
        failures
            .iter()
            .map(|failure| (
                failure.payload["tool_name"].clone(),
                failure.payload["failure_reason"].clone()
            ))
            .collect::<Vec<_>>(),
        [
            (json!(ATTESTED_TOOL), json!("caller_assertion_no_principal")),
            (json!(GMAIL_PROFILE), json!("delegated_token_no_principal")),
        ]
    );
    for failure in &failures {
        let actor = failure.actor.as_ref().expect("the caller is still audited");
        assert_eq!(actor.auth_mode, "service_token");
        assert!(actor.user_id.starts_with("service-token:"), "{actor:?}");
    }
    // Whatever records the refused attempt records no upstream answer and
    // no assertion: there was neither.
    for upstream in harness.events(audit::event::TOOL_UPSTREAM_REQUEST, SERVICE_REQUEST) {
        assert_ne!(upstream.payload["outcome"], json!("success"));
        assert!(upstream.payload.get("upstream_status").is_none());
        assert!(upstream.payload.get("caller_assertion").is_none());
    }
    assert!(harness
        .capture
        .events()
        .iter()
        .all(|event| event.event_type != audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE));

    harness.assert_no_secret_material(&logs);
    service.cancel().await.expect("the client should close");
    server.abort();
}
