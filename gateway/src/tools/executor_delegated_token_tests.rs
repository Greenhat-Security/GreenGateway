//! Delegated issuer tokens on the tool-call lane (#441): a Connection that calls its upstream as
//! the calling user, with that user's own token from an RFC 8693 issuer, and the purge that drops
//! a principal's tokens and revokes them at that issuer (RFC 7009).
//!
//! One in-process TLS server plays both parts. On the token-exchange path it is the issuer: it
//! hands each caller named by the subject token a token of their own, or refuses, or fails; on the
//! revocation path it records what it is asked to revoke. On every other path it is the upstream,
//! and answers with the mailbox of whoever the bearer token belongs to. No real identity provider
//! is involved, and every key is generated per test.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
    Algorithm, DecodingKey, Validation,
};
use tokio_util::sync::CancellationToken as StopSignal;

use super::*;
use crate::connections::{
    model::SubjectTokenSource,
    test::{
        ConnectionTestReason, ConnectionTestResult, ConnectionTestService, ConnectionTestStage,
        ConnectionTestStageName,
    },
    token_exchange::{DelegatedTokenPurgeTrigger, ManualTokenClock},
};

const EXCHANGE_PATH: &str = "/oauth2/token-exchange";
const REVOCATION_PATH: &str = "/oauth2/revoke";
const CLIENT_SECRET_ALIAS: &str = "issuer-exchange-secret";
/// The client secret the stub issuer expects. Low-entropy and obviously fake.
const CLIENT_SECRET: &str = "issuer-exchange-value";
const SUBJECT_TOKEN_AUDIENCE: &str = "https://issuer.example.test";
const SUBJECT_TOKEN_TYPE: &str = "caller-assertion+jwt";
/// What the stub issuer adds to every grant and to every refusal. None of it may ever surface.
const REFRESH_TOKEN_CANARY: &str = "delegated-refresh-token-canary";
const DENIAL_DESCRIPTION_CANARY: &str = "grant-revoked-description-canary";
const ISSUER_FAILURE_CANARY: &str = "issuer-failure-body-canary";

/// What the stub issuer does with the next exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Issuer {
    Grant { expires_in: u64 },
    Deny,
    Fail,
}

/// What the stub issuer's revocation endpoint answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Revoker {
    Accept,
    Refuse,
    Unavailable,
}

/// The stub issuer and upstream behind one TLS listener.
struct StubDeployment {
    addr: SocketAddr,
    ca_pem: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    issuer: Arc<Mutex<Issuer>>,
    revoker: Arc<Mutex<Revoker>>,
    /// When set, the upstream answers its next request `401`, as it would a
    /// token its provider revoked, and clears the flag.
    reject_next_upstream: Arc<AtomicBool>,
    stop: StopSignal,
}

impl Drop for StubDeployment {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl StubDeployment {
    async fn start(issuer: Issuer) -> Self {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "GreenGateway Delegated Token Test CA",
        );
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("test CA key generates");
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("test CA certificate builds");
        let mut server_params = rcgen::CertificateParams::default();
        server_params.distinguished_name = rcgen::DistinguishedName::new();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "127.0.0.1");
        server_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let server_key = rcgen::KeyPair::generate().expect("test server key generates");
        let server_certificate = server_params
            .signed_by(
                &server_key,
                &rcgen::Issuer::from_params(&ca_params, &ca_key),
            )
            .expect("test server certificate builds");
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    server_certificate.der().as_ref().to_vec(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("test TLS config builds");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener binds");
        let addr = listener.local_addr().expect("test listener has an address");

        let requests = Arc::new(Mutex::new(Vec::new()));
        let issuer = Arc::new(Mutex::new(issuer));
        let revoker = Arc::new(Mutex::new(Revoker::Accept));
        let issued = Arc::new(AtomicUsize::new(0));
        let reject_next_upstream = Arc::new(AtomicBool::new(false));
        let stop = StopSignal::new();
        let (server_requests, server_issuer, server_revoker, server_reject, server_stop) = (
            Arc::clone(&requests),
            Arc::clone(&issuer),
            Arc::clone(&revoker),
            Arc::clone(&reject_next_upstream),
            stop.clone(),
        );
        tokio::spawn(async move {
            loop {
                let (stream, _) = tokio::select! {
                    () = server_stop.cancelled() => return,
                    accepted = listener.accept() => match accepted {
                        Ok(accepted) => accepted,
                        Err(_) => return,
                    },
                };
                let acceptor = acceptor.clone();
                let requests = Arc::clone(&server_requests);
                let issuer = Arc::clone(&server_issuer);
                let revoker = Arc::clone(&server_revoker);
                let issued = Arc::clone(&issued);
                let reject = Arc::clone(&server_reject);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let request = read_http_request(&mut stream).await;
                    let (status, content_type, body) = if request.target == EXCHANGE_PATH {
                        let behaviour = *issuer.lock().expect("issuer lock");
                        answer_as_issuer(&request, behaviour, &issued)
                    } else if request.target == REVOCATION_PATH {
                        answer_as_revoker(*revoker.lock().expect("revoker lock"))
                    } else if reject.swap(false, Ordering::AcqRel) {
                        (StatusCode::UNAUTHORIZED, "application/json", b"{}".to_vec())
                    } else {
                        answer_as_upstream(&request)
                    };
                    requests.lock().expect("requests lock").push(request);
                    let reason = status.canonical_reason().unwrap_or("Response");
                    let head = format!(
                        "HTTP/1.1 {} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status.as_u16(),
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Self {
            addr,
            ca_pem: ca.pem(),
            requests,
            issuer,
            revoker,
            reject_next_upstream,
            stop,
        }
    }

    fn set_revoker(&self, revoker: Revoker) {
        *self.revoker.lock().expect("revoker lock") = revoker;
    }

    fn revocation_count(&self) -> usize {
        self.with_requests(|requests| {
            requests
                .iter()
                .filter(|request| request.target == REVOCATION_PATH)
                .count()
        })
    }

    fn reject_next_upstream_request(&self) {
        self.reject_next_upstream.store(true, Ordering::Release);
    }

    fn set_issuer(&self, issuer: Issuer) {
        *self.issuer.lock().expect("issuer lock") = issuer;
    }

    fn exchange_count(&self) -> usize {
        self.with_requests(|requests| {
            requests
                .iter()
                .filter(|request| request.target == EXCHANGE_PATH)
                .count()
        })
    }

    fn upstream_count(&self) -> usize {
        self.with_requests(|requests| {
            requests
                .iter()
                .filter(|request| {
                    request.target != EXCHANGE_PATH && request.target != REVOCATION_PATH
                })
                .count()
        })
    }

    fn with_requests<R>(&self, read: impl FnOnce(&[CapturedRequest]) -> R) -> R {
        read(&self.requests.lock().expect("requests lock"))
    }
}

/// The form fields of an exchange request, in order.
fn form_fields(request: &CapturedRequest) -> Vec<(String, String)> {
    url::form_urlencoded::parse(&request.body)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn form_field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(field, _)| field == name)
        .map(|(_, value)| value.as_str())
}

/// The claims of a JWT, unverified: what the stub issuer reads to pick a caller's grant.
fn unverified_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("a JWT has a payload");
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .expect("the payload is base64url"),
    )
    .expect("the payload is JSON")
}

fn answer_as_issuer(
    request: &CapturedRequest,
    behaviour: Issuer,
    issued: &AtomicUsize,
) -> (StatusCode, &'static str, Vec<u8>) {
    match behaviour {
        Issuer::Grant { expires_in } => {
            let fields = form_fields(request);
            let subject_token =
                form_field(&fields, "subject_token").expect("an exchange names its subject");
            let caller = unverified_claims(subject_token)["caller_sub"]
                .as_str()
                .expect("the subject token names the caller")
                .to_owned();
            let serial = issued.fetch_add(1, Ordering::AcqRel) + 1;
            let body = json!({
                "access_token": format!("delegated-{caller}-{serial}"),
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "Bearer",
                "expires_in": expires_in,
                "scope": form_field(&fields, "scope").unwrap_or_default(),
                "refresh_token": REFRESH_TOKEN_CANARY,
            });
            (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&body).expect("grant serializes"),
            )
        }
        Issuer::Deny => (
            StatusCode::BAD_REQUEST,
            "application/json",
            serde_json::to_vec(&json!({
                "error": "invalid_grant",
                "error_description": DENIAL_DESCRIPTION_CANARY,
            }))
            .expect("refusal serializes"),
        ),
        Issuer::Fail => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "text/plain",
            ISSUER_FAILURE_CANARY.as_bytes().to_vec(),
        ),
    }
}

/// RFC 7009: `200` for a revoked token, an error object for a refusal, `503` to say try later.
fn answer_as_revoker(behaviour: Revoker) -> (StatusCode, &'static str, Vec<u8>) {
    match behaviour {
        Revoker::Accept => (StatusCode::OK, "application/json", b"{}".to_vec()),
        Revoker::Refuse => (
            StatusCode::BAD_REQUEST,
            "application/json",
            serde_json::to_vec(&json!({
                "error": "unsupported_token_type",
                "error_description": DENIAL_DESCRIPTION_CANARY,
            }))
            .expect("refusal serializes"),
        ),
        Revoker::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            ISSUER_FAILURE_CANARY.as_bytes().to_vec(),
        ),
    }
}

/// The upstream knows its users only by their own tokens.
fn answer_as_upstream(request: &CapturedRequest) -> (StatusCode, &'static str, Vec<u8>) {
    let mailbox = request
        .header("authorization")
        .and_then(|value| value.strip_prefix("Bearer delegated-"))
        .and_then(|token| token.rsplit_once('-'))
        .map(|(caller, _)| caller.to_owned());
    match mailbox {
        Some(mailbox) => (
            StatusCode::OK,
            "application/json",
            serde_json::to_vec(&json!({ "mailbox": mailbox })).expect("mailbox serializes"),
        ),
        None => (StatusCode::UNAUTHORIZED, "application/json", b"{}".to_vec()),
    }
}

fn subject_token_settings() -> CallerAssertionSettings {
    let mut settings = TemporaryStaticAuthRuntime::caller_assertion_settings();
    settings.audience = SUBJECT_TOKEN_AUDIENCE.to_owned();
    settings.token_type = SUBJECT_TOKEN_TYPE.to_owned();
    settings.claims = vec![
        crate::connections::model::CallerAssertionClaim::Email,
        crate::connections::model::CallerAssertionClaim::Roles,
    ];
    settings
}

/// A delegated Connection to `deployment`, with its client secret and signing key served by the
/// returned counting provider, and the gateway's runtime configured by `customize`.
async fn delegated_connection(
    deployment: &StubDeployment,
    signing_key: &str,
    audit: &AuditLog,
    exchange_host: &str,
    revocation_host: Option<&str>,
    customize: impl FnOnce(ConnectionHttpRuntime) -> ConnectionHttpRuntime,
) -> (TemporaryStaticAuthRuntime, Arc<CountingSecretProvider>) {
    let root = std::env::temp_dir().join(format!(
        "greengateway-tool-static-auth-{}",
        uuid::Uuid::new_v4()
    ));
    fs::create_dir(&root).expect("temporary Connection root creates");
    let ca_path = root.join("test-ca.pem");
    fs::write(&ca_path, &deployment.ca_pem).expect("test CA writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("temporary root permissions set");
        fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
            .expect("test CA permissions set");
    }
    let secrets = Arc::new(CountingSecretProvider::new(vec![
        (CLIENT_SECRET_ALIAS, CLIENT_SECRET.as_bytes().to_vec()),
        ("assertion-signing-key", signing_key.as_bytes().to_vec()),
    ]));
    let mut config = Config::test_defaults();
    config.connections_sqlite_path = Some(root.join("connections.sqlite").display().to_string());
    config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
    config.connection_vault_provider = secrets.alias_declarations();
    let control_plane = ConnectionControlPlane::from_config(&config).expect("control plane builds");
    control_plane
        .install_network_secret_providers(vec![Arc::clone(&secrets) as Arc<dyn SecretResolver>]);
    let port = deployment.addr.port();
    let write = ConnectionWrite {
        display_name: "Mail API".to_owned(),
        description: None,
        enabled: true,
        kind: ConnectionKind::HttpApi,
        endpoint: ConnectionEndpoint {
            base_url: format!("https://127.0.0.1:{port}"),
            base_path: "/v1".to_owned(),
        },
        authentication: ConnectionAuthentication::DelegatedIssuerToken {
            token_exchange_url: format!("https://{exchange_host}:{port}{EXCHANGE_PATH}"),
            client_id: "greengateway".to_owned(),
            client_secret_id: Some(CLIENT_SECRET_ALIAS.to_owned()),
            requested_scopes: vec!["mail.read".to_owned()],
            audience: Some("https://mail.example.test".to_owned()),
            resource: None,
            revocation_url: revocation_host
                .map(|host| format!("https://{host}:{port}{REVOCATION_PATH}")),
            subject_token_source: SubjectTokenSource::CallerAssertion,
        },
        caller_assertion: Some(subject_token_settings()),
        additional_headers: Vec::new(),
        tls: TlsProfile::default(),
        timeouts: None,
        discovery: None,
        // What a stored Connection test sends, as the principal running it.
        test_profile: Some(crate::connections::model::ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/messages".to_owned(),
            expected_statuses: vec![200],
        }),
    };
    control_plane
        .ensure_deferred_bindings_resolvable(&write)
        .await
        .expect("the client secret resolves and the signing key loads");
    let initial = control_plane.runtime_snapshot();
    let created = control_plane
        .create_managed(
            initial.collection_etag(),
            write,
            &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
        )
        .await
        .expect("the delegated Connection saves");
    let mut egress_config = EgressConfig {
        allowed_hosts: ["127.0.0.1".to_owned()].into_iter().collect(),
        deny_private_ips: false,
        ..EgressConfig::default()
    };
    egress_config
        .apply_tls_ca_bundle_path(ca_path)
        .expect("test CA configures");
    let egress_client =
        Arc::new(EgressClient::new(egress_config.clone()).expect("egress client builds"));
    let runtime = customize(
        ConnectionHttpRuntime::new(
            control_plane.clone(),
            egress_config,
            Arc::clone(&egress_client),
        )
        .with_audit(audit.clone()),
    );
    (
        TemporaryStaticAuthRuntime {
            secret_path: root.join("unused"),
            root,
            connection_id: created.id.to_string(),
            control_plane,
            runtime,
            egress_client,
        },
        secrets,
    )
}

fn read_mail_tool(connection_id: &str) -> Value {
    let mapping = json!({
        "method": "GET",
        "path_template": "/messages"
    });
    json!({
        "name": "read_mail",
        "description": "Reads the caller's own mailbox through a delegated Connection.",
        "input_json_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": false
        },
        "target": {
            "type": "http",
            "connection_id": connection_id,
            "mapping": mapping
        },
        "source": { "type": "manual" },
        "upstream": mapping
    })
}

struct Harness {
    deployment: StubDeployment,
    connection: TemporaryStaticAuthRuntime,
    secrets: Arc<CountingSecretProvider>,
    executor: ToolExecutor,
    capture: CaptureSink,
    signing_key: String,
}

async fn harness(issuer: Issuer) -> Harness {
    harness_with(issuer, "127.0.0.1", |runtime| runtime).await
}

async fn harness_with(
    issuer: Issuer,
    exchange_host: &str,
    customize: impl FnOnce(ConnectionHttpRuntime) -> ConnectionHttpRuntime,
) -> Harness {
    build_harness(issuer, exchange_host, None, customize).await
}

/// A harness whose Connection names a revocation endpoint on `revocation_host`.
async fn harness_revoking(issuer: Issuer, revocation_host: &str) -> Harness {
    build_harness(issuer, "127.0.0.1", Some(revocation_host), |runtime| {
        runtime
    })
    .await
}

async fn build_harness(
    issuer: Issuer,
    exchange_host: &str,
    revocation_host: Option<&str>,
    customize: impl FnOnce(ConnectionHttpRuntime) -> ConnectionHttpRuntime,
) -> Harness {
    let deployment = StubDeployment::start(issuer).await;
    let signing_key = generated_es256_pem();
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let (connection, secrets) = delegated_connection(
        &deployment,
        &signing_key,
        &audit,
        exchange_host,
        revocation_host,
        customize,
    )
    .await;
    let runtime = ToolRuntime::new(
        runtime_config([("read_mail", enabled_tool(5_000, 4))], 8, 4, 1_000),
        audit.clone(),
    );
    let executor = executor_for_connection_tool(
        read_mail_tool(&connection.connection_id),
        &connection,
        runtime,
        audit,
    );
    Harness {
        deployment,
        connection,
        secrets,
        executor,
        capture,
        signing_key,
    }
}

impl Harness {
    async fn call(&self, caller: &Principal, request_id: &str) -> Result<Value, ToolRuntimeError> {
        self.call_with(context_for(caller, request_id)).await
    }

    async fn call_with(&self, context: ToolInvocationContext) -> Result<Value, ToolRuntimeError> {
        self.executor
            .execute("read_mail", json!({}), context, CancellationToken::new())
            .await
            .map(|result| {
                let response = http_response(result);
                assert_eq!(response.status, StatusCode::OK);
                serde_json::from_slice(&response.body).expect("the upstream answers JSON")
            })
    }

    fn events_of(&self, event_type: &str) -> Vec<audit::AuditEvent> {
        self.capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .collect()
    }

    async fn wait_for(&self, event_type: &str, count: usize) {
        wait_until(Duration::from_secs(2), || {
            self.events_of(event_type).len() >= count
        })
        .await;
        assert_eq!(self.events_of(event_type).len(), count, "{event_type}");
    }

    /// Everything that may never appear in an error, a log line or an audit event: the client
    /// secret, the signing key, every token the issuer handed out, every subject token sent, and
    /// whatever else the issuer said.
    fn secrets_on_the_wire(&self) -> Vec<String> {
        let mut canaries = vec![
            CLIENT_SECRET.to_owned(),
            base64::engine::general_purpose::STANDARD
                .encode(format!("greengateway:{CLIENT_SECRET}")),
            REFRESH_TOKEN_CANARY.to_owned(),
            DENIAL_DESCRIPTION_CANARY.to_owned(),
            ISSUER_FAILURE_CANARY.to_owned(),
            "delegated-alice-".to_owned(),
            "delegated-bob-".to_owned(),
        ];
        canaries.extend(
            pem_body_lines(&self.signing_key)
                .into_iter()
                .map(str::to_owned),
        );
        self.deployment.with_requests(|requests| {
            for request in requests {
                if request.target == EXCHANGE_PATH {
                    if let Some(token) = form_field(&form_fields(request), "subject_token") {
                        canaries.push(token.to_owned());
                        // The signature alone is as good as the token to anyone replaying it.
                        canaries.extend(token.rsplit('.').next().map(str::to_owned));
                    }
                }
            }
        });
        canaries
    }
}

fn work_failure_reason(error: ToolRuntimeError) -> Option<String> {
    match error {
        ToolRuntimeError::WorkFailed { reason, .. } => reason,
        other => panic!("expected a work failure, got {other:?}"),
    }
}

/// What a real issuer does with the subject token before it trusts it: verify it against the
/// gateway's published JWKS, with the algorithm the published key names.
async fn verify_subject_token(connection: &TemporaryStaticAuthRuntime, token: &str) -> Value {
    let jwks = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("the signing key is published");
    let header = decode_header(token).expect("the subject token header decodes");
    assert_eq!(header.typ.as_deref(), Some(SUBJECT_TOKEN_TYPE));
    let set: JwkSet = serde_json::from_str(jwks.body()).expect("the JWKS is a JWK Set");
    let jwk = set
        .find(&header.kid.expect("the subject token names its key"))
        .expect("the key is published");
    assert_eq!(jwk.common.key_algorithm, Some(KeyAlgorithm::ES256));
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_issuer(&["https://gateway.example.test"]);
    validation.set_audience(&[SUBJECT_TOKEN_AUDIENCE]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    decode::<Value>(
        token,
        &DecodingKey::from_jwk(jwk).expect("the published key loads"),
        &validation,
    )
    .expect("the subject token verifies against the published set")
    .claims
}

#[tokio::test]
async fn two_principals_each_reach_the_upstream_as_themselves_with_their_own_cached_token() {
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    let saved = harness.secrets.resolutions();
    let alice = bearer("alice", &["mail:read"]);
    let bob = bearer("bob", &["mail:read"]);

    for (caller, request_id) in [
        (&alice, "request-alice-1"),
        (&bob, "request-bob-1"),
        (&alice, "request-alice-2"),
        (&bob, "request-bob-2"),
    ] {
        let mailbox = harness
            .call(caller, request_id)
            .await
            .expect("a delegated call succeeds");
        assert_eq!(mailbox, json!({ "mailbox": caller.user_id }));
    }

    // One exchange per caller; each later call is served from the cache, with
    // no secret read at all. An exchange reads the signing key and the client
    // secret once each.
    assert_eq!(harness.deployment.exchange_count(), 2);
    assert_eq!(harness.deployment.upstream_count(), 4);
    assert_eq!(harness.secrets.resolutions(), saved + 4);
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        2
    );

    let mut subject_tokens = Vec::new();
    harness.deployment.with_requests(|requests| {
        for request in requests {
            if request.target == EXCHANGE_PATH {
                assert_eq!(request.method, "POST");
                assert_eq!(
                    request.header("authorization"),
                    Some(
                        format!(
                            "Basic {}",
                            base64::engine::general_purpose::STANDARD
                                .encode(format!("greengateway:{CLIENT_SECRET}"))
                        )
                        .as_str()
                    )
                );
                assert_eq!(
                    request.header("content-type"),
                    Some("application/x-www-form-urlencoded")
                );
                let fields = form_fields(request);
                assert_eq!(
                    form_field(&fields, "grant_type"),
                    Some("urn:ietf:params:oauth:grant-type:token-exchange")
                );
                assert_eq!(
                    form_field(&fields, "subject_token_type"),
                    Some("urn:ietf:params:oauth:token-type:jwt")
                );
                assert_eq!(
                    form_field(&fields, "requested_token_type"),
                    Some("urn:ietf:params:oauth:token-type:access_token")
                );
                assert_eq!(form_field(&fields, "scope"), Some("mail.read"));
                assert_eq!(
                    form_field(&fields, "audience"),
                    Some("https://mail.example.test")
                );
                subject_tokens.push(
                    form_field(&fields, "subject_token")
                        .expect("a subject token is sent")
                        .to_owned(),
                );
            } else {
                // The upstream gets the caller's own token and nothing that
                // names the caller in the gateway's terms: the assertion went
                // to the issuer only.
                assert!(request
                    .header("authorization")
                    .is_some_and(|value| value.starts_with("Bearer delegated-")));
                assert_eq!(request.header_count("x-caller-assertion"), 0);
            }
        }
    });

    let mut subjects = Vec::new();
    for token in &subject_tokens {
        let claims = verify_subject_token(&harness.connection, token).await;
        // Bound to no request: the token it buys serves many.
        for claim in ["method", "path", "request_sha256"] {
            assert!(claims.get(claim).is_none(), "{claim} must not be bound");
        }
        assert_eq!(claims["caller_iss"], json!("https://idp.example.test"));
        assert!(claims["jti"]
            .as_str()
            .is_some_and(|jti| uuid::Uuid::parse_str(jti).is_ok()));
        subjects.push((
            claims["caller_sub"].clone(),
            claims["email"].clone(),
            claims["sub"].clone(),
        ));
    }
    assert_eq!(
        subjects,
        vec![
            (
                json!("alice"),
                json!("alice@example.test"),
                json!("https://idp.example.test#alice")
            ),
            (
                json!("bob"),
                json!("bob@example.test"),
                json!("https://idp.example.test#bob")
            ),
        ]
    );

    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE, 2)
        .await;
    for (exchange, caller) in harness
        .events_of(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE)
        .iter()
        .zip([&alice, &bob])
    {
        assert_eq!(exchange.payload["outcome"], json!("success"));
        assert_eq!(exchange.payload["reason"], json!("exchanged"));
        assert_eq!(exchange.payload["issuer_status"], json!(200));
        assert_eq!(exchange.payload["subject_token"]["kid"], json!("gw-test-1"));
        let actor = exchange
            .actor
            .as_ref()
            .expect("the exchange names its caller");
        assert_eq!(actor.user_id, caller.user_id);
        assert_eq!(actor.auth_mode, "bearer_token");
    }
    harness
        .wait_for(audit::event::TOOL_UPSTREAM_REQUEST, 4)
        .await;
    for upstream in harness.events_of(audit::event::TOOL_UPSTREAM_REQUEST) {
        assert_eq!(upstream.payload["outcome"], json!("success"));
        assert!(upstream.payload.get("caller_assertion").is_none());
    }
}

#[tokio::test]
async fn a_token_is_exchanged_again_before_the_issuer_says_it_expires() {
    let clock = Arc::new(ManualTokenClock::new());
    let cache_clock = Arc::clone(&clock);
    let harness = harness_with(
        Issuer::Grant { expires_in: 60 },
        "127.0.0.1",
        move |runtime| runtime.with_delegated_token_cache_for_test(cache_clock, 8),
    )
    .await;
    let alice = bearer("alice", &["mail:read"]);

    harness.call(&alice, "request-1").await.expect("first call");
    clock.advance(Duration::from_secs(40));
    harness
        .call(&alice, "request-2")
        .await
        .expect("cached call");
    assert_eq!(harness.deployment.exchange_count(), 1);

    // Past the refresh point, before the issuer's own expiry.
    clock.advance(Duration::from_secs(15));
    harness
        .call(&alice, "request-3")
        .await
        .expect("refreshed call");
    assert_eq!(harness.deployment.exchange_count(), 2);
    harness.deployment.with_requests(|requests| {
        let bearers: Vec<_> = requests
            .iter()
            .filter(|request| request.target != EXCHANGE_PATH)
            .filter_map(|request| request.header("authorization"))
            .collect();
        assert_eq!(
            bearers,
            [
                "Bearer delegated-alice-1",
                "Bearer delegated-alice-1",
                "Bearer delegated-alice-2"
            ]
        );
    });
}

#[tokio::test]
async fn a_bounded_cache_evicts_an_idle_caller_who_is_then_exchanged_for_again() {
    let harness = harness_with(
        Issuer::Grant { expires_in: 3_600 },
        "127.0.0.1",
        |runtime| runtime.with_delegated_token_cache_for_test(Arc::new(ManualTokenClock::new()), 1),
    )
    .await;
    let alice = bearer("alice", &["mail:read"]);
    let bob = bearer("bob", &["mail:read"]);

    for (caller, request_id, expected_exchanges) in [
        (&alice, "request-1", 1),
        (&alice, "request-2", 1),
        (&bob, "request-3", 2),
        (&alice, "request-4", 3),
    ] {
        let mailbox = harness
            .call(caller, request_id)
            .await
            .expect("call succeeds");
        assert_eq!(mailbox, json!({ "mailbox": caller.user_id }));
        assert_eq!(harness.deployment.exchange_count(), expected_exchanges);
        assert_eq!(
            harness.connection.runtime.delegated_token_cache_entries(),
            1
        );
    }
}

#[tokio::test]
async fn an_exchange_that_fails_refuses_the_call_with_its_own_reason_and_sends_nothing_upstream() {
    let (logs, _logs_guard) = capture_all_logs();
    let harness = harness(Issuer::Deny).await;
    let alice = bearer("alice", &["mail:read"]);

    let denied = harness
        .call(&alice, "request-denied")
        .await
        .expect_err("a refused grant refuses the call");
    assert_eq!(
        work_failure_reason(denied).as_deref(),
        Some("delegated_token_denied")
    );

    harness.deployment.set_issuer(Issuer::Fail);
    let failed = harness
        .call(&alice, "request-failed")
        .await
        .expect_err("an issuer failure refuses the call");
    assert_eq!(
        work_failure_reason(failed).as_deref(),
        Some("delegated_token_exchange_failed")
    );

    // A failure is not cached: each call asked the issuer again, and the
    // upstream never received a request, with or without a credential.
    assert_eq!(harness.deployment.exchange_count(), 2);
    assert_eq!(harness.deployment.upstream_count(), 0);
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        1
    );

    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE, 2)
        .await;
    let exchanges = harness.events_of(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE);
    assert_eq!(
        exchanges[0].payload["reason"],
        json!("delegated_token_denied")
    );
    assert_eq!(exchanges[0].payload["issuer_status"], json!(400));
    assert_eq!(exchanges[0].payload["issuer_error"], json!("invalid_grant"));
    assert_eq!(
        exchanges[1].payload["reason"],
        json!("delegated_token_exchange_failed")
    );
    assert_eq!(exchanges[1].payload["issuer_status"], json!(500));
    assert_eq!(exchanges[1].payload["issuer_error"], Value::Null);
    for exchange in &exchanges {
        assert_eq!(exchange.payload["outcome"], json!("failure"));
        assert_eq!(
            exchange.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("alice")
        );
    }
    harness.wait_for(audit::event::TOOL_INVOKE_FAILURE, 2).await;
    let reasons: Vec<_> = harness
        .events_of(audit::event::TOOL_INVOKE_FAILURE)
        .iter()
        .map(|event| event.payload["failure_reason"].clone())
        .collect();
    assert_eq!(
        reasons,
        [
            json!("delegated_token_denied"),
            json!("delegated_token_exchange_failed")
        ]
    );

    let rendered_audit =
        serde_json::to_string(&harness.capture.events()).expect("audit serializes");
    let rendered_logs = logs.contents();
    for canary in harness.secrets_on_the_wire() {
        assert!(!rendered_audit.contains(&canary), "audit leaked {canary:?}");
        assert!(!rendered_logs.contains(&canary), "logs leaked {canary:?}");
    }
}

#[tokio::test]
async fn no_token_material_reaches_an_error_a_log_line_or_an_audit_event() {
    let (logs, _logs_guard) = capture_all_logs();
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    let alice = bearer("alice", &["mail:read"]);
    let bob = bearer("bob", &["mail:read"]);

    harness
        .call(&alice, "request-alice")
        .await
        .expect("alice's call");
    harness.call(&bob, "request-bob").await.expect("bob's call");
    harness.deployment.set_issuer(Issuer::Deny);
    let carol = bearer("carol", &["mail:read"]);
    let refused = harness
        .call(&carol, "request-carol")
        .await
        .expect_err("carol has no grant");
    let rendered_error = format!("{refused:?} {refused}");

    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE, 3)
        .await;
    let rendered_audit =
        serde_json::to_string(&harness.capture.events()).expect("audit serializes");
    let rendered_logs = logs.contents();
    let canaries = harness.secrets_on_the_wire();
    // Two subject tokens and their signatures, beside the fixed canaries.
    assert!(canaries.len() >= 10, "the canaries cover what was sent");
    for canary in &canaries {
        assert!(!rendered_error.contains(canary), "error leaked {canary:?}");
        assert!(!rendered_audit.contains(canary), "audit leaked {canary:?}");
        assert!(!rendered_logs.contains(canary), "logs leaked {canary:?}");
    }
    // The runtime's own rendering says how much is cached and nothing more.
    let rendered_runtime = format!("{:?}", harness.connection.runtime);
    assert!(rendered_runtime.contains("delegated_token_cache_entries: 3"));
    for canary in &canaries {
        assert!(!rendered_runtime.contains(canary));
    }
}

#[tokio::test]
async fn a_call_that_names_nobody_is_refused_before_any_exchange() {
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    let saved = harness.secrets.resolutions();
    let service = Principal {
        user_id: "service-token:svc_1".to_owned(),
        issuer: Some("https://idp.example.test".to_owned()),
        email: None,
        org_id: None,
        roles: vec!["mail:read".to_owned()],
        session_id: "svc_1".to_owned(),
        auth_method: AuthMethod::ServiceToken,
    };
    let service_context = context_for(&service, "request-service");
    assert!(service_context.caller.is_none());
    let anonymous = ToolInvocationContext {
        request_id: "request-anonymous".to_owned(),
        source_ip: "203.0.113.10".to_owned(),
        actor: None,
        caller: None,
        source: ToolInvocationSource::Mcp,
        admitted_deadline: None,
    };

    for context in [service_context, anonymous] {
        let refused = harness
            .call_with(context)
            .await
            .expect_err("nobody to exchange a token for");
        assert_eq!(
            work_failure_reason(refused).as_deref(),
            Some("delegated_token_no_principal")
        );
    }
    harness.wait_for(audit::event::TOOL_INVOKE_FAILURE, 2).await;
    for failure in harness.events_of(audit::event::TOOL_INVOKE_FAILURE) {
        assert_eq!(
            failure.payload["failure_reason"],
            json!("delegated_token_no_principal")
        );
    }
    // There is no shared identity to fall back to: nothing was read, asked
    // or sent.
    assert_eq!(harness.secrets.resolutions(), saved);
    assert_eq!(harness.deployment.exchange_count(), 0);
    assert_eq!(harness.deployment.upstream_count(), 0);
    assert!(harness
        .events_of(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE)
        .is_empty());
}

#[tokio::test]
async fn an_exchange_endpoint_outside_the_egress_allowlist_is_never_contacted() {
    let harness = harness_with(
        Issuer::Grant { expires_in: 3_600 },
        "issuer.example.test",
        |runtime| runtime,
    )
    .await;
    let saved = harness.secrets.resolutions();
    let refused = harness
        .call(&bearer("alice", &["mail:read"]), "request-1")
        .await
        .expect_err("the issuer is not an allowed host");
    assert_eq!(
        work_failure_reason(refused).as_deref(),
        Some("delegated_token_egress_denied")
    );
    // Refused before the signing key or the client secret was read.
    assert_eq!(harness.secrets.resolutions(), saved);
    assert_eq!(harness.deployment.exchange_count(), 0);
    assert_eq!(harness.deployment.upstream_count(), 0);
}

#[tokio::test]
async fn a_changed_connection_exchanges_again_and_forgets_the_old_tokens() {
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    let alice = bearer("alice", &["mail:read"]);
    harness.call(&alice, "request-1").await.expect("first call");
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        1
    );

    let current = harness
        .connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .cloned()
        .expect("the Connection is stored");
    let mut changed = current.write.clone();
    if let ConnectionAuthentication::DelegatedIssuerToken {
        requested_scopes, ..
    } = &mut changed.authentication
    {
        requested_scopes.push("mail.labels".to_owned());
    }
    harness
        .connection
        .control_plane
        .ensure_deferred_bindings_resolvable(&changed)
        .await
        .expect("the changed Connection's secrets resolve");
    harness
        .connection
        .control_plane
        .replace_managed(
            &current.id,
            &current.etag(),
            changed,
            &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
        )
        .await
        .expect("the change saves");

    harness
        .call(&alice, "request-2")
        .await
        .expect("second call");
    assert_eq!(harness.deployment.exchange_count(), 2);
    // The token exchanged under the old revision is gone, not merely unused.
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        1
    );
    harness.deployment.with_requests(|requests| {
        let scopes: Vec<_> = requests
            .iter()
            .filter(|request| request.target == EXCHANGE_PATH)
            .map(|request| form_field(&form_fields(request), "scope").map(str::to_owned))
            .collect();
        assert_eq!(
            scopes,
            [
                Some("mail.read".to_owned()),
                Some("mail.labels mail.read".to_owned())
            ]
        );
    });
}

#[tokio::test]
async fn an_upstream_401_drops_the_callers_token_and_the_next_call_exchanges_again() {
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    let alice = bearer("alice", &["mail:read"]);
    let bob = bearer("bob", &["mail:read"]);
    harness.call(&bob, "request-bob").await.expect("bob's call");

    harness.deployment.reject_next_upstream_request();
    let rejected = harness
        .call(&alice, "request-rejected")
        .await
        .expect_err("a rejected token fails the call");
    assert_eq!(
        work_failure_reason(rejected).as_deref(),
        Some("auth_failed")
    );
    assert_eq!(harness.deployment.exchange_count(), 2);

    // Alice's next call exchanges again; bob keeps the token he holds. The
    // rejected call itself is not replayed.
    let mailbox = harness
        .call(&alice, "request-retried")
        .await
        .expect("a fresh token serves the next call");
    assert_eq!(mailbox, json!({ "mailbox": "alice" }));
    harness
        .call(&bob, "request-bob-again")
        .await
        .expect("bob's call");
    assert_eq!(harness.deployment.exchange_count(), 3);
    harness.deployment.with_requests(|requests| {
        let bearers: Vec<_> = requests
            .iter()
            .filter(|request| request.target != EXCHANGE_PATH)
            .filter_map(|request| request.header("authorization"))
            .collect();
        assert_eq!(
            bearers,
            [
                "Bearer delegated-bob-1",
                "Bearer delegated-alice-2",
                "Bearer delegated-alice-3",
                "Bearer delegated-bob-1",
            ]
        );
    });
}

/// What an operator does after disabling a user at their identity provider.
fn operator_purge() -> DelegatedTokenPurgeTrigger {
    DelegatedTokenPurgeTrigger::Operator {
        actor: actor_from_principal(&bearer("operator", &["admin"])),
        request_id: "request-purge".to_owned(),
        source_ip: "203.0.113.20".to_owned(),
    }
}

#[tokio::test]
async fn purging_a_principal_drops_and_revokes_every_token_of_theirs_and_no_one_elses() {
    let (logs, _logs_guard) = capture_all_logs();
    let harness = harness_revoking(Issuer::Grant { expires_in: 3_600 }, "127.0.0.1").await;
    let alice = bearer("alice", &["mail:read"]);
    // The same principal with other claims is a cache entry of its own.
    let promoted = bearer("alice", &["mail:read", "mail:admin"]);
    let bob = bearer("bob", &["mail:read"]);
    for (caller, request_id) in [
        (&alice, "request-alice"),
        (&promoted, "request-alice-admin"),
        (&bob, "request-bob"),
    ] {
        harness
            .call(caller, request_id)
            .await
            .expect("a delegated call succeeds");
    }
    assert_eq!(harness.deployment.exchange_count(), 3);
    let saved = harness.secrets.resolutions();

    // The principal is named as the directory and audit name it; the issuer
    // is matched in canonical form.
    let purged = harness.connection.runtime.purge_delegated_tokens(
        "https://idp.example.test/",
        "alice",
        operator_purge(),
    );
    assert_eq!(purged, 2);
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        1,
        "only bob's token is left"
    );

    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION, 2)
        .await;
    // Each revocation read the client secret once, and nothing else.
    assert_eq!(harness.secrets.resolutions(), saved + 2);
    let mut revoked = Vec::new();
    harness.deployment.with_requests(|requests| {
        for request in requests
            .iter()
            .filter(|request| request.target == REVOCATION_PATH)
        {
            assert_eq!(request.method, "POST");
            assert_eq!(
                request.header("authorization"),
                Some(
                    format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD
                            .encode(format!("greengateway:{CLIENT_SECRET}"))
                    )
                    .as_str()
                )
            );
            assert_eq!(
                request.header("content-type"),
                Some("application/x-www-form-urlencoded")
            );
            let fields = form_fields(request);
            assert_eq!(fields.len(), 2, "{fields:?}");
            assert_eq!(form_field(&fields, "token_type_hint"), Some("access_token"));
            revoked.push(
                form_field(&fields, "token")
                    .expect("the token is named")
                    .to_owned(),
            );
        }
    });
    revoked.sort();
    assert_eq!(revoked, ["delegated-alice-1", "delegated-alice-2"]);

    let purges = harness.events_of(audit::event::CONNECTION_DELEGATED_TOKEN_PURGE);
    assert_eq!(purges.len(), 1);
    let purge = &purges[0];
    assert_eq!(purge.request_id, "request-purge");
    assert_eq!(purge.source_ip, "203.0.113.20");
    assert_eq!(
        purge.actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("operator")
    );
    let principal = json!({ "issuer": "https://idp.example.test", "subject": "alice" });
    assert_eq!(purge.payload["trigger"], json!("operator"));
    assert_eq!(purge.payload["principal"], principal);
    assert_eq!(purge.payload["purged_entries"], json!(2));
    for revocation in harness.events_of(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION) {
        assert_eq!(revocation.payload["purge_id"], purge.payload["purge_id"]);
        assert_eq!(
            revocation.payload["connection_id"],
            json!(harness.connection.connection_id)
        );
        assert_eq!(revocation.payload["principal"], principal);
        assert_eq!(revocation.payload["outcome"], json!("success"));
        assert_eq!(revocation.payload["reason"], json!("revoked"));
        assert_eq!(revocation.payload["issuer_status"], json!(200));
        assert_eq!(revocation.payload["issuer_error"], Value::Null);
        assert_eq!(revocation.request_id, "request-purge");
        assert_eq!(
            revocation
                .actor
                .as_ref()
                .map(|actor| actor.user_id.as_str()),
            Some("operator")
        );
    }

    // Alice's next call asks the issuer again; bob is still served from the
    // cache.
    let mailbox = harness
        .call(&alice, "request-alice-again")
        .await
        .expect("a purged principal is exchanged for again");
    assert_eq!(mailbox, json!({ "mailbox": "alice" }));
    harness
        .call(&bob, "request-bob-again")
        .await
        .expect("bob's call");
    assert_eq!(harness.deployment.exchange_count(), 4);
    harness.deployment.with_requests(|requests| {
        let bearers: Vec<_> = requests
            .iter()
            .filter(|request| request.target != EXCHANGE_PATH && request.target != REVOCATION_PATH)
            .filter_map(|request| request.header("authorization"))
            .collect();
        assert_eq!(
            bearers,
            [
                "Bearer delegated-alice-1",
                "Bearer delegated-alice-2",
                "Bearer delegated-bob-3",
                "Bearer delegated-alice-4",
                "Bearer delegated-bob-3",
            ]
        );
    });

    let rendered_audit =
        serde_json::to_string(&harness.capture.events()).expect("audit serializes");
    let rendered_logs = logs.contents();
    for canary in harness.secrets_on_the_wire() {
        assert!(!rendered_audit.contains(&canary), "audit leaked {canary:?}");
        assert!(!rendered_logs.contains(&canary), "logs leaked {canary:?}");
    }
}

#[tokio::test]
async fn a_revoked_credential_purges_on_its_own_and_without_an_endpoint_a_token_is_only_dropped() {
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    let alice = bearer("alice", &["mail:read"]);
    harness.call(&alice, "request-1").await.expect("first call");
    let saved = harness.secrets.resolutions();

    // What a JWT validator does when the denylist refuses one of alice's
    // tokens.
    let observer: &dyn crate::auth::RevokedCredentialObserver = &harness.connection.runtime;
    observer.credential_revoked("https://idp.example.test", "alice");
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        0
    );

    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION, 1)
        .await;
    let revocation = &harness.events_of(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION)[0];
    assert_eq!(revocation.payload["outcome"], json!("skipped"));
    assert_eq!(
        revocation.payload["reason"],
        json!("revocation_not_configured")
    );
    assert_eq!(revocation.payload["issuer_status"], Value::Null);
    // No operator asked: the purge has no actor and no request of its own.
    assert!(revocation.actor.is_none());
    assert_eq!(revocation.request_id, "connection-delegated-token-purge");
    let purges = harness.events_of(audit::event::CONNECTION_DELEGATED_TOKEN_PURGE);
    assert_eq!(purges.len(), 1);
    assert_eq!(purges[0].payload["trigger"], json!("credential_revoked"));
    assert_eq!(purges[0].payload["purged_entries"], json!(1));
    assert!(purges[0].actor.is_none());
    // Nothing was read or sent for a token with nowhere to be revoked.
    assert_eq!(harness.secrets.resolutions(), saved);
    assert_eq!(harness.deployment.revocation_count(), 0);

    // The same refused credential presented again finds nothing to purge and
    // records nothing; alice's next call simply exchanges again.
    observer.credential_revoked("https://idp.example.test", "alice");
    harness
        .call(&alice, "request-2")
        .await
        .expect("a purged principal is exchanged for again");
    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE, 2)
        .await;
    assert_eq!(
        harness
            .events_of(audit::event::CONNECTION_DELEGATED_TOKEN_PURGE)
            .len(),
        1
    );
    // Another principal is never touched.
    observer.credential_revoked("https://idp.example.test", "bob");
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        1
    );
}

#[tokio::test]
async fn a_refused_unavailable_or_disallowed_revocation_is_audited_once_and_never_retried() {
    let harness = harness_revoking(Issuer::Grant { expires_in: 3_600 }, "127.0.0.1").await;
    let alice = bearer("alice", &["mail:read"]);
    let observer: &dyn crate::auth::RevokedCredentialObserver = &harness.connection.runtime;

    harness.deployment.set_revoker(Revoker::Refuse);
    harness.call(&alice, "request-1").await.expect("call");
    observer.credential_revoked("https://idp.example.test", "alice");
    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION, 1)
        .await;

    harness.deployment.set_revoker(Revoker::Unavailable);
    harness.call(&alice, "request-2").await.expect("call");
    observer.credential_revoked("https://idp.example.test", "alice");
    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION, 2)
        .await;

    let revocations = harness.events_of(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION);
    assert_eq!(revocations[0].payload["outcome"], json!("failure"));
    assert_eq!(
        revocations[0].payload["reason"],
        json!("revocation_refused")
    );
    assert_eq!(revocations[0].payload["issuer_status"], json!(400));
    assert_eq!(
        revocations[0].payload["issuer_error"],
        json!("unsupported_token_type")
    );
    assert_eq!(revocations[1].payload["outcome"], json!("failure"));
    assert_eq!(revocations[1].payload["reason"], json!("revocation_failed"));
    assert_eq!(revocations[1].payload["issuer_status"], json!(503));
    assert_eq!(revocations[1].payload["issuer_error"], Value::Null);
    // One request each: a failed revocation is not retried, and the token
    // stays out of the cache either way.
    assert_eq!(harness.deployment.revocation_count(), 2);
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        0
    );
    let rendered_audit =
        serde_json::to_string(&harness.capture.events()).expect("audit serializes");
    for canary in harness.secrets_on_the_wire() {
        assert!(!rendered_audit.contains(&canary), "audit leaked {canary:?}");
    }

    // A revocation endpoint outside the egress allowlist is never contacted,
    // and the client secret is not read for it.
    let disallowed =
        harness_revoking(Issuer::Grant { expires_in: 3_600 }, "issuer.example.test").await;
    disallowed.call(&alice, "request-3").await.expect("call");
    let saved = disallowed.secrets.resolutions();
    disallowed.connection.runtime.purge_delegated_tokens(
        "https://idp.example.test",
        "alice",
        operator_purge(),
    );
    disallowed
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION, 1)
        .await;
    let revocation = &disallowed.events_of(audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION)[0];
    assert_eq!(revocation.payload["outcome"], json!("failure"));
    assert_eq!(
        revocation.payload["reason"],
        json!("revocation_egress_denied")
    );
    assert_eq!(revocation.payload["issuer_status"], Value::Null);
    assert_eq!(disallowed.secrets.resolutions(), saved);
    assert_eq!(disallowed.deployment.revocation_count(), 0);
}

/// The stored test of the harness's Connection, run as `tester` the way the admin endpoint runs
/// it for the principal who asked.
async fn test_connection_as(harness: &Harness, tester: Option<&Principal>) -> ConnectionTestResult {
    let record = harness
        .connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .cloned()
        .expect("the Connection is stored");
    let tester = tester.and_then(AttestedCaller::from_principal);
    ConnectionTestService::new(harness.connection.runtime.clone())
        .execute_as(&record, record.etag().as_str(), tester.as_ref())
        .await
        .result
}

#[tokio::test]
async fn a_connection_test_runs_as_the_tester_with_a_token_it_never_caches() {
    let (logs, _logs_guard) = capture_all_logs();
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    let alice = bearer("alice", &["mail:read"]);
    let bob = bearer("bob", &["mail:read"]);

    for tester in [&alice, &bob, &alice] {
        let result = test_connection_as(&harness, Some(tester)).await;
        assert!(result.ok, "{:?}", result.stages);
        assert_eq!(
            result.stages,
            [
                ConnectionTestStage::success(ConnectionTestStageName::EgressPolicy),
                ConnectionTestStage::success(ConnectionTestStageName::SecretAvailable),
                ConnectionTestStage::success(ConnectionTestStageName::Connected),
                ConnectionTestStage::not_applicable(ConnectionTestStageName::TlsValid),
                ConnectionTestStage::success(ConnectionTestStageName::Authenticated),
                ConnectionTestStage::success(ConnectionTestStageName::ProtocolValid),
            ]
        );
    }

    // Each test exchanged for its own tester and sent its one request with that tester's token.
    // Nothing was cached, so alice's second test exchanged again rather than reusing her first
    // token, and no later call can be served a token a test obtained.
    assert_eq!(harness.deployment.exchange_count(), 3);
    assert_eq!(harness.deployment.upstream_count(), 3);
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        0
    );
    harness.deployment.with_requests(|requests| {
        let upstream: Vec<_> = requests
            .iter()
            .filter(|request| request.target != EXCHANGE_PATH)
            .collect();
        for request in &upstream {
            assert_eq!(request.target, "/v1/messages");
            assert_eq!(request.header_count("x-caller-assertion"), 0);
        }
        let bearers: Vec<_> = upstream
            .iter()
            .filter_map(|request| request.header("authorization"))
            .collect();
        assert_eq!(
            bearers,
            [
                "Bearer delegated-alice-1",
                "Bearer delegated-bob-2",
                "Bearer delegated-alice-3",
            ]
        );
    });
    let mut subject_tokens = Vec::new();
    harness.deployment.with_requests(|requests| {
        for request in requests {
            if request.target == EXCHANGE_PATH {
                subject_tokens
                    .extend(form_field(&form_fields(request), "subject_token").map(str::to_owned));
            }
        }
    });
    let mut testers = Vec::new();
    for token in &subject_tokens {
        testers.push(verify_subject_token(&harness.connection, token).await["caller_sub"].clone());
    }
    assert_eq!(testers, [json!("alice"), json!("bob"), json!("alice")]);

    // A tool call afterwards exchanges for itself, and only it fills the cache.
    harness
        .call(&alice, "request-after-test")
        .await
        .expect("alice's call");
    assert_eq!(harness.deployment.exchange_count(), 4);
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        1
    );

    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE, 4)
        .await;
    let actors: Vec<_> = harness
        .events_of(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE)
        .iter()
        .map(|exchange| {
            assert_eq!(exchange.payload["outcome"], json!("success"));
            exchange
                .actor
                .as_ref()
                .map(|actor| actor.user_id.clone())
                .expect("the exchange names its tester")
        })
        .collect();
    assert_eq!(actors, ["alice", "bob", "alice", "alice"]);

    let rendered_audit =
        serde_json::to_string(&harness.capture.events()).expect("audit serializes");
    let rendered_logs = logs.contents();
    for canary in harness.secrets_on_the_wire() {
        assert!(!rendered_audit.contains(&canary), "audit leaked {canary:?}");
        assert!(!rendered_logs.contains(&canary), "logs leaked {canary:?}");
    }
}

#[tokio::test]
async fn a_connection_test_reports_why_the_tester_got_no_token_and_sends_nothing_upstream() {
    let harness = harness(Issuer::Deny).await;
    let saved = harness.secrets.resolutions();
    let alice = bearer("alice", &["mail:read"]);

    // Nobody an issuer could look up: no principal, a service token, or a principal without an
    // identity-provider issuer. Refused before the egress preflight or any secret read.
    let service = Principal {
        auth_method: AuthMethod::ServiceToken,
        ..bearer("service-token:svc_1", &["mail:read"])
    };
    let without_issuer = Principal {
        issuer: None,
        ..bearer("carol", &["mail:read"])
    };
    for tester in [None, Some(&service), Some(&without_issuer)] {
        let result = test_connection_as(&harness, tester).await;
        assert!(!result.ok);
        assert_eq!(
            result.stages,
            [ConnectionTestStage::failure(
                ConnectionTestStageName::SecretAvailable,
                ConnectionTestReason::DelegatedTokenNoPrincipal,
            )]
        );
    }
    assert_eq!(harness.secrets.resolutions(), saved);
    assert_eq!(harness.deployment.exchange_count(), 0);

    // The issuer refusing the tester, and the issuer failing, each keep the reason a tool call
    // would report, and the upstream is never contacted.
    for (issuer, reason) in [
        (Issuer::Deny, ConnectionTestReason::DelegatedTokenDenied),
        (
            Issuer::Fail,
            ConnectionTestReason::DelegatedTokenExchangeFailed,
        ),
    ] {
        harness.deployment.set_issuer(issuer);
        let result = test_connection_as(&harness, Some(&alice)).await;
        assert!(!result.ok);
        assert_eq!(
            result.stages,
            [
                ConnectionTestStage::success(ConnectionTestStageName::EgressPolicy),
                ConnectionTestStage::failure(ConnectionTestStageName::SecretAvailable, reason),
            ]
        );
    }
    assert_eq!(harness.deployment.exchange_count(), 2);
    assert_eq!(harness.deployment.upstream_count(), 0);
    assert_eq!(
        harness.connection.runtime.delegated_token_cache_entries(),
        0
    );
    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE, 2)
        .await;
    for exchange in harness.events_of(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE) {
        assert_eq!(exchange.payload["outcome"], json!("failure"));
        assert_eq!(
            exchange.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("alice")
        );
    }
}

#[tokio::test]
async fn a_disabled_delegated_connection_is_not_tested_because_its_keys_are_not_published() {
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    let current = harness
        .connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .cloned()
        .expect("the Connection is stored");
    let mut disabled = current.write.clone();
    disabled.enabled = false;
    harness
        .connection
        .control_plane
        .replace_managed(
            &current.id,
            &current.etag(),
            disabled,
            &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
        )
        .await
        .expect("the Connection disables");
    let saved = harness.secrets.resolutions();

    // The JWKS carries enabled Connections' keys only, so the issuer could not verify the
    // tester's subject token: the test says so instead of asking the issuer.
    let result = test_connection_as(&harness, Some(&bearer("alice", &["mail:read"]))).await;
    assert!(!result.ok);
    assert_eq!(
        result.stages,
        [ConnectionTestStage::failure(
            ConnectionTestStageName::Authenticated,
            ConnectionTestReason::CallerAssertionKeyNotPublished,
        )]
    );
    assert_eq!(harness.secrets.resolutions(), saved);
    assert_eq!(harness.deployment.exchange_count(), 0);
    assert_eq!(harness.deployment.upstream_count(), 0);
}

/// A managed OpenAPI tool as a catalog registers it once its user-consent
/// scheme binds to the delegated Connection (#443).
fn list_messages_openapi_definition(connection_id: &str) -> ToolDefinition {
    let mapping: crate::tools::definitions::HttpToolMapping = serde_json::from_value(json!({
        "method": "GET",
        "path_template": "/messages"
    }))
    .expect("the OpenAPI tool mapping deserializes");
    ToolDefinition {
        name: "list_messages".to_owned(),
        title: None,
        description: "Lists the caller's own messages through a delegated Connection.".to_owned(),
        input_schema: json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        target: Some(ToolTarget::Http {
            connection_id: connection_id.to_owned(),
            mapping: mapping.clone(),
        }),
        source: ToolSource::OpenApi {
            connection_id: connection_id.to_owned(),
            operation_id: Some("listMessages".to_owned()),
            catalog_revision: Some(1),
        },
        upstream: mapping,
        composite: None,
        visibility: crate::tools::definitions::ToolVisibility::Listed,
        transform: None,
        enum_bindings: Vec::new(),
        annotations: None,
    }
}

#[tokio::test]
async fn a_managed_openapi_tool_reaches_the_upstream_as_each_caller_with_their_own_token() {
    let harness = harness(Issuer::Grant { expires_in: 3_600 }).await;
    // The registry validates a catalog's binding with the lane's own
    // constructor on every change, so the catalog stays installed.
    assert!(harness
        .connection
        .runtime
        .validate_openapi_tool_binding(&harness.connection.connection_id)
        .is_ok());
    let (executor, _) = executor_for_composite_definitions(
        vec![list_messages_openapi_definition(
            &harness.connection.connection_id,
        )],
        &harness.connection,
        ["list_messages"],
    );
    let alice = bearer("alice", &["mail:read"]);
    let bob = bearer("bob", &["mail:read"]);

    for (caller, request_id) in [
        (&alice, "openapi-alice-1"),
        (&bob, "openapi-bob-1"),
        (&alice, "openapi-alice-2"),
    ] {
        let result = executor
            .execute(
                "list_messages",
                json!({}),
                context_for(caller, request_id),
                CancellationToken::new(),
            )
            .await
            .expect("a delegated OpenAPI tool call succeeds");
        let response = http_response(result);
        assert_eq!(response.status, StatusCode::OK);
        let mailbox: Value =
            serde_json::from_slice(&response.body).expect("the upstream answers JSON");
        assert_eq!(mailbox, json!({ "mailbox": caller.user_id }));
    }

    // The same exchange and cache as a manual tool: one exchange per caller,
    // and each upstream request carries that caller's own token and no
    // assertion, which went to the issuer only.
    assert_eq!(harness.deployment.exchange_count(), 2);
    assert_eq!(harness.deployment.upstream_count(), 3);
    harness.deployment.with_requests(|requests| {
        for request in requests
            .iter()
            .filter(|request| request.target != EXCHANGE_PATH)
        {
            assert_eq!(request.target, "/v1/messages");
            assert!(request
                .header("authorization")
                .is_some_and(|value| value.starts_with("Bearer delegated-")));
            assert_eq!(request.header_count("x-caller-assertion"), 0);
        }
    });
    harness
        .wait_for(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE, 2)
        .await;
    for (exchange, caller) in harness
        .events_of(audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE)
        .iter()
        .zip([&alice, &bob])
    {
        assert_eq!(exchange.payload["outcome"], json!("success"));
        assert_eq!(
            exchange.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some(caller.user_id.as_str())
        );
    }

    // A call that names nobody has no token to obtain and no shared identity
    // to fall back to: refused before anything is read, asked or sent.
    let saved = harness.secrets.resolutions();
    let anonymous = ToolInvocationContext {
        caller: None,
        ..context_for(&alice, "openapi-anonymous")
    };
    let refused = executor
        .execute(
            "list_messages",
            json!({}),
            anonymous,
            CancellationToken::new(),
        )
        .await
        .expect_err("nobody to exchange a token for");
    assert_eq!(
        work_failure_reason(refused).as_deref(),
        Some("delegated_token_no_principal")
    );
    assert_eq!(harness.secrets.resolutions(), saved);
    assert_eq!(harness.deployment.exchange_count(), 2);
    assert_eq!(harness.deployment.upstream_count(), 3);
}
