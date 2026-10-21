//! Delegated issuer tokens on the tool-call lane (#441): a Connection that calls its upstream as
//! the calling user, with that user's own token from an RFC 8693 issuer.
//!
//! One in-process TLS server plays both parts. On the token-exchange path it is the issuer: it
//! hands each caller named by the subject token a token of their own, or refuses, or fails. On
//! every other path it is the upstream, and answers with the mailbox of whoever the bearer token
//! belongs to. No real identity provider is involved, and every key is generated per test.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
    Algorithm, DecodingKey, Validation,
};
use tokio_util::sync::CancellationToken as StopSignal;

use super::*;
use crate::connections::{model::SubjectTokenSource, token_exchange::ManualTokenClock};

const EXCHANGE_PATH: &str = "/oauth2/token-exchange";
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

/// The stub issuer and upstream behind one TLS listener.
struct StubDeployment {
    addr: SocketAddr,
    ca_pem: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    issuer: Arc<Mutex<Issuer>>,
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
        let issued = Arc::new(AtomicUsize::new(0));
        let reject_next_upstream = Arc::new(AtomicBool::new(false));
        let stop = StopSignal::new();
        let (server_requests, server_issuer, server_reject, server_stop) = (
            Arc::clone(&requests),
            Arc::clone(&issuer),
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
            reject_next_upstream,
            stop,
        }
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
                .filter(|request| request.target != EXCHANGE_PATH)
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
            subject_token_source: SubjectTokenSource::CallerAssertion,
        },
        caller_assertion: Some(subject_token_settings()),
        additional_headers: Vec::new(),
        tls: TlsProfile::default(),
        timeouts: None,
        discovery: None,
        test_profile: None,
    };
    control_plane
        .ensure_deferred_bindings_resolvable(&write)
        .await
        .expect("the client secret resolves and the signing key loads");
    let initial = control_plane.runtime_snapshot();
    let created = control_plane
        .create_managed(initial.collection_etag(), write, "test-admin")
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
    let deployment = StubDeployment::start(issuer).await;
    let signing_key = generated_es256_pem();
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let (connection, secrets) =
        delegated_connection(&deployment, &signing_key, &audit, exchange_host, customize).await;
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
        .replace_managed(&current.id, &current.etag(), changed, "test-admin")
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
