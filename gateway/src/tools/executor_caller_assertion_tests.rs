//! Signed caller assertions on the tool-call lane (#463): what a Connection
//! that attests its caller signs, sends, refuses and records.
//!
//! Every key is generated per test. Each test verifies what the upstream
//! received the way an upstream would: against the gateway's published JWKS
//! alone.

use jsonwebtoken::{
    decode, decode_header,
    jwk::{JwkSet, KeyAlgorithm},
    Algorithm, DecodingKey, Validation,
};

use super::*;
use crate::{
    auth::{actor_from_principal, AuthMethod, Principal},
    connections::{
        caller_assertion::{body_digest, AttestedCaller, CallerAssertionKeyProblem},
        model::{CallerAssertionClaim, CallerAssertionPublishedKey},
        test_support::{generated_es256_pem, generated_rs256_pem, pem_body_lines},
    },
};

const API_KEY: &str = "attested-api-key-canary";
const ASSERTION_HEADER: &str = "x-caller-assertion";
const PROVIDER: &str = "https://idp.example.test";

fn principal(subject: &str, email: &str, roles: &[&str], auth_method: AuthMethod) -> Principal {
    Principal {
        user_id: subject.to_owned(),
        issuer: Some(format!("{PROVIDER}/")),
        email: Some(email.to_owned()),
        org_id: None,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: format!("session-{subject}"),
        auth_method,
    }
}

fn bearer(subject: &str, roles: &[&str]) -> Principal {
    principal(
        subject,
        &format!("{subject}@example.test"),
        roles,
        AuthMethod::Bearer,
    )
}

/// The context the MCP endpoint builds for an authenticated request: the
/// audit actor and, separately, the caller an assertion would name.
fn context_for(principal: &Principal, request_id: &str) -> ToolInvocationContext {
    ToolInvocationContext {
        request_id: request_id.to_owned(),
        source_ip: "203.0.113.10".to_owned(),
        actor: Some(actor_from_principal(principal)),
        caller: AttestedCaller::from_principal(principal).map(Arc::new),
        source: ToolInvocationSource::Mcp,
        admitted_deadline: None,
    }
}

/// What an upstream does with the header it received: select the key by
/// `kid` from the published set, take the algorithm from that key rather than
/// from the token, and check the signature, `typ`, `iss`, `aud` and `exp`.
fn verify_with_published_set(token: &str, jwks: &str) -> Value {
    let header = decode_header(token).expect("the assertion header decodes");
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    let set: JwkSet = serde_json::from_str(jwks).expect("the JWKS is a standard JWK Set");
    let kid = header.kid.expect("the assertion names its key");
    let jwk = set.find(&kid).expect("the signing key is published");
    let algorithm = match jwk.common.key_algorithm {
        Some(KeyAlgorithm::ES256) => Algorithm::ES256,
        Some(KeyAlgorithm::RS256) => Algorithm::RS256,
        other => panic!("unexpected published algorithm {other:?}"),
    };
    let key = DecodingKey::from_jwk(jwk).expect("the published key loads");
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&["https://gateway.example.test"]);
    validation.set_audience(&["https://billing.example.test"]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    decode::<Value>(token, &key, &validation)
        .expect("the assertion verifies against the published set")
        .claims
}

/// The hex SHA-256 an upstream computes over the body it received.
fn upstream_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

fn create_charge_tool(connection_id: &str) -> Value {
    let mapping = json!({
        "method": "POST",
        "path_template": "/customers/{customer}/charges",
        "query_params": [
            { "arg_name": "idempotency", "query_name": "idempotency", "required": true }
        ],
        "body": { "mode": "body_args_json" }
    });
    json!({
        "name": "create_charge",
        "description": "Creates a charge through an attested Connection.",
        "input_json_schema": {
            "type": "object",
            "required": ["customer", "idempotency", "amount"],
            "properties": {
                "customer": { "type": "string" },
                "idempotency": { "type": "string" },
                "amount": { "type": "integer" },
                "memo": { "type": "string" }
            },
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

fn audited_executor(
    tool: Value,
    tool_name: &str,
    connection: &TemporaryStaticAuthRuntime,
) -> (ToolExecutor, CaptureSink) {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([(tool_name, enabled_tool(5_000, 2))], 4, 2, 1_000),
        audit.clone(),
    );
    (
        executor_for_connection_tool(tool, connection, runtime, audit),
        capture,
    )
}

/// Everything a log line, error or audit event must never contain: the API
/// key, every line of the private key, and each assertion that was sent.
fn assert_absent(rendered: &str, canaries: &[&str], what: &str) {
    for canary in canaries {
        assert!(!rendered.contains(canary), "{what} leaked {canary:?}");
    }
}

#[derive(Clone, Default)]
struct CapturedLogs {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl CapturedLogs {
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

async fn two_principals_are_each_attested_as_themselves(
    algorithm: CallerAssertionAlgorithm,
    signing_key: String,
) {
    let (logs, _logs_guard) = capture_all_logs();
    let (addr, ca_pem, server) = scripted_tls_server(vec![
        (StatusCode::OK, json!({ "id": "ch_1" })),
        (StatusCode::OK, json!({ "id": "ch_1" })),
    ])
    .await;
    let mut settings = TemporaryStaticAuthRuntime::caller_assertion_settings();
    settings.algorithm = algorithm;
    settings.claims = vec![CallerAssertionClaim::Email, CallerAssertionClaim::Roles];
    let (connection, secrets) = TemporaryStaticAuthRuntime::attested(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
        settings,
        &[],
    )
    .await;
    let saved = secrets.resolutions();
    let (executor, capture) = audited_executor(
        connection_charge_tool(&connection.connection_id),
        "get_charge",
        &connection,
    );

    let alice = bearer("alice", &["billing:read"]);
    let bob = bearer("bob", &["billing:read", "billing:refund"]);
    for (caller, request_id) in [(&alice, "request-alice"), (&bob, "request-bob")] {
        let response = http_response(
            executor
                .execute(
                    "get_charge",
                    json!({ "charge_id": "ch_1" }),
                    context_for(caller, request_id),
                    CancellationToken::new(),
                )
                .await
                .expect("an attested call should succeed"),
        );
        assert_eq!(response.status, StatusCode::OK);
    }
    // Each call reads the API key and the signing key once, and nothing else.
    assert_eq!(secrets.resolutions(), saved + 4);

    let requests = server.await.expect("the TLS server task should join");
    assert_eq!(requests.len(), 2);
    let jwks = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("the signing key is published");
    let mut tokens = Vec::new();
    let mut claims = Vec::new();
    for request in &requests {
        // The assertion rides beside the credential, not instead of it, and
        // arrives exactly once.
        assert_eq!(request.header("x-api-key"), Some(API_KEY));
        assert_eq!(request.header_count(ASSERTION_HEADER), 1);
        let token = request
            .header(ASSERTION_HEADER)
            .expect("the upstream receives the assertion")
            .to_owned();
        claims.push(verify_with_published_set(&token, jwks.body()));
        tokens.push(token);
    }

    for (claims, (caller, request_id)) in claims
        .iter()
        .zip([(&alice, "request-alice"), (&bob, "request-bob")])
    {
        // The provider's issuer is canonical: the trailing slash the
        // principal carried is gone.
        assert_eq!(
            claims["sub"],
            json!(format!("{PROVIDER}#{}", caller.user_id))
        );
        assert_eq!(claims["caller_iss"], json!(PROVIDER));
        assert_eq!(claims["caller_sub"], json!(caller.user_id));
        assert_eq!(claims["email"], json!(caller.email));
        assert_eq!(claims["roles"], json!(caller.roles));
        assert_eq!(claims["jti"], json!(request_id));
        let issued_at = claims["iat"].as_u64().expect("iat is a number");
        assert_eq!(claims["exp"].as_u64(), Some(issued_at + 60));
        // Not bound to the request unless the Connection asks for it.
        assert!(claims.get("request_sha256").is_none());
        assert!(claims.get("method").is_none());
    }
    assert_ne!(claims[0]["sub"], claims[1]["sub"]);
    // The service credential is the same for both; only the assertion says
    // on whose behalf each call was made.
    assert_eq!(
        requests[0].header("x-api-key"),
        requests[1].header("x-api-key")
    );

    wait_until(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .count()
            == 2
    })
    .await;
    let events = capture.events();
    for (caller, request_id) in [(&alice, "request-alice"), (&bob, "request-bob")] {
        let upstream = events
            .iter()
            .find(|event| {
                event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                    && event.request_id == request_id
            })
            .expect("each call is audited");
        assert_eq!(upstream.payload["outcome"], json!("success"));
        assert_eq!(
            upstream.payload["caller_assertion"],
            json!({ "kid": "gw-test-1", "jti": request_id })
        );
        let actor = upstream.actor.as_ref().expect("the actor is recorded");
        assert_eq!(actor.user_id, caller.user_id);
    }

    let mut canaries = vec![API_KEY];
    canaries.extend(pem_body_lines(&signing_key));
    canaries.extend(tokens.iter().map(String::as_str));
    // A token's signature is enough to replay it; check it on its own too.
    let signatures = tokens
        .iter()
        .filter_map(|token| token.rsplit('.').next())
        .collect::<Vec<_>>();
    canaries.extend(signatures);
    let rendered = serde_json::to_string(&events).expect("events serialize");
    assert_absent(&rendered, &canaries, "the audit");
    assert_absent(&logs.contents(), &canaries, "the logs");
}

#[tokio::test]
async fn two_principals_get_different_es256_subjects_that_verify_against_the_jwks() {
    two_principals_are_each_attested_as_themselves(
        CallerAssertionAlgorithm::Es256,
        generated_es256_pem(),
    )
    .await;
}

#[tokio::test]
async fn two_principals_get_different_rs256_subjects_that_verify_against_the_jwks() {
    two_principals_are_each_attested_as_themselves(
        CallerAssertionAlgorithm::Rs256,
        generated_rs256_pem(),
    )
    .await;
}

#[tokio::test]
async fn a_bound_assertion_covers_the_method_target_and_exact_body_sent() {
    let (addr, ca_pem, server) =
        scripted_tls_server(vec![(StatusCode::OK, json!({ "id": "ch_2" }))]).await;
    let signing_key = generated_es256_pem();
    let mut settings = TemporaryStaticAuthRuntime::caller_assertion_settings();
    settings.bind_request = true;
    let (connection, _secrets) = TemporaryStaticAuthRuntime::attested(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
        settings,
        &[],
    )
    .await;
    let (executor, _capture) = audited_executor(
        create_charge_tool(&connection.connection_id),
        "create_charge",
        &connection,
    );

    executor
        .execute(
            "create_charge",
            json!({
                "customer": "cus_9",
                "idempotency": "key 1",
                "amount": 1250,
                "memo": "caf\u{e9} \u{1f600}"
            }),
            context_for(&bearer("alice", &[]), "request-bound"),
            CancellationToken::new(),
        )
        .await
        .expect("a bound call should succeed");

    let requests = server.await.expect("the TLS server task should join");
    let request = &requests[0];
    let jwks = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("the signing key is published");
    let claims = verify_with_published_set(
        request
            .header(ASSERTION_HEADER)
            .expect("the upstream receives the assertion"),
        jwks.body(),
    );

    // The upstream compares with the request line and the bytes it received,
    // never with a reconstruction of them.
    assert_eq!(claims["method"], json!(request.method));
    assert_eq!(claims["path"], json!(request.target));
    assert_eq!(
        request.target, "/v1/customers/cus_9/charges?idempotency=key+1",
        "the bound target is the base path, path and query as sent"
    );
    // The digest is over the exact bytes the upstream received, so a body an
    // intermediary changed after signing, down to one byte or a key order
    // that parses to the same JSON, no longer matches it.
    assert!(!request.body.is_empty());
    assert_eq!(
        claims["request_sha256"],
        json!(upstream_digest(&request.body))
    );
    // The gateway's hex encoding is the one an upstream's SHA-256 produces.
    assert_eq!(body_digest(&request.body), upstream_digest(&request.body));
}

#[tokio::test]
async fn a_service_token_is_not_a_principal_an_assertion_can_name() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let signing_key = generated_es256_pem();
    let (connection, secrets) = TemporaryStaticAuthRuntime::header_api_key_with_caller_assertion(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
    )
    .await;
    let saved = secrets.resolutions();
    let (executor, capture) = audited_executor(
        connection_charge_tool(&connection.connection_id),
        "get_charge",
        &connection,
    );
    let service = Principal {
        user_id: "service-token:svc_1".to_owned(),
        issuer: None,
        email: None,
        org_id: None,
        roles: vec!["billing:read".to_owned()],
        session_id: "svc_1".to_owned(),
        auth_method: AuthMethod::ServiceToken,
    };
    // A service token carrying an issuer is still not a provider-vouched
    // identity.
    let mut with_issuer = service.clone();
    with_issuer.issuer = Some(PROVIDER.to_owned());
    for (index, token) in [service, with_issuer].iter().enumerate() {
        let context = context_for(token, &format!("request-service-{index}"));
        assert!(context.caller.is_none());
        assert!(context.actor.is_some(), "the caller is still audited");
        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_svc" }),
                context,
                CancellationToken::new(),
            )
            .await
            .expect_err("a service token must not be attested");
        let ToolRuntimeError::WorkFailed { reason, .. } = error else {
            panic!("the refusal should surface as a work failure");
        };
        assert_eq!(reason.as_deref(), Some("caller_assertion_no_principal"));
    }
    wait_until(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_INVOKE_FAILURE)
            .count()
            == 2
    })
    .await;
    let events = capture.events();
    for failure in events
        .iter()
        .filter(|event| event.event_type == audit::event::TOOL_INVOKE_FAILURE)
    {
        assert_eq!(
            failure.payload["failure_reason"],
            json!("caller_assertion_no_principal")
        );
        assert_eq!(
            failure.actor.as_ref().map(|actor| actor.auth_mode.as_str()),
            Some("service_token")
        );
    }
    assert_eq!(secrets.resolutions(), saved, "no secret is read");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "the upstream receives nothing"
    );
}

#[tokio::test]
async fn the_assertion_header_cannot_be_overridden_or_duplicated() {
    // An additional header rides on the same request; the assertion must
    // arrive once, with the gateway's value, whatever else is configured.
    let (addr, ca_pem, server) =
        scripted_tls_server(vec![(StatusCode::OK, json!({ "id": "ch_3" }))]).await;
    let signing_key = generated_es256_pem();
    let (connection, _secrets) = TemporaryStaticAuthRuntime::attested(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
        TemporaryStaticAuthRuntime::caller_assertion_settings(),
        &[("cf-access-client-id", "proxy-client-id", b"proxy-id-value")],
    )
    .await;
    let (executor, _capture) = audited_executor(
        connection_charge_tool(&connection.connection_id),
        "get_charge",
        &connection,
    );
    executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_3" }),
            context_for(&bearer("alice", &[]), "request-headers"),
            CancellationToken::new(),
        )
        .await
        .expect("the attested call should succeed");
    let requests = server.await.expect("the TLS server task should join");
    let request = &requests[0];
    assert_eq!(request.header_count(ASSERTION_HEADER), 1);
    assert_eq!(
        request.header("cf-access-client-id"),
        Some("proxy-id-value")
    );
    assert_eq!(request.header("x-api-key"), Some(API_KEY));
    let jwks = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("published");
    let claims = verify_with_published_set(
        request.header(ASSERTION_HEADER).expect("assertion sent"),
        jwks.body(),
    );
    assert_eq!(claims["caller_sub"], json!("alice"));

    // A stored document from before the collision rule, whose additional
    // header shares the assertion's name, is readable but never served: the
    // upstream would keep one of the two values, and nothing says which.
    let current = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .cloned()
        .expect("the Connection is stored");
    let mut colliding = current.clone();
    colliding.write.additional_headers[0].header_name = "X-Caller-Assertion".to_owned();
    connection
        .control_plane
        .publish_authoritative_records(vec![colliding])
        .await
        .expect("a legacy document still loads");
    assert_eq!(
        connection
            .runtime
            .validate_tool_binding(&connection.connection_id),
        Err(ConnectionHttpError::CallerAssertionNotEnforced)
    );
    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_3" }),
            context_for(&bearer("alice", &[]), "request-collision"),
            CancellationToken::new(),
        )
        .await
        .expect_err("a colliding assertion header must not be served");
    let ToolRuntimeError::WorkFailed { reason, .. } = error else {
        panic!("the refusal should surface as a work failure");
    };
    assert_eq!(reason.as_deref(), Some("caller_assertion_not_enforced"));
}

#[tokio::test]
async fn an_attested_connection_is_never_served_over_plain_http() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let signing_key = generated_es256_pem();
    let (connection, secrets) = TemporaryStaticAuthRuntime::header_api_key_with_caller_assertion(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
    )
    .await;
    let current = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .cloned()
        .expect("the Connection is stored");

    // A new or replacement write cannot ask for one over HTTP.
    let mut plain = current.write.clone();
    plain.endpoint.base_url = format!("http://127.0.0.1:{}", addr.port());
    let errors = plain
        .clone()
        .validated()
        .expect_err("an attested Connection must use HTTPS");
    assert!(errors
        .iter()
        .any(|error| error.field == "endpoint.base_url" && error.code == "https_required"));
    // Without the assertion, the same unauthenticated Connection would be
    // allowed over HTTP: it is the assertion that requires TLS.
    let mut bare = plain.clone();
    bare.caller_assertion = None;
    bare.authentication = ConnectionAuthentication::None;
    bare.validated()
        .expect("an unauthenticated, unattested Connection may use HTTP");

    // A document stored before the rule still loads, and is refused before
    // any secret is read or any byte is sent.
    let mut stored = current.clone();
    stored.write.endpoint.base_url = plain.endpoint.base_url.clone();
    connection
        .control_plane
        .publish_authoritative_records(vec![stored])
        .await
        .expect("a legacy document still loads");
    let saved = secrets.resolutions();
    let (executor, _capture) = audited_executor(
        connection_charge_tool(&connection.connection_id),
        "get_charge",
        &connection,
    );
    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_plain" }),
            context_for(&bearer("alice", &[]), "request-plain"),
            CancellationToken::new(),
        )
        .await
        .expect_err("an attested Connection must not be called over HTTP");
    let ToolRuntimeError::WorkFailed { reason, .. } = error else {
        panic!("the refusal should surface as a work failure");
    };
    assert_eq!(reason.as_deref(), Some("caller_assertion_not_enforced"));
    assert_eq!(secrets.resolutions(), saved);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "the upstream receives nothing"
    );
}

#[tokio::test]
async fn a_signing_key_that_no_longer_loads_refuses_the_call_with_its_own_reason() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let signing_key = generated_es256_pem();
    let (connection, secrets) = TemporaryStaticAuthRuntime::attested(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
        TemporaryStaticAuthRuntime::caller_assertion_settings(),
        &[],
    )
    .await;
    // The alias now holds an RSA key while the Connection says ES256: the
    // material behind an unpinned alias changed after the save.
    let replacement = generated_rs256_pem();
    secrets.replace("assertion-signing-key", replacement.clone().into_bytes());
    let (executor, capture) = audited_executor(
        connection_charge_tool(&connection.connection_id),
        "get_charge",
        &connection,
    );
    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_key" }),
            context_for(&bearer("alice", &[]), "request-key"),
            CancellationToken::new(),
        )
        .await
        .expect_err("a key that does not load must not sign");
    let ToolRuntimeError::WorkFailed {
        reason, message, ..
    } = error
    else {
        panic!("the refusal should surface as a work failure");
    };
    assert_eq!(reason.as_deref(), Some("caller_assertion_key_unusable"));
    wait_until(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::CONNECTION_SECRET_RESOLUTION_FAILED)
    })
    .await;
    let events = capture.events();
    let resolution = events
        .iter()
        .find(|event| event.event_type == audit::event::CONNECTION_SECRET_RESOLUTION_FAILED)
        .expect("the key failure is reported like any secret failure");
    assert_eq!(
        resolution.payload["reason"],
        json!("caller_assertion_key_unusable")
    );
    let mut canaries = vec![API_KEY];
    canaries.extend(pem_body_lines(&signing_key));
    canaries.extend(pem_body_lines(&replacement));
    assert_absent(&message, &canaries, "the caller error");
    assert_absent(
        &serde_json::to_string(&events).expect("events serialize"),
        &canaries,
        "the audit",
    );
    // The key is signed with only after the egress preflight and the
    // credential, but nothing reaches the upstream.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "the upstream receives nothing"
    );
}

/// A Connection whose keys this replica leaves out of the JWKS: its signing
/// key loads, but a key it also publishes no longer does.
async fn withheld_connection() -> (
    TemporaryStaticAuthRuntime,
    Arc<CountingSecretProvider>,
    tokio::task::JoinHandle<Vec<CapturedRequest>>,
) {
    let (addr, ca_pem, server) =
        scripted_tls_server(vec![(StatusCode::OK, json!({ "id": "ch_4" }))]).await;
    let signing_key = generated_es256_pem();
    let next_key = generated_es256_pem();
    let mut settings = TemporaryStaticAuthRuntime::caller_assertion_settings();
    settings.published_keys = vec![CallerAssertionPublishedKey {
        signing_key_id: "assertion-next-key".to_owned(),
        kid: "gw-test-2".to_owned(),
        algorithm: CallerAssertionAlgorithm::Es256,
    }];
    let (connection, secrets) = TemporaryStaticAuthRuntime::attested_with_keys(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        &[
            ("assertion-signing-key", signing_key.as_bytes()),
            ("assertion-next-key", next_key.as_bytes()),
        ],
        settings,
        &[],
    )
    .await;
    let complete = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("both keys are published");
    assert_eq!(complete.key_count(), 2);

    // The published key's alias now holds something that is not a key. The
    // next build leaves every key of the Connection out, the signing key
    // included, and says why.
    secrets.replace("assertion-next-key", b"not a key".to_vec());
    connection.control_plane.expire_caller_assertion_jwks();
    let withheld = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("a set that leaves a Connection out is still a set");
    assert_eq!(withheld.key_count(), 0);
    let stored = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .cloned()
        .expect("the Connection is stored");
    assert_eq!(
        connection
            .control_plane
            .caller_assertion_key_problem(&stored),
        Some(CallerAssertionKeyProblem {
            field: "caller_assertion.published_keys.signing_key_id",
            code: "invalid_signing_key",
        })
    );
    (connection, secrets, server)
}

#[tokio::test]
async fn a_connection_left_out_of_the_jwks_is_refused_before_any_io() {
    // Its signing key still loads, so signing would succeed, but no upstream
    // that fetched the current set could verify what it signed.
    let (connection, secrets, server) = withheld_connection().await;
    let (executor, capture) = audited_executor(
        connection_charge_tool(&connection.connection_id),
        "get_charge",
        &connection,
    );
    let before = secrets.resolutions();
    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_4" }),
            context_for(&bearer("alice", &[]), "request-withheld"),
            CancellationToken::new(),
        )
        .await
        .expect_err("a Connection whose keys are not published must not sign");
    let ToolRuntimeError::WorkFailed { reason, .. } = error else {
        panic!("the refusal should surface as a work failure");
    };
    assert_eq!(
        reason.as_deref(),
        Some("caller_assertion_key_not_published")
    );
    // Neither the API key nor the signing key is read, and the set built
    // moments ago is not rebuilt for the call.
    assert_eq!(secrets.resolutions(), before, "no secret is read");

    wait_until(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::TOOL_INVOKE_FAILURE)
    })
    .await;
    let events = capture.events();
    let failure = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_INVOKE_FAILURE)
        .expect("the refusal is audited");
    assert_eq!(
        failure.payload["failure_reason"],
        json!("caller_assertion_key_not_published")
    );
    let upstream = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
        .expect("the refused request is audited");
    assert_eq!(
        upstream.payload["reason"],
        json!("caller_assertion_key_not_published")
    );
    assert!(
        upstream.payload.get("caller_assertion").is_none(),
        "nothing was signed"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "the upstream receives nothing"
    );
}

#[tokio::test]
async fn a_withheld_connection_serves_again_once_its_keys_load_without_a_fetch() {
    let (connection, secrets, server) = withheld_connection().await;
    let (executor, _capture) = audited_executor(
        connection_charge_tool(&connection.connection_id),
        "get_charge",
        &connection,
    );
    secrets.replace("assertion-next-key", generated_es256_pem().into_bytes());
    // Once the retry interval has passed, the call itself reads the keys
    // again rather than wait for a verifier to fetch the set: a verifier
    // that sees no calls may never fetch it.
    connection.control_plane.expire_caller_assertion_jwks();
    let before = secrets.resolutions();
    let response = http_response(
        executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_4" }),
                context_for(&bearer("alice", &[]), "request-restored"),
                CancellationToken::new(),
            )
            .await
            .expect("a Connection whose keys load again serves calls"),
    );
    assert_eq!(response.status, StatusCode::OK);
    // The rebuild reads both keys once; the call reads the signing key and
    // the API key.
    assert_eq!(secrets.resolutions(), before + 4);
    let requests = server.await.expect("the TLS server task should join");
    let published = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("the keys are published again");
    assert_eq!(published.key_count(), 2);
    let claims = verify_with_published_set(
        requests[0]
            .header(ASSERTION_HEADER)
            .expect("the upstream receives the assertion"),
        published.body(),
    );
    assert_eq!(claims["caller_sub"], json!("alice"));
}

#[tokio::test]
async fn a_verifier_holding_both_published_keys_accepts_either_signing_key() {
    // #463's rotation contract: once both keys are published, the signing
    // key can move from one to the other without any verifier that fetched
    // the set rejecting a call.
    let (addr, ca_pem, server) = scripted_tls_server(vec![
        (StatusCode::OK, json!({ "id": "ch_5" })),
        (StatusCode::OK, json!({ "id": "ch_5" })),
    ])
    .await;
    let current_key = generated_es256_pem();
    let next_key = generated_rs256_pem();
    let mut settings = TemporaryStaticAuthRuntime::caller_assertion_settings();
    settings.published_keys = vec![CallerAssertionPublishedKey {
        signing_key_id: "assertion-next-key".to_owned(),
        kid: "gw-test-2".to_owned(),
        algorithm: CallerAssertionAlgorithm::Rs256,
    }];
    let (connection, _secrets) = TemporaryStaticAuthRuntime::attested_with_keys(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        &[
            ("assertion-signing-key", current_key.as_bytes()),
            ("assertion-next-key", next_key.as_bytes()),
        ],
        settings,
        &[],
    )
    .await;
    let (executor, _capture) = audited_executor(
        connection_charge_tool(&connection.connection_id),
        "get_charge",
        &connection,
    );
    // Step 1 of the rotation: the verifier fetches a set with both keys.
    let held = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("both keys are published");
    assert_eq!(held.key_count(), 2);
    executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_5" }),
            context_for(&bearer("alice", &[]), "request-before-rotation"),
            CancellationToken::new(),
        )
        .await
        .expect("the current key signs");

    // Step 3: in one save, the next key signs and the previous one is only
    // published.
    let stored = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .cloned()
        .expect("the Connection is stored");
    let mut rotated = stored.write.clone();
    let assertion = rotated
        .caller_assertion
        .as_mut()
        .expect("the Connection attests its caller");
    assertion.signing_key_id = "assertion-next-key".to_owned();
    assertion.kid = "gw-test-2".to_owned();
    assertion.algorithm = CallerAssertionAlgorithm::Rs256;
    assertion.published_keys = vec![CallerAssertionPublishedKey {
        signing_key_id: "assertion-signing-key".to_owned(),
        kid: "gw-test-1".to_owned(),
        algorithm: CallerAssertionAlgorithm::Es256,
    }];
    connection
        .control_plane
        .ensure_deferred_bindings_resolvable(&rotated)
        .await
        .expect("both keys still load");
    connection
        .control_plane
        .replace_managed(
            &stored.id,
            &stored.etag(),
            rotated,
            &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
        )
        .await
        .expect("the rotation saves");
    executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_5" }),
            context_for(&bearer("alice", &[]), "request-after-rotation"),
            CancellationToken::new(),
        )
        .await
        .expect("the next key signs");

    let requests = server.await.expect("the TLS server task should join");
    let mut kids = Vec::new();
    for request in &requests {
        let token = request
            .header(ASSERTION_HEADER)
            .expect("the upstream receives the assertion");
        kids.push(
            decode_header(token)
                .expect("the assertion header decodes")
                .kid
                .expect("the assertion names its key"),
        );
        // Both verify against the set fetched before the rotation.
        let claims = verify_with_published_set(token, held.body());
        assert_eq!(claims["caller_sub"], json!("alice"));
    }
    assert_eq!(kids, vec!["gw-test-1", "gw-test-2"]);
    // And the set after it still publishes both.
    assert_eq!(
        connection
            .control_plane
            .caller_assertion_jwks()
            .await
            .expect("both keys are still published")
            .key_count(),
        2
    );
}

/// A managed OpenAPI tool on `connection_id` that sends its arguments as a
/// JSON body, as a catalog registered from an operator's specification
/// generates it.
fn openapi_pay_invoice(connection_id: &str) -> ToolDefinition {
    let mapping: crate::tools::definitions::HttpToolMapping = serde_json::from_value(json!({
        "method": "POST",
        "path_template": "/invoices/{invoice_id}/payments",
        "body": { "mode": "body_args_json" }
    }))
    .expect("the OpenAPI tool mapping deserializes");
    ToolDefinition {
        name: "pay_invoice".to_owned(),
        title: None,
        description: "Pays an invoice through an attested Connection.".to_owned(),
        input_schema: json!({
            "type": "object",
            "required": ["invoice_id", "amount"],
            "properties": {
                "invoice_id": { "type": "string" },
                "amount": { "type": "integer" }
            },
            "additionalProperties": false
        }),
        target: Some(ToolTarget::Http {
            connection_id: connection_id.to_owned(),
            mapping: mapping.clone(),
        }),
        source: ToolSource::OpenApi {
            connection_id: connection_id.to_owned(),
            operation_id: Some("pay_invoice".to_owned()),
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
async fn an_openapi_tool_call_is_attested_and_bound_like_a_manual_one() {
    let (addr, ca_pem, server) =
        scripted_tls_server(vec![(StatusCode::OK, json!({ "paid": true }))]).await;
    let signing_key = generated_es256_pem();
    let mut settings = TemporaryStaticAuthRuntime::caller_assertion_settings();
    settings.bind_request = true;
    settings.claims = vec![CallerAssertionClaim::Email];
    let (connection, secrets) = TemporaryStaticAuthRuntime::attested(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
        settings,
        &[],
    )
    .await;
    // The catalog's binding is accepted on an attesting Connection, as the
    // registry validates it on every change.
    assert!(connection
        .runtime
        .validate_openapi_tool_binding(&connection.connection_id)
        .is_ok());
    let (executor, capture) = executor_for_composite_definitions(
        vec![openapi_pay_invoice(&connection.connection_id)],
        &connection,
        ["pay_invoice"],
    );
    let saved = secrets.resolutions();

    // A call that names nobody is refused before any secret is read or any
    // byte is sent; the scripted upstream answers exactly one request.
    let anonymous = ToolInvocationContext {
        caller: None,
        ..context_for(&bearer("alice", &[]), "request-openapi-anonymous")
    };
    let error = executor
        .execute(
            "pay_invoice",
            json!({ "invoice_id": "inv_1", "amount": 1250 }),
            anonymous,
            CancellationToken::new(),
        )
        .await
        .expect_err("a call naming nobody is refused");
    let ToolRuntimeError::WorkFailed { reason, .. } = error else {
        panic!("the refusal should surface as a work failure");
    };
    assert_eq!(reason.as_deref(), Some("caller_assertion_no_principal"));
    assert_eq!(secrets.resolutions(), saved, "no secret is read");

    executor
        .execute(
            "pay_invoice",
            json!({ "invoice_id": "inv_1", "amount": 1250 }),
            context_for(&bearer("alice", &[]), "request-openapi"),
            CancellationToken::new(),
        )
        .await
        .expect("an attested OpenAPI tool call should succeed");
    let requests = server.await.expect("the TLS server task should join");
    assert_eq!(
        requests.len(),
        1,
        "only the attested call reached the upstream"
    );
    let request = &requests[0];
    assert_eq!(request.header("x-api-key"), Some(API_KEY));
    assert_eq!(request.header_count(ASSERTION_HEADER), 1);
    let jwks = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("the signing key is published");
    let claims = verify_with_published_set(
        request
            .header(ASSERTION_HEADER)
            .expect("the upstream receives the assertion"),
        jwks.body(),
    );
    assert_eq!(claims["sub"], json!(format!("{PROVIDER}#alice")));
    assert_eq!(claims["email"], json!("alice@example.test"));
    assert_eq!(claims["jti"], json!("request-openapi"));
    assert_eq!(claims["method"], json!(request.method));
    assert_eq!(claims["path"], json!(request.target));
    assert_eq!(request.target, "/v1/invoices/inv_1/payments");
    assert!(!request.body.is_empty());
    assert_eq!(
        claims["request_sha256"],
        json!(upstream_digest(&request.body))
    );

    wait_until(Duration::from_secs(1), || {
        let events = capture.events();
        events.iter().any(|event| {
            event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                && event.request_id == "request-openapi"
        }) && events.iter().any(|event| {
            event.event_type == audit::event::TOOL_INVOKE_FAILURE
                && event.request_id == "request-openapi-anonymous"
        })
    })
    .await;
    let events = capture.events();
    let attested = events
        .iter()
        .find(|event| {
            event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                && event.request_id == "request-openapi"
        })
        .expect("the attested call is audited");
    assert_eq!(attested.payload["outcome"], json!("success"));
    assert_eq!(
        attested.payload["caller_assertion"],
        json!({ "kid": "gw-test-1", "jti": "request-openapi" })
    );
    assert_eq!(
        attested.actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("alice")
    );
    let refused = events
        .iter()
        .find(|event| {
            event.event_type == audit::event::TOOL_INVOKE_FAILURE
                && event.request_id == "request-openapi-anonymous"
        })
        .expect("the refused call is audited");
    assert_eq!(
        refused.payload["failure_reason"],
        json!("caller_assertion_no_principal")
    );
    let mut canaries = vec![API_KEY];
    canaries.extend(pem_body_lines(&signing_key));
    let token = request
        .header(ASSERTION_HEADER)
        .expect("the upstream receives the assertion");
    canaries.push(token);
    let rendered = serde_json::to_string(&events).expect("events serialize");
    assert_absent(&rendered, &canaries, "the audit");
}

/// The tools of the composite fixture: the composite, its two forward steps
/// and their compensations.
const COMPOSITE_TOOLS: [&str; 5] = [
    "create_note_for_records",
    "create_note",
    "attach_note",
    "delete_attachment",
    "delete_note",
];

fn composite_failure(error: ToolRuntimeError) -> (Option<String>, Value) {
    let ToolRuntimeError::WorkFailed {
        reason,
        details: Some(details),
        ..
    } = error
    else {
        panic!("a composite failure should carry its structured details");
    };
    (reason, details)
}

#[tokio::test]
async fn every_composite_leaf_signs_its_own_assertion_with_a_distinct_jti() {
    let (logs, _logs_guard) = capture_all_logs();
    // A note, then two attachments of which the second is rejected, then the
    // two compensations that undo the first attachment and the note.
    let (addr, ca_pem, server) = scripted_tls_server(vec![
        (StatusCode::CREATED, json!({ "id": "note-1" })),
        (StatusCode::CREATED, json!({ "id": "attachment-a" })),
        (StatusCode::BAD_REQUEST, json!({ "error": "rejected" })),
        (StatusCode::NO_CONTENT, Value::Null),
        (StatusCode::NO_CONTENT, Value::Null),
    ])
    .await;
    let signing_key = generated_es256_pem();
    let mut settings = TemporaryStaticAuthRuntime::caller_assertion_settings();
    settings.bind_request = true;
    let (connection, secrets) = TemporaryStaticAuthRuntime::attested(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
        settings,
        &[],
    )
    .await;
    let saved = secrets.resolutions();
    let (executor, capture) = executor_for_composite_definitions(
        composite_note_definitions(&connection.connection_id),
        &connection,
        COMPOSITE_TOOLS,
    );

    let error = executor
        .execute(
            "create_note_for_records",
            json!({ "title": "hello", "targets": ["a", "b"] }),
            context_for(&bearer("alice", &[]), "request-composite"),
            CancellationToken::new(),
        )
        .await
        .expect_err("the rejected attachment fails the composite");
    let (reason, details) = composite_failure(error);
    assert_eq!(reason.as_deref(), Some("composite_failed"));
    assert_eq!(details["failure_reason"], json!("upstream_status:400"));
    assert_eq!(details["compensation"], json!("complete"));
    // Each leaf reads the API key and the signing key once, as a tool call
    // does.
    assert_eq!(secrets.resolutions(), saved + 10);

    let requests = server.await.expect("the TLS server task should join");
    assert_eq!(
        requests
            .iter()
            .map(|request| (request.method.as_str(), request.target.as_str()))
            .collect::<Vec<_>>(),
        vec![
            ("POST", "/v1/notes"),
            ("POST", "/v1/attachments/a"),
            ("POST", "/v1/attachments/b"),
            ("DELETE", "/v1/attachments/a"),
            ("DELETE", "/v1/notes/note-1"),
        ]
    );
    let jwks = connection
        .control_plane
        .caller_assertion_jwks()
        .await
        .expect("the signing key is published");
    let mut tokens = Vec::new();
    let mut jtis = Vec::new();
    for request in &requests {
        // Every leaf carries the credential and exactly one assertion.
        assert_eq!(request.header("x-api-key"), Some(API_KEY));
        assert_eq!(request.header_count(ASSERTION_HEADER), 1);
        let token = request
            .header(ASSERTION_HEADER)
            .expect("every leaf carries an assertion")
            .to_owned();
        let claims = verify_with_published_set(&token, jwks.body());
        assert_eq!(claims["sub"], json!(format!("{PROVIDER}#alice")));
        // Each binds its own leaf: the method, target and exact body sent.
        assert_eq!(claims["method"], json!(request.method));
        assert_eq!(claims["path"], json!(request.target));
        assert_eq!(
            claims["request_sha256"],
            json!(upstream_digest(&request.body))
        );
        jtis.push(
            claims["jti"]
                .as_str()
                .expect("the jti is a string")
                .to_owned(),
        );
        tokens.push(token);
    }
    // Forward steps, fan-out iterations and compensations alike each have
    // their own `jti`, numbered in the order they were sent, so a replay
    // cache keyed on `sub` and `jti` accepts the whole call.
    assert_eq!(
        jtis,
        (1..=5)
            .map(|leaf| format!("request-composite.{leaf}"))
            .collect::<Vec<_>>()
    );

    wait_until(Duration::from_secs(1), || {
        let events = capture.events();
        events
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .count()
            == 5
            && events
                .iter()
                .any(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
    })
    .await;
    let events = capture.events();
    // Each leaf's event names the `jti` its upstream received, which is how
    // the upstream's log line is joined to the leaf that sent it.
    for (jti, tool_name) in jtis.iter().zip([
        "create_note",
        "attach_note",
        "attach_note",
        "delete_attachment",
        "delete_note",
    ]) {
        let upstream = events
            .iter()
            .find(|event| {
                event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                    && event.payload["caller_assertion"]["jti"] == json!(jti)
            })
            .expect("every leaf is audited with the jti it sent");
        assert_eq!(upstream.request_id, "request-composite");
        assert_eq!(upstream.payload["tool_name"], json!(tool_name));
        assert_eq!(
            upstream.payload["caller_assertion"],
            json!({ "kid": "gw-test-1", "jti": jti })
        );
        assert_eq!(
            upstream.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("alice")
        );
    }
    let completed = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
        .expect("the composite is audited");
    assert_eq!(completed.payload["outcome"], json!("failed"));
    assert_eq!(
        completed.payload["compensations"]
            .as_array()
            .map(|compensations| {
                compensations
                    .iter()
                    .map(|compensation| compensation["outcome"].clone())
                    .collect::<Vec<_>>()
            }),
        Some(vec![json!("succeeded"), json!("succeeded")])
    );

    let mut canaries = vec![API_KEY];
    canaries.extend(pem_body_lines(&signing_key));
    canaries.extend(tokens.iter().map(String::as_str));
    let signatures = tokens
        .iter()
        .filter_map(|token| token.rsplit('.').next())
        .collect::<Vec<_>>();
    canaries.extend(signatures);
    let rendered = serde_json::to_string(&events).expect("events serialize");
    assert_absent(&rendered, &canaries, "the audit");
    assert_absent(&logs.contents(), &canaries, "the logs");
    assert_absent(&details.to_string(), &canaries, "the caller error");
}

#[tokio::test]
async fn a_composite_call_naming_nobody_is_refused_before_any_leaf_io() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let (connection, secrets) = TemporaryStaticAuthRuntime::header_api_key_with_caller_assertion(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        generated_es256_pem().as_bytes(),
    )
    .await;
    let saved = secrets.resolutions();
    let (executor, capture) = executor_for_composite_definitions(
        composite_note_definitions(&connection.connection_id),
        &connection,
        COMPOSITE_TOOLS,
    );
    let service = Principal {
        user_id: "service-token:svc_1".to_owned(),
        issuer: None,
        email: None,
        org_id: None,
        roles: Vec::new(),
        session_id: "svc_1".to_owned(),
        auth_method: AuthMethod::ServiceToken,
    };
    let context = context_for(&service, "request-composite-service");
    assert!(context.caller.is_none());

    let error = executor
        .execute(
            "create_note_for_records",
            json!({ "title": "hello", "targets": ["a"] }),
            context,
            CancellationToken::new(),
        )
        .await
        .expect_err("a composite naming nobody must not be attested");
    // The composite fails as a whole, and its first leaf's reason survives
    // into what the caller is told.
    let (reason, details) = composite_failure(error);
    assert_eq!(reason.as_deref(), Some("composite_failed"));
    assert_eq!(details["failed_step"], json!("note"));
    assert_eq!(
        details["failure_reason"],
        json!("caller_assertion_no_principal")
    );
    assert_eq!(details["compensation"], json!("complete"));
    assert_eq!(details["orphans"], json!([]));

    wait_until(Duration::from_secs(1), || {
        let events = capture.events();
        events
            .iter()
            .any(|event| event.event_type == audit::event::TOOL_INVOKE_FAILURE)
            && events
                .iter()
                .any(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
    })
    .await;
    let events = capture.events();
    // The refused leaf is audited with its reason and without an assertion.
    let refused = events
        .iter()
        .filter(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
        .collect::<Vec<_>>();
    assert_eq!(refused.len(), 1, "only the first leaf was attempted");
    assert_eq!(refused[0].payload["tool_name"], json!("create_note"));
    assert_eq!(refused[0].payload["outcome"], json!("failure"));
    assert_eq!(
        refused[0].payload["reason"],
        json!("caller_assertion_no_principal")
    );
    assert!(refused[0].payload.get("caller_assertion").is_none());
    assert_eq!(
        refused[0]
            .actor
            .as_ref()
            .map(|actor| actor.auth_mode.as_str()),
        Some("service_token")
    );
    let failure = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_INVOKE_FAILURE)
        .expect("the composite refusal is audited");
    assert_eq!(failure.payload["failure_reason"], json!("composite_failed"));
    let completed = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
        .expect("the composite is audited");
    assert_eq!(completed.payload["outcome"], json!("failed"));
    assert_eq!(completed.payload["failed_step"], json!("note"));
    assert_eq!(completed.payload["steps"][0]["outcome"], json!("failed"));

    assert_eq!(secrets.resolutions(), saved, "no secret is read");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "the upstream receives nothing"
    );
}

#[tokio::test]
async fn a_compensation_the_key_can_no_longer_sign_is_skipped_with_its_reason() {
    let (addr, ca_pem, server, requests_seen) = scripted_tls_server_with_delays(vec![
        (
            StatusCode::CREATED,
            json!({ "id": "note-1" }),
            Duration::ZERO,
        ),
        // Held until the key has changed, then rejected, so the note has to
        // be undone with the changed key.
        (
            StatusCode::BAD_REQUEST,
            json!({ "error": "rejected" }),
            Duration::from_millis(1_000),
        ),
    ])
    .await;
    let signing_key = generated_es256_pem();
    let (connection, secrets) = TemporaryStaticAuthRuntime::header_api_key_with_caller_assertion(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        signing_key.as_bytes(),
    )
    .await;
    let (executor, capture) = executor_for_composite_definitions(
        composite_note_definitions(&connection.connection_id),
        &connection,
        COMPOSITE_TOOLS,
    );
    // An RSA key behind an alias the Connection uses for ES256.
    let replacement = generated_rs256_pem();

    let (result, ()) = tokio::join!(
        executor.execute(
            "create_note_for_records",
            json!({ "title": "hello", "targets": ["a"] }),
            context_for(&bearer("alice", &[]), "request-composite-key"),
            CancellationToken::new(),
        ),
        async {
            // The attachment was signed with the configured key before it
            // was sent; the compensation after it is not.
            wait_until(Duration::from_secs(2), || {
                requests_seen.load(Ordering::Acquire) == 2
            })
            .await;
            secrets.replace("assertion-signing-key", replacement.clone().into_bytes());
        },
    );
    let (reason, details) =
        composite_failure(result.expect_err("the rejected attachment fails the composite"));
    assert_eq!(
        reason.as_deref(),
        Some("composite_failed_compensation_incomplete")
    );
    assert_eq!(details["failed_step"], json!("attach"));
    assert_eq!(details["failure_reason"], json!("upstream_status:400"));
    assert_eq!(details["compensation"], json!("incomplete"));
    // The note stays, for the reason the compensation could not be sent
    // rather than as a transport error.
    assert_eq!(
        details["orphans"],
        json!([{
            "step": "note",
            "tool": "create_note",
            "certainty": "confirmed",
            "reason": "caller_assertion_key_unusable"
        }])
    );

    let requests = server.await.expect("the TLS server task should join");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        vec!["/v1/notes", "/v1/attachments/a"],
        "nothing was sent to undo the note"
    );

    wait_until(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
    })
    .await;
    let events = capture.events();
    let completed = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
        .expect("the composite is audited");
    assert_eq!(
        completed.payload["outcome"],
        json!("failed_compensation_incomplete")
    );
    assert_eq!(
        completed.payload["compensations"],
        json!([{
            "for_step": "note",
            "tool": "delete_note",
            "outcome": "skipped",
            "reason": "caller_assertion_key_unusable"
        }])
    );
    assert_eq!(
        completed.payload["pending_compensation"],
        json!([{ "step": "note", "tool": "delete_note" }])
    );
    let signed = events
        .iter()
        .filter(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
        .filter_map(|event| event.payload["caller_assertion"]["jti"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        signed,
        vec!["request-composite-key.1", "request-composite-key.2"]
    );
    let refused = events
        .iter()
        .find(|event| {
            event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                && event.payload["tool_name"] == json!("delete_note")
        })
        .expect("the refused compensation is audited");
    assert_eq!(
        refused.payload["reason"],
        json!("caller_assertion_key_unusable")
    );
    assert!(refused.payload.get("caller_assertion").is_none());
    let resolution = events
        .iter()
        .find(|event| event.event_type == audit::event::CONNECTION_SECRET_RESOLUTION_FAILED)
        .expect("the key failure is reported like any secret failure");
    assert_eq!(
        resolution.payload["reason"],
        json!("caller_assertion_key_unusable")
    );
    assert_eq!(resolution.payload["consumer_id"], json!("delete_note"));

    let mut canaries = vec![API_KEY];
    canaries.extend(pem_body_lines(&signing_key));
    canaries.extend(pem_body_lines(&replacement));
    let rendered = serde_json::to_string(&events).expect("events serialize");
    assert_absent(&rendered, &canaries, "the audit");
    assert_absent(&details.to_string(), &canaries, "the caller error");
}

#[tokio::test]
async fn a_composite_leaf_on_a_block_no_lane_honours_is_refused_before_member_io() {
    // A block only an earlier release accepted is honoured by no lane, so the
    // leaf is refused while it is prepared, and the composite reports why.
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let (connection, secrets) = TemporaryStaticAuthRuntime::header_api_key_with_caller_assertion(
        addr,
        &ca_pem,
        API_KEY.as_bytes(),
        generated_es256_pem().as_bytes(),
    )
    .await;
    let mut legacy = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .next()
        .cloned()
        .expect("the Connection is stored");
    legacy
        .write
        .caller_assertion
        .as_mut()
        .expect("the Connection attests its caller")
        .bind_approval = true;
    assert!(!legacy.write.caller_assertion_enforceable());
    connection
        .control_plane
        .publish_authoritative_records(vec![legacy])
        .await
        .expect("a legacy document still loads");
    let saved = secrets.resolutions();
    let (executor, capture) = executor_for_composite_definitions(
        composite_note_definitions(&connection.connection_id),
        &connection,
        COMPOSITE_TOOLS,
    );

    let error = executor
        .execute(
            "create_note_for_records",
            json!({ "title": "hello", "targets": ["a"] }),
            context_for(&bearer("alice", &[]), "request-composite-legacy"),
            CancellationToken::new(),
        )
        .await
        .expect_err("a composite leaf on a block no lane honours must fail closed");
    let (reason, details) = composite_failure(error);
    assert_eq!(reason.as_deref(), Some("composite_failed"));
    assert_eq!(details["failed_step"], json!("note"));
    assert_eq!(
        details["failure_reason"],
        json!("caller_assertion_not_enforced")
    );
    assert_eq!(details["orphans"], json!([]));

    wait_until(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
    })
    .await;
    let events = capture.events();
    assert!(
        events
            .iter()
            .all(|event| event.event_type != audit::event::TOOL_UPSTREAM_REQUEST),
        "no leaf request was attempted"
    );
    assert_eq!(
        secrets.resolutions(),
        saved,
        "a refused composite leaf must not consult a secret provider"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "the refusal must happen before composite member I/O"
    );
}

#[test]
fn composite_leaves_are_numbered_by_the_assertions_they_sign() {
    let mut leaves = CompositeLeafAssertions::new("request-9");
    assert_eq!(leaves.next_jti(), "request-9.1");
    // A leaf that signed nothing, refused or on a Connection that attests
    // nobody, takes no number.
    leaves.record(None);
    assert_eq!(leaves.next_jti(), "request-9.1");
    let issued = IssuedCallerAssertion {
        kid: "gw-test-1".to_owned(),
        jti: leaves.next_jti(),
    };
    leaves.record(Some(&issued));
    assert_eq!(leaves.next_jti(), "request-9.2");
}

#[test]
fn a_refused_composite_leaf_keeps_its_caller_assertion_reason() {
    let refusals = [
        CallerAssertionError::NoPrincipal,
        CallerAssertionError::InvalidClaim("jti"),
        CallerAssertionError::InvalidLifetime,
        CallerAssertionError::KeyUnusable,
        CallerAssertionError::KeyUnavailable,
        CallerAssertionError::KeyNotPublished,
        CallerAssertionError::HeaderConflict,
        CallerAssertionError::ApprovalRequired,
        CallerAssertionError::SignatureFailed,
        CallerAssertionError::TokenTooLong,
    ];
    // Exhaustive, so a new refusal is listed above before this compiles.
    for refusal in refusals {
        match refusal {
            CallerAssertionError::NoPrincipal
            | CallerAssertionError::InvalidClaim(_)
            | CallerAssertionError::InvalidLifetime
            | CallerAssertionError::KeyUnusable
            | CallerAssertionError::KeyUnavailable
            | CallerAssertionError::KeyNotPublished
            | CallerAssertionError::HeaderConflict
            | CallerAssertionError::ApprovalRequired
            | CallerAssertionError::SignatureFailed
            | CallerAssertionError::TokenTooLong => {}
        }
    }
    let reasons = refusals
        .map(CallerAssertionError::safe_reason)
        .into_iter()
        .chain([ConnectionHttpError::CallerAssertionNotEnforced.safe_reason()]);
    for reason in reasons {
        assert!(is_caller_assertion_refusal(reason), "{reason}");
        // A compensation refused while it was prepared reports it as it is.
        assert_eq!(composite_compensation_preflight_reason(reason), reason);
    }
    // Every other failure keeps the reason a composite already gave it.
    assert!(!is_caller_assertion_refusal(
        "upstream_authentication_rejected"
    ));
    assert_eq!(
        composite_compensation_preflight_reason("catalog_stale"),
        "compensation_transport_error"
    );
    assert_eq!(
        composite_compensation_preflight_reason("timeout"),
        "compensation_timeout"
    );
}

#[path = "executor_delegated_token_tests.rs"]
mod delegated_token_tests;
