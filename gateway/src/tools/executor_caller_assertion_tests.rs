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
        caller_assertion::{body_digest, AttestedCaller},
        model::CallerAssertionClaim,
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
    assert!(!request.body.is_empty());
    assert_eq!(
        claims["request_sha256"],
        json!(upstream_digest(&request.body))
    );
    assert_eq!(body_digest(&request.body), upstream_digest(&request.body));

    // Any change to the body after signing, down to one byte or a key order
    // that parses to the same JSON, no longer matches the digest the
    // assertion carries.
    let mut tampered = request.body.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;
    assert_ne!(claims["request_sha256"], json!(upstream_digest(&tampered)));
    let sent: Value = serde_json::from_slice(&request.body).expect("the body is JSON");
    let reordered = format!(
        r#"{{"memo":{},"amount":{}}}"#,
        serde_json::to_string(&sent["memo"]).expect("memo serializes"),
        sent["amount"]
    )
    .into_bytes();
    assert_ne!(reordered, request.body);
    assert_eq!(
        serde_json::from_slice::<Value>(&reordered).expect("the reordered body is JSON"),
        sent,
        "the reordered body means the same JSON"
    );
    assert_ne!(claims["request_sha256"], json!(upstream_digest(&reordered)));
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
