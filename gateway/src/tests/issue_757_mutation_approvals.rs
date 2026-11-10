//! Exercise mutation preparation and independent review through authenticated HTTP.
use super::*;
use sha2::{Digest, Sha256};

const ISSUER: &str = "https://approval-identity.example.test";
const PRIVATE_ID: &str = "private widget";
const PRIVATE_NAME: &str = "unpublished widget name";
const SPEC: &str = r#"
openapi: 3.0.3
info: { title: Widgets, version: '1' }
paths:
  /widgets/{id}:
    get:
      operationId: getWidget
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
      responses: { '200': { description: Widget } }
    put:
      operationId: updateWidget
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties: { name: { type: string } }
      responses: { '200': { description: Updated } }
"#;

pub(super) async fn call(
    router: &Router,
    method: Method,
    uri: &str,
    token: &str,
    etag: Option<&str>,
    body: Option<Value>,
    expected: StatusCode,
) -> (HeaderMap, Value) {
    let mut request =
        connection_admin_request(method, uri, None, body.map(|v| v.to_string()), etag, false);
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let wire = body_string(response).await;
    assert!(!wire.contains(PRIVATE_ID) && !wire.contains("private%20widget"));
    assert!(!wire.contains(PRIVATE_NAME) && !wire.contains(token));
    assert_eq!(status, expected, "{uri}: {wire}");
    (headers, serde_json::from_str(&wire).unwrap_or(Value::Null))
}

pub(super) async fn prepare_route(router: &Router, token: &str, name: &str) -> (String, String) {
    let (_, inventory) = call(
        router,
        Method::GET,
        &format!("{TOOLS_ADMIN_ROUTE}?text={name}"),
        token,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    let tool_id = inventory["capabilities"][0]["id"].as_str().unwrap();
    let detail = format!("{TOOLS_ADMIN_ROUTE}/{tool_id}");
    let (headers, _) = call(
        router,
        Method::GET,
        &detail,
        token,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    (
        format!("{detail}/mutation-approvals"),
        headers[header::ETAG].to_str().unwrap().to_owned(),
    )
}

pub(super) async fn register_widgets(
    router: &Router,
    operator: &str,
    connection_id: &str,
    connection_etag: &str,
) -> Value {
    let catalog = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi");
    let (_, preview) = call(
        router,
        Method::POST,
        &format!("{catalog}/preview"),
        operator,
        None,
        Some(json!({"spec":SPEC})),
        StatusCode::OK,
    )
    .await;
    let registration = json!({
        "spec": SPEC,
        "spec_digest": preview["spec_digest"],
        "expected_spec_revision": preview["spec_revision"],
        "expected_catalog_revision": preview["catalog_revision"],
        "security_confirmations": preview["security_confirmations"],
        "selected_tool_names": ["getWidget", "updateWidget"]
    });
    let (_, registered) = call(
        router,
        Method::POST,
        &format!("{catalog}/register"),
        operator,
        Some(connection_etag),
        Some(registration),
        StatusCode::CREATED,
    )
    .await;
    registered
}

#[tokio::test]
async fn mutation_approval_binds_rendered_request_and_enforces_independent_review() {
    let destination = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let origin = format!("https://{}", destination.local_addr().unwrap());
    let db = TempDb::new("issue-757-approvals");
    let token_db = TempDb::new("issue-757-tokens");
    let service = create_service_token(
        &auth::SqliteTokenStore::open(&token_db.path).unwrap(),
        &["requester", "reviewer"],
    );
    let tools = TempToolsFile::new(&empty_tools_document());
    let policy = TempPolicyFile::new(&json!({
        "schema_version": "0.1.0", "id": "approval-policy",
        "default_action": "allow", "enforcement_mode": "enforce", "routes": [],
        "roles": {
            "operator": {"permissions": ["*"]},
            "requester": {"permissions": [ADMIN_TOOLS_READ_PERMISSION, ADMIN_TOOLS_EXECUTE_PERMISSION]},
            "reviewer": {"permissions": [connections::permissions::ADMIN_MUTATION_APPROVAL_REVIEW]}
        },
        "tools": {
            "updateWidget": {"allowed_roles": ["requester"], "timeout_ms": 5000, "max_concurrent": 2},
            "getWidget": {"allowed_roles": ["requester"], "timeout_ms": 5000, "max_concurrent": 2}
        }
    }).to_string());
    let mut config = test_config(Vec::new());
    configure_test_jwt_provider(&mut config, spawn_test_jwks_server().await);
    config.auth_providers[0].issuer = Some(ISSUER.to_owned());
    config.tools_file = Some(tools.path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.connections_sqlite_path = Some(db.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    config.rate_limit_write_rps = 1000.0;
    config.rate_limit_write_burst = 1000;
    let capture = audit::sink::tests::CaptureSink::new();
    let log = audit::AuditLog::new(Arc::new(capture.clone()));
    let mut required_config = config.clone();
    required_config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
    let router = app(
        config,
        PrometheusBuilder::new().build_recorder().handle(),
        log.clone(),
        test_audit_event_sender(),
    )
    .unwrap();
    let operator = signed_token_with_issuer("operator", &["operator"], ISSUER);
    let requester = signed_token_with_issuer("alice", &["requester"], ISSUER);
    let other = signed_token_with_issuer("other", &["requester"], ISSUER);
    let reviewer = signed_token_with_issuer("bob", &["reviewer"], ISSUER);
    let requester_as_reviewer = signed_token_with_issuer("alice", &["reviewer"], ISSUER);

    let (headers, _) = call(
        &router,
        Method::GET,
        CONNECTIONS_ADMIN_ROUTE,
        &operator,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    let (headers, connection) = call(
        &router,
        Method::POST,
        CONNECTIONS_ADMIN_ROUTE,
        &operator,
        Some(headers[CONNECTION_COLLECTION_ETAG_HEADER].to_str().unwrap()),
        Some(
            json!({"display_name":"Widgets","kind":"http_api","enabled":true,
            "endpoint":{"base_url":origin, "base_path":"/v1"}, "authentication":{"type":"none"},
            "discovery":{"type":"managed_openapi","use_connection_authentication":false}}),
        ),
        StatusCode::CREATED,
    )
    .await;
    let connection_id = connection["id"].as_str().unwrap();
    let connection_etag = headers[header::ETAG].to_str().unwrap();
    let registered = register_widgets(&router, &operator, connection_id, connection_etag).await;
    let (read_only, read_etag) = prepare_route(&router, &requester, "getWidget").await;
    let (_, unsupported) = call(
        &router,
        Method::POST,
        &read_only,
        &requester,
        Some(&read_etag),
        Some(json!({"arguments":{"id":PRIVATE_ID}})),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
    assert_eq!(unsupported["reason"], "mutation_approval_unsupported");

    let (prepare, etag) = prepare_route(&router, &requester, "updateWidget").await;
    let etag = Some(etag.as_str());
    let arguments = json!({"id": PRIVATE_ID, "name": PRIVATE_NAME});
    let body = Some(json!({"arguments": arguments}));
    let (service_prepare, service_etag) = prepare_route(&router, &service, "updateWidget").await;
    call(
        &router,
        Method::POST,
        &service_prepare,
        &service,
        Some(&service_etag),
        body.clone(),
        StatusCode::FORBIDDEN,
    )
    .await;
    call(
        &router,
        Method::POST,
        &prepare,
        "invalid-approval-test-jwt",
        etag,
        body.clone(),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    call(
        &router,
        Method::POST,
        &prepare,
        &reviewer,
        etag,
        body.clone(),
        StatusCode::FORBIDDEN,
    )
    .await;
    call(
        &router,
        Method::POST,
        &prepare,
        &requester,
        None,
        body.clone(),
        StatusCode::PRECONDITION_REQUIRED,
    )
    .await;
    call(
        &router,
        Method::POST,
        &prepare,
        &requester,
        Some("\"stale\""),
        body.clone(),
        StatusCode::PRECONDITION_FAILED,
    )
    .await;
    call(
        &router,
        Method::POST,
        &prepare,
        &requester,
        etag,
        Some(json!({"arguments":arguments, "caller":{"subject":"bob"}})),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let (_, pending) = call(
        &router,
        Method::POST,
        &prepare,
        &requester,
        etag,
        body.clone(),
        StatusCode::CREATED,
    )
    .await;
    let action = &pending["action"];
    assert_eq!(pending["status"], "pending");
    assert_eq!(
        pending["expires_at"].as_i64().unwrap() - pending["created_at"].as_i64().unwrap(),
        connections::mutation_approval::APPROVAL_LIFETIME_SECS
    );
    assert_eq!(action["caller"], json!({"issuer":ISSUER,"subject":"alice"}));
    assert_eq!(action["connection_id"], connection_id);
    assert_eq!(action["connection_etag"], connection_etag);
    assert_eq!(action["catalog_revision"], registered["catalog_revision"]);
    assert_eq!(action["tool_name"], "updateWidget");
    assert_eq!(action["operation"], "updateWidget");
    assert_eq!(action["method"], "PUT");
    let expected_target = format!("{origin}/v1/widgets/private%20widget");
    assert_eq!(
        action["target_sha256"],
        hex::encode(Sha256::digest(expected_target.as_bytes()))
    );
    let expected_body = br#"{"id":"private widget","name":"unpublished widget name"}"#;
    assert_eq!(
        action["body_sha256"],
        hex::encode(Sha256::digest(expected_body))
    );

    let record = format!(
        "/v1/admin/mutation-approvals/{}",
        pending["id"].as_str().unwrap()
    );
    let review = format!("{record}/review");
    let approve = Some(json!({"decision":"approve"}));
    let required = app(
        required_config,
        PrometheusBuilder::new().build_recorder().handle(),
        log.clone(),
        test_audit_event_sender(),
    )
    .unwrap();
    let revoke = format!("{record}/revoke");
    let execute = format!("{prepare}/{}/execute", pending["id"].as_str().unwrap());
    for (path, token, tag, payload, operation) in [
        (
            &prepare,
            &requester,
            etag,
            body.clone(),
            "mutation_approval.prepare",
        ),
        (
            &review,
            &reviewer,
            None,
            approve.clone(),
            "mutation_approval.review",
        ),
        (&revoke, &reviewer, None, None, "mutation_approval.revoke"),
        (
            &execute,
            &requester,
            etag,
            body.clone(),
            "mutation_approval.consume",
        ),
    ] {
        let (_, refused) = call(
            &required,
            Method::POST,
            path,
            token,
            tag,
            payload,
            StatusCode::CONFLICT,
        )
        .await;
        assert_eq!(refused["reason"], "authority_evidence_unsupported");
        assert_eq!(refused["operation"], operation);
    }
    let (_, still_pending) = call(
        &required,
        Method::GET,
        &record,
        &reviewer,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(still_pending["status"], "pending");
    call(
        &router,
        Method::POST,
        &review,
        &service,
        None,
        approve.clone(),
        StatusCode::FORBIDDEN,
    )
    .await;
    let (_, hidden) = call(
        &router,
        Method::GET,
        &record,
        &other,
        None,
        None,
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_eq!(
        hidden,
        json!({"error":"mutation approval request failed","reason":"mutation_approval_not_found"})
    );
    let (_, visible) = call(
        &router,
        Method::GET,
        &record,
        &requester,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(visible, pending);
    call(
        &router,
        Method::POST,
        &review,
        &other,
        None,
        approve.clone(),
        StatusCode::FORBIDDEN,
    )
    .await;
    let (_, refused) = call(
        &router,
        Method::POST,
        &review,
        &requester_as_reviewer,
        None,
        approve.clone(),
        StatusCode::FORBIDDEN,
    )
    .await;
    assert_eq!(refused["reason"], "mutation_approval_self_review");
    call(
        &router,
        Method::POST,
        &review,
        &reviewer,
        None,
        Some(json!({"decision":"approve","reviewer":{"subject":"alice"}})),
        StatusCode::BAD_REQUEST,
    )
    .await;
    let (_, unchanged) = call(
        &router,
        Method::GET,
        &record,
        &reviewer,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(unchanged, pending);
    let (_, approved) = call(
        &router,
        Method::POST,
        &review,
        &reviewer,
        None,
        approve.clone(),
        StatusCode::OK,
    )
    .await;
    assert_eq!(approved["action"], *action);
    assert_eq!(approved["status"], "approved");
    assert_eq!(
        approved["reviewer"],
        json!({"issuer":ISSUER, "subject":"bob"})
    );
    let revoke = format!("{record}/revoke");
    call(
        &router,
        Method::POST,
        &revoke,
        &requester,
        None,
        None,
        StatusCode::FORBIDDEN,
    )
    .await;
    let (_, revoked) = call(
        &router,
        Method::POST,
        &revoke,
        &reviewer,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    assert_eq!(revoked["status"], "revoked");
    assert_eq!(revoked["revoked_by"], approved["reviewer"]);
    let (_, next) = call(
        &router,
        Method::POST,
        &prepare,
        &requester,
        etag,
        body,
        StatusCode::CREATED,
    )
    .await;
    let second_review = format!(
        "/v1/admin/mutation-approvals/{}/review",
        next["id"].as_str().unwrap()
    );
    let (_, rejected) = call(
        &router,
        Method::POST,
        &second_review,
        &reviewer,
        None,
        Some(json!({"decision":"reject"})),
        StatusCode::OK,
    )
    .await;
    assert_eq!(rejected["status"], "rejected");
    call(
        &router,
        Method::POST,
        &second_review,
        &reviewer,
        None,
        approve,
        StatusCode::CONFLICT,
    )
    .await;

    log.close_and_drain(Duration::from_secs(5)).await.unwrap();
    let events = capture.events();
    assert!(events.iter().any(
        |e| e.event_type == audit::event::CONNECTION_MUTATION_APPROVAL
            && e.payload["reason"] == "mutation_approval_self_review"
    ));
    let audit = serde_json::to_string(&events).unwrap();
    for private in [
        PRIVATE_ID,
        "private%20widget",
        PRIVATE_NAME,
        &requester,
        &reviewer,
        &service,
    ] {
        assert!(
            !audit.contains(private),
            "sensitive approval input reached the audit sink"
        );
    }
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "preparing, reading and reviewing an approval must send no upstream bytes"
    );
}
