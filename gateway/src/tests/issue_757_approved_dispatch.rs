//! One approved mutation through the admin router, the TLS upstream and its JWKS verifier.
use super::super::issue_757_mutation_approvals::{call, prepare_route, register_widgets};
use super::*;

struct Invocation<'a> {
    router: &'a Router,
    prepare: String,
    etag: String,
    requester: String,
    reviewer: String,
    body: Value,
}

impl Invocation<'_> {
    async fn prepare(&self) -> String {
        let (_, record) = call(
            self.router,
            Method::POST,
            &self.prepare,
            &self.requester,
            Some(&self.etag),
            Some(self.body.clone()),
            StatusCode::CREATED,
        )
        .await;
        record["id"].as_str().unwrap().to_owned()
    }

    async fn approve(&self, id: &str) {
        call(
            self.router,
            Method::POST,
            &format!("/v1/admin/mutation-approvals/{id}/review"),
            &self.reviewer,
            None,
            Some(json!({"decision":"approve"})),
            StatusCode::OK,
        )
        .await;
    }

    async fn dispatch(
        &self,
        id: &str,
        token: &str,
        etag: &str,
        body: Value,
        status: StatusCode,
    ) -> Value {
        let (_, result) = call(
            self.router,
            Method::POST,
            &format!("{}/{id}/execute", self.prepare),
            token,
            Some(etag),
            Some(body),
            status,
        )
        .await;
        result
    }

    async fn dispatch_original(&self, id: &str, status: StatusCode) -> Value {
        self.dispatch(id, &self.requester, &self.etag, self.body.clone(), status)
            .await
    }
}

// Move only this test database row along its normal 15-minute lifetime.
// The signature test shortens the remaining window below its 60-second JWT TTL.
fn remaining_lifetime(db: &TempDb, id: &str, remaining: i64) -> i64 {
    let conn = rusqlite::Connection::open(&db.path).unwrap();
    conn.query_row(
        "UPDATE connection_mutation_approvals
         SET created_at = unixepoch() + ?2 - ?3, expires_at = unixepoch() + ?2,
             reviewed_at = unixepoch() - 1 WHERE id = ?1 RETURNING expires_at",
        rusqlite::params![
            id,
            remaining,
            connections::mutation_approval::APPROVAL_LIFETIME_SECS
        ],
        |row| row.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn mutation_approval_dispatch_sends_one_signed_https_request() {
    let stub = Phase8Stub::start().await;
    let secrets = SecretsRoot::new(&stub.ca_pem);
    let db = TempDb::new("issue-757-dispatch");
    let token_db = TempDb::new("issue-757-dispatch-tokens");
    let tools = TempToolsFile::new(&empty_tools_document());
    let policy = TempPolicyFile::new(&json!({
        "schema_version": "0.1.0", "id":"dispatch-policy", "default_action":"allow",
        "enforcement_mode":"enforce", "routes": [],
        "roles": {
            "operator": {"permissions":["*"]},
            "requester": {"permissions":[ADMIN_MCP_USE_PERMISSION,ADMIN_TOOLS_READ_PERMISSION,ADMIN_TOOLS_EXECUTE_PERMISSION]},
            "reviewer": {"permissions":[connections::permissions::ADMIN_MUTATION_APPROVAL_REVIEW]}
        },
        "tools": {"updateWidget":{"allowed_roles":["requester"],"timeout_ms":5000,"max_concurrent":2}}
    }).to_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let router = phase8_router(
        &Phase8Parts {
            jwks_addr: spawn_test_jwks_server().await,
            connection_db: &db,
            token_db: &token_db,
            policy: &policy,
            tools: &tools,
            secrets: &secrets,
        },
        &capture,
    );
    let operator = signed_token_with_issuer("operator", &["operator"], CALLER_IDP);
    let requester = signed_token_with_issuer("alice", &["requester"], CALLER_IDP);
    let reviewer = signed_token_with_issuer("bob", &["reviewer"], CALLER_IDP);
    let other = signed_token_with_issuer("other", &["requester"], CALLER_IDP);

    let mut doc = attested_connection(&stub);
    doc["discovery"] = json!({"type":"managed_openapi","use_connection_authentication":false});
    doc["authentication"] = json!({"type":"none"});
    doc["caller_assertion"]["bind_approval"] = json!(true);
    doc["caller_assertion"]["approval_mode"] = json!("managed_http_mutation_v1");
    let (connection_id, conn_etag) = create_connection(&router, &operator, doc).await;
    register_widgets(&router, &operator, &connection_id, &conn_etag).await;
    let (prepare, etag) = prepare_route(&router, &requester, "updateWidget").await;
    let (_, other_etag) = prepare_route(&router, &other, "updateWidget").await;
    let invocation = Invocation {
        router: &router,
        prepare,
        etag,
        requester,
        reviewer,
        body: json!({"arguments":{"id":"private widget","name":"unpublished widget name"}}),
    };
    let id = invocation.prepare().await;
    let missing = invocation
        .dispatch_original(&uuid::Uuid::new_v4().to_string(), StatusCode::NOT_FOUND)
        .await;
    assert_eq!(missing["reason"], "mutation_approval_not_found");
    let pending = invocation
        .dispatch_original(&id, StatusCode::CONFLICT)
        .await;
    assert_eq!(pending["reason"], "mutation_approval_state_conflict");
    invocation.approve(&id).await;

    // Even with a live, approved record, ordinary execution names no approval.
    let ordinary = format!(
        "{}/execute",
        invocation
            .prepare
            .strip_suffix("/mutation-approvals")
            .unwrap()
    );
    let ordinary_response = router
        .clone()
        .oneshot(admin_request(
            Method::POST,
            &ordinary,
            &invocation.requester,
            Some(invocation.body.clone()),
            Some(&invocation.etag),
        ))
        .await
        .unwrap();
    let refused = ordinary_response.status();
    assert!(
        refused.is_client_error() || refused.is_server_error(),
        "ordinary execute answered {refused}"
    );
    let (gateway, server) = spawn_gateway_router(router.clone()).await;
    let mcp = mcp_client(gateway, &invocation.requester, "issue-757-no-approval").await;
    call_tool(&mcp, "updateWidget", invocation.body["arguments"].clone())
        .await
        .expect_err("ordinary MCP cannot spend an approval");
    mcp.cancel().await.unwrap();
    server.abort();
    let foreign = invocation
        .dispatch(
            &id,
            &other,
            &other_etag,
            invocation.body.clone(),
            StatusCode::NOT_FOUND,
        )
        .await;
    assert_eq!(foreign, missing);
    let changed = json!({"arguments":{"id":"private widget","name":"changed widget"}});
    let wrong_body = invocation
        .dispatch(
            &id,
            &invocation.requester,
            &invocation.etag,
            changed,
            StatusCode::CONFLICT,
        )
        .await;
    assert_eq!(wrong_body["reason"], "mutation_approval_mismatch");

    let rejected = invocation.prepare().await;
    call(
        &router,
        Method::POST,
        &format!("/v1/admin/mutation-approvals/{rejected}/review"),
        &invocation.reviewer,
        None,
        Some(json!({"decision":"reject"})),
        StatusCode::OK,
    )
    .await;
    let refused = invocation
        .dispatch_original(&rejected, StatusCode::CONFLICT)
        .await;
    assert_eq!(refused["reason"], "mutation_approval_state_conflict");

    let revoked = invocation.prepare().await;
    invocation.approve(&revoked).await;
    call(
        &router,
        Method::POST,
        &format!("/v1/admin/mutation-approvals/{revoked}/revoke"),
        &invocation.reviewer,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    let refused = invocation
        .dispatch_original(&revoked, StatusCode::CONFLICT)
        .await;
    assert_eq!(refused["reason"], "mutation_approval_state_conflict");
    let expired = invocation.prepare().await;
    invocation.approve(&expired).await;
    remaining_lifetime(&db, &expired, 0);
    let expired = invocation
        .dispatch_original(&expired, StatusCode::GONE)
        .await;
    assert_eq!(expired["reason"], "mutation_approval_expired");

    assert_eq!(
        stub.accepted_connections(),
        0,
        "preparation, review and refusals opened a socket"
    );
    let expires_at = remaining_lifetime(&db, &id, 30);
    let output = invocation.dispatch_original(&id, StatusCode::OK).await;
    assert_eq!(output["kind"], "http");
    assert_eq!(output["status"], 201);
    assert_eq!(
        output["body"],
        json!({"type":"json","value":{"recorded":true}})
    );

    let wire = stub.requests();
    assert_eq!(wire.len(), 1);
    let request = &wire[0];
    assert_eq!(request.method, "PUT");
    assert_eq!(
        request.target,
        format!("{ATTESTED_BASE_PATH}/widgets/private%20widget")
    );
    assert_eq!(
        request.body.as_slice(),
        br#"{"id":"private widget","name":"unpublished widget name"}"#
    );
    assert_eq!(request.header_count(ASSERTION_HEADER), 1);
    assert!(request.header("authorization").is_none());
    let jwks = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(JWKS_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
    let claims = verify_with_published_set(
        request.header(ASSERTION_HEADER).unwrap(),
        &body_string(jwks).await,
        ATTESTED_AUDIENCE,
        "at+jwt",
    );
    assert_eq!(claims["approval_id"], id);
    assert_eq!(claims["caller_iss"], CALLER_IDP);
    assert_eq!(claims["caller_sub"], "alice");
    assert_eq!(claims["method"], request.method);
    assert_eq!(claims["path"], request.target);
    assert_eq!(
        claims["request_sha256"],
        hex::encode(Sha256::digest(&request.body))
    );
    let target = format!("{}{}", stub.base_url(), request.target);
    assert_eq!(
        claims["target_sha256"],
        hex::encode(Sha256::digest(target.as_bytes()))
    );
    assert_eq!(claims["exp"], expires_at);
    let spent = invocation
        .dispatch_original(&id, StatusCode::CONFLICT)
        .await;
    assert_eq!(spent["reason"], "mutation_approval_state_conflict");
    assert_eq!(
        stub.accepted_connections(),
        1,
        "a spent approval opened another connection"
    );

    assert_eventually(std::time::Duration::from_secs(5), || {
        let events = capture.events();
        let reasons = [
            "mutation_approval_not_found",
            "mutation_approval_mismatch",
            "mutation_approval_expired",
            "mutation_approval_state_conflict",
        ];
        reasons.iter().all(|reason| {
            events.iter().any(|event| {
                event.event_type == audit::event::TOOL_INVOKE_FAILURE
                    && event.payload["failure_reason"] == *reason
            })
        }) && events
            .iter()
            .filter(|event| {
                event.event_type == audit::event::CONNECTION_MUTATION_APPROVAL
                    && event.payload["operation"] == "consume"
                    && event.payload["approval_id"] == id
            })
            .count()
            == 1
    });
    let audit = serde_json::to_string(&capture.events()).unwrap();
    for sensitive in [
        "private widget",
        "private%20widget",
        "unpublished widget name",
        request.header(ASSERTION_HEADER).unwrap(),
    ] {
        assert!(!audit.contains(sensitive));
    }
}
