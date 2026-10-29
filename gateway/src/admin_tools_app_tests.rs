use super::*;

#[tokio::test]
async fn playground_transform_rejection_is_422_with_structured_problems() {
    let response = tool_playground_runtime_error_response(
        tools::runtime::ToolRuntimeError::WorkFailed {
            tool_name: "createCompany".to_owned(),
            message: "tool 'createCompany' argument 'amount' could not be encoded".to_owned(),
            reason: Some("invalid_params".to_owned()),
            details: Some(json!({
                "problems": [{
                    "path": "/amount",
                    "keyword": "codec",
                    "reason": "value has 7 fraction digits, codec allows 6",
                }],
            })),
        },
        None,
    );
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("playground error body should collect");
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("playground error should be JSON"),
        json!({
            "error": "tool arguments were rejected",
            "reason": "invalid_params",
            "problems": [{
                "path": "/amount",
                "keyword": "codec",
                "reason": "value has 7 fraction digits, codec allows 6",
            }],
        })
    );
}

#[test]
fn playground_if_match_requires_exactly_one_strong_entity_tag() {
    let mut headers = HeaderMap::new();
    assert!(matches!(
        exact_strong_if_match(&headers),
        Err(ToolPlaygroundIfMatchError::Missing)
    ));

    headers.insert(
        header::IF_MATCH,
        HeaderValue::from_static("\"execution-tag\""),
    );
    assert_eq!(
        exact_strong_if_match(&headers).expect("one strong tag should parse"),
        "\"execution-tag\""
    );

    for invalid in [
        "*",
        "W/\"execution-tag\"",
        "\"first\", \"second\"",
        "execution-tag",
        "\"contains space\"",
    ] {
        headers.insert(
            header::IF_MATCH,
            HeaderValue::from_str(invalid).expect("test header should build"),
        );
        assert!(
            matches!(
                exact_strong_if_match(&headers),
                Err(ToolPlaygroundIfMatchError::Invalid)
            ),
            "{invalid} must not be accepted"
        );
    }

    headers.insert(header::IF_MATCH, HeaderValue::from_static("\"first\""));
    headers.append(header::IF_MATCH, HeaderValue::from_static("\"second\""));
    assert!(matches!(
        exact_strong_if_match(&headers),
        Err(ToolPlaygroundIfMatchError::Invalid)
    ));
}

#[tokio::test]
async fn capability_inventory_list_works_without_tools_file_and_sets_cache_headers() {
    let token_db = TempDb::new("capability-inventory-no-tools-file-token");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let admin_token = create_service_token(&token_store, &["admin"]);
    let policy = TempPolicyFile::new(&tools_policy_document());
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("capability inventory app should build without TOOLS_FILE");

    let response = router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&admin_token),
            TOOLS_ADMIN_ROUTE,
        ))
        .await
        .expect("capability inventory request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().contains_key(header::ETAG),
        "inventory response should include an ETag"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );

    let invalid_query = router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&admin_token),
            &format!("{TOOLS_ADMIN_ROUTE}?limit=0"),
        ))
        .await
        .expect("invalid capability inventory query should complete");
    assert_eq!(invalid_query.status(), StatusCode::BAD_REQUEST);
    assert_capability_inventory_no_store(&invalid_query);

    let unauthenticated_invalid_query = router
        .oneshot(tools_inventory_request(
            None,
            &format!("{TOOLS_ADMIN_ROUTE}?limit=0"),
        ))
        .await
        .expect("unauthenticated invalid inventory query should complete");
    assert_eq!(
        unauthenticated_invalid_query.status(),
        StatusCode::UNAUTHORIZED,
        "authentication must run before query validation"
    );
    assert_capability_inventory_no_store(&unauthenticated_invalid_query);
}

#[tokio::test]
async fn capability_inventory_authenticated_without_policy_fails_closed_without_caching() {
    let token_db = TempDb::new("capability-inventory-no-policy-token");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let token = create_service_token(&token_store, &["admin"]);
    let mut config = test_config(Vec::new());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("capability inventory app should build without POLICY_FILE");

    for uri in [
        TOOLS_ADMIN_ROUTE.to_owned(),
        format!("{TOOLS_ADMIN_ROUTE}/cap_{}", "0".repeat(64)),
    ] {
        let response = router
            .clone()
            .oneshot(tools_inventory_request(Some(&token), &uri))
            .await
            .expect("policy-unconfigured capability inventory request should complete");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_capability_inventory_no_store(&response);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"tools API requires POLICY_FILE to be configured"}"#
        );
    }
}

#[tokio::test]
async fn capability_inventory_custom_prefix_accepts_wildcard_permission() {
    const CUSTOM_TOOLS_ROUTE: &str = "/v1/ops/tools";

    let token_db = TempDb::new("capability-inventory-custom-prefix-token");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let token = create_service_token(&token_store, &["superadmin"]);
    let policy = TempPolicyFile::new(
        &json!({
            "schema_version": "0.1.0",
            "id": "capability-inventory-custom-prefix-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "superadmin": {
                    "permissions": ["*"]
                }
            },
            "routes": [
                {
                    "methods": ["GET"],
                    "path_prefix": CUSTOM_TOOLS_ROUTE,
                    "permission": ADMIN_TOOLS_READ_PERMISSION
                }
            ]
        })
        .to_string(),
    );
    let mut config = test_config(Vec::new());
    config.admin_prefix = "/ops".to_owned();
    config
        .auth_exempt_paths
        .retain(|path| path != config::DEFAULT_ADMIN_PREFIX);
    config.auth_exempt_paths.push("/ops".to_owned());
    config.rbac_exempt_paths = config.auth_exempt_paths.clone();
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("custom-prefix capability inventory app should build");

    let collection = router
        .clone()
        .oneshot(tools_inventory_request(Some(&token), CUSTOM_TOOLS_ROUTE))
        .await
        .expect("custom-prefix capability inventory request should complete");
    assert_eq!(collection.status(), StatusCode::OK);
    assert_capability_inventory_no_store(&collection);

    let detail = router
        .oneshot(tools_inventory_request(
            Some(&token),
            &format!("{CUSTOM_TOOLS_ROUTE}/cap_{}", "0".repeat(64)),
        ))
        .await
        .expect("custom-prefix capability detail request should complete");
    assert_eq!(detail.status(), StatusCode::NOT_FOUND);
    assert_capability_inventory_no_store(&detail);
}

#[tokio::test]
async fn capability_inventory_paginates_filters_and_returns_safe_detail() {
    let harness = tools_admin_harness(mcp_tools_document(), test_audit_log()).await;
    let first_response = harness
            .router
            .clone()
            .oneshot(tools_inventory_request(
                Some(&harness.reader_token),
                &format!(
                    "{TOOLS_ADMIN_ROUTE}?kind=tool&source=manual_file&connection_id=legacy-default-http&available=true&limit=1"
                ),
            ))
            .await
            .expect("first capability inventory page should complete");
    assert_eq!(first_response.status(), StatusCode::OK);
    let first_etag = first_response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("first capability page should include an ETag")
        .to_owned();
    let first = json_body(first_response).await;
    assert_eq!(first["total_count"], json!(2));
    let first_capability = first["capabilities"]
        .as_array()
        .and_then(|capabilities| capabilities.first())
        .expect("first page should contain one capability");
    assert_eq!(first_capability["kind"], json!("tool"));
    assert_eq!(first_capability["source"]["type"], json!("manual_file"));
    assert_eq!(
        first_capability["connection"]["id"],
        json!("legacy-default-http")
    );
    assert_eq!(first_capability["state"]["available"], json!(true));
    assert_eq!(first_capability["policy"]["eligible"], json!(false));
    assert_eq!(
        first_capability["policy"]["reason"],
        json!("principal_not_eligible")
    );
    let first_id = first_capability["id"]
        .as_str()
        .expect("capability should have an opaque id")
        .to_owned();
    let cursor = first["next_cursor"]
        .as_str()
        .expect("first page should include a cursor");

    let second_response = harness
            .router
            .clone()
            .oneshot(tools_inventory_request(
                Some(&harness.reader_token),
                &format!(
                    "{TOOLS_ADMIN_ROUTE}?kind=tool&source=manual_file&connection_id=legacy-default-http&available=true&limit=1&cursor={cursor}"
                ),
            ))
            .await
            .expect("second capability inventory page should complete");
    assert_eq!(second_response.status(), StatusCode::OK);
    let second_etag = second_response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("second capability page should include an ETag")
        .to_owned();
    assert_ne!(
        first_etag, second_etag,
        "different pages must not share a standard HTTP entity ETag"
    );
    let second = json_body(second_response).await;
    assert_eq!(
        second["total_count"],
        json!(2),
        "total_count should describe the full filtered collection on every page"
    );
    assert!(
        second.get("next_cursor").is_none(),
        "the final page should not include a cursor"
    );
    let second_id = second["capabilities"][0]["id"]
        .as_str()
        .expect("second capability should have an opaque id");
    assert_ne!(first_id, second_id);

    let filtered_response = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.reader_token),
            &format!("{TOOLS_ADMIN_ROUTE}?text=widget"),
        ))
        .await
        .expect("filtered capability inventory request should complete");
    assert_eq!(filtered_response.status(), StatusCode::OK);
    let filtered_etag = filtered_response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("filtered capability page should include an ETag")
        .to_owned();
    assert_ne!(
        first_etag, filtered_etag,
        "different filtered representations must not share an ETag"
    );
    let filtered = json_body(filtered_response).await;
    assert_eq!(filtered["total_count"], json!(1));
    assert_eq!(filtered["capabilities"][0]["name"], json!("get_widget"));

    let detail_response = harness
        .router
        .oneshot(tools_inventory_request(
            Some(&harness.reader_token),
            &format!("{TOOLS_ADMIN_ROUTE}/{first_id}"),
        ))
        .await
        .expect("capability detail request should complete");
    assert_eq!(detail_response.status(), StatusCode::OK);
    assert_capability_inventory_no_store(&detail_response);
    let detail = json_body(detail_response).await;
    assert_eq!(detail["id"], json!(first_id));
    assert_eq!(detail["mapping"]["type"], json!("http"));
    assert_eq!(detail["input_json_schema"]["type"], json!("object"));
    let serialized = serde_json::to_string(&detail).expect("detail should serialize");
    assert!(!serialized.contains("Authorization"));
    assert!(!serialized.contains("Cookie"));
}

#[tokio::test]
async fn capability_inventory_detail_authorizes_before_lookup_and_hides_id_validity() {
    let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;
    let malformed_uri = format!("{TOOLS_ADMIN_ROUTE}/not-a-capability-id");
    let unknown_uri = format!("{TOOLS_ADMIN_ROUTE}/cap_{}", "0".repeat(64));

    let unauthenticated = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(None, &malformed_uri))
        .await
        .expect("unauthenticated inventory detail request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let forbidden_malformed = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.blocked_token),
            &malformed_uri,
        ))
        .await
        .expect("forbidden malformed inventory detail request should complete");
    let forbidden_malformed_status = forbidden_malformed.status();
    assert_capability_inventory_no_store(&forbidden_malformed);
    let forbidden_malformed_body = body_string(forbidden_malformed).await;
    let forbidden_unknown = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.blocked_token),
            &unknown_uri,
        ))
        .await
        .expect("forbidden unknown inventory detail request should complete");
    let forbidden_unknown_status = forbidden_unknown.status();
    assert_capability_inventory_no_store(&forbidden_unknown);
    let forbidden_unknown_body = body_string(forbidden_unknown).await;
    assert_eq!(forbidden_malformed_status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden_unknown_status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden_malformed_body, forbidden_unknown_body);

    let authorized_malformed = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.reader_token),
            &malformed_uri,
        ))
        .await
        .expect("authorized malformed inventory detail request should complete");
    let authorized_malformed_status = authorized_malformed.status();
    assert_capability_inventory_no_store(&authorized_malformed);
    let authorized_malformed_body = body_string(authorized_malformed).await;
    let authorized_unknown = harness
        .router
        .oneshot(tools_inventory_request(
            Some(&harness.reader_token),
            &unknown_uri,
        ))
        .await
        .expect("authorized unknown inventory detail request should complete");
    let authorized_unknown_status = authorized_unknown.status();
    assert_capability_inventory_no_store(&authorized_unknown);
    let authorized_unknown_body = body_string(authorized_unknown).await;
    assert_eq!(authorized_malformed_status, StatusCode::NOT_FOUND);
    assert_eq!(authorized_unknown_status, StatusCode::NOT_FOUND);
    assert_eq!(authorized_malformed_body, authorized_unknown_body);
}

#[tokio::test]
async fn tool_playground_enforces_permission_validator_and_strict_body_before_upstream() {
    const REJECTED_OUTPUT_CANARY: &str = "Bearer playground-reflected-credential-output-canary";
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&upstream_calls);
    let upstream = Router::new().route(
        "/v1/echo",
        post(move |Json(arguments): Json<Value>| {
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if arguments["message"] == json!("emit-unsafe-binary-output") {
                    let mut body =
                        format!("authorization={REJECTED_OUTPUT_CANARY}; api_key=reflected-key")
                            .into_bytes();
                    body.push(0xff);
                    return (
                        [(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/octet-stream"),
                        )],
                        body,
                    )
                        .into_response();
                }
                Json(json!({ "echoed": arguments })).into_response()
            }
        }),
    );
    let upstream_addr = spawn_router(upstream).await;
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let harness = tools_admin_harness_with_policy_and_upstream(
        mcp_tools_document(),
        audit_log,
        format!("http://{upstream_addr}"),
        tools_policy_document_with_execute_route_permission(ADMIN_TOOLS_READ_PERMISSION),
    )
    .await;

    let list_response = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.admin_token),
            &format!("{TOOLS_ADMIN_ROUTE}?text=echo"),
        ))
        .await
        .expect("tool inventory request should complete");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list = json_body(list_response).await;
    let capability_id = list["capabilities"][0]["id"]
        .as_str()
        .expect("echo should have an opaque capability ID")
        .to_owned();

    let detail_response = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.admin_token),
            &format!("{TOOLS_ADMIN_ROUTE}/{capability_id}"),
        ))
        .await
        .expect("tool detail request should complete");
    assert_eq!(detail_response.status(), StatusCode::OK);
    let execution_etag = detail_response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("tool detail should include an execution ETag")
        .to_owned();
    assert!(execution_etag.starts_with("\"capability-execution:sha256:"));
    let detail = json_body(detail_response).await;
    assert_eq!(detail["actions"]["can_execute"], json!(true));
    assert_eq!(detail["actions"]["reason"], json!("allowed"));

    let argument_canary = "playground-argument-canary";
    let unauthenticated = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some("invalid-service-token"),
            &capability_id,
            None,
            Body::from("not-json"),
        ))
        .await
        .expect("unauthenticated playground request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_capability_inventory_no_store(&unauthenticated);
    assert_eq!(upstream_calls.load(Ordering::SeqCst), 0);

    let csrf_denied = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            None,
            &capability_id,
            None,
            Body::from("not-json"),
        ))
        .await
        .expect("CSRF-denied playground request should complete");
    assert_eq!(csrf_denied.status(), StatusCode::FORBIDDEN);
    assert_capability_inventory_no_store(&csrf_denied);
    assert_eq!(upstream_calls.load(Ordering::SeqCst), 0);

    let forbidden = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.reader_token),
            &capability_id,
            None,
            Body::from(format!(
                r#"{{"arguments":{{"message":"{argument_canary}"}}}}"#
            )),
        ))
        .await
        .expect("permission-denied playground request should complete");
    assert_eq!(
        forbidden.status(),
        StatusCode::FORBIDDEN,
        "admin execution authorization must precede If-Match and body validation"
    );
    assert_capability_inventory_no_store(&forbidden);
    assert_eq!(upstream_calls.load(Ordering::SeqCst), 0);

    let missing_if_match = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            None,
            Body::from(r#"{"arguments":{"message":"hello"}}"#),
        ))
        .await
        .expect("missing If-Match request should complete");
    assert_eq!(missing_if_match.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_capability_inventory_no_store(&missing_if_match);

    let weak_if_match = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            Some("W/\"stale\""),
            Body::from(r#"{"arguments":{"message":"hello"}}"#),
        ))
        .await
        .expect("weak If-Match request should complete");
    assert_eq!(weak_if_match.status(), StatusCode::BAD_REQUEST);
    assert_capability_inventory_no_store(&weak_if_match);

    let invalid_body = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            Some(&execution_etag),
            Body::from(r#"{"arguments":{"message":"hello"},"url":"https://override.invalid"}"#),
        ))
        .await
        .expect("override-field request should complete");
    assert_eq!(invalid_body.status(), StatusCode::BAD_REQUEST);
    assert_capability_inventory_no_store(&invalid_body);
    assert_eq!(upstream_calls.load(Ordering::SeqCst), 0);

    let oversized_body = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            Some(&execution_etag),
            Body::from(vec![
                b' ';
                tools::playground::TOOL_PLAYGROUND_REQUEST_LIMIT_BYTES
                    + 1
            ]),
        ))
        .await
        .expect("oversized playground request should complete");
    assert_eq!(oversized_body.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_capability_inventory_no_store(&oversized_body);
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        0,
        "oversized bodies must fail before tool execution"
    );

    let stale = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            Some("\"capability-execution:sha256:stale\""),
            Body::from(r#"{"arguments":{"message":"hello"}}"#),
        ))
        .await
        .expect("stale-validator request should complete");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_capability_inventory_no_store(&stale);
    assert_eq!(
        json_body(stale).await["reason"],
        json!("precondition_failed")
    );
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        0,
        "stale validators must fail before upstream I/O"
    );

    let rejected_argument_canary = "Bearer rejected-playground-argument-must-not-be-reflected";
    let rejected_argument = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            Some(&execution_etag),
            Body::from(format!(
                r#"{{"arguments":{{"message":{{"token":"{rejected_argument_canary}"}}}}}}"#
            )),
        ))
        .await
        .expect("invalid-argument playground request should complete");
    assert_eq!(rejected_argument.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_capability_inventory_no_store(&rejected_argument);
    let rejected_argument_body = json_body(rejected_argument).await;
    assert_eq!(
        rejected_argument_body["error"],
        json!("tool arguments were rejected")
    );
    assert_eq!(rejected_argument_body["reason"], json!("invalid_params"));
    assert_eq!(
        rejected_argument_body["problems"][0]["path"],
        json!("/message")
    );
    assert_eq!(
        rejected_argument_body["problems"][0]["keyword"],
        json!("type")
    );
    assert_eq!(
        rejected_argument_body["problems"][0]["message"],
        json!("value has the wrong JSON type")
    );
    assert!(rejected_argument_body["problems"][0]
        .get("allowed")
        .is_none());
    assert!(!rejected_argument_body
        .to_string()
        .contains(rejected_argument_canary));
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        0,
        "invalid arguments must fail before upstream I/O"
    );

    let rejected_output = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            Some(&execution_etag),
            Body::from(r#"{"arguments":{"message":"emit-unsafe-binary-output"}}"#),
        ))
        .await
        .expect("unsafe-output playground request should complete");
    assert_eq!(rejected_output.status(), StatusCode::BAD_GATEWAY);
    assert_capability_inventory_no_store(&rejected_output);
    let rejected_output_body = json_body(rejected_output).await;
    assert_eq!(rejected_output_body["reason"], json!("unsupported_output"));
    assert!(
        !rejected_output_body
            .to_string()
            .contains(REJECTED_OUTPUT_CANARY),
        "rejected upstream output must not be reflected to the administrator"
    );
    assert_eq!(upstream_calls.load(Ordering::SeqCst), 1);

    let success = harness
        .router
        .clone()
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            Some(&execution_etag),
            Body::from(format!(
                r#"{{"arguments":{{"message":"{argument_canary}"}}}}"#
            )),
        ))
        .await
        .expect("valid playground request should complete");
    assert_eq!(success.status(), StatusCode::OK);
    assert_capability_inventory_no_store(&success);
    assert_eq!(
        success.headers().get(header::ETAG),
        Some(&HeaderValue::from_str(&execution_etag).expect("execution ETag should be valid"))
    );
    let success_body = json_body(success).await;
    assert_eq!(success_body["kind"], json!("http"));
    assert_eq!(success_body["status"], json!(200));
    assert_eq!(
        success_body["body"]["value"]["echoed"]["message"],
        json!(argument_canary)
    );
    assert_eq!(upstream_calls.load(Ordering::SeqCst), 2);

    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        events.iter().any(|event| {
            event.event_type == "authz.denied"
                && event.payload["authorization_layer"] == json!("tool_playground_endpoint")
        }) && events.iter().any(|event| {
            event.event_type == audit::event::TOOL_INVOKE_SUCCESS
                && event.payload["invocation_source"] == json!("admin_playground")
        }) && events.iter().any(|event| {
            event.event_type == audit::event::TOOL_PLAYGROUND_OUTPUT_REJECTED
                && event.payload["invocation_source"] == json!("admin_playground")
                && event.payload["reason"] == json!("unsupported_output")
        })
    });
    let events = capture.events();
    let permission_denial = events
        .iter()
        .find(|event| {
            event.event_type == "authz.denied"
                && event.payload["authorization_layer"] == json!("tool_playground_endpoint")
        })
        .expect("execute-permission denial should be audited");
    assert_eq!(
        permission_denial.payload["invocation_source"],
        json!("admin_playground")
    );
    assert!(
        events.iter().any(|event| {
            event.event_type == audit::event::TOOL_INVOKE_SUCCESS
                && event.payload["invocation_source"] == json!("admin_playground")
        }),
        "normal execution audit events should retain playground provenance: {events:#?}"
    );
    let output_rejection = events
        .iter()
        .find(|event| {
            event.event_type == audit::event::TOOL_PLAYGROUND_OUTPUT_REJECTED
                && event.payload["invocation_source"] == json!("admin_playground")
        })
        .expect("the post-execution playground output gate should emit a rejection event");
    assert_eq!(
        output_rejection.payload,
        json!({
            "tool_name": "echo",
            "reason": "unsupported_output",
            "invocation_source": "admin_playground",
        })
    );
    let serialized_events = serde_json::to_string(&events).expect("audit events should serialize");
    assert!(
        !serialized_events.contains(argument_canary),
        "arguments and results must never enter playground audit payloads"
    );
    assert!(
        !serialized_events.contains(REJECTED_OUTPUT_CANARY),
        "rejected output bytes must never enter playground audit payloads"
    );
}

#[tokio::test]
async fn tool_playground_queued_execution_rechecks_live_execute_permission() {
    const FIRST_REQUEST_ID: &str = "playground-live-revocation-first";
    const SECOND_REQUEST_ID: &str = "playground-live-revocation-second";
    const SECOND_ARGUMENT_CANARY: &str = "playground-live-revocation-argument-canary";

    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let upstream = Router::new().route(
        "/v1/echo",
        post({
            let upstream_calls = Arc::clone(&upstream_calls);
            let first_started = Arc::clone(&first_started);
            let release_first = Arc::clone(&release_first);
            move |Json(arguments): Json<Value>| {
                let upstream_calls = Arc::clone(&upstream_calls);
                let first_started = Arc::clone(&first_started);
                let release_first = Arc::clone(&release_first);
                async move {
                    let call_index = upstream_calls.fetch_add(1, Ordering::SeqCst);
                    if call_index == 0 {
                        first_started.notify_one();
                        release_first.notified().await;
                    }
                    Json(json!({ "echoed": arguments }))
                }
            }
        }),
    );
    let upstream_addr = spawn_router(upstream).await;

    let mut initial_policy: Value = serde_json::from_str(
        &tools_policy_document_with_execute_route_permission(ADMIN_TOOLS_READ_PERMISSION),
    )
    .expect("initial playground policy should parse");
    initial_policy["tools"]["echo"]["max_concurrent"] = json!(1);
    initial_policy["rules"] = json!([{
        "id": "allow-admin-playground-echo",
        "tool_name": "echo",
        "principal": {
            "roles": ["admin"]
        },
        "action": "allow"
    }]);
    let mut revoked_policy = initial_policy.clone();
    revoked_policy["roles"]["admin"]["permissions"]
        .as_array_mut()
        .expect("admin permissions should be an array")
        .retain(|permission| permission.as_str() != Some(ADMIN_TOOLS_EXECUTE_PERMISSION));

    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let resolver = Arc::new(CountingDnsResolver {
        calls: AtomicUsize::new(0),
        address_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    });
    let resolver_trait: Arc<dyn egress::DnsResolver> = resolver.clone();
    let harness = tools_admin_harness_with_options(
        mcp_tools_document(),
        audit_log,
        format!("http://playground.test:{}", upstream_addr.port()),
        initial_policy.to_string(),
        |config| {
            config.egress_allowed_hosts = vec!["playground.test".to_owned()];
            config.tool_runtime_queue_depth = 8;
            config.tool_runtime_global_concurrency = 1;
            config.tool_runtime_queue_timeout_ms = 5_000;
        },
        GatewayAppBuildOverrides {
            egress_resolver: Some(resolver_trait),
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .await;

    let list_response = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.admin_token),
            &format!("{TOOLS_ADMIN_ROUTE}?text=echo"),
        ))
        .await
        .expect("tool inventory request should complete");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list = json_body(list_response).await;
    let capability_id = list["capabilities"][0]["id"]
        .as_str()
        .expect("echo should have an opaque capability ID")
        .to_owned();
    let detail_response = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.admin_token),
            &format!("{TOOLS_ADMIN_ROUTE}/{capability_id}"),
        ))
        .await
        .expect("tool detail request should complete");
    assert_eq!(detail_response.status(), StatusCode::OK);
    let execution_etag = detail_response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("tool detail should include an execution ETag")
        .to_owned();

    let mut first_request = tool_playground_request(
        Some(&harness.admin_token),
        &capability_id,
        Some(&execution_etag),
        Body::from(r#"{"arguments":{"message":"occupy-runtime-permit"}}"#),
    );
    first_request.headers_mut().insert(
        HeaderName::from_static(REQUEST_ID_HEADER),
        HeaderValue::from_static(FIRST_REQUEST_ID),
    );
    let first = tokio::spawn({
        let router = harness.router.clone();
        async move {
            router
                .oneshot(first_request)
                .await
                .expect("first playground request should complete")
        }
    });
    tokio::time::timeout(Duration::from_secs(2), first_started.notified())
        .await
        .expect("first request should occupy the runtime permit");
    let dns_calls_after_first = resolver.calls.load(Ordering::SeqCst);
    assert!(
        dns_calls_after_first > 0,
        "the first request should prove DNS and upstream work are instrumented"
    );

    let mut second_request = tool_playground_request(
        Some(&harness.admin_token),
        &capability_id,
        Some(&execution_etag),
        Body::from(format!(
            r#"{{"arguments":{{"message":"{SECOND_ARGUMENT_CANARY}"}}}}"#
        )),
    );
    second_request.headers_mut().insert(
        HeaderName::from_static(REQUEST_ID_HEADER),
        HeaderValue::from_static(SECOND_REQUEST_ID),
    );
    let second = tokio::spawn({
        let router = harness.router.clone();
        async move {
            router
                .oneshot(second_request)
                .await
                .expect("queued playground request should complete")
        }
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if capture.events().iter().any(|event| {
                event.request_id == SECOND_REQUEST_ID
                    && event.event_type == "authz.allowed"
                    && event.payload["matched_rule_id"] == json!("allow-admin-playground-echo")
                    && event.payload["invocation_source"] == json!("admin_playground")
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("second request should pass normal tool policy before queueing");
    assert!(
        !second.is_finished(),
        "the second request must still be queued behind the first"
    );

    harness._policy.write(&revoked_policy.to_string());
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let probe = harness
                .router
                .clone()
                .oneshot(tool_playground_request(
                    Some(&harness.admin_token),
                    &capability_id,
                    None,
                    Body::from("not-json"),
                ))
                .await
                .expect("permission reload probe should complete");
            assert_capability_inventory_no_store(&probe);
            if probe.status() == StatusCode::FORBIDDEN {
                break;
            }
            assert_eq!(
                probe.status(),
                StatusCode::PRECONDITION_REQUIRED,
                "the probe may only observe the old or revoked permission state"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("live policy should revoke the execute permission");

    release_first.notify_one();
    let first_response = tokio::time::timeout(Duration::from_secs(2), first)
        .await
        .expect("first playground task should finish")
        .expect("first playground task should join");
    assert_eq!(first_response.status(), StatusCode::OK);
    assert_capability_inventory_no_store(&first_response);
    let second_response = tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .expect("queued playground task should finish")
        .expect("queued playground task should join");
    assert_eq!(
        second_response.status(),
        StatusCode::PRECONDITION_FAILED,
        "permission revoked while queued must fail the final execution precondition"
    );
    assert_capability_inventory_no_store(&second_response);
    assert_eq!(
        json_body(second_response).await["reason"],
        json!("precondition_failed")
    );
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        1,
        "the revoked queued request must not reach the upstream"
    );
    assert_eq!(
        resolver.calls.load(Ordering::SeqCst),
        dns_calls_after_first,
        "the revoked queued request must not start another DNS resolution"
    );

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if capture.events().iter().any(|event| {
                event.request_id == SECOND_REQUEST_ID
                    && event.event_type == audit::event::TOOL_INVOKE_REJECTED
                    && event.payload["reason"] == json!("precondition_failed")
                    && event.payload["invocation_source"] == json!("admin_playground")
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("queued permission revocation should emit a safe rejection audit");
    let second_events = capture
        .events()
        .into_iter()
        .filter(|event| event.request_id == SECOND_REQUEST_ID)
        .collect::<Vec<_>>();
    assert!(second_events.iter().all(|event| {
        event.event_type != audit::event::TOOL_UPSTREAM_REQUEST
            && event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED
    }));
    let serialized_events =
        serde_json::to_string(&second_events).expect("audit events should serialize");
    assert!(
        !serialized_events.contains(SECOND_ARGUMENT_CANARY),
        "queued request arguments must not enter audit payloads"
    );
}

#[tokio::test]
async fn tool_playground_preserves_arbitrary_precision_numbers_to_http_upstream() {
    const INPUT_ARGUMENTS: &str = r#"{"beyond_u64":18446744073709551616,"high_precision_decimal":0.123456789012345678901234567890123456789,"huge_exponent":1e400}"#;
    const EXPECTED_UPSTREAM_BODY: &str = r#"{"beyond_u64":18446744073709551616,"high_precision_decimal":0.123456789012345678901234567890123456789,"huge_exponent":1e+400}"#;

    let captured_body = Arc::new(Mutex::new(None::<String>));
    let upstream = Router::new().route(
        "/v1/echo",
        post({
            let captured_body = Arc::clone(&captured_body);
            move |body: Bytes| {
                let captured_body = Arc::clone(&captured_body);
                async move {
                    let body = String::from_utf8(body.to_vec())
                        .expect("playground upstream body should be UTF-8 JSON");
                    *captured_body
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(body);
                    Json(json!({ "accepted": true }))
                }
            }
        }),
    );
    let upstream_addr = spawn_router(upstream).await;
    let tools_document = json!({
        "schema_version": "0.1.0",
        "tools": [{
            "name": "echo",
            "description": "Preserves arbitrary-precision numeric arguments.",
            "input_json_schema": {
                "type": "object",
                "required": ["beyond_u64", "high_precision_decimal", "huge_exponent"],
                "properties": {
                    "beyond_u64": { "type": "integer" },
                    "high_precision_decimal": { "type": "number" },
                    "huge_exponent": { "type": "number" }
                },
                "additionalProperties": false
            },
            "upstream": {
                "method": "POST",
                "path_template": "/v1/echo",
                "body": {
                    "mode": "whole_args_json"
                }
            }
        }]
    })
    .to_string();
    let harness = tools_admin_harness_with_upstream(
        tools_document,
        test_audit_log(),
        format!("http://{upstream_addr}"),
    )
    .await;

    let list_response = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.admin_token),
            &format!("{TOOLS_ADMIN_ROUTE}?text=echo"),
        ))
        .await
        .expect("tool inventory request should complete");
    assert_eq!(list_response.status(), StatusCode::OK);
    let list = json_body(list_response).await;
    let capability_id = list["capabilities"][0]["id"]
        .as_str()
        .expect("echo should have an opaque capability ID")
        .to_owned();
    let detail_response = harness
        .router
        .clone()
        .oneshot(tools_inventory_request(
            Some(&harness.admin_token),
            &format!("{TOOLS_ADMIN_ROUTE}/{capability_id}"),
        ))
        .await
        .expect("tool detail request should complete");
    assert_eq!(detail_response.status(), StatusCode::OK);
    let execution_etag = detail_response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("tool detail should include an execution ETag")
        .to_owned();

    let response = harness
        .router
        .oneshot(tool_playground_request(
            Some(&harness.admin_token),
            &capability_id,
            Some(&execution_etag),
            Body::from(format!(r#"{{"arguments":{INPUT_ARGUMENTS}}}"#)),
        ))
        .await
        .expect("arbitrary-precision playground request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_capability_inventory_no_store(&response);
    assert_eq!(
            captured_body
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_deref(),
            Some(EXPECTED_UPSTREAM_BODY),
            "the endpoint parser and whole-args HTTP mapping must preserve exact numeric values; serde_json may normalize the positive exponent sign"
        );
}

#[tokio::test]
async fn openapi_tools_preview_returns_generated_tools_and_current_tools_etag() {
    let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;

    let response = harness
        .router
        .clone()
        .oneshot(tools_openapi_preview_request(
            &harness.admin_token,
            widget_openapi_spec(),
        ))
        .await
        .expect("OpenAPI tools preview request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("preview response should include current tools ETag")
        .to_owned();
    assert!(
        etag.starts_with("\"sha256:"),
        "tools ETag should be a quoted sha256 digest: {etag}"
    );
    let body = json_body(response).await;

    let tools = body["tools"]
        .as_array()
        .expect("preview response should include tools");
    assert_eq!(tools.len(), 2);
    let create_widget = tools
        .iter()
        .find(|tool| tool["name"] == json!("createWidget"))
        .expect("createWidget should be generated");
    assert_eq!(create_widget["upstream"]["method"], json!("POST"));
    assert_eq!(
        create_widget["upstream"]["path_template"],
        json!("/widgets")
    );
    let get_widget = tools
        .iter()
        .find(|tool| tool["name"] == json!("getWidget"))
        .expect("getWidget should be generated");
    assert_eq!(get_widget["upstream"]["method"], json!("GET"));
    assert_eq!(
        body["api_key_header_auth_requirements"],
        json!([
            {
                "tool_name": "getWidget",
                "method": "GET",
                "path_template": "/widgets/{widgetId}",
                "scheme_name": "ApiKeyAuth",
                "header_name": "X-API-Key"
            }
        ])
    );
    assert_eq!(body["skipped_operations"], json!([]));
}

#[tokio::test]
async fn openapi_tools_preview_accepts_spec_content_types() {
    for content_type in [
        "text/plain; charset=utf-8",
        "application/yaml",
        "application/x-yaml",
    ] {
        let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;

        let response = harness
            .router
            .oneshot(tools_openapi_preview_request_with_content_type(
                &harness.admin_token,
                widget_openapi_spec(),
                content_type,
            ))
            .await
            .expect("OpenAPI tools preview request should complete");

        assert_eq!(response.status(), StatusCode::OK, "{content_type}");
        let body = json_body(response).await;
        assert!(
            body["tools"]
                .as_array()
                .expect("preview response should include tools")
                .iter()
                .any(|tool| tool["name"] == json!("createWidget")),
            "preview response should include createWidget for {content_type}: {body}"
        );
    }
}

#[tokio::test]
async fn openapi_tools_preview_rejects_invalid_spec_without_500() {
    let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;

    let response = harness
        .router
        .oneshot(tools_openapi_preview_request(
            &harness.admin_token,
            "openapi: [",
        ))
        .await
        .expect("invalid OpenAPI tools preview request should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert!(
        body["error"]
            .as_str()
            .expect("error response should include message")
            .contains("invalid OpenAPI spec"),
        "unexpected body: {body}"
    );
}

#[tokio::test]
async fn openapi_tools_preview_requires_read_permission_and_tools_file() {
    let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;

    let forbidden = harness
        .router
        .clone()
        .oneshot(tools_openapi_preview_request(
            &harness.blocked_token,
            widget_openapi_spec(),
        ))
        .await
        .expect("read-forbidden OpenAPI tools preview request should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert_managed_admin_no_store(&forbidden);

    let policy = TempPolicyFile::new(&tools_policy_document());
    let token_db = TempDb::new("tools-preview-no-tools-file-token");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let admin_token = create_service_token(&token_store, &["admin"]);
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build without TOOLS_FILE");

    let not_configured = router
        .oneshot(tools_openapi_preview_request(
            &admin_token,
            widget_openapi_spec(),
        ))
        .await
        .expect("tools-file-unconfigured OpenAPI tools preview request should complete");
    assert_eq!(not_configured.status(), StatusCode::NOT_FOUND);
    assert_managed_admin_no_store(&not_configured);
    assert_eq!(
        body_string(not_configured).await,
        r#"{"error":"tools API requires TOOLS_FILE to be configured"}"#
    );
}

#[tokio::test]
async fn openapi_tools_register_persists_selection_reloads_registry_and_audits() {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
    let harness = tools_admin_harness(empty_tools_document(), audit_log).await;
    let preview = harness
        .router
        .clone()
        .oneshot(tools_openapi_preview_request(
            &harness.admin_token,
            widget_openapi_spec(),
        ))
        .await
        .expect("OpenAPI tools preview request should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let etag = preview
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("preview should include ETag")
        .to_owned();

    let register = harness
        .router
        .clone()
        .oneshot(tools_openapi_register_request(
            &harness.admin_token,
            json!({
                "spec": widget_openapi_spec(),
                "selected_tool_names": ["createWidget"]
            }),
            Some(&etag),
        ))
        .await
        .expect("OpenAPI tools register request should complete");

    assert_eq!(register.status(), StatusCode::CREATED);
    let register_body = json_body(register).await;
    assert_eq!(
        register_body["registered_tool_names"],
        json!(["createWidget"])
    );
    assert_eq!(register_body["tool_count"], json!(1));
    let persisted = fs::read_to_string(&harness.tools.path).expect("tools file should read");
    let persisted: Value = serde_json::from_str(&persisted).expect("tools file should remain JSON");
    assert_eq!(persisted["tools"][0]["name"], json!("createWidget"));

    let (list_status, list_body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        41,
        "tools/list",
        None,
        "mcp-list-after-openapi-register",
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    let listed_tools = list_body["result"]["tools"]
        .as_array()
        .expect("tools/list response should include tools");
    assert!(
        listed_tools
            .iter()
            .any(|tool| tool["name"] == json!("createWidget")),
        "registered tool should be visible through live MCP tools/list: {list_body}"
    );

    let event = captured_tool_registry_change(&capture, "openapi_tools_registered");
    assert_eq!(
        event.payload["registered_tool_names"],
        json!(["createWidget"])
    );
    assert_eq!(event.payload["registered_tool_count"], json!(1));
    assert_eq!(event.payload["tool_count"], json!(1));
    let actor = event.actor.as_ref().expect("actor should be set");
    assert_eq!(actor.roles, Some(vec!["admin".to_owned()]));
}

#[tokio::test]
async fn openapi_tools_register_rejects_name_collisions_without_partial_persist() {
    let harness = tools_admin_harness(
        json!({
            "schema_version": "0.1.0",
            "tools": [
                {
                    "name": "createWidget",
                    "description": "Existing hand-authored widget creator.",
                    "input_json_schema": {
                        "type": "object",
                        "properties": {
                            "message": { "type": "string" }
                        },
                        "additionalProperties": false
                    },
                    "upstream": {
                        "method": "POST",
                        "path_template": "/manual/widgets",
                        "body": { "mode": "whole_args_json" }
                    }
                }
            ]
        })
        .to_string(),
        test_audit_log(),
    )
    .await;
    let before_contents = fs::read_to_string(&harness.tools.path).expect("tools file should read");
    let preview = harness
        .router
        .clone()
        .oneshot(tools_openapi_preview_request(
            &harness.admin_token,
            widget_openapi_spec(),
        ))
        .await
        .expect("OpenAPI tools preview request should complete");
    let etag = preview
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("preview should include ETag")
        .to_owned();

    let response = harness
        .router
        .oneshot(tools_openapi_register_request(
            &harness.admin_token,
            json!({
                "spec": widget_openapi_spec(),
                "selected_tool_names": ["createWidget"]
            }),
            Some(&etag),
        ))
        .await
        .expect("colliding OpenAPI tools register request should complete");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert_eq!(body["error"], json!("tool name collision"));
    assert_eq!(body["conflicts"], json!(["createWidget"]));
    assert_eq!(
        fs::read_to_string(&harness.tools.path).expect("tools file should read"),
        before_contents,
        "colliding register must not partially persist selected tools"
    );
}

#[tokio::test]
async fn openapi_tools_register_rejects_auth_required_tools_without_partial_persist() {
    let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;
    let before_contents = fs::read_to_string(&harness.tools.path).expect("tools file should read");
    let preview = harness
        .router
        .clone()
        .oneshot(tools_openapi_preview_request(
            &harness.admin_token,
            widget_openapi_spec(),
        ))
        .await
        .expect("OpenAPI tools preview request should complete");
    let etag = preview
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("preview should include ETag")
        .to_owned();

    let response = harness
        .router
        .oneshot(tools_openapi_register_request(
            &harness.admin_token,
            json!({
                "spec": widget_openapi_spec(),
                "selected_tool_names": ["createWidget", "getWidget"]
            }),
            Some(&etag),
        ))
        .await
        .expect("auth-required OpenAPI tools register request should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(
            body["error"],
            json!("cannot register selected OpenAPI tools: upstream API-key header injection is not yet supported; see issue #36's known limitation")
        );
    assert_eq!(body["unsupported_tool_names"], json!(["getWidget"]));
    assert_eq!(
        fs::read_to_string(&harness.tools.path).expect("tools file should read"),
        before_contents,
        "auth-required register must not partially persist selected tools"
    );
}

#[tokio::test]
async fn openapi_tools_register_requires_write_permission() {
    let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;
    let preview = harness
        .router
        .clone()
        .oneshot(tools_openapi_preview_request(
            &harness.admin_token,
            widget_openapi_spec(),
        ))
        .await
        .expect("OpenAPI tools preview request should complete");
    let etag = preview
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("preview should include ETag")
        .to_owned();

    let forbidden = harness
        .router
        .oneshot(tools_openapi_register_request(
            &harness.reader_token,
            json!({
                "spec": widget_openapi_spec(),
                "selected_tool_names": ["createWidget"]
            }),
            Some(&etag),
        ))
        .await
        .expect("write-forbidden OpenAPI tools register request should complete");

    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
}

async fn tools_admin_harness(
    tools_document: String,
    audit_log: audit::AuditLog,
) -> ToolsAdminTestHarness {
    tools_admin_harness_with_upstream(
        tools_document,
        audit_log,
        "http://127.0.0.1:65535".to_owned(),
    )
    .await
}

async fn tools_admin_harness_with_upstream(
    tools_document: String,
    audit_log: audit::AuditLog,
    upstream_url: String,
) -> ToolsAdminTestHarness {
    tools_admin_harness_with_policy_and_upstream(
        tools_document,
        audit_log,
        upstream_url,
        tools_policy_document(),
    )
    .await
}

async fn tools_admin_harness_with_policy_and_upstream(
    tools_document: String,
    audit_log: audit::AuditLog,
    upstream_url: String,
    policy_document: String,
) -> ToolsAdminTestHarness {
    tools_admin_harness_with_options(
        tools_document,
        audit_log,
        upstream_url,
        policy_document,
        |_| {},
        GatewayAppBuildOverrides::default(),
    )
    .await
}

fn tools_openapi_preview_request(token: &str, spec: &str) -> Request<Body> {
    tools_openapi_preview_request_with_content_type(token, spec, "text/plain; charset=utf-8")
}

fn tools_openapi_preview_request_with_content_type(
    token: &str,
    spec: &str,
    content_type: &str,
) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(spec.to_owned()))
        .expect("OpenAPI tools preview request should build")
}

// ------------------------------------------------------------------
// Cluster-mode tools control plane (issue #241, PR 8): seeding, CAS,
// the multi-resource gate, and reconciliation against a real
// PostgreSQL. Docker-gated on the same locator as the storage suites.
// ------------------------------------------------------------------

#[cfg(feature = "postgres")]
mod cluster_tools_tests {
    use super::*;
    use crate::security_cluster::{ClusterSecurityRuntime, PolicyResource, ToolsResource};
    use crate::storage::postgres::PostgresFoundation;
    use crate::storage::postgres_policy::PostgresPolicyStore;
    use crate::storage::postgres_tools::PostgresToolStore;
    use crate::storage::{
        self, migrations, PolicyCommitPrecondition, PolicyCommitRequest, PolicyControlPlane,
    };
    use crate::tools::definitions::ToolRegistry;

    fn locator() -> Option<String> {
        let key = "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned();
        let file = std::env::var(&key).ok()?;
        if file.trim().is_empty() {
            return None;
        }
        let contents = std::fs::read_to_string(file).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    struct DsnFile {
        path: String,
        directory: std::path::PathBuf,
    }

    impl Drop for DsnFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn write_dsn_file(dsn: &str) -> DsnFile {
        let directory = std::env::temp_dir().join(format!(
            "greengateway-cluster-tools-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory should create");
        let path = directory.join("database-url");
        std::fs::write(&path, format!("{dsn}\n")).expect("DSN file should write");
        // The foundation's permission check is part of the contract:
        // credential material grants group/other nothing. On Unix CI
        // the default mode would be 0644, which the check (correctly)
        // refuses.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("DSN permissions should set");
        }
        DsnFile {
            path: path.display().to_string(),
            directory,
        }
    }

    struct TestDatabase {
        dsn: String,
        admin_dsn: String,
        name: String,
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let admin_dsn = self.admin_dsn.clone();
            let name = self.name.clone();
            std::thread::spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let Ok((client, connection)) =
                        tokio_postgres::connect(&admin_dsn, tokio_postgres::NoTls).await
                    else {
                        return;
                    };
                    let connection = tokio::spawn(connection);
                    let _ = client
                        .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                        .await;
                    let _ = connection.await;
                });
            });
        }
    }

    async fn create_test_database(admin_dsn: &str) -> TestDatabase {
        let name = format!("ggw_tools_test_{}", uuid::Uuid::new_v4().simple());
        let (client, connection) = tokio_postgres::connect(admin_dsn, tokio_postgres::NoTls)
            .await
            .expect("admin connection");
        let connection_task = tokio::spawn(connection);
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .expect("test database should create");
        drop(client);
        let _ = connection_task.await;
        let database_start = admin_dsn
            .rfind('/')
            .expect("locator DSN has a database path segment");
        let dsn = format!("{}/{}", &admin_dsn[..database_start], name);
        TestDatabase {
            dsn,
            admin_dsn: admin_dsn.to_owned(),
            name,
        }
    }

    async fn migrated_stores(
        dsn: &str,
    ) -> (
        Arc<PostgresPolicyStore>,
        Arc<PostgresToolStore>,
        deadpool_postgres::Pool,
    ) {
        let dsn_file = write_dsn_file(dsn);
        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-cluster-tools".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("schema should migrate");
        let pool = foundation.pool().clone();
        (
            Arc::new(PostgresPolicyStore::new(pool.clone())),
            Arc::new(PostgresToolStore::new(pool.clone())),
            pool,
        )
    }

    fn tools_document_with(tool_name: &str) -> Value {
        json!({
            "schema_version": "0.1.0",
            "tools": [{
                "name": tool_name,
                "description": "Echoes the provided message.",
                "input_json_schema": {
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": { "type": "string" }
                    },
                    "additionalProperties": false
                },
                "upstream": {
                    "method": "POST",
                    "path_template": "/v1/echo",
                    "body": { "mode": "whole_args_json" }
                }
            }]
        })
    }

    static DIFF: std::sync::LazyLock<Value> =
        std::sync::LazyLock::new(|| json!({ "action": "test" }));

    fn cluster_policy(id: &str) -> rbac::Policy {
        parse_policy_body(&Bytes::from(format!(
                r#"{{
                    "schema_version": "0.1.0",
                    "id": "{id}",
                    "default_action": "deny",
                    "roles": {{
                        "admin": {{ "permissions": ["admin:policy:read", "admin:policy:write", "admin:tools:write"] }}
                    }}
                }}"#
            )))
            .expect("cluster policy should parse")
    }

    #[tokio::test]
    async fn tools_control_plane_seeds_once_and_commits_with_cas() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (policy_store, tools_store, pool) = migrated_stores(&database.dsn).await;

        // The policy plane initializes first (its startup contract).
        PolicyControlPlane::commit(
            &*policy_store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &cluster_policy("tools-cas"),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("policy should initialize");

        // Two replicas' first boots seed concurrently: exactly one
        // seeded document exists afterwards.
        let (seed_a, seed_b) = tokio::join!(
            tools_store.seed_empty_document(),
            tools_store.seed_empty_document()
        );
        seed_a.expect("replica A seed");
        seed_b.expect("replica B seed");
        let active = tools_store
            .active_tools()
            .await
            .expect("active tools read")
            .expect("seeded document exists");
        assert_eq!(
            active.document["tools"]
                .as_array()
                .expect("tools array")
                .len(),
            0,
            "the seeded document is the empty local lane"
        );

        // A commit with the current ETag wins and advances the shared
        // revision; the same ETag loses afterwards with 412 semantics
        // and writes nothing.
        let winner = tools_store
            .commit_tools(
                PolicyCommitPrecondition::Expected {
                    etag: active.etag.clone(),
                },
                &tools_document_with("cluster_echo"),
                crate::storage::DocumentChange::test_tools("op-1"),
                &DIFF,
            )
            .await
            .expect("tools commit should win");
        assert!(winner.security_revision > active.security_revision);
        let loser = tools_store
            .commit_tools(
                PolicyCommitPrecondition::Expected {
                    etag: active.etag.clone(),
                },
                &tools_document_with("cluster_other"),
                crate::storage::DocumentChange::test_tools("op-2"),
                &DIFF,
            )
            .await
            .expect_err("the stale ETag must lose");
        assert_eq!(
            loser,
            storage::PolicyCommitError::PreconditionFailed,
            "{loser}"
        );

        // One seeded version plus one committed version; the outbox
        // rows carry the tools resource type.
        let client = pool.get().await.expect("count checkout");
        let documents: i64 = client
            .query_one("SELECT count(*) FROM greengateway.tool_documents", &[])
            .await
            .expect("count")
            .get(0);
        assert_eq!(documents, 2, "seeding and the winning commit only");
        let outbox_tools: i64 = client
            .query_one(
                "SELECT count(*) FROM greengateway.security_outbox WHERE resource_type = 'tools'",
                &[],
            )
            .await
            .expect("count")
            .get(0);
        assert_eq!(outbox_tools, 2, "seed + commit each wrote one record");
    }

    #[tokio::test]
    async fn a_tools_revision_does_not_livelock_the_security_gate() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (policy_store, tools_store, _pool) = migrated_stores(&database.dsn).await;

        let active_policy = PolicyControlPlane::commit(
            &*policy_store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &cluster_policy("gate-tools"),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("policy should initialize");
        tools_store
            .seed_empty_document()
            .await
            .expect("tools should seed");

        // A replica boots with both resources registered.
        let rbac_state = middleware::rbac::RbacState::new(
            active_policy.policy.clone(),
            Vec::new(),
            false,
            test_audit_log(),
        );
        rbac_state
            .install_revision_snapshot(
                active_policy.policy.clone(),
                active_policy.security_revision,
            )
            .await
            .expect("the authority's revision should install");
        let registry =
            ToolRegistry::from_definitions_with_audit(Vec::new(), Some(test_audit_log()));
        let boot_tools = tools_store
            .active_tools()
            .await
            .expect("active tools read")
            .expect("seeded");
        let runtime = ClusterSecurityRuntime::new(
            policy_store.revision_source(),
            PolicyResource::new(policy_store.clone(), rbac_state.clone()),
        );
        runtime.register_resource(ToolsResource::new(
            tools_store.clone(),
            registry.clone(),
            boot_tools.security_revision,
        ));

        // The pin: with the PR 7 policy-only gate, any revision the
        // POLICY did not produce (the tools seeding above already
        // bumped the counter past the policy activation) sent every
        // replica into a reconcile loop it could not win until the
        // 250ms deadline, failing closed on healthy state. The
        // multi-resource gate must reconcile the tools resource (a
        // no-op at the boot revision) and return Ok.
        //
        // Livelock is counted, not timed. Each pass is a handful of
        // round trips to the shared authority, so on a loaded machine
        // a healthy pass can spend the 250ms request budget and fail
        // closed for reasons that have nothing to do with looping --
        // whereas a gate that truly cannot converge spins the loop
        // until whatever budget it is given expires. The passes the
        // gate takes are therefore what distinguishes the two, and the
        // budget is not: these calls run on the background budget so
        // load cannot fail them, and the assertions below pin
        // convergence to a bounded number of passes. That is strictly
        // sharper than the deadline was -- a regression that looped a
        // few times and then converged used to pass and now does not.
        // The 250ms request deadline keeps its own dedicated guard in
        // `the_background_pass_outlives_the_request_deadline`.
        let before = runtime.admit_passes_for_test();
        let served = runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("a tools-only revision must not livelock the gate");
        assert!(
            runtime.admit_passes_for_test() - before <= 2,
            "a tools-only revision must converge in a bounded number of gate passes, took {}",
            runtime.admit_passes_for_test() - before
        );
        assert!(
            served >= boot_tools.security_revision,
            "the compiled watermark covers the tools revision ({served} < {})",
            boot_tools.security_revision
        );

        // A tools COMMIT after boot: the gate must observe it, install
        // the new local lane, and stay current -- still no loop.
        let committed = tools_store
            .commit_tools(
                PolicyCommitPrecondition::Expected {
                    etag: boot_tools.etag.clone(),
                },
                &tools_document_with("post_boot_tool"),
                crate::storage::DocumentChange::test_tools("op"),
                &DIFF,
            )
            .await
            .expect("tools commit should win");
        let before = runtime.admit_passes_for_test();
        let served = runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("the gate must reconcile a tools commit, not loop");
        assert!(
            runtime.admit_passes_for_test() - before <= 2,
            "a tools commit must converge in a bounded number of gate passes, took {}",
            runtime.admit_passes_for_test() - before
        );
        assert_eq!(served, committed.security_revision);
        assert!(
            registry
                .current_local_definitions()
                .iter()
                .any(|tool| tool.name == "post_boot_tool"),
            "reconciliation must install the committed local lane"
        );
        // The policy snapshot is untouched: a tools revision re-reads
        // the policy authority but must not change the active policy.
        assert_eq!(
            rbac_state.current_policy().id.as_deref(),
            Some("gate-tools")
        );
    }

    /// A revoke committed through one replica is refused by the very
    /// next request on another replica, inside that replica's cache
    /// TTL. This is the property the documented standalone caveat
    /// ("revocations made in another process take effect no later
    /// than the TTL") gives up, and the one cluster mode must hold.
    #[tokio::test]
    async fn a_revoke_on_one_replica_is_refused_by_the_next_request_on_another() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (_policy_store, _tools_store, pool) = migrated_stores(&database.dsn).await;
        let store = Arc::new(storage::PostgresServiceTokenStore::new(pool.clone()));
        let created = storage::ServiceTokenStore::create(
            &*store,
            auth::tokens::CreateTokenRequest {
                scopes: vec!["admin:tokens:read".to_owned()],
                created_by: "seed".to_owned(),
                expires_at: None,
            },
        )
        .await
        .expect("token should create");
        let replica = || {
            Arc::new(
                auth::ServiceTokenValidator::new(
                    store.clone() as Arc<dyn storage::ServiceTokenStore>,
                    Duration::from_secs(60),
                )
                .with_revision_source(Arc::new(store.revision_source())),
            )
        };
        let replica_a = replica();
        let replica_b = replica();
        let bearer = auth::SessionCredential::Bearer(created.plaintext_token.clone());

        auth::SessionValidator::validate_session(&*replica_a, &bearer)
            .await
            .expect("replica A accepts and caches");
        auth::SessionValidator::validate_session(&*replica_b, &bearer)
            .await
            .expect("replica B accepts and caches");

        // The revoke commits through replica A's admin path.
        storage::ServiceTokenStore::revoke(
            &*store,
            &created.record.id,
            &auth::change_actor::ChangeActor::for_test("revoking-admin"),
        )
        .await
        .expect("revoke should commit")
        .expect("token exists");

        // Replica B's very next request, 60 s of TTL to spare.
        let refused = auth::SessionValidator::validate_session(&*replica_b, &bearer)
            .await
            .expect_err("the revoked token must be refused on the next request");
        assert!(
            matches!(refused, auth::AuthError::InvalidSession(_)),
            "refused as an invalid credential, got {refused:?}"
        );
    }

    /// A register that paused between its commit and its install must
    /// not roll the live lane back over a newer commit the reconciler
    /// already installed. Pinned at the adapter: install N+1, then try
    /// to install N.
    #[tokio::test]
    async fn a_stale_tools_install_never_rolls_the_live_lane_back() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (_policy_store, tools_store, _pool) = migrated_stores(&database.dsn).await;
        tools_store
            .seed_empty_document()
            .await
            .expect("tools should seed");
        let registry =
            ToolRegistry::from_definitions_with_audit(Vec::new(), Some(test_audit_log()));
        let resource = ToolsResource::new(tools_store.clone(), registry.clone(), 0);

        let older = tools_document_with("older_tool");
        let newer = tools_document_with("newer_tool");
        let older_definitions =
            tools::definitions::definitions_from_json_value(older, None).expect("older");
        let newer_definitions =
            tools::definitions::definitions_from_json_value(newer, None).expect("newer");

        // Revision 11 is live; a register committed at 10 resumes late.
        assert!(resource
            .install_committed(newer_definitions, 11)
            .await
            .expect("the newer lane installs"));
        assert!(
            !resource
                .install_committed(older_definitions, 10)
                .await
                .expect("the older install is refused, not failed"),
            "an older commit must not install over a newer live lane"
        );
        let live = registry.current_local_definitions();
        assert!(live.iter().any(|tool| tool.name == "newer_tool"));
        assert!(
            !live.iter().any(|tool| tool.name == "older_tool"),
            "the live lane is still revision 11's"
        );
    }

    /// A resource registered after the gate already confirmed a
    /// watermark must be reconciled on the next check. Without the
    /// reset on registration, the watermark would already cover the
    /// resource's commits and every later check would return early
    /// with the resource stale.
    #[tokio::test]
    async fn a_resource_registered_after_the_watermark_advanced_is_reconciled() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (policy_store, _tools_store, pool) = migrated_stores(&database.dsn).await;
        let connection_store = Arc::new(
            connections::pg_store::PostgresConnectionStore::new(
                pool.clone(),
                connections::model::MAX_CONNECTIONS,
            )
            .expect("connection store should build"),
        );
        let active_policy = PolicyControlPlane::commit(
            &*policy_store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &cluster_policy("gate-late-register"),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("policy should initialize");
        // A connection commit lands BEFORE the connections resource is
        // registered -- the startup window the poller could observe.
        connection_store
            .create(cluster_connection_candidate(), "op", None)
            .await
            .expect("connection create should commit");
        let committed_at = connection_store
            .state_revision()
            .await
            .expect("connections state revision should read");

        let rbac_state = middleware::rbac::RbacState::new(
            active_policy.policy.clone(),
            Vec::new(),
            false,
            test_audit_log(),
        );
        rbac_state
            .install_revision_snapshot(
                active_policy.policy.clone(),
                active_policy.security_revision,
            )
            .await
            .expect("the authority's revision should install");
        let runtime = ClusterSecurityRuntime::new(
            policy_store.revision_source(),
            PolicyResource::new(policy_store.clone(), rbac_state.clone()),
        );
        // Both passes run on the background budget, not the 250 ms
        // request deadline: what is under test is *which* resources a
        // pass confirms, not how fast a pass runs. Each pass is a
        // handful of round trips to the authority, and on a loaded
        // machine those alone can spend the request budget -- a
        // `ReconcileDeadlineExceeded` here says nothing about the
        // watermark reset. The assertions below are budget-independent:
        // without the reset on registration the second pass returns
        // early on a watermark that already covers `committed_at`, the
        // recording resource is never reconciled, and `reconciled`
        // stays 0 however long the pass is given.
        // Policy alone confirms a watermark past the connection commit.
        let served = runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("policy-only pass serves");
        assert!(served >= committed_at);

        // Late registration, then the next check.
        let reconciled = Arc::new(std::sync::atomic::AtomicI64::new(0));
        runtime.register_resource(Arc::new(RecordingConnectionsResource {
            store: connection_store.clone(),
            reconciled: reconciled.clone(),
        }));
        runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("the check after registration serves");
        assert_eq!(
            reconciled.load(std::sync::atomic::Ordering::Acquire),
            committed_at,
            "the late-registered resource must be reconciled by the next check"
        );
    }

    /// The background pass has its own budget. A resource whose
    /// reconcile takes longer than the request deadline fails a
    /// request closed, but the background pass -- the one that does the
    /// work -- must be allowed to finish, or the replica never becomes
    /// current.
    #[tokio::test]
    async fn the_background_pass_outlives_the_request_deadline() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (policy_store, _tools_store, pool) = migrated_stores(&database.dsn).await;
        let connection_store = Arc::new(
            connections::pg_store::PostgresConnectionStore::new(
                pool.clone(),
                connections::model::MAX_CONNECTIONS,
            )
            .expect("connection store should build"),
        );
        let active_policy = PolicyControlPlane::commit(
            &*policy_store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &cluster_policy("gate-budget"),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("policy should initialize");
        connection_store
            .create(cluster_connection_candidate(), "op", None)
            .await
            .expect("connection create should commit");

        let rbac_state = middleware::rbac::RbacState::new(
            active_policy.policy.clone(),
            Vec::new(),
            false,
            test_audit_log(),
        );
        rbac_state
            .install_revision_snapshot(
                active_policy.policy.clone(),
                active_policy.security_revision,
            )
            .await
            .expect("the authority's revision should install");
        let runtime = ClusterSecurityRuntime::new(
            policy_store.revision_source(),
            PolicyResource::new(policy_store.clone(), rbac_state.clone()),
        );
        runtime.register_resource(Arc::new(SlowConnectionsResource {
            store: connection_store.clone(),
            delay: Duration::from_millis(600),
        }));

        let request =
            middleware::rbac::SecurityRevisionGate::ensure_current_revision(&*runtime).await;
        assert_eq!(
            request.err(),
            Some(middleware::rbac::SecurityRevisionCheckError::ReconcileDeadlineExceeded),
            "a request cannot wait out a slow reconcile"
        );

        // The refusal that request just took is the fact readiness
        // reads. It is recorded by the gate as it happens, so a
        // probe sees a replica failing protected traffic closed
        // even though this failure moved neither watermark -- the
        // counter read succeeded, the reconcile is what ran out of
        // budget.
        assert!(
            runtime.admission_failing_for().is_some(),
            "a refused admission starts the failing streak the probe reads"
        );
        let readiness = ha::ClusterReadiness::new();
        readiness.record_fingerprint_agreement();
        let probe = ha_status::ReadinessProbe::new(
            readiness,
            ha_status::test_support::ScriptedAuthority::healthy(9),
            Some(runtime.clone()),
            ha_status::ReadinessProbeSettings {
                revision_reconcile_grace: Duration::ZERO,
                ..ha_status::test_support::healthy_settings()
            },
        );
        assert_eq!(
            probe.blocked_reason().await,
            Some(ha_status::SECURITY_REVISION_NOT_COMPILED),
            "a gate refusing past its grace is not ready, whatever the watermarks read"
        );

        runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("the background budget lets the slow reconcile finish");
        middleware::rbac::SecurityRevisionGate::ensure_current_revision(&*runtime)
            .await
            .expect("once reconciled, requests serve inside their own deadline");
        assert_eq!(
            runtime.admission_failing_for(),
            None,
            "one admission clears the streak"
        );
        assert_eq!(
            probe.blocked_reason().await,
            None,
            "a replica admitting requests is ready again on the next probe"
        );
    }

    /// A resource whose reconcile is deliberately slower than the
    /// request deadline.
    struct SlowConnectionsResource {
        store: Arc<connections::pg_store::PostgresConnectionStore>,
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl security_cluster::ReconciledResource for SlowConnectionsResource {
        fn name(&self) -> &'static str {
            "slow-connections"
        }

        async fn activation_revision(
            &self,
        ) -> Result<i64, middleware::rbac::SecurityRevisionCheckError> {
            self.store
                .state_revision()
                .await
                .map_err(|_| middleware::rbac::SecurityRevisionCheckError::Unavailable)
        }

        async fn reconcile(
            &self,
            _compiled_revision: i64,
        ) -> Result<(), middleware::rbac::SecurityRevisionCheckError> {
            tokio::time::sleep(self.delay).await;
            Ok(())
        }
    }

    /// The connections resource must keep reconciling after an
    /// unrelated resource has moved the shared counter.
    ///
    /// This pins a defect that compiled, passed every other test, and
    /// would have silently disabled cluster-mode Connection
    /// reconciliation in production. `connection_state_revision` was
    /// being incremented on its own (`last_revision + 1`) rather than
    /// set to the shared security revision the committing transaction
    /// had just taken. The gate compares a resource's activation
    /// revision against a watermark of the SHARED counter, which policy
    /// and tools commits also advance -- so a private counter drifts
    /// permanently below the watermark, `activation > compiled` stops
    /// being true, and connection commits stop triggering
    /// `ConnectionsResource::reconcile` on every replica. Replicas
    /// would keep serving withdrawn upstreams and stale credential
    /// bindings, which is exactly the stale-allow the gate exists to
    /// prevent.
    ///
    /// The shape below is what makes it visible: commit tools FIRST so
    /// the shared counter runs ahead of anything connections has ever
    /// written, and only then commit a connection.
    #[tokio::test]
    async fn a_connection_commit_reconciles_after_another_resource_moved_the_counter() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (policy_store, tools_store, pool) = migrated_stores(&database.dsn).await;
        let connection_store = Arc::new(
            connections::pg_store::PostgresConnectionStore::new(
                pool.clone(),
                connections::model::MAX_CONNECTIONS,
            )
            .expect("connection store should build"),
        );

        let active_policy = PolicyControlPlane::commit(
            &*policy_store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &cluster_policy("gate-connections"),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("policy should initialize");
        tools_store
            .seed_empty_document()
            .await
            .expect("tools should seed");

        // Push the shared counter well ahead of the connections
        // high-water mark. On the defective code the connections
        // counter is still 0 here while the shared counter is 4+, and
        // no connection commit can ever catch up.
        let mut tools_etag = tools_store
            .active_tools()
            .await
            .expect("active tools read")
            .expect("seeded")
            .etag;
        for index in 0..3 {
            tools_etag = tools_store
                .commit_tools(
                    PolicyCommitPrecondition::Expected { etag: tools_etag },
                    &tools_document_with(&format!("counter_mover_{index}")),
                    crate::storage::DocumentChange::test_tools("op"),
                    &DIFF,
                )
                .await
                .expect("tools commit should win")
                .etag;
        }

        let boot_revision = connection_store
            .state_revision()
            .await
            .expect("connections state revision should read");
        let created = connection_store
            .create(cluster_connection_candidate(), "op", None)
            .await
            .expect("connection create should commit");
        let after_commit = connection_store
            .state_revision()
            .await
            .expect("connections state revision should read");

        // The property, stated directly against the store: a committed
        // connection mutation must leave the connections high-water
        // mark at the shared revision it took, not one above whatever
        // it happened to be before. Under the defect this was
        // `boot_revision + 1` -- far below the shared counter.
        let shared_now = policy_store
            .revision_source()
            .current()
            .await
            .expect("shared revision should read");
        assert_eq!(
            after_commit, shared_now,
            "a connection commit must record the SHARED security revision \
                 ({shared_now}), not a private commit count ({after_commit}); \
                 the gate compares this against a watermark of the shared counter"
        );
        assert!(
            after_commit > boot_revision + 1,
            "the tools commits above moved the shared counter, so the \
                 connections mark must jump past a private increment \
                 ({after_commit} vs {})",
            boot_revision + 1
        );

        // And the consequence, stated through the gate: a replica whose
        // watermark was compiled before the connection commit must
        // reconcile it. `ensure_current_revision` returns the watermark
        // it served under; it must cover the connection commit.
        let rbac_state = middleware::rbac::RbacState::new(
            active_policy.policy.clone(),
            Vec::new(),
            false,
            test_audit_log(),
        );
        rbac_state
            .install_revision_snapshot(
                active_policy.policy.clone(),
                active_policy.security_revision,
            )
            .await
            .expect("the authority's revision should install");
        let runtime = ClusterSecurityRuntime::new(
            policy_store.revision_source(),
            PolicyResource::new(policy_store.clone(), rbac_state.clone()),
        );
        let reconciled = Arc::new(std::sync::atomic::AtomicI64::new(0));
        runtime.register_resource(Arc::new(RecordingConnectionsResource {
            store: connection_store.clone(),
            reconciled: reconciled.clone(),
        }));

        // The background budget: the assertion is which revision the
        // watermark covers, not how fast the pass reaching it ran. See
        // `the_background_pass_outlives_the_request_deadline` for the
        // 250 ms request deadline's own guard.
        let served = runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("the gate must reconcile a connection commit, not loop");
        assert!(
            served >= after_commit,
            "the compiled watermark must cover the connection commit \
                 ({served} < {after_commit})"
        );
        assert_eq!(
            reconciled.load(std::sync::atomic::Ordering::Acquire),
            after_commit,
            "the connections resource must have been asked to reconcile at \
                 the revision the commit recorded; under the defect its \
                 activation revision stayed below the watermark and reconcile \
                 was never called"
        );
        assert!(
            connection_store
                .get(&created.id)
                .await
                .expect("record read")
                .is_some(),
            "the committed connection is readable from the authority"
        );
    }

    fn cluster_connection_candidate() -> connections::model::ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": "Gate fixture",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://gate.example.test",
                "base_path": "/v1"
            },
            "authentication": { "type": "none" }
        }))
        .expect("gate connection candidate should deserialize")
    }

    /// A `ReconciledResource` with the real activation-revision read but
    /// a recording install, so the test can assert that reconciliation
    /// was actually reached rather than inferring it.
    struct RecordingConnectionsResource {
        store: Arc<connections::pg_store::PostgresConnectionStore>,
        reconciled: Arc<std::sync::atomic::AtomicI64>,
    }

    #[async_trait::async_trait]
    impl security_cluster::ReconciledResource for RecordingConnectionsResource {
        fn name(&self) -> &'static str {
            "connections"
        }

        async fn activation_revision(
            &self,
        ) -> Result<i64, middleware::rbac::SecurityRevisionCheckError> {
            self.store
                .state_revision()
                .await
                .map_err(|_| middleware::rbac::SecurityRevisionCheckError::Unavailable)
        }

        async fn reconcile(
            &self,
            _compiled_revision: i64,
        ) -> Result<(), middleware::rbac::SecurityRevisionCheckError> {
            let revision = self
                .store
                .state_revision()
                .await
                .map_err(|_| middleware::rbac::SecurityRevisionCheckError::Unavailable)?;
            self.reconciled
                .store(revision, std::sync::atomic::Ordering::Release);
            Ok(())
        }
    }

    #[tokio::test]
    async fn tools_reconciliation_installs_and_fails_closed() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (policy_store, tools_store, _pool) = migrated_stores(&database.dsn).await;

        let active_policy = PolicyControlPlane::commit(
            &*policy_store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &cluster_policy("gate-invalid"),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("policy should initialize");
        tools_store
            .seed_empty_document()
            .await
            .expect("tools should seed");

        let rbac_state = middleware::rbac::RbacState::new(
            active_policy.policy.clone(),
            Vec::new(),
            false,
            test_audit_log(),
        );
        rbac_state
            .install_revision_snapshot(
                active_policy.policy.clone(),
                active_policy.security_revision,
            )
            .await
            .expect("the authority's revision should install");
        let registry =
            ToolRegistry::from_definitions_with_audit(Vec::new(), Some(test_audit_log()));
        let boot_tools = tools_store
            .active_tools()
            .await
            .expect("active tools read")
            .expect("seeded");
        let tools_resource = ToolsResource::new(tools_store.clone(), registry.clone(), 0);
        let runtime = ClusterSecurityRuntime::new(
            policy_store.revision_source(),
            PolicyResource::new(policy_store.clone(), rbac_state.clone()),
        );
        runtime.register_resource(tools_resource.clone());

        // Commit a new tools document; the gate reconciles it in.
        tools_store
            .commit_tools(
                PolicyCommitPrecondition::Expected {
                    etag: boot_tools.etag.clone(),
                },
                &tools_document_with("reconciled_tool"),
                crate::storage::DocumentChange::test_tools("op"),
                &DIFF,
            )
            .await
            .expect("tools commit should win");
        // The background budget: the assertion is that the committed
        // lane is installed, not how fast the pass installing it ran.
        // See `the_background_pass_outlives_the_request_deadline` for
        // the 250 ms request deadline's own guard.
        runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("reconcile should succeed");
        assert!(
            registry
                .current_local_definitions()
                .iter()
                .any(|tool| tool.name == "reconciled_tool"),
            "the reconciled lane must contain the committed tool"
        );

        // A document the registry cannot validate (an unknown field
        // the tools schema rejects) fails closed: the gate refuses and
        // the installed lane does not regress.
        let active = tools_store
            .active_tools()
            .await
            .expect("active read")
            .expect("active");
        let mut invalid = tools_document_with("never_installs");
        invalid["not_a_tools_file_field"] = json!(true);
        tools_store
            .commit_tools(
                PolicyCommitPrecondition::Expected {
                    etag: active.etag.clone(),
                },
                &invalid,
                crate::storage::DocumentChange::test_tools("op"),
                &DIFF,
            )
            .await
            .expect("the authority accepts the commit; validation is replica-side");
        let probe =
            middleware::rbac::SecurityRevisionGate::ensure_current_revision(&*runtime).await;
        assert!(
            probe.is_err(),
            "an invalid tools document must fail closed, not install"
        );
        assert!(
            registry
                .current_local_definitions()
                .iter()
                .any(|tool| tool.name == "reconciled_tool"),
            "the last valid lane remains installed; nothing regressed"
        );
    }

    #[tokio::test]
    async fn register_via_control_plane_commits_and_rejects_stale_etags() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (policy_store, tools_store, _pool) = migrated_stores(&database.dsn).await;

        PolicyControlPlane::commit(
            &*policy_store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &cluster_policy("register-tools"),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("policy should initialize");
        tools_store
            .seed_empty_document()
            .await
            .expect("tools should seed");

        // The endpoint's cluster arm, exercised directly: a registry
        // with the validator hook unset (no connections configured),
        // a principal, and the merged candidate.
        let registry =
            ToolRegistry::from_definitions_with_audit(Vec::new(), Some(test_audit_log()));
        let control_plane: Arc<dyn storage::ToolControlPlane> = tools_store.clone();
        let principal = test_principal(&["admin"]);

        let active = control_plane
            .active_tools()
            .await
            .expect("active read")
            .expect("seeded");
        let mut headers_with_etag = HeaderMap::new();
        headers_with_etag.insert(
            header::IF_MATCH,
            header::HeaderValue::from_str(&active.etag).expect("etag is a valid header value"),
        );
        let merged = merge_tools_candidate(
            &headers_with_etag,
            &active.etag,
            ToolsFileAdminDocument {
                schema_version: "0.1.0".to_owned(),
                tools: Vec::new(),
            },
            crate::tools::definitions::definitions_from_json_value(
                tools_document_with("registered_tool"),
                None,
            )
            .expect("candidate should parse"),
        )
        .expect("merge should pass with a fresh If-Match");
        let committed = register_tools_via_control_plane(
            &control_plane,
            None,
            &registry,
            &active.etag,
            &principal,
            merged,
        )
        .await
        .expect("register should commit");
        assert_eq!(committed.tool_count, 1);
        assert!(
            registry
                .current_local_definitions()
                .iter()
                .any(|tool| tool.name == "registered_tool"),
            "the committed lane must be installed locally"
        );

        // The stale ETag now loses with 412.
        let stale = merge_tools_candidate(
            &headers_with_etag,
            &active.etag,
            ToolsFileAdminDocument {
                schema_version: "0.1.0".to_owned(),
                tools: Vec::new(),
            },
            crate::tools::definitions::definitions_from_json_value(
                tools_document_with("second_tool"),
                None,
            )
            .expect("candidate should parse"),
        )
        .expect("merge should pass with the stale If-Match");
        let response = register_tools_via_control_plane(
            &control_plane,
            None,
            &registry,
            &active.etag,
            &principal,
            stale,
        )
        .await
        .expect_err("the stale ETag must lose");
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }
}
