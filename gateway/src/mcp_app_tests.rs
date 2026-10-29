//! The MCP endpoint in `mcp.rs` and `tools/`: `/mcp` and how it
//! authenticates, protected-resource metadata, tool listing and calls,
//! upstream MCP tools, the MCP route's streaming body limit, and the traffic
//! inventory rows MCP calls record. Shared fixtures stay in `app_tests.rs`.
use super::*;

#[tokio::test]
async fn mcp_initialize_handshake_succeeds() {
    let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        1,
        "initialize",
        Some(mcp_initialize_params()),
        "mcp-init-request",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["jsonrpc"], json!("2.0"));
    assert_eq!(body["id"], json!(1));
    assert_eq!(body["result"]["serverInfo"]["name"], json!("greengateway"));
    assert_eq!(body["result"]["capabilities"]["tools"], json!({}));
}

#[test]
fn mcp_exempt_overlap_detection_is_segment_aware_and_ignores_exact_entries() {
    let covering = vec!["/admin".to_owned(), "/other".to_owned()];
    assert_eq!(
        mcp_route_covering_exempt_prefix("/admin/mcp", &covering),
        Some("/admin")
    );

    let exact = vec!["/admin/mcp".to_owned()];
    assert_eq!(mcp_route_covering_exempt_prefix("/admin/mcp", &exact), None);

    let lookalike = vec!["/admin-mcp".to_owned(), "/administrator".to_owned()];
    assert_eq!(
        mcp_route_covering_exempt_prefix("/admin/mcp", &lookalike),
        None
    );
}

#[tokio::test]
async fn mcp_alias_under_admin_exempt_prefix_rejects_junk_bearer() {
    let harness = mcp_test_harness_with_public_url(
        &["admin"],
        test_audit_log(),
        "https://gateway.example.test/admin",
    )
    .await;

    let rejected = harness
        .router
        .clone()
        .oneshot(mcp_request_to(
            "/admin/mcp",
            Some("junk"),
            1,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-admin-alias-junk-bearer",
        ))
        .await
        .expect("MCP alias request should complete");

    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(rejected).await,
        json!({ "error": "unauthorized" })
    );

    let allowed = harness
        .router
        .oneshot(mcp_request_to(
            "/admin/mcp",
            Some(&harness.admin_token),
            2,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-admin-alias-valid-bearer",
        ))
        .await
        .expect("authenticated MCP alias request should complete");

    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(
        json_body(allowed).await["result"]["serverInfo"]["name"],
        json!("greengateway")
    );
}

#[tokio::test]
async fn mcp_path_prefixed_public_url_serves_advertised_resource_route() {
    let harness = mcp_test_harness_with_public_url(
        &["admin"],
        test_audit_log(),
        "https://gateway.example.test/base",
    )
    .await;

    let response = harness
        .router
        .clone()
        .oneshot(mcp_request_to(
            "/base/mcp",
            Some(&harness.admin_token),
            1,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-prefixed-init-request",
        ))
        .await
        .expect("prefixed MCP request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["jsonrpc"], json!("2.0"));
    assert_eq!(body["id"], json!(1));
    assert_eq!(body["result"]["serverInfo"]["name"], json!("greengateway"));
}

#[tokio::test]
async fn oauth_protected_resource_metadata_returns_mcp_resource_document() {
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test/base/".to_owned());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: Some("https://auth.example.test/.well-known/jwks.json".to_owned()),
        issuer: Some("https://auth.example.test/".to_owned()),
        audience: None,
        jwks_timeout_ms: config.jwt_jwks_timeout_ms,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = router
        .oneshot(
            Request::builder()
                .uri(auth::protected_resource::WELL_KNOWN_PATH)
                .body(Body::empty())
                .expect("metadata request should build"),
        )
        .await
        .expect("metadata request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(
        body,
        json!({
            "resource": "https://gateway.example.test/base/mcp",
            "authorization_servers": ["https://auth.example.test"],
            "scopes_supported": ["mcp:tools"],
            "bearer_methods_supported": ["header"]
        })
    );
}

#[tokio::test]
async fn oauth_protected_resource_metadata_serves_rfc9728_path_for_mcp_resource_path() {
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test/base".to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource/base/mcp")
                .body(Body::empty())
                .expect("metadata request should build"),
        )
        .await
        .expect("metadata request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(
        body["resource"],
        json!("https://gateway.example.test/base/mcp")
    );
}

#[tokio::test]
async fn oauth_protected_resource_metadata_returns_clear_not_configured_error() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = router
        .oneshot(
            Request::builder()
                .uri(auth::protected_resource::WELL_KNOWN_PATH)
                .body(Body::empty())
                .expect("metadata request should build"),
        )
        .await
        .expect("metadata request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"OAuth protected-resource metadata requires GATEWAY_PUBLIC_URL to be configured"}"#
    );
}

#[tokio::test]
async fn mcp_cookieless_initialize_challenges_and_cookie_mutations_require_csrf() {
    for public_url in [
        None,
        Some("https://gateway.example.test"),
        Some("https://gateway.example.test/base"),
    ] {
        let mut config = test_config(Vec::new());
        config.gateway_public_url = public_url.map(str::to_owned);
        let cookie_name = config.auth_cookie_name.clone();
        assert!(config.csrf_enabled);
        let routes = auth::protected_resource::mcp_route_paths(&config);
        let metadata =
            auth::protected_resource::ProtectedResourceMetadataConfig::from_config(&config);
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app");
        for route in routes {
            let mut request = mcp_request_to(
                &route,
                None,
                1,
                "initialize",
                Some(mcp_initialize_params()),
                "oauth-bootstrap",
            );
            request.headers_mut().remove(header::COOKIE);
            request.headers_mut().remove("x-csrf-token");
            let response = router
                .clone()
                .oneshot(request)
                .await
                .expect("initialize response");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let expected = metadata.as_ref().map_or_else(
                || "Bearer".to_owned(),
                |metadata| {
                    format!(
                        "Bearer realm=\"mcp\", resource_metadata=\"{}\"",
                        metadata.metadata_url()
                    )
                },
            );
            assert_eq!(response.headers()[header::WWW_AUTHENTICATE], expected);
            for csrf_header in [None, Some("wrong-token")] {
                let mut request = mcp_request_to(
                    &route,
                    None,
                    2,
                    "initialize",
                    Some(mcp_initialize_params()),
                    "cookie-csrf",
                );
                request.headers_mut().insert(
                    header::COOKIE,
                    HeaderValue::from_str(&format!(
                        "{cookie_name}=test-session; csrf_token=expected-token"
                    ))
                    .expect("cookie"),
                );
                request.headers_mut().remove("x-csrf-token");
                if let Some(value) = csrf_header {
                    request
                        .headers_mut()
                        .insert("x-csrf-token", HeaderValue::from_static(value));
                }
                let response = router
                    .clone()
                    .oneshot(request)
                    .await
                    .expect("cookie response");
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert_eq!(
                    json_body(response).await["error"],
                    "csrf token missing or invalid"
                );
            }
        }
        for csrf_header in [None, Some("wrong-token")] {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri(CONNECTIONS_ADMIN_ROUTE)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    format!("{cookie_name}=test-session; csrf_token=expected-token"),
                )
                .body(Body::from("{}"))
                .expect("admin request");
            if let Some(value) = csrf_header {
                request
                    .headers_mut()
                    .insert("x-csrf-token", HeaderValue::from_static(value));
            }
            let response = router
                .clone()
                .oneshot(request)
                .await
                .expect("admin response");
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                json_body(response).await["error"],
                "csrf token missing or invalid"
            );
        }
    }
}

#[tokio::test]
async fn mcp_unauthorized_challenge_includes_resource_metadata_for_prefixed_route() {
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test/base".to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/base/mcp")
                .body(Body::empty())
                .expect("prefixed MCP request should build"),
        )
        .await
        .expect("prefixed MCP request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(
                "Bearer realm=\"mcp\", resource_metadata=\"https://gateway.example.test/.well-known/oauth-protected-resource/base/mcp\""
            ))
        );
}

#[tokio::test]
async fn mcp_unauthorized_challenge_includes_resource_metadata_only_for_mcp() {
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test".to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let mcp_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(auth::protected_resource::MCP_RESOURCE_PATH)
                .body(Body::empty())
                .expect("MCP request should build"),
        )
        .await
        .expect("MCP request should complete");

    assert_eq!(mcp_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
            mcp_response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(
                "Bearer realm=\"mcp\", resource_metadata=\"https://gateway.example.test/.well-known/oauth-protected-resource/mcp\""
            ))
        );

    let non_mcp_response = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .body(Body::empty())
                .expect("non-MCP request should build"),
        )
        .await
        .expect("non-MCP request should complete");

    assert_eq!(non_mcp_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        non_mcp_response.headers().get(header::WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static("Bearer"))
    );
}

#[tokio::test]
async fn mcp_unauthorized_challenge_inserts_metadata_path_before_mcp_resource_path() {
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test/base".to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = router
        .oneshot(
            Request::builder()
                // Bare /mcp remains a compatibility route even when the
                // public resource URL is advertised under /base/mcp.
                .uri(auth::protected_resource::MCP_RESOURCE_PATH)
                .body(Body::empty())
                .expect("MCP request should build"),
        )
        .await
        .expect("MCP request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(
                "Bearer realm=\"mcp\", resource_metadata=\"https://gateway.example.test/.well-known/oauth-protected-resource/base/mcp\""
            ))
        );
}

#[tokio::test]
async fn mcp_jwt_requires_resource_audience_when_public_url_is_configured() {
    let jwks_addr = spawn_test_jwks_server().await;
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test".to_owned());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let missing_audience = signed_token("mcp-missing-audience", &["member"]);
    let (missing_status, _) = mcp_rpc(
        &router,
        Some(&missing_audience),
        91,
        "initialize",
        Some(mcp_initialize_params()),
        "mcp-missing-audience",
    )
    .await;
    assert_eq!(missing_status, StatusCode::UNAUTHORIZED);

    let wrong_audience = signed_token_with_claims(json!({
        "sub": "mcp-wrong-audience",
        "email": "mcp-wrong-audience@example.test",
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
        "jti": "mcp-wrong-audience-session",
        "roles": ["member"],
        "aud": "https://other-api.example.test"
    }));
    let (wrong_status, _) = mcp_rpc(
        &router,
        Some(&wrong_audience),
        92,
        "initialize",
        Some(mcp_initialize_params()),
        "mcp-wrong-audience",
    )
    .await;
    assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);

    let matching_audience = signed_token_with_claims(json!({
        "sub": "mcp-matching-audience",
        "email": "mcp-matching-audience@example.test",
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
        "jti": "mcp-matching-audience-session",
        "roles": ["member"],
        "aud": ["https://other-api.example.test", "https://gateway.example.test/mcp"]
    }));
    let (matching_status, body) = mcp_rpc(
        &router,
        Some(&matching_audience),
        93,
        "initialize",
        Some(mcp_initialize_params()),
        "mcp-matching-audience",
    )
    .await;

    assert_eq!(matching_status, StatusCode::OK);
    assert_eq!(body["result"]["serverInfo"]["name"], json!("greengateway"));
}

#[tokio::test]
async fn mcp_service_token_requires_mcp_scope_when_public_url_is_configured() {
    let token_db = TempDb::new("mcp-resource-service-token");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let token_without_mcp_scope = create_service_token(&token_store, &["admin"]);
    let token_with_mcp_scope = create_service_token(&token_store, &["admin", "mcp:tools"]);
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test".to_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 20;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let (missing_scope_status, missing_scope_body) = mcp_rpc(
        &router,
        Some(&token_without_mcp_scope),
        94,
        "initialize",
        Some(mcp_initialize_params()),
        "mcp-service-token-missing-scope",
    )
    .await;
    assert_eq!(missing_scope_status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing_scope_body, json!({ "error": "unauthorized" }));

    let non_mcp_response = authenticated_principal_probe(&router, &token_without_mcp_scope).await;
    assert_eq!(non_mcp_response.status(), StatusCode::OK);
    let non_mcp_body = json_body(non_mcp_response).await;
    assert_eq!(non_mcp_body["auth_method"], json!("service_token"));
    assert_eq!(non_mcp_body["roles"], json!(["admin"]));

    let (matching_scope_status, matching_scope_body) = mcp_rpc(
        &router,
        Some(&token_with_mcp_scope),
        95,
        "initialize",
        Some(mcp_initialize_params()),
        "mcp-service-token-matching-scope",
    )
    .await;

    assert_eq!(matching_scope_status, StatusCode::OK);
    assert_eq!(
        matching_scope_body["result"]["serverInfo"]["name"],
        json!("greengateway")
    );
}

#[tokio::test]
async fn mcp_cookie_session_is_rejected_when_public_url_is_configured() {
    let (introspection_url, introspection_server) =
        spawn_blocking_cookie_session_server(Ipv4Addr::LOCALHOST, 1);
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test".to_owned());
    configure_test_cookie_session_provider(&mut config, introspection_url);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let mcp_response = router
        .clone()
        .oneshot(mcp_cookie_request(
            "session=session-secret-123",
            96,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-cookie-session",
        ))
        .await
        .expect("MCP cookie request should complete");

    assert_eq!(mcp_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        json_body(mcp_response).await,
        json!({ "error": "unauthorized" })
    );

    let non_mcp_response = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(header::COOKIE, "session=session-secret-123")
                .body(Body::empty())
                .expect("non-MCP cookie request should build"),
        )
        .await
        .expect("non-MCP cookie request should complete");

    assert_eq!(non_mcp_response.status(), StatusCode::OK);
    let non_mcp_body = json_body(non_mcp_response).await;
    assert_eq!(non_mcp_body["user_id"], json!("cookie-user"));
    assert_eq!(non_mcp_body["auth_method"], json!("session_cookie"));
    assert_eq!(introspection_server.finish(), 1);
}

#[tokio::test]
async fn mcp_tools_list_returns_registry_tools_and_schemas() {
    let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        2,
        "tools/list",
        None,
        "mcp-list-request",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let tools = body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    let echo = tools
        .iter()
        .find(|tool| tool["name"] == json!("echo"))
        .expect("echo tool should be listed");
    let widget = tools
        .iter()
        .find(|tool| tool["name"] == json!("get_widget"))
        .expect("get_widget tool should be listed");

    assert_eq!(
        echo["description"],
        json!("Echoes a message through a generic upstream endpoint.")
    );
    assert_eq!(echo["inputSchema"]["required"], json!(["message"]));
    assert_eq!(
        echo["inputSchema"]["properties"]["message"]["type"],
        json!("string")
    );
    assert_eq!(widget["inputSchema"]["required"], json!(["widget_id"]));
    assert_eq!(
        widget["inputSchema"]["properties"]["include_details"]["type"],
        json!("boolean")
    );
}

#[tokio::test]
async fn mcp_tools_list_filters_tools_by_allowed_roles() {
    let harness = mcp_test_harness(&[], test_audit_log()).await;

    let (reader_status, reader_body) = mcp_rpc(
        &harness.router,
        Some(&harness.reader_token),
        11,
        "tools/list",
        None,
        "mcp-list-reader",
    )
    .await;
    assert_eq!(reader_status, StatusCode::OK);
    let reader_tools = reader_body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    assert!(
        reader_tools
            .iter()
            .any(|tool| tool["name"] == json!("echo")),
        "unrestricted tool should be listed"
    );
    assert!(
        !reader_tools
            .iter()
            .any(|tool| tool["name"] == json!("get_widget")),
        "admin-only tool should not be listed to reader"
    );

    let (admin_status, admin_body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        12,
        "tools/list",
        None,
        "mcp-list-admin",
    )
    .await;
    assert_eq!(admin_status, StatusCode::OK);
    let admin_tools = admin_body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    assert!(
        admin_tools
            .iter()
            .any(|tool| tool["name"] == json!("get_widget")),
        "matching role should see role-restricted tool"
    );
}

#[tokio::test]
async fn mcp_tools_list_follows_live_tool_enabled_and_membership_policy() {
    let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

    let (before_status, before_body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        53,
        "tools/list",
        None,
        "mcp-list-before-tool-membership-reload",
    )
    .await;
    assert_eq!(before_status, StatusCode::OK);
    let before_tools = before_body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    assert!(before_tools
        .iter()
        .any(|tool| tool["name"] == json!("echo")));
    assert!(before_tools
        .iter()
        .any(|tool| tool["name"] == json!("get_widget")));

    let current_policy =
        rbac::Policy::from_file(&harness._policy.path).expect("current MCP policy should parse");
    let etag = policy_etag(&current_policy).expect("current MCP policy ETag should compute");
    let mut policy =
        serde_json::to_value(&current_policy).expect("current MCP policy should serialize");
    policy["tools"]["echo"]["enabled"] = json!(false);
    policy["tools"]
        .as_object_mut()
        .expect("tools policy should be an object")
        .remove("get_widget");

    let put_response = harness
        .router
        .clone()
        .oneshot(authenticated_json_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &harness.admin_token,
            Some(policy.to_string()),
            Some(&etag),
        ))
        .await
        .expect("policy PUT should complete");
    assert_eq!(put_response.status(), StatusCode::OK);

    let (after_status, after_body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        54,
        "tools/list",
        None,
        "mcp-list-after-tool-membership-reload",
    )
    .await;
    assert_eq!(after_status, StatusCode::OK);
    let after_tools = after_body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    assert!(
        !after_tools.iter().any(|tool| tool["name"] == json!("echo")),
        "disabled echo tool should not be listed after policy reload: {after_body}"
    );
    assert!(
        !after_tools
            .iter()
            .any(|tool| tool["name"] == json!("get_widget")),
        "removed get_widget tool should not be listed after policy reload: {after_body}"
    );
}

#[tokio::test]
async fn mcp_route_rejects_missing_authentication_and_missing_permission() {
    let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

    let (missing_status, missing_body) = mcp_rpc(
        &harness.router,
        None,
        3,
        "tools/list",
        None,
        "mcp-missing-auth",
    )
    .await;
    assert_eq!(missing_status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing_body, json!({ "error": "unauthorized" }));

    let (forbidden_status, forbidden_body) = mcp_rpc(
        &harness.router,
        Some(&harness.blocked_token),
        4,
        "tools/list",
        None,
        "mcp-forbidden",
    )
    .await;
    assert_eq!(forbidden_status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden_body, json!({ "error": "forbidden" }));
}

#[tokio::test]
async fn mcp_tools_call_echo_succeeds() {
    let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        5,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "hello from mcp"
            }
        })),
        "mcp-call-success",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["result"]["isError"], json!(false));
    assert_eq!(body["result"]["structuredContent"]["status"], json!(200));
    assert_eq!(
        body["result"]["structuredContent"]["body"],
        json!({ "message": "hello from mcp" })
    );
}

#[tokio::test]
async fn mcp_tool_name_rules_follow_policy_admin_reload() {
    let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

    let (before_status, before_body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        51,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "before reload"
            }
        })),
        "mcp-call-before-tool-rule-reload",
    )
    .await;

    assert_eq!(before_status, StatusCode::OK);
    assert_eq!(before_body["error"], Value::Null);
    assert_eq!(before_body["result"]["isError"], json!(false));

    let current_policy =
        rbac::Policy::from_file(&harness._policy.path).expect("current MCP policy should parse");
    let etag = policy_etag(&current_policy).expect("current MCP policy ETag should compute");
    let mut policy =
        serde_json::to_value(&current_policy).expect("current MCP policy should serialize");
    policy["rules"] = json!([
        {
            "id": "deny-echo-after-reload",
            "tool_name": "echo",
            "principal": {
                "roles": ["admin"]
            },
            "action": "deny"
        }
    ]);

    let put_response = harness
        .router
        .clone()
        .oneshot(authenticated_json_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &harness.admin_token,
            Some(policy.to_string()),
            Some(&etag),
        ))
        .await
        .expect("policy PUT should complete");
    assert_eq!(put_response.status(), StatusCode::OK);

    let (after_status, after_body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        52,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "after reload"
            }
        })),
        "mcp-call-after-tool-rule-reload",
    )
    .await;

    assert_eq!(after_status, StatusCode::OK);
    assert_eq!(after_body["error"]["code"], json!(-32001));
    assert_eq!(after_body["error"]["data"]["tool_name"], json!("echo"));
    assert_eq!(after_body["error"]["data"]["reason"], json!("matched_rule"));
}

#[tokio::test]
async fn mcp_tools_call_get_widget_succeeds() {
    let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        10,
        "tools/call",
        Some(json!({
            "name": "get_widget",
            "arguments": {
                "widget_id": "widget-123",
                "include_details": true
            }
        })),
        "mcp-call-widget-success",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["result"]["isError"], json!(false));
    assert_eq!(body["result"]["structuredContent"]["status"], json!(200));
    assert_eq!(
        body["result"]["structuredContent"]["body"],
        json!({
            "widget_id": "widget-123",
            "include_details": true
        })
    );
}

#[tokio::test]
async fn mcp_tools_call_errors_are_mapped_to_json_rpc_errors() {
    let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

    let (unknown_status, unknown_body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        6,
        "tools/call",
        Some(json!({
            "name": "missing_tool",
            "arguments": {}
        })),
        "mcp-call-unknown",
    )
    .await;
    assert_eq!(unknown_status, StatusCode::OK);
    assert_eq!(unknown_body["error"]["code"], json!(-32601));
    assert_eq!(
        unknown_body["error"]["message"],
        json!("tool 'missing_tool' is not defined")
    );
    assert_eq!(
        unknown_body["error"]["data"]["tool_name"],
        json!("missing_tool")
    );

    let (schema_status, schema_body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        7,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {}
        })),
        "mcp-call-schema",
    )
    .await;
    assert_eq!(schema_status, StatusCode::OK);
    assert_eq!(schema_body["error"]["code"], json!(-32602));
    assert_eq!(schema_body["error"]["data"]["tool_name"], json!("echo"));
    assert!(schema_body["error"]["message"]
        .as_str()
        .expect("invalid params error should include a message")
        .contains("failed input schema validation"));

    let (role_status, role_body) = mcp_rpc(
        &harness.router,
        Some(&harness.reader_token),
        8,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "reader should be denied by tool policy"
            }
        })),
        "mcp-call-role-denied",
    )
    .await;
    assert_eq!(role_status, StatusCode::OK);
    assert_eq!(role_body["error"]["code"], json!(-32001));
    assert_eq!(
        role_body["error"]["message"],
        json!("tool invocation is denied by role policy")
    );
    assert_eq!(role_body["error"]["data"]["tool_name"], json!("echo"));
    assert_eq!(role_body["error"]["data"]["reason"], json!("role_denied"));
}

#[tokio::test]
async fn mcp_tools_call_transport_failure_uses_sanitized_error_reason() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let upstream_addr = listener
        .local_addr()
        .expect("listener address should be available");
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept a connection");
            drop(stream);
        }
    });
    let harness = mcp_test_harness_with_upstream_url(
        &["admin"],
        test_audit_log(),
        format!("http://{upstream_addr}"),
        mcp_tools_document(),
        vec!["127.0.0.1".to_owned()],
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        13,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "trigger reset"
            }
        })),
        "mcp-call-reset-upstream",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32603));
    assert_eq!(body["error"]["message"], json!("tool invocation failed"));
    assert_eq!(body["error"]["data"]["tool_name"], json!("echo"));
    assert_eq!(body["error"]["data"]["reason"], json!("http_error"));
    let body_string = body.to_string();
    assert!(!body_string.contains("127.0.0.1"));
    assert!(!body_string.contains(&upstream_addr.port().to_string()));
    assert!(!body_string.contains("connection"));
    assert!(!body_string.contains(concat!("req", "west")));
    assert!(!body_string.contains("error sending request"));
    server.abort();
}

#[tokio::test]
async fn mcp_tools_call_sanitizes_non_success_upstream_error_body() {
    let upstream_addr = spawn_fixed_echo_upstream(
        StatusCode::BAD_REQUEST,
        "application/json",
        json!({
            "statusCode": 400,
            "error": "BadRequestException",
            "messages": [
                "filter must use a supported comparison operator",
                "validation failed against https://api.example.test/check?token=gg_test_fake_secret_400"
            ],
            "message": "validation failed against api.internal.example.test",
            "errors": [
                {
                    "detail": "bad value used secret=gg_test_fake_secret_400"
                }
            ],
            "debug": "stack trace from api.internal.example.test with gg_test_fake_secret_400"
        })
        .to_string(),
    )
    .await;
    let harness = mcp_test_harness_with_upstream_url(
        &["admin"],
        test_audit_log(),
        format!("http://{upstream_addr}"),
        mcp_tools_document(),
        vec!["127.0.0.1".to_owned()],
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        14,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "bad input"
            }
        })),
        "mcp-call-upstream-400",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["result"]["isError"], json!(true));
    assert_eq!(body["result"]["structuredContent"]["status"], json!(400));
    assert_eq!(
        body["result"]["structuredContent"]["body"]["statusCode"],
        json!(400)
    );
    assert_eq!(
        body["result"]["structuredContent"]["body"]["error"],
        json!("BadRequestException")
    );
    assert_eq!(
        body["result"]["structuredContent"]["body"]["messages"],
        json!([
            "filter must use a supported comparison operator",
            "validation failed against [redacted]"
        ])
    );
    assert_eq!(
        body["result"]["structuredContent"]["body"]["message"],
        json!("validation failed against [redacted]")
    );
    assert_eq!(
        body["result"]["structuredContent"]["body"]["errors"][0]["detail"],
        json!("bad value used [redacted]")
    );
    let body_string = body.to_string();
    assert!(!body_string.contains("api.internal.example.test"));
    assert!(!body_string.contains("https://api.example.test"));
    assert!(!body_string.contains("gg_test_fake_secret_400"));
    assert!(!body_string.contains("stack trace"));
    assert!(!mcp_content_text(&body).contains("api.internal.example.test"));
    assert!(!mcp_content_text(&body).contains("gg_test_fake_secret_400"));
}

#[tokio::test]
async fn mcp_tools_call_plain_http_marker_header_is_not_trusted() {
    let upstream_addr = spawn_fixed_echo_upstream_with_headers(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json",
            json!({
                "content": [{
                    "type": "text",
                    "text": "spoofed success from api.internal.example.test with secret=gg_test_fake_secret_spoof"
                }],
                "structuredContent": {
                    "summary": "spoofed success",
                    "leak": "api.internal.example.test"
                },
                "isError": false,
                "message": "upstream failed at api.internal.example.test with secret=gg_test_fake_secret_spoof"
            })
            .to_string(),
            vec![(crate::tools::mcp_upstream::MCP_CALL_TOOL_RESULT_HEADER, "call-tool-result")],
        )
        .await;
    let harness = mcp_test_harness_with_upstream_url(
        &["admin"],
        test_audit_log(),
        format!("http://{upstream_addr}"),
        mcp_tools_document(),
        vec!["127.0.0.1".to_owned()],
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        16,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "trigger spoofed marker"
            }
        })),
        "mcp-call-spoofed-marker",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["result"]["isError"], json!(true));
    assert_eq!(body["result"]["structuredContent"]["status"], json!(500));
    assert_eq!(
        body["result"]["structuredContent"]["body"]["message"],
        json!("upstream failed at [redacted] with [redacted]")
    );
    let body_string = body.to_string();
    assert!(!body_string.contains("spoofed success"));
    assert!(!body_string.contains("api.internal.example.test"));
    assert!(!body_string.contains("gg_test_fake_secret_spoof"));
}

#[tokio::test]
async fn mcp_tools_call_success_body_is_forwarded_faithfully() {
    let upstream_body = json!({
        "message": "ok",
        "diagnostic": "api.internal.example.test",
        "marker": "gg_test_fake_secret_success"
    });
    let upstream_addr = spawn_fixed_echo_upstream(
        StatusCode::OK,
        "application/json",
        upstream_body.to_string(),
    )
    .await;
    let harness = mcp_test_harness_with_upstream_url(
        &["admin"],
        test_audit_log(),
        format!("http://{upstream_addr}"),
        mcp_tools_document(),
        vec!["127.0.0.1".to_owned()],
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        15,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "successful output"
            }
        })),
        "mcp-call-success-passthrough",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["result"]["isError"], json!(false));
    assert_eq!(body["result"]["structuredContent"]["status"], json!(200));
    assert_eq!(body["result"]["structuredContent"]["body"], upstream_body);
    assert!(mcp_content_text(&body).contains("api.internal.example.test"));
    assert!(mcp_content_text(&body).contains("gg_test_fake_secret_success"));
}

#[tokio::test]
async fn mcp_tools_call_emits_http_observation_event() {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let harness = mcp_test_harness(&["admin"], audit_log).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        9,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "observe me"
            }
        })),
        "mcp-observed-request",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], json!(false));

    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == "http.request_observed"
                && event.request_id == "mcp-observed-request"
                && event.payload["path"] == json!(MCP_ROUTE)
                && event.payload["method"] == json!("POST")
                && event.payload["status"] == json!(200)
        })
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_real_client_connects_lists_calls_and_records_observability() {
    let upstream_addr = spawn_echo_json_upstream().await;
    let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
        upstream_url: Some(format!("http://{upstream_addr}")),
        tools_document: mcp_tools_document(),
        mcp_upstream_servers: Vec::new(),
        egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
    })
    .await;
    let (gateway_addr, gateway_server) = spawn_gateway_router(harness.router.clone()).await;
    let request_id = "mcp-sdk-conformance";
    let custom_headers = HashMap::from([
        (
            HeaderName::from_static(REQUEST_ID_HEADER),
            HeaderValue::from_static(request_id),
        ),
        (
            header::COOKIE,
            HeaderValue::from_static("csrf_token=mcp-test-csrf"),
        ),
        (
            HeaderName::from_static("x-csrf-token"),
            HeaderValue::from_static("mcp-test-csrf"),
        ),
    ]);
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(format!("http://{gateway_addr}{MCP_ROUTE}"))
            .auth_header(harness.admin_token.clone())
            .custom_headers(custom_headers),
    );
    let client = ().serve(transport).await.expect("rmcp client should initialize");

    let tools = client
        .list_all_tools()
        .await
        .expect("rmcp client should list tools");
    assert!(
        tools.iter().any(|tool| tool.name == "echo"),
        "rmcp tools/list should include echo: {tools:?}"
    );

    let arguments: RmcpJsonObject =
        serde_json::from_value(json!({ "message": "hello from real rmcp client" }))
            .expect("tool arguments should be a JSON object");
    let result = client
        .call_tool(RmcpCallToolRequestParams::new("echo").with_arguments(arguments))
        .await
        .expect("rmcp client should call echo");
    assert_eq!(result.is_error, Some(false));
    assert_eq!(
        result.structured_content,
        Some(json!({
            "status": 200,
            "body": {
                "message": "hello from real rmcp client"
            }
        }))
    );

    // Audit/discovery completion may still be queued after the SDK receives
    // its response; wait for delivery without blocking this current-thread
    // runtime, which still has that work to drive.
    wait_for_delivered_audit_events(
        &harness.capture,
        "the MCP start, success and observation events",
        |events| {
            let has_start = events.iter().any(|event| {
                event.event_type == audit::event::TOOL_INVOKE_START
                    && event.request_id == request_id
                    && event.payload["tool_name"] == json!("echo")
            });
            let has_success = events.iter().any(|event| {
                event.event_type == audit::event::TOOL_INVOKE_SUCCESS
                    && event.request_id == request_id
                    && event.payload["tool_name"] == json!("echo")
            });
            let has_tool_observation = events.iter().any(|event| {
                is_mcp_tool_observation(event, request_id)
                    && event.payload["path"] == json!("/mcp/tools/echo")
                    && event.payload["status"] == json!(200)
            });
            has_start && has_success && has_tool_observation
        },
    )
    .await;

    let row = wait_for_mcp_tool_inventory_row(&harness, &[request_id], "echo", |row| {
        row["call_count"] == json!(1) && status_count(row, 200) == Some(1)
    })
    .await;
    assert_eq!(row["method"], json!("MCP"));
    assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
    assert_eq!(row["call_count"], json!(1));
    assert_eq!(row["schema_mismatch_count"], json!(0));
    assert_eq!(row["distinct_principal_count"], json!(1));
    assert_eq!(status_count(&row, 200), Some(1));

    client
        .cancel()
        .await
        .expect("rmcp client should cancel cleanly");
    gateway_server.abort();
}

#[tokio::test]
async fn successful_mcp_tool_call_appears_as_per_tool_traffic_inventory_row() {
    let upstream_addr = spawn_echo_json_upstream().await;
    let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
        upstream_url: Some(format!("http://{upstream_addr}")),
        tools_document: mcp_tools_document(),
        mcp_upstream_servers: Vec::new(),
        egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
    })
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        30,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "inventory success"
            }
        })),
        "mcp-inventory-success",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], json!(false));

    let row =
        wait_for_mcp_tool_inventory_row(&harness, &["mcp-inventory-success"], "echo", |row| {
            row["call_count"] == json!(1) && status_count(row, 200) == Some(1)
        })
        .await;
    assert_eq!(row["method"], json!("MCP"));
    assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
    assert_eq!(row["call_count"], json!(1));
    assert_eq!(row["schema_mismatch_count"], json!(0));
    assert_eq!(row["distinct_principal_count"], json!(1));
    assert_eq!(status_count(&row, 200), Some(1));
    let open_signal_types = row["open_signals"]["signal_types"]
        .as_array()
        .expect("tool inventory row should include open signal types");
    assert!(
        open_signal_types
            .iter()
            .any(|signal_type| signal_type == "new_endpoint_seen"),
        "successful tool call should open a new_endpoint_seen signal: {row}"
    );
    assert!(row["latency"]["p50_ms"].as_u64().is_some());
    assert!(row["latency"]["p95_ms"].as_u64().is_some());
    assert!(row["latency"]["p99_ms"].as_u64().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxied_mcp_tool_call_appears_as_per_tool_traffic_inventory_row() {
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
        upstream_url: None,
        tools_document: empty_tools_document(),
        mcp_upstream_servers: vec![config::McpUpstreamServerConfig {
            name: "alpha".to_owned(),
            url: upstream.url.clone(),
            timeout_ms: Some(2_000),
            response_idle_timeout_ms: Some(2_000),
            connect_timeout_ms: Some(2_000),
        }],
        egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
    })
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        31,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "inventory proxied"
            }
        })),
        "mcp-inventory-proxied",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], json!(false));

    let row = wait_for_mcp_tool_inventory_row(
        &harness,
        &["mcp-inventory-proxied"],
        "alpha:remote_echo",
        |row| row["call_count"] == json!(1) && status_count(row, 200) == Some(1),
    )
    .await;
    assert_eq!(row["method"], json!("MCP"));
    assert_eq!(
        row["endpoint_template"],
        json!("/mcp/tools/alpha:remote_echo")
    );
    assert_eq!(row["call_count"], json!(1));
    assert_eq!(row["schema_mismatch_count"], json!(0));
    assert_eq!(status_count(&row, 200), Some(1));
}

#[tokio::test]
async fn non_schema_mismatch_mcp_tool_failure_appears_as_error_inventory_row() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let upstream_addr = listener
        .local_addr()
        .expect("listener address should be available");
    drop(listener);
    let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
        upstream_url: Some(format!("http://{upstream_addr}")),
        tools_document: mcp_tools_document(),
        mcp_upstream_servers: Vec::new(),
        egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
    })
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        32,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "inventory failure"
            }
        })),
        "mcp-inventory-failure",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32603));

    let row =
        wait_for_mcp_tool_inventory_row(&harness, &["mcp-inventory-failure"], "echo", |row| {
            row["call_count"] == json!(1) && status_count(row, 502) == Some(1)
        })
        .await;
    assert_eq!(row["method"], json!("MCP"));
    assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
    assert_eq!(row["call_count"], json!(1));
    assert_eq!(row["schema_mismatch_count"], json!(0));
    assert_eq!(status_count(&row, 502), Some(1));
}

#[tokio::test]
async fn unknown_mcp_tool_call_appears_as_inventory_row() {
    let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
        upstream_url: Some("http://127.0.0.1:1".to_owned()),
        tools_document: mcp_tools_document(),
        mcp_upstream_servers: Vec::new(),
        egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
    })
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        36,
        "tools/call",
        Some(json!({
            "name": "missing_tool",
            "arguments": {}
        })),
        "mcp-inventory-unknown-tool",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32601));
    assert_eq!(body["error"]["data"]["tool_name"], json!("missing_tool"));

    // The call is still inventoried, but under the shared unknown-tool
    // template: a caller-supplied name may not mint an inventory key.
    let row = wait_for_mcp_tool_inventory_row(
        &harness,
        &["mcp-inventory-unknown-tool"],
        "{tool}",
        |row| row["call_count"] == json!(1) && status_count(row, 404) == Some(1),
    )
    .await;
    assert_eq!(row["method"], json!("MCP"));
    assert_eq!(row["endpoint_template"], json!("/mcp/tools/{tool}"));
    assert_eq!(row["call_count"], json!(1));
    assert_eq!(row["schema_mismatch_count"], json!(0));
    assert_eq!(row["distinct_principal_count"], json!(1));
    assert_eq!(status_count(&row, 404), Some(1));
    assert!(
        inventory_rows_for_tool(&harness.router, &harness.admin_token, "missing_tool")
            .await
            .is_empty(),
        "the caller-supplied name must not become its own inventory row"
    );
}

#[tokio::test]
async fn task_style_mcp_tool_call_is_rejected_by_gateway_and_records_inventory() {
    let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
        upstream_url: Some("http://127.0.0.1:1".to_owned()),
        tools_document: mcp_tools_document(),
        mcp_upstream_servers: Vec::new(),
        egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
    })
    .await;

    let request_id = "mcp-inventory-task-unsupported";
    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        37,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": {
                "message": "task style"
            },
            "task": {}
        })),
        request_id,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32602));
    assert_eq!(
        body["error"]["message"],
        json!("task-based tool invocation is not supported by GreenGateway")
    );
    assert_eq!(body["error"]["data"]["tool_name"], json!("echo"));
    assert_eq!(body["error"]["data"]["reason"], json!("task_unsupported"));

    wait_for_delivered_audit_events(
        &harness.capture,
        "the task-style failure and its observation",
        |events| {
            let failure_seen = events.iter().any(|event| {
                event.event_type == audit::event::TOOL_INVOKE_FAILURE
                    && event.request_id == request_id
                    && event.payload["tool_name"] == json!("echo")
            });
            let observation_seen = events.iter().any(|event| {
                is_mcp_tool_observation(event, request_id)
                    && event.payload["tool_name"] == json!("echo")
                    && event.payload["status"] == json!(400)
                    && event.payload["reason"] == json!("task_unsupported")
            });
            failure_seen && observation_seen
        },
    )
    .await;

    let row = wait_for_mcp_tool_inventory_row(&harness, &[request_id], "echo", |row| {
        row["call_count"] == json!(1) && status_count(row, 400) == Some(1)
    })
    .await;
    assert_eq!(row["method"], json!("MCP"));
    assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
    assert_eq!(row["call_count"], json!(1));
    assert_eq!(row["schema_mismatch_count"], json!(0));
    assert_eq!(status_count(&row, 400), Some(1));
}

#[tokio::test]
async fn task_style_unknown_mcp_tool_call_uses_unknown_tool_inventory_path() {
    let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
        upstream_url: Some("http://127.0.0.1:1".to_owned()),
        tools_document: mcp_tools_document(),
        mcp_upstream_servers: Vec::new(),
        egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
    })
    .await;

    let request_id = "mcp-inventory-task-unknown-tool";
    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        38,
        "tools/call",
        Some(json!({
            "name": "missing_tool",
            "arguments": {},
            "task": {}
        })),
        request_id,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32601));
    assert_eq!(
        body["error"]["message"],
        json!("tool 'missing_tool' is not defined")
    );
    assert_eq!(body["error"]["data"]["tool_name"], json!("missing_tool"));

    wait_for_delivered_audit_events(&harness.capture, "the unknown-tool observation", |events| {
        events.iter().any(|event| {
            is_mcp_tool_observation(event, request_id)
                && event.payload["tool_name"] == json!("missing_tool")
                && event.payload["status"] == json!(404)
                && event.payload["reason"] == json!("unknown_tool")
        })
    })
    .await;

    let row = wait_for_mcp_tool_inventory_row(&harness, &[request_id], "{tool}", |row| {
        row["call_count"] == json!(1) && status_count(row, 404) == Some(1)
    })
    .await;
    assert_eq!(row["method"], json!("MCP"));
    assert_eq!(row["endpoint_template"], json!("/mcp/tools/{tool}"));
    assert_eq!(row["call_count"], json!(1));
    assert_eq!(row["schema_mismatch_count"], json!(0));
    assert_eq!(status_count(&row, 404), Some(1));
}

#[tokio::test]
async fn repeated_mcp_tool_calls_accumulate_into_one_inventory_row() {
    let upstream_addr = spawn_echo_json_upstream().await;
    let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
        upstream_url: Some(format!("http://{upstream_addr}")),
        tools_document: mcp_tools_document(),
        mcp_upstream_servers: Vec::new(),
        egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
    })
    .await;

    let request_ids = (0..3)
        .map(|index| format!("mcp-inventory-repeat-{index}"))
        .collect::<Vec<_>>();
    for (index, request_id) in (0..).zip(&request_ids) {
        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            33 + index,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": format!("inventory repeat {index}")
                }
            })),
            request_id,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["isError"], json!(false));
    }

    let request_ids = request_ids.iter().map(String::as_str).collect::<Vec<_>>();
    let row = wait_for_mcp_tool_inventory_row(&harness, &request_ids, "echo", |row| {
        row["call_count"] == json!(3) && status_count(row, 200) == Some(3)
    })
    .await;
    assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
    assert_eq!(row["call_count"], json!(3));
    assert_eq!(status_count(&row, 200), Some(3));
    assert_eq!(
        inventory_rows_for_tool(&harness.router, &harness.admin_token, "echo")
            .await
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tools_are_discovered_and_namespaced_in_tools_list() {
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let harness =
        mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        20,
        "tools/list",
        None,
        "mcp-upstream-list",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let tools = body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    let remote = tools
        .iter()
        .find(|tool| tool["name"] == json!("alpha:remote_echo"))
        .expect("upstream tool should be listed under its namespace");
    assert_eq!(remote["description"], json!("Remote test tool"));
    assert_eq!(remote["inputSchema"]["required"], json!(["message"]));
    assert_eq!(
        remote["inputSchema"]["properties"]["message"]["type"],
        json!("string")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tools_call_forwards_to_remote_tool_and_returns_result() {
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let calls = Arc::clone(&upstream.calls);
    let harness =
        mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        21,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "proxied hello"
            }
        })),
        "mcp-upstream-call",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["result"]["isError"], json!(false));
    assert_eq!(
        body["result"]["structuredContent"],
        json!({
            "remote_tool": "remote_echo",
            "arguments": {
                "message": "proxied hello"
            }
        })
    );
    assert_eq!(
        calls
            .lock()
            .expect("upstream calls lock should not poison")
            .as_slice(),
        &[json!({
            "name": "remote_echo",
            "arguments": {
                "message": "proxied hello"
            }
        })]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tool_call_rejects_response_larger_than_egress_limit() {
    const RESPONSE_LIMIT: usize = 512;

    let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::ToolCall, RESPONSE_LIMIT).await;
    let harness = mcp_upstream_test_harness_with_response_limit(
        "alpha",
        upstream.url.clone(),
        &["admin", "reader"],
        RESPONSE_LIMIT,
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        31,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "oversized upstream response"
            }
        })),
        "mcp-upstream-call-too-large",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32603));
    assert_eq!(body["error"]["message"], json!("tool invocation failed"));
    assert_eq!(
        body["error"]["data"]["tool_name"],
        json!("alpha:remote_echo")
    );
    assert_eq!(body["error"]["data"]["reason"], json!("response_too_large"));
    assert!(
        !upstream.oversized_body_started.load(Ordering::SeqCst),
        "Content-Length precheck should reject before the oversized call body is sent"
    );

    upstream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tool_call_rejects_request_larger_than_egress_limit_before_send() {
    const REQUEST_LIMIT: usize = 1024;

    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::None, 0).await;
    let tool_call_request_count = Arc::clone(&upstream.tool_call_request_count);
    let harness = mcp_upstream_test_harness_with_audit_and_limits(
        "alpha",
        upstream.url.clone(),
        &["admin", "reader"],
        audit_log,
        None,
        Some(REQUEST_LIMIT),
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        34,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "x".repeat(REQUEST_LIMIT)
            }
        })),
        "mcp-upstream-call-request-too-large",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32603));
    assert_eq!(body["error"]["message"], json!("tool invocation failed"));
    assert_eq!(
        body["error"]["data"]["tool_name"],
        json!("alpha:remote_echo")
    );
    assert_eq!(
        body["error"]["data"]["reason"],
        json!("request_body_too_large")
    );
    assert_eq!(
        tool_call_request_count.load(Ordering::SeqCst),
        0,
        "oversized MCP tools/call request must not reach the upstream"
    );
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                && event.request_id == "mcp-upstream-call-request-too-large"
                && event.payload["tool_name"] == json!("alpha:remote_echo")
                && event.payload["method"] == json!("MCP")
                && event.payload["outcome"] == json!("failure")
                && event.payload["reason"] == json!("request_body_too_large")
        })
    });

    upstream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tools_list_discovery_rejects_response_larger_than_egress_limit() {
    const RESPONSE_LIMIT: usize = 512;

    let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::ToolsList, RESPONSE_LIMIT).await;
    let harness = mcp_upstream_test_harness_with_response_limit(
        "alpha",
        upstream.url.clone(),
        &["admin", "reader"],
        RESPONSE_LIMIT,
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        32,
        "tools/list",
        None,
        "mcp-upstream-list-too-large",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let tools = body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    assert!(
        tools
            .iter()
            .all(|tool| tool["name"] != json!("alpha:remote_echo")),
        "oversized discovery response must not import upstream tools"
    );

    upstream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tools_list_discovery_rejects_excessive_pagination() {
    let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::TooManyToolsListPages, 0).await;
    let list_request_count = Arc::clone(&upstream.tools_list_request_count);
    let harness =
        mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        36,
        "tools/list",
        None,
        "mcp-upstream-list-too-many-pages",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let tools = body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    assert!(
        tools
            .iter()
            .all(|tool| tool["name"] != json!("alpha:remote_echo")),
        "excessive paginated discovery must fail closed and import no upstream tools"
    );
    assert!(
        list_request_count.load(Ordering::SeqCst) < RAW_MCP_EXCESSIVE_TOOLS_LIST_PAGES,
        "discovery should stop at its aggregate pagination cap"
    );

    upstream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tools_list_discovery_accepts_small_pagination() {
    let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::TwoPageToolsList, 0).await;
    let harness =
        mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        37,
        "tools/list",
        None,
        "mcp-upstream-list-small-pages",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let tools = body["result"]["tools"]
        .as_array()
        .expect("tools/list result should include tools array");
    assert!(
        tools
            .iter()
            .any(|tool| tool["name"] == json!("alpha:remote_echo")),
        "small paginated discovery should import the upstream tool"
    );

    upstream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tool_call_under_egress_limit_still_returns_result() {
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let harness = mcp_upstream_test_harness_with_response_limit(
        "alpha",
        upstream.url.clone(),
        &["admin", "reader"],
        16 * 1024,
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        33,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "small proxied hello"
            }
        })),
        "mcp-upstream-call-under-limit",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["result"]["isError"], json!(false));
    assert_eq!(
        body["result"]["structuredContent"],
        json!({
            "remote_tool": "remote_echo",
            "arguments": {
                "message": "small proxied hello"
            }
        })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tool_call_under_request_egress_limit_still_returns_result() {
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let calls = Arc::clone(&upstream.calls);
    let harness = mcp_upstream_test_harness_with_request_limit(
        "alpha",
        upstream.url.clone(),
        &["admin", "reader"],
        16 * 1024,
    )
    .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        35,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "small proxied hello"
            }
        })),
        "mcp-upstream-call-under-request-limit",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["result"]["isError"], json!(false));
    assert_eq!(
        body["result"]["structuredContent"],
        json!({
            "remote_tool": "remote_echo",
            "arguments": {
                "message": "small proxied hello"
            }
        })
    );
    assert_eq!(
        calls
            .lock()
            .expect("upstream calls lock should not poison")
            .len(),
        1,
        "under-limit MCP tools/call request should reach upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tool_call_emits_mcp_upstream_audit_event() {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let harness =
        mcp_upstream_test_harness_with_audit("alpha", upstream.url.clone(), &["admin"], audit_log)
            .await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        25,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "audit me"
            }
        })),
        "mcp-upstream-audit",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["isError"], json!(false));
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                && event.request_id == "mcp-upstream-audit"
                && event.payload["tool_name"] == json!("alpha:remote_echo")
                && event.payload["method"] == json!("MCP")
                && event.payload["upstream_type"] == json!("mcp")
                && event.payload["mcp_server_name"] == json!("alpha")
                && event.payload["mcp_tool_name"] == json!("remote_echo")
                && event.payload["outcome"] == json!("success")
        })
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tool_role_policy_is_enforced_before_forwarding() {
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let calls = Arc::clone(&upstream.calls);
    let harness = mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin"]).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.reader_token),
        22,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "reader should not forward"
            }
        })),
        "mcp-upstream-role-denied",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32001));
    assert_eq!(
        body["error"]["message"],
        json!("tool invocation is denied by role policy")
    );
    assert_eq!(
        body["error"]["data"]["tool_name"],
        json!("alpha:remote_echo")
    );
    assert_eq!(body["error"]["data"]["reason"], json!("role_denied"));
    assert!(
        calls
            .lock()
            .expect("upstream calls lock should not poison")
            .is_empty(),
        "role-denied proxy call must not reach upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_tool_schema_validation_applies_before_forwarding() {
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let calls = Arc::clone(&upstream.calls);
    let harness =
        mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        23,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "valid field",
                "unexpected": true
            }
        })),
        "mcp-upstream-schema-denied",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32602));
    assert_eq!(
        body["error"]["data"]["tool_name"],
        json!("alpha:remote_echo")
    );
    assert!(body["error"]["message"]
        .as_str()
        .expect("invalid params error should include a message")
        .contains("failed input schema validation"));
    assert!(
        calls
            .lock()
            .expect("upstream calls lock should not poison")
            .is_empty(),
        "schema-invalid proxy call must not reach upstream"
    );
}

#[tokio::test]
async fn mcp_upstream_url_rejected_by_egress_allowlist_fails_startup() {
    let secret_host = "secret-blocked-mcp.example.test";
    let mut config = test_config(Vec::new());
    config.mcp_upstream_servers = vec![config::McpUpstreamServerConfig {
        name: "alpha".to_owned(),
        url: format!("http://{secret_host}/mcp"),
        timeout_ms: Some(500),
        response_idle_timeout_ms: Some(500),
        connect_timeout_ms: Some(500),
    }];
    config.egress_allowed_hosts = Vec::new();
    config.egress_deny_private_ips = false;

    let recorder = PrometheusBuilder::new().build_recorder();
    let error = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect_err("non-allowlisted MCP upstream should fail startup");
    let message = format!("{error} {error:?}");
    assert!(
        message.contains("MCP upstream server 'alpha' URL is rejected by egress policy"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("host_not_allowed"),
        "unexpected error: {message}"
    );
    assert!(
        !message.contains(secret_host),
        "startup error leaked rejected MCP destination: {message}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_namespaced_name_collision_fails_startup() {
    let first = spawn_test_mcp_upstream("beta:echo").await;
    let second = spawn_test_mcp_upstream("echo").await;
    let mut config = test_config(Vec::new());
    config.mcp_upstream_servers = vec![
        config::McpUpstreamServerConfig {
            name: "alpha".to_owned(),
            url: first.url,
            timeout_ms: Some(1000),
            response_idle_timeout_ms: Some(1000),
            connect_timeout_ms: Some(1000),
        },
        config::McpUpstreamServerConfig {
            name: "alpha:beta".to_owned(),
            url: second.url,
            timeout_ms: Some(1000),
            response_idle_timeout_ms: Some(1000),
            connect_timeout_ms: Some(1000),
        },
    ];
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;

    let recorder = PrometheusBuilder::new().build_recorder();
    let error = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect_err("namespaced MCP upstream tool collision should fail startup");
    let message = error.to_string();
    assert!(
        message.contains("duplicate tool name 'alpha:beta:echo'"),
        "unexpected error: {message}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_upstream_unreachable_call_uses_sanitized_error() {
    let upstream = spawn_test_mcp_upstream("remote_echo").await;
    let port = upstream.addr.port();
    let url = upstream.url.clone();
    let harness = mcp_upstream_test_harness("alpha", url, &["admin"]).await;
    upstream.shutdown().await;

    let (status, body) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        24,
        "tools/call",
        Some(json!({
            "name": "alpha:remote_echo",
            "arguments": {
                "message": "after shutdown"
            }
        })),
        "mcp-upstream-unreachable",
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], json!(-32603));
    assert_eq!(body["error"]["message"], json!("tool invocation failed"));
    assert_eq!(
        body["error"]["data"]["tool_name"],
        json!("alpha:remote_echo")
    );
    assert_eq!(body["error"]["data"]["reason"], json!("connect_failed"));
    let body_string = body.to_string();
    assert!(!body_string.contains("127.0.0.1"));
    assert!(!body_string.contains(&port.to_string()));
    assert!(!body_string.contains("connection"));
    assert!(!body_string.contains(concat!("req", "west")));
}

#[tokio::test]
async fn mcp_streaming_body_limit_rejects_missing_or_underdeclared_content_length() {
    const MAX_BODY_SIZE: usize = 32;

    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.csrf_enabled = false;
    config.max_body_size = MAX_BODY_SIZE;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    for declared_length in [None, Some("1")] {
        let chunks = stream::iter(vec![
            Ok::<Bytes, Infallible>(Bytes::from(vec![b'a'; MAX_BODY_SIZE])),
            Ok::<Bytes, Infallible>(Bytes::from_static(b"b")),
        ]);
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(MCP_ROUTE)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(declared_length) = declared_length {
            builder = builder.header(header::CONTENT_LENGTH, declared_length);
        }
        let request = builder
            .body(Body::from_stream(chunks))
            .expect("streaming MCP request should build");

        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("streaming MCP request should complete");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            json_body(response).await,
            json!({
                "error": "payload too large",
                "max_body_size": MAX_BODY_SIZE
            })
        );
    }
}

#[tokio::test]
async fn mcp_streaming_body_limit_allows_body_at_exact_limit() {
    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "body-limit-test",
                "version": "1.0.0"
            }
        }
    })
    .to_string();
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.csrf_enabled = false;
    config.max_body_size = request_body.len();
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let chunks = stream::iter(vec![Ok::<Bytes, Infallible>(Bytes::from(request_body))]);
    let request = Request::builder()
        .method(Method::POST)
        .uri(MCP_ROUTE)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .body(Body::from_stream(chunks))
        .expect("streaming MCP request should build");

    let response = router
        .oneshot(request)
        .await
        .expect("MCP request at exact limit should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

async fn mcp_test_harness_with_public_url(
    echo_allowed_roles: &[&str],
    audit_log: audit::AuditLog,
    gateway_public_url: &str,
) -> McpTestHarness {
    let upstream_addr = spawn_echo_json_upstream().await;
    mcp_test_harness_from_parts(
        echo_allowed_roles,
        audit_log,
        format!("http://{upstream_addr}"),
        mcp_tools_document(),
        vec!["127.0.0.1".to_owned()],
        Some(gateway_public_url.to_owned()),
        &["admin", auth::protected_resource::MCP_SCOPE],
    )
    .await
}

struct McpUpstreamTestHarness {
    router: Router,
    admin_token: String,
    reader_token: String,
    _blocked_token: String,
    _policy: TempPolicyFile,
    _token_db: TempDb,
}

struct McpInventoryHarnessConfig {
    upstream_url: Option<String>,
    tools_document: String,
    mcp_upstream_servers: Vec<config::McpUpstreamServerConfig>,
    egress_allowed_hosts: Vec<String>,
}

struct McpInventoryTestHarness {
    router: Router,
    admin_token: String,
    capture: audit::sink::tests::CaptureSink,
    _policy: TempPolicyFile,
    _tools: TempToolsFile,
    _token_db: TempDb,
    _discovery_db: TempDb,
}

async fn mcp_inventory_test_harness(
    harness_config: McpInventoryHarnessConfig,
) -> McpInventoryTestHarness {
    let token_db = TempDb::new("mcp-inventory-service-tokens");
    let discovery_db = TempDb::new("mcp-inventory-discovery");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let admin_token = create_service_token(&token_store, &["admin"]);
    let policy = TempPolicyFile::new(&mcp_inventory_policy_document());
    let tools = TempToolsFile::new(&harness_config.tools_document);

    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.tools_file = Some(tools.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 20;
    config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
    config.upstream_url = harness_config.upstream_url;
    config.mcp_upstream_servers = harness_config.mcp_upstream_servers;
    config.egress_allowed_hosts = harness_config.egress_allowed_hosts;
    config.egress_deny_private_ips = false;

    // No audit store of record here: this test is not about durability,
    // so it runs the explicit best-effort opt-out (issue #425).
    config.audit_durability = config::AuditDurability::BestEffort;
    let (sink, audit_event_sender) =
        audit::sink::build_sink_from_config(&config).expect("audit sink should build");
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(audit::sink::CompositeSink::new(vec![
        sink,
        Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>,
    ])) as Arc<dyn audit::AuditSink>);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(config, recorder.handle(), audit_log, audit_event_sender)
        .expect("MCP inventory test app should build");

    McpInventoryTestHarness {
        router,
        admin_token,
        capture,
        _policy: policy,
        _tools: tools,
        _token_db: token_db,
        _discovery_db: discovery_db,
    }
}

async fn mcp_upstream_test_harness(
    server_name: &str,
    upstream_url: String,
    allowed_roles: &[&str],
) -> McpUpstreamTestHarness {
    mcp_upstream_test_harness_with_audit(server_name, upstream_url, allowed_roles, test_audit_log())
        .await
}

async fn mcp_upstream_test_harness_with_response_limit(
    server_name: &str,
    upstream_url: String,
    allowed_roles: &[&str],
    max_response_bytes: usize,
) -> McpUpstreamTestHarness {
    mcp_upstream_test_harness_with_audit_and_response_limit(
        server_name,
        upstream_url,
        allowed_roles,
        test_audit_log(),
        Some(max_response_bytes),
    )
    .await
}

async fn mcp_upstream_test_harness_with_request_limit(
    server_name: &str,
    upstream_url: String,
    allowed_roles: &[&str],
    max_request_body_bytes: usize,
) -> McpUpstreamTestHarness {
    mcp_upstream_test_harness_with_audit_and_limits(
        server_name,
        upstream_url,
        allowed_roles,
        test_audit_log(),
        None,
        Some(max_request_body_bytes),
    )
    .await
}

async fn mcp_upstream_test_harness_with_audit(
    server_name: &str,
    upstream_url: String,
    allowed_roles: &[&str],
    audit_log: audit::AuditLog,
) -> McpUpstreamTestHarness {
    mcp_upstream_test_harness_with_audit_and_response_limit(
        server_name,
        upstream_url,
        allowed_roles,
        audit_log,
        None,
    )
    .await
}

async fn mcp_upstream_test_harness_with_audit_and_response_limit(
    server_name: &str,
    upstream_url: String,
    allowed_roles: &[&str],
    audit_log: audit::AuditLog,
    max_response_bytes: Option<usize>,
) -> McpUpstreamTestHarness {
    mcp_upstream_test_harness_with_audit_and_limits(
        server_name,
        upstream_url,
        allowed_roles,
        audit_log,
        max_response_bytes,
        None,
    )
    .await
}

async fn mcp_upstream_test_harness_with_audit_and_limits(
    server_name: &str,
    upstream_url: String,
    allowed_roles: &[&str],
    audit_log: audit::AuditLog,
    max_response_bytes: Option<usize>,
    max_request_body_bytes: Option<usize>,
) -> McpUpstreamTestHarness {
    let token_db = TempDb::new("mcp-upstream-service-tokens");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let admin_token = create_service_token(&token_store, &["admin"]);
    let reader_token = create_service_token(&token_store, &["reader"]);
    let blocked_token = create_service_token(&token_store, &["blocked"]);
    let tool_name = format!("{server_name}:remote_echo");
    let policy = TempPolicyFile::new(&mcp_upstream_policy_document(&tool_name, allowed_roles));

    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 20;
    config.mcp_upstream_servers = vec![config::McpUpstreamServerConfig {
        name: server_name.to_owned(),
        url: upstream_url,
        timeout_ms: Some(2_000),
        response_idle_timeout_ms: Some(2_000),
        connect_timeout_ms: Some(2_000),
    }];
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    if let Some(max_response_bytes) = max_response_bytes {
        config.egress_max_response_bytes = max_response_bytes;
    }
    if let Some(max_request_body_bytes) = max_request_body_bytes {
        config.egress_max_request_body_bytes = max_request_body_bytes;
    }

    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("MCP upstream test app should build");

    McpUpstreamTestHarness {
        router,
        admin_token,
        reader_token,
        _blocked_token: blocked_token,
        _policy: policy,
        _token_db: token_db,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RawMcpOversizeTarget {
    None,
    ToolsList,
    ToolCall,
    TooManyToolsListPages,
    TwoPageToolsList,
}

const RAW_MCP_EXCESSIVE_TOOLS_LIST_PAGES: usize = 40;

struct RawMcpUpstream {
    url: String,
    oversized_body_started: Arc<AtomicBool>,
    tool_call_request_count: Arc<AtomicUsize>,
    tools_list_request_count: Arc<AtomicUsize>,
    shutdown: tokio_util::sync::CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl RawMcpUpstream {
    async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(1), self.handle).await;
    }
}

async fn spawn_raw_mcp_upstream(
    oversize_target: RawMcpOversizeTarget,
    max_response_bytes: usize,
) -> RawMcpUpstream {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("raw MCP upstream should bind");
    let addr = listener
        .local_addr()
        .expect("raw MCP upstream address should be available");
    let shutdown = tokio_util::sync::CancellationToken::new();
    let shutdown_task = shutdown.clone();
    let oversized_body_started = Arc::new(AtomicBool::new(false));
    let oversized_body_started_task = Arc::clone(&oversized_body_started);
    let tool_call_request_count = Arc::new(AtomicUsize::new(0));
    let tool_call_request_count_task = Arc::clone(&tool_call_request_count);
    let tools_list_request_count = Arc::new(AtomicUsize::new(0));
    let tools_list_request_count_task = Arc::clone(&tools_list_request_count);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_task.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else {
                        break;
                    };
                    let shutdown_connection = shutdown_task.clone();
                    let oversized_body_started_connection =
                        Arc::clone(&oversized_body_started_task);
                    let tool_call_request_count_connection =
                        Arc::clone(&tool_call_request_count_task);
                    let tools_list_request_count_connection =
                        Arc::clone(&tools_list_request_count_task);
                    tokio::spawn(async move {
                        handle_raw_mcp_connection(
                            &mut stream,
                            oversize_target,
                            max_response_bytes,
                            oversized_body_started_connection,
                            tool_call_request_count_connection,
                            tools_list_request_count_connection,
                            shutdown_connection,
                        )
                        .await;
                    });
                }
            }
        }
    });

    RawMcpUpstream {
        url: format!("http://{addr}/mcp"),
        oversized_body_started,
        tool_call_request_count,
        tools_list_request_count,
        shutdown,
        handle,
    }
}

async fn handle_raw_mcp_connection(
    stream: &mut tokio::net::TcpStream,
    oversize_target: RawMcpOversizeTarget,
    max_response_bytes: usize,
    oversized_body_started: Arc<AtomicBool>,
    tool_call_request_count: Arc<AtomicUsize>,
    tools_list_request_count: Arc<AtomicUsize>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let Some(request) = read_raw_mcp_http_request(stream).await else {
        return;
    };
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if method == "tools/call" {
        tool_call_request_count.fetch_add(1, Ordering::SeqCst);
    }
    if method == "tools/list" {
        tools_list_request_count.fetch_add(1, Ordering::SeqCst);
    }

    match method {
        "initialize" => {
            write_raw_mcp_json_response(stream, raw_mcp_initialize_response(&request)).await;
        }
        "notifications/initialized" => {
            write_raw_mcp_accepted_response(stream).await;
        }
        "tools/list" if oversize_target == RawMcpOversizeTarget::ToolsList => {
            write_raw_mcp_oversized_response(
                stream,
                raw_mcp_oversized_tools_list_response(&request, max_response_bytes),
                true,
                oversized_body_started,
                shutdown,
            )
            .await;
        }
        "tools/list" if oversize_target == RawMcpOversizeTarget::TooManyToolsListPages => {
            write_raw_mcp_json_response(
                stream,
                raw_mcp_excessive_tools_list_page_response(&request),
            )
            .await;
        }
        "tools/list" if oversize_target == RawMcpOversizeTarget::TwoPageToolsList => {
            write_raw_mcp_json_response(stream, raw_mcp_two_page_tools_list_response(&request))
                .await;
        }
        "tools/list" => {
            write_raw_mcp_json_response(stream, raw_mcp_tools_list_response(&request)).await;
        }
        "tools/call" if oversize_target == RawMcpOversizeTarget::ToolCall => {
            write_raw_mcp_oversized_response(
                stream,
                raw_mcp_oversized_call_response(&request, max_response_bytes),
                false,
                oversized_body_started,
                shutdown,
            )
            .await;
        }
        "tools/call" => {
            write_raw_mcp_json_response(stream, raw_mcp_call_response(&request)).await;
        }
        _ => {
            write_raw_mcp_json_response(
                stream,
                json!({
                    "jsonrpc": "2.0",
                    "id": raw_mcp_request_id(&request),
                    "error": {
                        "code": -32601,
                        "message": "method not found"
                    }
                }),
            )
            .await;
        }
    }
}

async fn read_raw_mcp_http_request(stream: &mut tokio::net::TcpStream) -> Option<Value> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .await
            .expect("raw MCP upstream should read request");
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break index;
        }
        assert!(
            buffer.len() <= 16 * 1024,
            "raw MCP request headers should stay bounded"
        );
    };
    let raw_headers = std::str::from_utf8(&buffer[..header_end])
        .expect("raw MCP request headers should be UTF-8");
    let content_length = raw_headers
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let read = stream
            .read(&mut chunk)
            .await
            .expect("raw MCP upstream should read request body");
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }

    Some(
        serde_json::from_slice::<Value>(&buffer[body_start..body_start + content_length])
            .unwrap_or_else(|err| panic!("raw MCP request body should be JSON: {err}")),
    )
}

async fn write_raw_mcp_json_response(stream: &mut tokio::net::TcpStream, body: Value) {
    let body = body.to_string();
    let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("raw MCP upstream should write JSON response");
}

async fn write_raw_mcp_accepted_response(stream: &mut tokio::net::TcpStream) {
    stream
        .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .expect("raw MCP upstream should write accepted response");
}

async fn write_raw_mcp_oversized_response(
    stream: &mut tokio::net::TcpStream,
    body: Value,
    send_body: bool,
    oversized_body_started: Arc<AtomicBool>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let body = body.to_string();
    let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
    stream
        .write_all(headers.as_bytes())
        .await
        .expect("raw MCP upstream should write oversized response headers");

    if send_body {
        oversized_body_started.store(true, Ordering::SeqCst);
        stream
            .write_all(body.as_bytes())
            .await
            .expect("raw MCP upstream should write oversized response body");
        return;
    }

    tokio::select! {
        _ = shutdown.cancelled() => {}
        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
    }
}

fn raw_mcp_request_id(request: &Value) -> Value {
    request.get("id").cloned().unwrap_or(Value::Null)
}

fn raw_mcp_initialize_response(request: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": raw_mcp_request_id(request),
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "raw-greengateway-test-upstream",
                "version": "0.0.0"
            }
        }
    })
}

fn raw_mcp_tools_list_response(request: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": raw_mcp_request_id(request),
        "result": {
            "tools": [raw_mcp_tool("Remote test tool")]
        }
    })
}

fn raw_mcp_excessive_tools_list_page_response(request: &Value) -> Value {
    let page = raw_mcp_request_page(request);
    let tool_name = if page == 0 {
        "remote_echo".to_owned()
    } else {
        format!("remote_echo_page_{page}")
    };
    let mut result = json!({
        "tools": [raw_mcp_named_tool(tool_name, "Remote paginated test tool")]
    });
    if page + 1 < RAW_MCP_EXCESSIVE_TOOLS_LIST_PAGES {
        result["nextCursor"] = json!((page + 1).to_string());
    }

    json!({
        "jsonrpc": "2.0",
        "id": raw_mcp_request_id(request),
        "result": result
    })
}

fn raw_mcp_two_page_tools_list_response(request: &Value) -> Value {
    let page = raw_mcp_request_page(request);
    let result = if page == 0 {
        json!({
            "tools": [],
            "nextCursor": "1"
        })
    } else {
        json!({
            "tools": [raw_mcp_tool("Remote paginated test tool")]
        })
    };

    json!({
        "jsonrpc": "2.0",
        "id": raw_mcp_request_id(request),
        "result": result
    })
}

fn raw_mcp_request_page(request: &Value) -> usize {
    request
        .get("params")
        .and_then(|params| params.get("cursor"))
        .and_then(Value::as_str)
        .and_then(|cursor| cursor.parse::<usize>().ok())
        .unwrap_or(0)
}

fn raw_mcp_oversized_tools_list_response(request: &Value, max_response_bytes: usize) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": raw_mcp_request_id(request),
        "result": {
            "tools": [raw_mcp_tool("x".repeat(max_response_bytes + 256))]
        }
    })
}

fn raw_mcp_tool(description: impl Into<String>) -> Value {
    raw_mcp_named_tool("remote_echo", description)
}

fn raw_mcp_named_tool(name: impl Into<String>, description: impl Into<String>) -> Value {
    json!({
        "name": name.into(),
        "description": description.into(),
        "inputSchema": remote_echo_input_schema()
    })
}

fn raw_mcp_call_response(request: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": raw_mcp_request_id(request),
        "result": {
            "content": [],
            "structuredContent": {
                "remote_tool": "remote_echo",
                "arguments": {}
            },
            "isError": false
        }
    })
}

fn raw_mcp_oversized_call_response(request: &Value, max_response_bytes: usize) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": raw_mcp_request_id(request),
        "result": {
            "content": [{
                "type": "text",
                "text": "x".repeat(max_response_bytes + 256)
            }],
            "isError": false
        }
    })
}

async fn spawn_fixed_echo_upstream(
    status: StatusCode,
    content_type: &'static str,
    body: String,
) -> std::net::SocketAddr {
    spawn_fixed_echo_upstream_with_headers(status, content_type, body, Vec::new()).await
}

async fn spawn_fixed_echo_upstream_with_headers(
    status: StatusCode,
    content_type: &'static str,
    body: String,
    headers: Vec<(&'static str, &'static str)>,
) -> std::net::SocketAddr {
    let body = Arc::new(body);
    let headers = Arc::new(headers);

    spawn_router(Router::new().route(
        "/v1/echo",
        post(move || {
            let body = Arc::clone(&body);
            let headers = Arc::clone(&headers);
            async move {
                let mut builder = Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, content_type);
                for (name, value) in headers.iter() {
                    builder = builder.header(*name, *value);
                }

                builder
                    .body(Body::from(body.as_ref().clone()))
                    .expect("fixed upstream response should build")
            }
        }),
    ))
    .await
}

fn authenticated_json_request(
    method: Method,
    uri: &str,
    token: &str,
    body: Option<String>,
    if_match: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, "csrf_token=mcp-test-csrf")
        .header("x-csrf-token", "mcp-test-csrf");

    if let Some(if_match) = if_match {
        builder = builder.header(header::IF_MATCH, if_match);
    }

    builder
        .body(Body::from(body.unwrap_or_default()))
        .expect("authenticated JSON request should build")
}

fn mcp_cookie_request(
    session_cookie: &str,
    id: u64,
    method: &str,
    params: Option<Value>,
    request_id: &str,
) -> Request<Body> {
    let mut request = mcp_request(None, id, method, params, request_id);
    request.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("{session_cookie}; csrf_token=mcp-test-csrf"))
            .expect("test cookie header should be valid"),
    );
    request
}

fn mcp_content_text(body: &Value) -> &str {
    body["result"]["content"][0]["text"]
        .as_str()
        .expect("MCP result should include text content")
}

/// The per-tool observation an MCP `tools/call` emits (method `MCP`), as
/// opposed to the HTTP observation of the `POST /mcp` that carried it.
fn is_mcp_tool_observation(event: &audit::AuditEvent, request_id: &str) -> bool {
    event.event_type == "http.request_observed"
        && event.request_id == request_id
        && event.payload["method"] == json!("MCP")
}

/// The inventory row for `tool_name` once it matches `condition`. Reading it
/// before the observations it is built from reached the aggregator would
/// charge the aggregation window for the audit writer's delivery, so the
/// observation of every request in `request_ids` is awaited first.
async fn wait_for_mcp_tool_inventory_row(
    harness: &McpInventoryTestHarness,
    request_ids: &[&str],
    tool_name: &str,
    condition: impl Fn(&Value) -> bool,
) -> Value {
    wait_for_delivered_audit_events(&harness.capture, "the MCP tool observations", |events| {
        request_ids.iter().all(|request_id| {
            events
                .iter()
                .any(|event| is_mcp_tool_observation(event, request_id))
        })
    })
    .await;
    let (router, token) = (&harness.router, harness.admin_token.as_str());

    // From here the aggregator holds every observation, and the bound is
    // its flush (every 250 ms) and the query on an instrumented, loaded
    // Windows runner, not a throughput SLO; the exact row/count assertions
    // stay unchanged.
    let started = Instant::now();

    loop {
        let rows = inventory_rows_for_tool(router, token, tool_name).await;
        if let Some(row) = rows.iter().find(|row| condition(row)) {
            return row.clone();
        }

        assert!(
            started.elapsed() < Duration::from_secs(10),
            "MCP tool inventory row did not match condition: {rows:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn inventory_rows_for_tool(router: &Router, token: &str, tool_name: &str) -> Vec<Value> {
    let endpoint_template = format!("/mcp/tools/{tool_name}");
    // Query on the shared prefix and filter exactly, so a template holding
    // URI-hostile characters (the unknown-tool placeholder) still resolves.
    let uri =
        format!("{TRAFFIC_ENDPOINTS_ADMIN_ROUTE}?method=MCP&endpoint_template_prefix=/mcp/tools/");
    let response = router
        .clone()
        .oneshot(bearer_get_request(&uri, token))
        .await;
    let response = response.expect("traffic inventory request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;

    body["endpoints"]
        .as_array()
        .expect("traffic response should include endpoints")
        .iter()
        .filter(|row| row["endpoint_template"] == json!(endpoint_template))
        .cloned()
        .collect()
}

fn status_count(row: &Value, status: u16) -> Option<u64> {
    row["status_counts"]
        .as_array()?
        .iter()
        .find(|count| count["status"] == json!(status))
        .and_then(|count| count["count"].as_u64())
}

fn mcp_inventory_policy_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "mcp-inventory-test-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_MCP_USE_PERMISSION,
                    ADMIN_TRAFFIC_READ_PERMISSION,
                    ADMIN_SIGNALS_READ_PERMISSION
                ]
            }
        },
        "routes": [
            {
                "methods": ["POST"],
                "path_prefix": MCP_ROUTE,
                "permission": ADMIN_MCP_USE_PERMISSION
            },
            {
                "methods": ["GET"],
                "path_prefix": TRAFFIC_ENDPOINTS_ADMIN_ROUTE,
                "permission": ADMIN_TRAFFIC_READ_PERMISSION
            }
        ],
        "tools": {
            "echo": {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            },
            "get_widget": {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            },
            "alpha:remote_echo": {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            }
        }
    })
    .to_string()
}

fn mcp_upstream_policy_document(tool_name: &str, allowed_roles: &[&str]) -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "mcp-upstream-test-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [ADMIN_MCP_USE_PERMISSION]
            },
            "reader": {
                "permissions": [ADMIN_MCP_USE_PERMISSION]
            },
            "blocked": {
                "permissions": []
            }
        },
        "routes": [
            {
                "methods": ["POST"],
                "path_prefix": MCP_ROUTE,
                "permission": ADMIN_MCP_USE_PERMISSION
            }
        ],
        "tools": {
            tool_name: {
                "allowed_roles": allowed_roles,
                "timeout_ms": 5000,
                "max_concurrent": 2
            }
        }
    })
    .to_string()
}
