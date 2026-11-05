//! The MCP client configuration templates route (issue #242, ADR-0008 "MCP
//! client templates"): its permission, the URL it computes, and what can
//! never reach a template.
use super::*;
use gateway_config::mcp_client_configs::{
    self, Auth, ClientKind, Format, McpClientConfigs, DEFAULT_SERVER_NAME, TOKEN_VARIABLE,
};

/// A value placed wherever a credential or a hostile origin could come
/// from; no response may ever carry it.
const CANARY: &str = "gg-canary-mcp-clients-91c7e2";

fn clients_policy(default_action: &str, routes: Value) -> TempPolicyFile {
    TempPolicyFile::new(
        &json!({
            "schema_version": "0.1.0",
            "id": "mcp-client-configs-policy",
            "default_action": default_action,
            "roles": {
                "mcp-clients-reader": {"permissions": [ADMIN_MCP_CLIENTS_READ_PERMISSION]},
                "config-reader": {"permissions": [ADMIN_CONFIG_READ_PERMISSION]},
                "tokens-writer": {"permissions": [ADMIN_TOKENS_WRITE_PERMISSION]}
            },
            "routes": routes
        })
        .to_string(),
    )
}

/// Exempts the route from the RBAC middleware so the handler's own
/// permission check is what decides, as the capability route's tests do.
fn handler_checked_config(policy: &TempPolicyFile, public_url: Option<&str>) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.gateway_public_url = public_url.map(str::to_owned);
    config
        .rbac_exempt_paths
        .push(MCP_CLIENT_CONFIGS_ADMIN_ROUTE.to_owned());
    config
}

async fn clients_response(router: Router, uri: &str, roles: Option<&[&str]>) -> Response {
    router
        .oneshot(audit_query_request(uri, roles.map(test_principal)))
        .await
        .expect("request should complete")
}

async fn templates_for(config: config::Config, uri: &str) -> McpClientConfigs {
    let response = clients_response(
        status_router(config, Instant::now()),
        uri,
        Some(&["mcp-clients-reader"]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    assert!(!String::from_utf8_lossy(&body).contains(CANARY));
    mcp_client_configs::read(&body).expect("the shared reader accepts what the gateway serves")
}

async fn refusal(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let body: Value = serde_json::from_str(&body_string(response).await).expect("JSON body");
    (status, body)
}

#[tokio::test]
async fn mcp_client_configs_require_a_principal_a_policy_and_their_own_permission() {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.gateway_public_url = Some("https://gateway.example.test".to_owned());
    let response = clients_response(
        status_router(config.clone(), Instant::now()),
        MCP_CLIENT_CONFIGS_ADMIN_ROUTE,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = clients_response(
        status_router(config, Instant::now()),
        MCP_CLIENT_CONFIGS_ADMIN_ROUTE,
        Some(&["mcp-clients-reader"]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"MCP client configuration API requires POLICY_FILE to be configured"}"#
    );

    // Neither configuration read nor token management grants the templates.
    let policy = clients_policy("allow", json!([]));
    for roles in [&["config-reader"][..], &["tokens-writer"], &[]] {
        let response = clients_response(
            status_router(
                handler_checked_config(&policy, Some("https://gateway.example.test")),
                Instant::now(),
            ),
            MCP_CLIENT_CONFIGS_ADMIN_ROUTE,
            Some(roles),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
        assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
    }
    let document = templates_for(
        handler_checked_config(&policy, Some("https://gateway.example.test")),
        MCP_CLIENT_CONFIGS_ADMIN_ROUTE,
    )
    .await;
    assert_eq!(document.mcp_url, "https://gateway.example.test/mcp");
}

#[tokio::test]
async fn the_admin_capabilities_report_the_template_permission_to_its_holder_only() {
    let policy = clients_policy("allow", json!([]));
    let config = handler_checked_config(&policy, None);
    for (roles, listed) in [
        (&["mcp-clients-reader"][..], true),
        (&["config-reader"], false),
    ] {
        let response = clients_response(
            status_router(config.clone(), Instant::now()),
            ADMIN_CAPABILITIES_ROUTE,
            Some(roles),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_str(&body_string(response).await).expect("JSON");
        let permissions = body["permissions"].as_array().expect("permissions");
        assert_eq!(
            permissions.contains(&json!(ADMIN_MCP_CLIENTS_READ_PERMISSION)),
            listed,
            "{roles:?}"
        );
    }
}

#[tokio::test]
async fn templates_name_the_public_mcp_endpoint_whatever_the_request_says() {
    let policy = clients_policy("allow", json!([]));
    let config = handler_checked_config(&policy, Some("https://gateway.example.test/base/"));
    let metadata = auth::protected_resource::ProtectedResourceMetadataConfig::from_config(&config)
        .expect("a public URL configures the metadata");
    let router = status_router(config, Instant::now());

    let mut request = audit_query_request(
        MCP_CLIENT_CONFIGS_ADMIN_ROUTE,
        Some(test_principal(&["mcp-clients-reader"])),
    );
    let hostile = format!("{CANARY}.example.test");
    for (name, value) in [
        ("host", hostile.clone()),
        ("x-forwarded-host", hostile.clone()),
        ("x-forwarded-proto", "http".to_owned()),
        ("x-forwarded-prefix", format!("/{CANARY}")),
        ("x-original-url", format!("/{CANARY}/mcp")),
        ("forwarded", format!("host={hostile};proto=http")),
        ("origin", format!("https://{hostile}")),
        ("referer", format!("https://{hostile}/admin")),
        ("authorization", format!("Bearer {CANARY}")),
        ("cookie", format!("session={CANARY}")),
    ] {
        request.headers_mut().insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value).expect("header value"),
        );
    }
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert!(!body.contains(CANARY), "{body}");
    let document = mcp_client_configs::read(body.as_bytes()).expect("readable");

    // The URL is the protected resource the gateway enforces, the one its
    // public metadata document advertises: never an upstream, never the
    // caller's origin.
    assert_eq!(document.mcp_url, "https://gateway.example.test/base/mcp");
    assert_eq!(document.mcp_url, metadata.mcp_resource());
    let advertised = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource/base/mcp")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(advertised.status(), StatusCode::OK);
    let advertised: Value =
        serde_json::from_str(&body_string(advertised).await).expect("metadata JSON");
    assert_eq!(advertised["resource"], document.mcp_url.as_str());
}

#[tokio::test]
async fn the_url_is_normalized_exactly_as_the_resource_identifier_is() {
    let policy = clients_policy("allow", json!([]));
    for (public_url, expected) in [
        (
            "https://gateway.example.test",
            "https://gateway.example.test/mcp",
        ),
        (
            "https://gateway.example.test/",
            "https://gateway.example.test/mcp",
        ),
        (
            "https://GATEWAY.Example.Test:443/Base/",
            "https://gateway.example.test/Base/mcp",
        ),
        (
            "https://gateway.example.test\\base\\",
            "https://gateway.example.test/base/mcp",
        ),
        (
            "https://gateway.example.test/a/../base",
            "https://gateway.example.test/base/mcp",
        ),
        (
            "https://gateway.example.test/caf\u{e9} \"x\"",
            "https://gateway.example.test/caf%C3%A9%20%22x%22/mcp",
        ),
        (
            "https://b\u{fc}cher.example.test/base",
            "https://xn--bcher-kva.example.test/base/mcp",
        ),
        (
            "https://gateway.example.test:8443/base?tenant=a",
            "https://gateway.example.test:8443/base/mcp?tenant=a",
        ),
        (
            "http://127.0.0.1:8080/base",
            "http://127.0.0.1:8080/base/mcp",
        ),
    ] {
        let config = handler_checked_config(&policy, Some(public_url));
        let resource =
            auth::protected_resource::ProtectedResourceMetadataConfig::from_config(&config)
                .expect("metadata")
                .mcp_resource();
        assert_eq!(resource, expected, "{public_url}");
        let document = templates_for(config, MCP_CLIENT_CONFIGS_ADMIN_ROUTE).await;
        assert_eq!(document.mcp_url, expected, "{public_url}");
        for template in &document.templates {
            assert!(template.content.contains(expected), "{public_url}");
        }
    }
}

#[tokio::test]
async fn without_a_usable_public_url_the_route_refuses_rather_than_guessing() {
    let policy = clients_policy("allow", json!([]));
    for (public_url, reason) in [
        (None, "public_url_not_configured"),
        (
            Some("https://gateway.example.test/$base"),
            "public_url_not_templatable",
        ),
        (
            Some("https://gateway.example.test/base?x=${env:HOME}"),
            "public_url_not_templatable",
        ),
    ] {
        let mut request = audit_query_request(
            MCP_CLIENT_CONFIGS_ADMIN_ROUTE,
            Some(test_principal(&["mcp-clients-reader"])),
        );
        request.headers_mut().insert(
            header::HOST,
            HeaderValue::from_static("gateway.example.test"),
        );
        let response = status_router(handler_checked_config(&policy, public_url), Instant::now())
            .oneshot(request)
            .await
            .expect("request should complete");
        let (status, body) = refusal(response).await;
        assert_eq!(status, StatusCode::CONFLICT, "{public_url:?}");
        assert_eq!(body["reason"], reason, "{public_url:?}");
        assert!(body["error"].is_string());
        assert!(body.get("templates").is_none());
    }
}

#[tokio::test]
async fn oauth_templates_appear_only_with_an_advertised_authorization_server() {
    let policy = clients_policy("allow", json!([]));
    let config = handler_checked_config(&policy, Some("https://gateway.example.test"));
    let document = templates_for(config.clone(), MCP_CLIENT_CONFIGS_ADMIN_ROUTE).await;
    assert!(!document.oauth);
    assert!(document
        .templates
        .iter()
        .all(|template| template.auth == Auth::Token));
    assert!(document
        .template(ClientKind::ClaudeDesktop, Auth::Oauth)
        .is_none());

    let mut with_issuer = config;
    configure_test_jwt_provider(
        &mut with_issuer,
        "127.0.0.1:9".parse().expect("socket address"),
    );
    with_issuer.auth_providers[0].issuer = Some("https://issuer.example.test".to_owned());
    with_issuer.egress_deny_private_ips = false;
    // A provider secret is configuration, never template material.
    with_issuer.auth_providers[0].client_secret = Some(CANARY.to_owned());
    let document = templates_for(with_issuer, MCP_CLIENT_CONFIGS_ADMIN_ROUTE).await;
    assert!(document.oauth);
    assert_eq!(document.templates.len(), 7);
    let desktop = document
        .template(ClientKind::ClaudeDesktop, Auth::Oauth)
        .expect("Claude Desktop takes the URL");
    assert_eq!(desktop.format, Format::Url);
    assert_eq!(desktop.content, "https://gateway.example.test/mcp\n");
    for template in &document.templates {
        let names_variable = template.content.contains(TOKEN_VARIABLE);
        assert_eq!(names_variable, template.auth == Auth::Token);
        assert!(!template.content.contains("ggw_"));
    }
}

#[tokio::test]
async fn a_valid_name_is_used_and_a_hostile_one_or_query_is_refused_unechoed() {
    let policy = clients_policy("allow", json!([]));
    let config = handler_checked_config(&policy, Some("https://gateway.example.test"));
    let document = templates_for(
        config.clone(),
        &format!("{MCP_CLIENT_CONFIGS_ADMIN_ROUTE}?name=prod-gateway_2"),
    )
    .await;
    assert_eq!(document.server_name, "prod-gateway_2");
    let cursor = document
        .template(ClientKind::Cursor, Auth::Token)
        .expect("Cursor token template");
    let file: Value = serde_json::from_str(&cursor.content).expect("Cursor JSON");
    assert_eq!(
        file["mcpServers"]["prod-gateway_2"]["url"],
        "https://gateway.example.test/mcp"
    );
    assert_eq!(
        templates_for(config.clone(), MCP_CLIENT_CONFIGS_ADMIN_ROUTE)
            .await
            .server_name,
        DEFAULT_SERVER_NAME
    );

    for (query, reason) in [
        ("name=", "invalid_server_name"),
        ("name=a%22b", "invalid_server_name"),
        ("name=%24%7Benv%3AHOME%7D", "invalid_server_name"),
        ("name=__proto__", "invalid_server_name"),
        ("name=a%2Fb", "invalid_server_name"),
        ("name=gg%0Acanary", "invalid_server_name"),
        (&format!("name={}", "a".repeat(65)), "invalid_server_name"),
        ("name=a&name=b", "invalid_query"),
        (
            "url=https%3A%2F%2Fupstream.example.test%2Fmcp",
            "invalid_query",
        ),
        // Undecodable bytes become U+FFFD, outside the name grammar.
        ("name=%FF", "invalid_server_name"),
    ] {
        let response = clients_response(
            status_router(config.clone(), Instant::now()),
            &format!("{MCP_CLIENT_CONFIGS_ADMIN_ROUTE}?{query}"),
            Some(&["mcp-clients-reader"]),
        )
        .await;
        let (status, body) = refusal(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(body["reason"], reason, "{query}");
        let text = body.to_string();
        for echoed in ["proto", "env:HOME", "upstream", "canary", "aaaaaaaa"] {
            assert!(!text.contains(echoed), "{query}: {text}");
        }
    }

    // An unauthorized caller learns nothing about its query.
    let response = clients_response(
        status_router(config, Instant::now()),
        &format!("{MCP_CLIENT_CONFIGS_ADMIN_ROUTE}?name=%22"),
        Some(&["config-reader"]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_documented_policy_route_passes_under_default_deny_and_nothing_else_does() {
    for (routes, expected) in [
        (
            json!([{
                "methods": ["GET"],
                "path_prefix": "/v1/admin/mcp",
                "permission": ADMIN_MCP_CLIENTS_READ_PERMISSION
            }]),
            StatusCode::OK,
        ),
        (
            json!([{
                "methods": ["GET"],
                "path_prefix": "/v1/admin/config",
                "permission": ADMIN_CONFIG_READ_PERMISSION
            }]),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let policy = clients_policy("deny", routes);
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.gateway_public_url = Some("https://gateway.example.test".to_owned());
        let response = clients_response(
            status_router(config, Instant::now()),
            MCP_CLIENT_CONFIGS_ADMIN_ROUTE,
            Some(&["mcp-clients-reader"]),
        )
        .await;
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn the_route_follows_a_custom_prefix_on_the_admin_listener_only() {
    let policy = clients_policy("allow", json!([]));
    let mut config = handler_checked_config(&policy, Some("https://gateway.example.test"));
    config.admin_prefix = "/operations".to_owned();
    config.admin_listen_addr = Some("127.0.0.1:0".parse().expect("address"));
    let route = GatewayRoutes::from_config(&config)
        .admin
        .mcp_client_configs_route;
    assert_eq!(route, "/v1/operations/mcp/client-configs");
    config.rbac_exempt_paths.push(route.clone());
    let recorder = PrometheusBuilder::new().build_recorder();
    let apps = gateway_app_with_process_started_at(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
    )
    .expect("apps should build");
    let GatewayApp::Split { admin, data } = apps.http else {
        panic!("a separate admin listener splits the routers");
    };
    for (router, uri, status) in [
        (admin.clone(), route.as_str(), StatusCode::OK),
        (admin, MCP_CLIENT_CONFIGS_ADMIN_ROUTE, StatusCode::NOT_FOUND),
        (data, route.as_str(), StatusCode::NOT_FOUND),
    ] {
        let response = clients_response(router, uri, Some(&["mcp-clients-reader"])).await;
        assert_eq!(response.status(), status, "{uri}");
    }
}

fn openapi_contract() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/openapi/admin-mcp-client-configs.v1alpha1.openapi.json"
    );
    serde_json::from_str(&fs::read_to_string(path).expect("the OpenAPI document is committed"))
        .expect("the OpenAPI document is JSON")
}

fn validator(schema: &Value) -> jsonschema::Validator {
    jsonschema::validator_for(schema).expect("schema compiles")
}

/// The published OpenAPI document names this route, its permission and
/// every status it answers, and every body the route actually sends is one
/// the document describes.
#[tokio::test]
async fn the_openapi_contract_matches_the_route_and_every_answer_it_gives() {
    let contract = openapi_contract();
    assert_eq!(contract["openapi"], "3.1.0");
    let paths = contract["paths"].as_object().expect("paths");
    assert_eq!(
        paths.keys().collect::<Vec<_>>(),
        [MCP_CLIENT_CONFIGS_ADMIN_ROUTE]
    );
    let methods = paths[MCP_CLIENT_CONFIGS_ADMIN_ROUTE]
        .as_object()
        .expect("methods");
    assert_eq!(methods.keys().collect::<Vec<_>>(), ["get"]);
    let operation = &methods["get"];
    assert_eq!(operation["operationId"], "getMcpClientConfigs");
    assert_eq!(
        operation["x-greengateway-permission"],
        ADMIN_MCP_CLIENTS_READ_PERMISSION
    );
    assert!(operation["description"]
        .as_str()
        .expect("description")
        .starts_with(&format!("Requires {ADMIN_MCP_CLIENTS_READ_PERMISSION}")));
    let responses = operation["responses"].as_object().expect("responses");
    assert_eq!(
        responses.keys().collect::<Vec<_>>(),
        ["200", "400", "401", "403", "404", "409"]
    );
    assert_eq!(
        responses["200"]["content"]["application/json"]["schema"]["$ref"],
        "../schemas/mcp-client-configs.v1alpha1.schema.json"
    );
    let published = gateway_config::documents::published_schema(
        gateway_config::documents::API_VERSION_V1ALPHA1,
        gateway_config::documents::MCP_CLIENT_CONFIGS_KIND,
    )
    .expect("published");
    let published: Value = serde_json::from_str(published.json).expect("schema JSON");
    assert_eq!(
        operation["parameters"][0]["schema"]["pattern"],
        published["properties"]["serverName"]["pattern"]
    );

    let refusal_schema = validator(&contract["components"]["schemas"]["TemplateRefusal"]);
    let error_schema = validator(&contract["components"]["schemas"]["AdminError"]);
    let document_schema = validator(&published);
    let reasons: Vec<&str> = contract["components"]["schemas"]["TemplateRefusal"]["properties"]
        ["reason"]["enum"]
        .as_array()
        .expect("reasons")
        .iter()
        .map(|reason| reason.as_str().expect("reason"))
        .collect();

    let policy = clients_policy("allow", json!([]));
    let mut answered = Vec::new();
    for (public_url, query, roles, expected_status) in [
        (
            Some("https://gateway.example.test"),
            "",
            Some(&["mcp-clients-reader"][..]),
            200,
        ),
        (
            Some("https://gateway.example.test"),
            "?x=1",
            Some(&["mcp-clients-reader"]),
            400,
        ),
        (
            Some("https://gateway.example.test"),
            "?name=%22",
            Some(&["mcp-clients-reader"]),
            400,
        ),
        (Some("https://gateway.example.test"), "", None, 401),
        (
            Some("https://gateway.example.test"),
            "",
            Some(&["config-reader"]),
            403,
        ),
        (None, "", Some(&["mcp-clients-reader"]), 409),
        (
            Some("https://gateway.example.test/$x"),
            "",
            Some(&["mcp-clients-reader"]),
            409,
        ),
    ] {
        let response = clients_response(
            status_router(handler_checked_config(&policy, public_url), Instant::now()),
            &format!("{MCP_CLIENT_CONFIGS_ADMIN_ROUTE}{query}"),
            roles,
        )
        .await;
        let status = response.status().as_u16();
        assert_eq!(status, expected_status, "{public_url:?} {query}");
        let body: Value = serde_json::from_str(&body_string(response).await).expect("JSON body");
        match status {
            200 => assert!(document_schema.is_valid(&body), "{body}"),
            400 | 409 => {
                assert!(refusal_schema.is_valid(&body), "{body}");
                answered.push(body["reason"].as_str().expect("reason").to_owned());
            }
            _ => assert!(error_schema.is_valid(&body), "{body}"),
        }
    }
    let mut mcp_config = test_config(Vec::new());
    mcp_config.auth_enabled = false;
    let response = clients_response(
        status_router(mcp_config, Instant::now()),
        MCP_CLIENT_CONFIGS_ADMIN_ROUTE,
        Some(&["mcp-clients-reader"]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_str(&body_string(response).await).expect("JSON body");
    assert!(error_schema.is_valid(&body), "{body}");
    answered.sort();
    answered.dedup();
    let mut documented: Vec<String> = reasons.iter().map(|reason| (*reason).to_owned()).collect();
    documented.sort();
    assert_eq!(answered, documented);
}
