//! Server contract tests use the existing disposable OIDC/JWKS fixtures. They
//! do not replace the real HTTPS browser/IdP acceptance still tracked in #424.
use super::*;
use axum::body::to_bytes;

const ORIGIN: &str = "https://management.example.test";
const PREFIX: &str = "/v1/operations";

fn request(
    method: Method,
    path: &str,
    cookies: &str,
    csrf: Option<&str>,
    origin: Option<&str>,
    body: Value,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookies)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(csrf) = csrf {
        builder = builder.header("x-ops-csrf", csrf);
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn admin_session_oidc_contract_preserves_csrf_origins_prefix_and_listener_boundaries() {
    for split in [false, true] {
        let jwks_addr = spawn_test_jwks_server().await;
        let token_endpoint =
            spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
        let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
        let access = signed_token_with_issuer("admin-operator", &["admin"], &oidc.issuer);
        token_endpoint.set_access_token(access.clone());
        let policy_body = json!({
            "schema_version":"0.1.0", "default_action":"deny",
            "roles":{"admin":{"permissions":["admin:status:read", "admin:policy:read"]}},
            "routes":[
                {"methods":["GET"], "path_prefix":format!("{PREFIX}/status"), "permission":"admin:status:read"},
                {"methods":["POST"], "path_prefix":format!("{PREFIX}/policy/validate"), "permission":"admin:policy:read"}
            ]
        });
        let policy = TempPolicyFile::new(&policy_body.to_string());
        let mut config = admin_oidc_login_config(&oidc.issuer);
        config.admin_prefix = "/operations".to_owned();
        config.admin_session = Some(auth::admin_session::AdminSessionConfig {
            ttl: Duration::from_secs(60),
            max_entries: 8,
        });
        config.auth_providers[0].jwks_url =
            Some(format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port()));
        config.auth_providers[0].redirect_uri = Some(format!("{ORIGIN}{PREFIX}/auth/callback"));
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.gateway_public_url = Some("https://public.example.test/mcp".to_owned());
        config.csrf_cookie_name = "ops_csrf".to_owned();
        config.csrf_header_name = "x-ops-csrf".to_owned();
        config.egress_deny_private_ips = false;
        if split {
            config.admin_listen_addr = Some("127.0.0.1:0".parse().unwrap());
        }
        for route in ["login", "callback", "logout", "config"] {
            config
                .auth_exempt_paths
                .push(format!("{PREFIX}/auth/{route}"));
            config
                .rbac_exempt_paths
                .push(format!("{PREFIX}/auth/{route}"));
        }
        let recorder = PrometheusBuilder::new().build_recorder();
        let apps = gateway_app_with_process_started_at(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
            Instant::now(),
        )
        .unwrap();
        let (admin, data) = match apps.http {
            GatewayApp::Unified(router) => (router, None),
            GatewayApp::Split { admin, data } => (admin, Some(data)),
        };
        let discovery = admin
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{PREFIX}/auth/config"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(discovery.status(), StatusCode::OK);
        assert_eq!(discovery.headers()[header::CACHE_CONTROL], "no-store");
        let metadata: Value =
            serde_json::from_slice(&to_bytes(discovery.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            metadata,
            json!({
                "bearer_completion": true,
                "admin_session": {
                    "storage":"standalone_memory", "completion_mode":"cookie",
                    "login_url":format!("{PREFIX}/auth/login"),
                    "completion_url":format!("{PREFIX}/auth/callback"),
                    "logout_url":format!("{PREFIX}/auth/logout"),
                    "max_age_seconds":60
                }
            })
        );
        let version = data
            .as_ref()
            .unwrap_or(&admin)
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(version.status(), StatusCode::OK);
        let version: Value =
            serde_json::from_slice(&to_bytes(version.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(version["admin_session"]["storage"], "standalone_memory");
        assert_eq!(
            version["admin_session"]["logout_url"],
            format!("{PREFIX}/auth/logout")
        );
        let login = admin
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{PREFIX}/auth/login"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::FOUND);
        let login_cookies = admin_oidc_cookies(&login);
        let csrf = login_cookies
            .split(';')
            .find_map(|pair| pair.trim().strip_prefix("ops_csrf="))
            .unwrap()
            .to_owned();
        let query = url_query_pairs(&Url::parse(&response_location(&login)).unwrap());
        token_endpoint.set_id_token(signed_admin_id_token(
            &oidc.issuer,
            "admin-ui",
            &query["nonce"],
        ));
        let completion =
            json!({"code":"generated-fixture-code", "state":query["state"], "mode":"cookie"});
        let denied = admin
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("{PREFIX}/auth/callback"),
                &login_cookies,
                None,
                Some(ORIGIN),
                completion.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(token_endpoint.requests().is_empty());
        let response = admin
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("{PREFIX}/auth/callback"),
                &login_cookies,
                Some(&csrf),
                Some(ORIGIN),
                completion,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let session_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find(|cookie| cookie.to_str().unwrap().contains("ggw-admin-session-"))
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        for attribute in ["__Host-", "HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
            assert!(session_cookie.contains(attribute));
        }
        let cookies = format!(
            "{}; ops_csrf={csrf}",
            session_cookie.split(';').next().unwrap()
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({"authenticated":true, "expires_in":60}));
        let read = admin
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("{PREFIX}/status"),
                &cookies,
                None,
                None,
                Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        for (csrf_header, origin, expected) in [
            (None, Some(ORIGIN), StatusCode::FORBIDDEN),
            (Some("wrong"), Some(ORIGIN), StatusCode::FORBIDDEN),
            (
                Some(csrf.as_str()),
                Some("https://other.example.test"),
                StatusCode::FORBIDDEN,
            ),
            (Some(csrf.as_str()), Some(ORIGIN), StatusCode::OK),
        ] {
            let response = admin
                .clone()
                .oneshot(request(
                    Method::POST,
                    &format!("{PREFIX}/policy/validate"),
                    &cookies,
                    csrf_header,
                    origin,
                    policy_body.clone(),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        for path in ["/mcp", "/v1/operations/unregistered"] {
            let response = admin
                .clone()
                .oneshot(request(
                    Method::GET,
                    path,
                    &cookies,
                    None,
                    None,
                    Value::Null,
                ))
                .await
                .unwrap();
            assert!(!response.status().is_success());
        }
        if let Some(data) = data {
            let response = data
                .clone()
                .oneshot(request(
                    Method::GET,
                    &format!("{PREFIX}/status"),
                    &cookies,
                    None,
                    None,
                    Value::Null,
                ))
                .await
                .unwrap();
            assert!(!response.status().is_success());
            let response = data
                .oneshot(
                    Request::builder()
                        .uri(format!("{PREFIX}/auth/config"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
        let denied = admin
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("{PREFIX}/auth/logout"),
                &cookies,
                None,
                Some(ORIGIN),
                Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let logout = admin
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("{PREFIX}/auth/logout"),
                &cookies,
                Some(&csrf),
                Some(ORIGIN),
                Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
        let cleared = logout
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find(|cookie| cookie.to_str().unwrap().contains("ggw-admin-session-"))
            .unwrap()
            .to_str()
            .unwrap();
        for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=0"] {
            assert!(cleared.contains(attribute));
        }
        let rejected = admin
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("{PREFIX}/status"),
                &cookies,
                None,
                None,
                Value::Null,
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        let bearer = admin
            .oneshot(
                Request::builder()
                    .uri(format!("{PREFIX}/status"))
                    .header(header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            bearer.status(),
            StatusCode::OK,
            "local logout does not revoke automation bearer tokens at the issuer"
        );
        oidc.finish();
        token_endpoint.abort();
    }
}

#[tokio::test]
async fn admin_session_discovery_is_absent_when_mode_is_disabled() {
    let jwks_addr = spawn_test_jwks_server().await;
    let oidc = spawn_mock_oidc_discovery_endpoint(None);
    let mut config = admin_oidc_login_config(&oidc.issuer);
    config.admin_prefix = "/operations".to_owned();
    config.auth_providers[0].jwks_url =
        Some(format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port()));
    config.auth_providers[0].redirect_uri = Some(format!("{ORIGIN}{PREFIX}/auth/callback"));
    let router = admin_oidc_login_router_from_config(config);
    let version = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(version.status(), StatusCode::OK);
    let metadata: Value =
        serde_json::from_slice(&to_bytes(version.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(metadata["admin_login_configured"], true);
    assert!(metadata.get("admin_session").is_none());
    let bearer = signed_token_with_issuer("admin-operator", &["admin"], &oidc.issuer);
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("{PREFIX}/auth/config"))
                .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    oidc.finish();
}
