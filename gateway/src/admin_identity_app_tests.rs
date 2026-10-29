use super::*;

fn admin_oidc_login_router(issuer: &str) -> Router {
    admin_oidc_login_router_from_config(admin_oidc_login_config(issuer))
}

fn admin_oidc_complete_request(cookies: &str, code: &str, state: &str) -> Request<Body> {
    let csrf = cookies
        .split(';')
        .find_map(|pair| pair.trim().strip_prefix("csrf_token="))
        .unwrap_or("test-csrf");
    let cookies = if cookies.contains("csrf_token=") {
        cookies.to_owned()
    } else {
        format!("{cookies}; csrf_token={csrf}")
    };
    Request::builder()
        .method(Method::POST)
        .uri(ADMIN_AUTH_CALLBACK_ROUTE)
        .header(header::COOKIE, cookies)
        .header("x-csrf-token", csrf)
        .header(header::ORIGIN, "http://gateway.example.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"code": code, "state": state}).to_string(),
        ))
        .expect("completion request")
}

async fn assert_admin_oidc_token(response: Response, expected: &str) {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key(header::LOCATION));
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|value| value.to_str().unwrap().contains("Max-Age=0")));
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["access_token"],
        expected
    );
}

async fn admin_oidc_id_token_callback_response(
    id_token_for_nonce: impl FnOnce(&str, &str) -> String,
) -> (Response, String) {
    let jwks_addr = spawn_test_jwks_server().await;
    let jwks_url = format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port());
    let token_endpoint = spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
    let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
    let access_token = signed_token_with_issuer("admin-operator", &["admin"], &oidc.issuer);
    token_endpoint.set_access_token(access_token.clone());

    let mut config = admin_oidc_login_config(&oidc.issuer);
    config.auth_providers[0].jwks_url = Some(jwks_url);
    let router = admin_oidc_login_router_from_config(config);

    let login_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/admin/auth/login")
                .body(Body::empty())
                .expect("login request should build"),
        )
        .await
        .expect("login request should complete");
    let cookies = admin_oidc_cookies(&login_response);
    let login_location = response_location(&login_response);
    let authorization_url =
        Url::parse(&login_location).expect("authorization redirect should be absolute");
    let authorization_query = url_query_pairs(&authorization_url);
    let state = authorization_query
        .get("state")
        .expect("authorization redirect should include state");
    let nonce = authorization_query
        .get("nonce")
        .expect("authorization redirect should include nonce");
    token_endpoint.set_id_token(id_token_for_nonce(nonce, &oidc.issuer));

    let callback_response = router
        .oneshot(admin_oidc_complete_request(&cookies, "admin-code", state))
        .await
        .expect("completion request should complete");

    oidc.finish();
    token_endpoint.abort();

    (callback_response, access_token)
}

fn admin_oidc_login_request(peer_ip: Ipv4Addr, forwarded_for: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(ADMIN_AUTH_LOGIN_ROUTE)
        .body(Body::empty())
        .expect("admin OIDC login request should build");
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::new(
            IpAddr::V4(peer_ip),
            12_345,
        )));
    if let Some(forwarded_for) = forwarded_for {
        request.headers_mut().insert(
            X_FORWARDED_FOR_HEADER,
            HeaderValue::from_str(forwarded_for)
                .expect("forwarded client IP should be a valid header value"),
        );
    }
    request
}

fn form_pairs(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

fn fragment_query_pairs(location: &str, expected_path: &str) -> Option<HashMap<String, String>> {
    let url = Url::parse(&format!("http://gateway.test{location}"))
        .expect("relative redirect location should parse against test origin");
    let fragment = url.fragment()?;
    let (path, query) = fragment.split_once('?')?;
    if path != expected_path {
        return None;
    }

    Some(form_pairs(query))
}

fn pkce_challenge_for_verifier(verifier: &str) -> String {
    base64url_no_padding(&Sha256::digest(verifier.as_bytes()))
}

fn is_pkce_unreserved(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

#[tokio::test]
async fn admin_capabilities_use_effective_permissions_without_policy_read() {
    let token_db = TempDb::new("admin-capabilities");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let router = token_admin_router(&token_db, &policy, test_audit_log());
    let response = router
        .clone()
        .oneshot(token_admin_request(
            Method::GET,
            "/v1/admin/capabilities",
            Some(test_principal(&["tokens-writer"])),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let value = json_body(response).await;
    assert!(value["permissions"]
        .as_array()
        .unwrap()
        .contains(&json!(ADMIN_TOKENS_WRITE_PERMISSION)));
    assert!(!value["permissions"]
        .as_array()
        .unwrap()
        .contains(&json!(ADMIN_POLICY_READ_PERMISSION)));
    let response = router
        .oneshot(token_admin_request(
            Method::GET,
            "/v1/admin/capabilities",
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_endpoint_denial_preserves_decision_and_emits_one_audit_event() {
    let token_db = TempDb::new("endpoint-denial-audit");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let log = audit::AuditLog::new(Arc::new(capture.clone()));
    let router = token_admin_router(&token_db, &policy, log.clone());
    let response = router
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-reader"])),
            Some(json!({ "scopes": ["probe-reader"] }).to_string()),
        ))
        .await
        .unwrap();
    assert_admin_denial(&response, &log, &capture, ADMIN_TOKENS_WRITE_PERMISSION).await;
}

#[tokio::test]
async fn admin_oidc_login_rejects_new_attempt_when_global_pending_limit_is_full() {
    let oidc = spawn_mock_oidc_discovery_endpoint(None);
    let mut config = admin_oidc_login_config(&oidc.issuer);
    config.admin_login_pending_max_entries = 1;
    config.admin_login_pending_max_per_ip = 1;
    let router = admin_oidc_login_router_from_config(config);

    let first_response = router
        .clone()
        .oneshot(admin_oidc_login_request(Ipv4Addr::new(192, 0, 2, 10), None))
        .await
        .expect("first login request should complete");
    assert_eq!(first_response.status(), StatusCode::FOUND);
    let first_location = response_location(&first_response);
    assert_eq!(
        Url::parse(&first_location)
            .expect("authorization redirect should be absolute")
            .as_str()
            .split('?')
            .next(),
        Some(oidc.authorization_endpoint.as_str())
    );

    let second_response = router
        .oneshot(admin_oidc_login_request(Ipv4Addr::new(192, 0, 2, 11), None))
        .await
        .expect("second login request should complete");
    assert_eq!(second_response.status(), StatusCode::FOUND);
    assert!(
        fragment_query_pairs(&response_location(&second_response), "/auth/error")
            .expect("capacity rejection should redirect to auth error fragment")
            .get("error")
            .is_some_and(|error| error == "login_start_failed")
    );

    oidc.finish();
}

#[tokio::test]
async fn admin_oidc_login_enforces_peer_ip_limit_despite_untrusted_forwarding_headers() {
    let oidc = spawn_mock_oidc_discovery_endpoint(None);
    let mut config = admin_oidc_login_config(&oidc.issuer);
    config.admin_login_pending_max_entries = 3;
    config.admin_login_pending_max_per_ip = 1;
    let router = admin_oidc_login_router_from_config(config);
    let peer_ip = Ipv4Addr::new(192, 0, 2, 20);

    let first_response = router
        .clone()
        .oneshot(admin_oidc_login_request(peer_ip, Some("198.51.100.1")))
        .await
        .expect("first login request should complete");
    assert_eq!(first_response.status(), StatusCode::FOUND);
    let first_location = response_location(&first_response);
    assert_eq!(
        Url::parse(&first_location)
            .expect("authorization redirect should be absolute")
            .as_str()
            .split('?')
            .next(),
        Some(oidc.authorization_endpoint.as_str())
    );

    let same_peer_response = router
        .clone()
        .oneshot(admin_oidc_login_request(peer_ip, Some("198.51.100.2")))
        .await
        .expect("same-peer login request should complete");
    assert_eq!(same_peer_response.status(), StatusCode::FOUND);
    assert!(
        fragment_query_pairs(&response_location(&same_peer_response), "/auth/error")
            .expect("per-IP rejection should redirect to auth error fragment")
            .get("error")
            .is_some_and(|error| error == "login_start_failed")
    );

    let different_peer_response = router
        .oneshot(admin_oidc_login_request(
            Ipv4Addr::new(192, 0, 2, 21),
            Some("198.51.100.2"),
        ))
        .await
        .expect("different-peer login request should complete");
    assert_eq!(different_peer_response.status(), StatusCode::FOUND);
    let different_peer_location = response_location(&different_peer_response);
    assert_eq!(
        Url::parse(&different_peer_location)
            .expect("authorization redirect should be absolute")
            .as_str()
            .split('?')
            .next(),
        Some(oidc.authorization_endpoint.as_str())
    );

    oidc.finish();
}

struct UnavailablePendingLoginBackend;

fn unavailable_pending_login_store() -> auth::oidc_login::PendingLoginStoreError {
    auth::oidc_login::PendingLoginStoreError(storage::RepositoryError::new(
        storage::RepositoryErrorKind::Unavailable,
        "pending_login_test",
    ))
}

#[async_trait::async_trait]
impl auth::oidc_login::PendingLoginBackend for UnavailablePendingLoginBackend {
    async fn insert(
        &self,
        _state: &str,
        _pending: auth::oidc_login::PendingLogin,
    ) -> Result<bool, auth::oidc_login::PendingLoginStoreError> {
        Err(unavailable_pending_login_store())
    }

    async fn take(
        &self,
        _state: &str,
    ) -> Result<Option<auth::oidc_login::PendingLogin>, auth::oidc_login::PendingLoginStoreError>
    {
        Err(unavailable_pending_login_store())
    }
}

async fn json_error_message(response: Response) -> String {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body should be readable");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("response body should be JSON");
    json["error"]
        .as_str()
        .expect("response should carry an error message")
        .to_owned()
}

/// A pending-login store that cannot be consulted is a dependency
/// failure on both legs: `503`, never "login failed" and never
/// "unknown state" -- "cannot check" is not "checked and denied" --
/// and the callback exchanges no code at the provider.
#[tokio::test]
async fn admin_oidc_login_answers_503_when_the_pending_login_store_is_unavailable() {
    let token_endpoint = spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
    let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
    let mut config = admin_oidc_login_config(&oidc.issuer);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let apps = gateway_app_with_process_started_at_and_overrides(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            pending_login_backend: Some(Arc::new(UnavailablePendingLoginBackend)),
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("admin OIDC login app should build");
    let router = match apps.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("admin OIDC login app should be unified"),
    };

    let login_response = router
        .clone()
        .oneshot(admin_oidc_login_request(Ipv4Addr::new(192, 0, 2, 7), None))
        .await
        .expect("login request should complete");
    assert_eq!(login_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_error_message(login_response).await,
        "login state store is unavailable"
    );

    let binding = "a".repeat(43);
    let oauth_state = base64url_no_padding(&Sha256::digest(
        format!("greengateway.admin-login.browser.v1\0{binding}").as_bytes(),
    ));
    let cookie_name = format!(
        "ggw-admin-login-{}",
        &hex::encode(Sha256::digest(b"/admin"))[..16]
    );
    let callback_response = router
        .oneshot(admin_oidc_complete_request(
            &format!("{cookie_name}={binding}"),
            "admin-code",
            &oauth_state,
        ))
        .await
        .unwrap();
    assert_eq!(callback_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_error_message(callback_response).await,
        "login state store is unavailable"
    );
    assert!(
        token_endpoint.requests().is_empty(),
        "no code is exchanged when the state cannot be checked"
    );
    oidc.finish();
}

#[tokio::test]
async fn admin_oidc_login_redirects_exchanges_code_and_consumes_state_once() {
    let jwks_addr = spawn_test_jwks_server().await;
    let jwks_url = format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port());
    let token_endpoint = spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
    let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
    let access_token = signed_token_with_issuer("admin-operator", &["admin"], &oidc.issuer);
    token_endpoint.set_access_token(access_token.clone());
    let mut config = admin_oidc_login_config(&oidc.issuer);
    config.auth_providers[0].jwks_url = Some(jwks_url);
    let router = admin_oidc_login_router_from_config(config);

    let login_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/admin/auth/login")
                .body(Body::empty())
                .expect("login request should build"),
        )
        .await
        .expect("login request should complete");

    assert_eq!(login_response.status(), StatusCode::FOUND);
    let cookies = admin_oidc_cookies(&login_response);
    let login_location = response_location(&login_response);
    let authorization_url =
        Url::parse(&login_location).expect("authorization redirect should be absolute");
    assert_eq!(
        authorization_url.as_str().split('?').next(),
        Some(oidc.authorization_endpoint.as_str())
    );
    let authorization_query = url_query_pairs(&authorization_url);
    assert_eq!(
        authorization_query.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        authorization_query.get("client_id").map(String::as_str),
        Some("admin-ui")
    );
    assert_eq!(
        authorization_query.get("redirect_uri").map(String::as_str),
        Some("http://gateway.example.test/v1/admin/auth/callback")
    );
    assert_eq!(
        authorization_query.get("scope").map(String::as_str),
        Some("openid email profile")
    );
    assert_eq!(
        authorization_query
            .get("code_challenge_method")
            .map(String::as_str),
        Some("S256")
    );
    let state = authorization_query
        .get("state")
        .expect("authorization redirect should include state");
    let nonce = authorization_query
        .get("nonce")
        .expect("authorization redirect should include nonce");
    assert!(!state.is_empty());
    assert!(!nonce.is_empty());
    token_endpoint.set_id_token(signed_admin_id_token(&oidc.issuer, "admin-ui", nonce));
    let challenge = authorization_query
        .get("code_challenge")
        .expect("authorization redirect should include PKCE challenge");
    assert_eq!(challenge.len(), 43);
    assert!(is_pkce_unreserved(challenge));

    let callback_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/admin/auth/callback?code=admin-code&state={}",
                    query_encode(state)
                ))
                .header(header::COOKIE, &cookies)
                .body(Body::empty())
                .expect("callback request should build"),
        )
        .await
        .expect("callback request should complete");

    assert_eq!(callback_response.status(), StatusCode::FOUND);
    let callback_location = response_location(&callback_response);
    let completion = fragment_query_pairs(&callback_location, "/auth/complete")
        .expect("callback should redirect to auth completion fragment");
    assert_eq!(
        completion.get("code").map(String::as_str),
        Some("admin-code")
    );
    assert_eq!(completion.get("state"), Some(state));
    assert!(!callback_location.contains(&access_token));
    assert!(token_endpoint.requests().is_empty());
    let response = router
        .clone()
        .oneshot(admin_oidc_complete_request(&cookies, "admin-code", state))
        .await
        .unwrap();
    assert_admin_oidc_token(response, &access_token).await;

    let token_requests = token_endpoint.requests();
    assert_eq!(token_requests.len(), 1);
    assert_eq!(token_requests[0].method, Method::POST);
    assert_eq!(
        token_requests[0].headers.get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static(
            "application/x-www-form-urlencoded"
        ))
    );
    let token_form = form_pairs(&token_requests[0].body);
    assert_eq!(
        token_form.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        token_form.get("code").map(String::as_str),
        Some("admin-code")
    );
    assert_eq!(
        token_form.get("redirect_uri").map(String::as_str),
        Some("http://gateway.example.test/v1/admin/auth/callback")
    );
    assert_eq!(
        token_form.get("client_id").map(String::as_str),
        Some("admin-ui")
    );
    assert_eq!(
        token_form.get("client_secret").map(String::as_str),
        Some("secret-value")
    );
    let verifier = token_form
        .get("code_verifier")
        .expect("token exchange should include the PKCE verifier");
    assert!((43..=128).contains(&verifier.len()));
    assert!(is_pkce_unreserved(verifier));
    assert_eq!(pkce_challenge_for_verifier(verifier), *challenge);

    let replay_response = router
        .oneshot(admin_oidc_complete_request(&cookies, "admin-code", state))
        .await
        .expect("replay completion");
    assert_eq!(replay_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_error_message(replay_response).await, "invalid_state");
    assert_eq!(token_endpoint.requests().len(), 1);

    oidc.finish();
    token_endpoint.abort();
}

#[tokio::test]
async fn admin_oidc_completion_requires_initiating_browser_and_same_origin_without_spending_state()
{
    let jwks_addr = spawn_test_jwks_server().await;
    let token_endpoint = spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
    let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
    let mut config = admin_oidc_login_config(&oidc.issuer);
    config.auth_providers[0].jwks_url =
        Some(format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port()));
    config.egress_deny_private_ips = false;
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .unwrap();
    let login = router
        .clone()
        .oneshot(admin_oidc_login_request(Ipv4Addr::LOCALHOST, None))
        .await
        .unwrap();
    let cookies = admin_oidc_cookies(&login);
    let query = url_query_pairs(&Url::parse(&response_location(&login)).unwrap());
    let state = &query["state"];
    let other_login = router
        .clone()
        .oneshot(admin_oidc_login_request(Ipv4Addr::LOCALHOST, None))
        .await
        .unwrap();
    let other_cookies = admin_oidc_cookies(&other_login);
    let access_token = signed_token_with_issuer("admin-operator", &["admin"], &oidc.issuer);
    token_endpoint.set_access_token(access_token.clone());
    token_endpoint.set_id_token(signed_admin_id_token(
        &oidc.issuer,
        "admin-ui",
        &query["nonce"],
    ));

    // Rejections must leave the original transaction usable. Each test
    // supplies valid CSRF material so it reaches the browser-binding gate.
    for cookie in [
        String::new(),
        other_cookies,
        format!("{cookies}; {cookies}"),
    ] {
        let callback = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "{ADMIN_AUTH_CALLBACK_ROUTE}?code=admin-code&state={state}"
                    ))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response_location(&callback).contains("error=invalid_state"));
        assert_eq!(callback.headers()[header::CACHE_CONTROL], "no-store");
        let completion = router
            .clone()
            .oneshot(admin_oidc_complete_request(&cookie, "admin-code", state))
            .await
            .unwrap();
        assert_eq!(completion.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_error_message(completion).await, "invalid_state");
    }
    for origin in [None, Some("https://other.example.test"), Some("null")] {
        let mut request = admin_oidc_complete_request(&cookies, "admin-code", state);
        request.headers_mut().remove(header::ORIGIN);
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        }
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_error_message(response).await, "invalid_origin");
    }
    let mut request = admin_oidc_complete_request(&cookies, "admin-code", state);
    request.headers_mut().remove("x-csrf-token");
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert!(token_endpoint.requests().is_empty());

    let (first, second) = tokio::join!(
        router
            .clone()
            .oneshot(admin_oidc_complete_request(&cookies, "admin-code", state)),
        router.oneshot(admin_oidc_complete_request(&cookies, "admin-code", state)),
    );
    let mut successes = 0;
    for response in [first.unwrap(), second.unwrap()] {
        if response.status() == StatusCode::OK {
            assert_admin_oidc_token(response, &access_token).await;
            successes += 1;
        } else {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(json_error_message(response).await, "invalid_state");
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(token_endpoint.requests().len(), 1);
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .filter(|event| event.event_type == "admin_login.transaction")
            .count()
            == 13
    });
    let events: Vec<_> = capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == "admin_login.transaction")
        .collect();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.payload["reason"] == "token_exchanged")
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.payload["reason"] == "browser_binding_mismatch")
            .count(),
        6
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.payload["reason"] == "origin_mismatch")
            .count(),
        3
    );
    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains(&access_token));
    assert!(!serialized.contains(state));
    assert!(!serialized.contains("admin-code"));
    for pair in cookies.split(';') {
        if let Some((name, value)) = pair.trim().split_once('=') {
            if name.contains("ggw-admin-login-") {
                assert!(!serialized.contains(value));
            }
        }
    }
    oidc.finish();
    token_endpoint.abort();
}

#[tokio::test]
async fn admin_oidc_browser_cookie_tracks_custom_prefix_https_and_expiry() {
    let token_endpoint = spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
    let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
    let mut config = admin_oidc_login_config(&oidc.issuer);
    config.admin_prefix = "/ops".to_owned();
    config.admin_login_pending_ttl_secs = 1;
    config.auth_exempt_paths.push("/v1/ops/auth".to_owned());
    config.rbac_exempt_paths.push("/v1/ops/auth".to_owned());
    config.auth_providers[0].redirect_uri =
        Some("https://gateway.example.test/v1/ops/auth/callback".to_owned());
    let router = admin_oidc_login_router_from_config(config);
    let login = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/ops/auth/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cookies = admin_oidc_cookies(&login);
    let binding_cookie = login
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .find(|value| value.starts_with("__Host-ggw-admin-login-"))
        .unwrap();
    assert!(binding_cookie.contains("; Path=/; HttpOnly; SameSite=Lax; Max-Age=1; Secure"));
    assert!(!binding_cookie.contains("Domain="));
    let query = url_query_pairs(&Url::parse(&response_location(&login)).unwrap());
    let binding = binding_cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1;
    assert_ne!(binding, query["state"]);
    assert!(!response_location(&login).contains(binding));
    let callback = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/ops/auth/callback?code=admin-code&state={}",
                    query["state"]
                ))
                .header(header::COOKIE, &cookies)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response_location(&callback).starts_with("/ops/#/auth/complete?code="));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let mut request = admin_oidc_complete_request(&cookies, "admin-code", &query["state"]);
    *request.uri_mut() = "/v1/ops/auth/callback".parse().unwrap();
    request.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://gateway.example.test"),
    );
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_error_message(response).await, "invalid_state");
    assert!(token_endpoint.requests().is_empty());
    oidc.finish();
    token_endpoint.abort();
}

#[tokio::test]
async fn admin_oidc_login_rejects_token_response_without_id_token() {
    let token_endpoint = spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
    let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
    token_endpoint.set_access_token(signed_token_with_issuer(
        "admin-operator",
        &["admin"],
        &oidc.issuer,
    ));
    let router = admin_oidc_login_router(&oidc.issuer);

    let login_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/admin/auth/login")
                .body(Body::empty())
                .expect("login request should build"),
        )
        .await
        .expect("login request should complete");
    let cookies = admin_oidc_cookies(&login_response);
    let login_location = response_location(&login_response);
    let authorization_url =
        Url::parse(&login_location).expect("authorization redirect should be absolute");
    let authorization_query = url_query_pairs(&authorization_url);
    let state = authorization_query
        .get("state")
        .expect("authorization redirect should include state");

    let callback_response = router
        .oneshot(admin_oidc_complete_request(&cookies, "admin-code", state))
        .await
        .expect("completion request should complete");

    assert_eq!(callback_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_error_message(callback_response).await,
        "token_exchange_failed"
    );
    assert_eq!(token_endpoint.requests().len(), 1);

    oidc.finish();
    token_endpoint.abort();
}

#[tokio::test]
async fn admin_oidc_login_accepts_valid_id_token_with_matching_nonce_audience_and_issuer() {
    let (callback_response, access_token) =
        admin_oidc_id_token_callback_response(|nonce, issuer| {
            signed_admin_id_token(issuer, "admin-ui", nonce)
        })
        .await;

    assert_admin_oidc_token(callback_response, &access_token).await;
}

#[tokio::test]
async fn admin_oidc_login_rejects_id_token_with_mismatched_nonce() {
    let (callback_response, _) = admin_oidc_id_token_callback_response(|_, issuer| {
        signed_admin_id_token(issuer, "admin-ui", "other-nonce")
    })
    .await;

    assert_eq!(callback_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_error_message(callback_response).await,
        "token_exchange_failed"
    );
}

#[tokio::test]
async fn admin_oidc_login_rejects_id_token_with_mismatched_audience() {
    let (callback_response, _) = admin_oidc_id_token_callback_response(|nonce, issuer| {
        signed_admin_id_token(issuer, "other-client", nonce)
    })
    .await;

    assert_eq!(callback_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_error_message(callback_response).await,
        "token_exchange_failed"
    );
}

#[tokio::test]
async fn admin_oidc_login_rejects_id_token_with_mismatched_issuer() {
    let (callback_response, _) = admin_oidc_id_token_callback_response(|nonce, _| {
        signed_admin_id_token("http://other-issuer.example.test", "admin-ui", nonce)
    })
    .await;

    assert_eq!(callback_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_error_message(callback_response).await,
        "token_exchange_failed"
    );
}

#[tokio::test]
async fn admin_oidc_login_rejects_id_token_with_invalid_signature() {
    let (callback_response, _) = admin_oidc_id_token_callback_response(|nonce, issuer| {
        corrupt_jwt_signature(&signed_admin_id_token(issuer, "admin-ui", nonce))
    })
    .await;

    assert_eq!(callback_response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_error_message(callback_response).await,
        "token_exchange_failed"
    );
}

#[tokio::test]
async fn admin_oidc_callback_with_unknown_state_does_not_exchange_token() {
    let token_endpoint = spawn_mock_oidc_token_endpoint(Ipv4Addr::LOCALHOST, None).await;
    let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
    token_endpoint.set_access_token(signed_token_with_issuer(
        "admin-operator",
        &["admin"],
        &oidc.issuer,
    ));
    let router = admin_oidc_login_router(&oidc.issuer);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/v1/admin/auth/callback?code=admin-code&state=unknown-state")
                .body(Body::empty())
                .expect("callback request should build"),
        )
        .await
        .expect("callback request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        fragment_query_pairs(&response_location(&response), "/auth/error")
            .expect("unknown state should redirect to auth error fragment")
            .get("error")
            .is_some_and(|error| error == "invalid_state")
    );
    assert!(token_endpoint.requests().is_empty());

    oidc.finish();
    token_endpoint.abort();
}

#[test]
fn admin_oidc_login_provider_rejects_discovery_with_mismatched_issuer() {
    let (issuer, server) = spawn_oidc_discovery_server(
        json!({
            "issuer": "http://attacker.example.test",
            "jwks_uri": "http://127.0.0.1:1/jwks.json",
            "authorization_endpoint": "http://127.0.0.1:1/authorize",
            "token_endpoint": "http://127.0.0.1:1/token"
        }),
        1,
    );
    let mut config = admin_oidc_login_config(&issuer);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();

    let error = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect_err("admin login discovery with mismatched issuer should fail startup");

    assert!(error.to_string().contains("OIDC discovery issuer mismatch"));
    server.finish();
}

#[test]
fn admin_oidc_login_provider_rejects_discovery_without_issuer() {
    let (issuer, server) = spawn_oidc_discovery_server(
        json!({
            "jwks_uri": "http://127.0.0.1:1/jwks.json",
            "authorization_endpoint": "http://127.0.0.1:1/authorize",
            "token_endpoint": "http://127.0.0.1:1/token"
        }),
        1,
    );
    let mut config = admin_oidc_login_config(&issuer);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();

    let error = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect_err("admin login discovery without issuer should fail startup");

    assert!(error
        .to_string()
        .contains("OIDC discovery response missing issuer"));
    server.finish();
}

#[test]
fn admin_oidc_login_provider_requires_discovered_authorize_and_token_endpoints() {
    let (issuer, server) = spawn_oidc_discovery_server_with(
        |issuer| {
            json!({
                "issuer": issuer,
                "jwks_uri": "http://127.0.0.1:1/jwks.json",
                "authorization_endpoint": "http://127.0.0.1:1/authorize"
            })
        },
        1,
    );
    let mut config = admin_oidc_login_config(&issuer);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();

    let error = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect_err("admin login discovery without token endpoint should fail startup");

    assert!(error
        .to_string()
        .contains("OIDC discovery response missing token_endpoint"));
    server.finish();
}

#[tokio::test]
async fn admin_oidc_login_routes_are_absent_when_provider_unset() {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build without admin login provider");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/v1/admin/auth/login")
                .body(Body::empty())
                .expect("login request should build"),
        )
        .await
        .expect("login request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

fn corrupt_jwt_signature(token: &str) -> String {
    let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let replacement = if parts[2].ends_with('A') { 'B' } else { 'A' };
    parts[2].pop();
    parts[2].push(replacement);
    parts.join(".")
}
