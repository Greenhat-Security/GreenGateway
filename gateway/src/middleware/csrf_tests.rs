use super::*;
use axum::{body::Body, middleware::from_fn_with_state, routing::get, Router};
use http::header::AUTHORIZATION;
use serde_json::Value;
use tower::ServiceExt;

fn test_config(enabled: bool) -> CsrfConfig {
    CsrfConfig {
        enabled,
        cookie_name: "csrf_token".to_owned(),
        cookie_domain: None,
        header_name: "x-csrf-token".to_owned(),
        exempt_paths: vec!["/exempt".to_owned()],
        mcp_route_paths: vec![protected_resource::MCP_RESOURCE_PATH.to_owned()],
    }
}

fn test_router(config: CsrfConfig) -> Router {
    async fn ok() -> &'static str {
        "ok"
    }

    Router::new()
        .route("/", get(ok).post(ok))
        .route("/exempt", get(ok).post(ok))
        .route("/mcp", get(ok).post(ok))
        .layer(from_fn_with_state(config, csrf_middleware))
}

#[tokio::test]
async fn disabled_post_without_token_passes_through() {
    let response = test_router(test_config(false))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn enabled_post_without_cookie_or_header_is_forbidden() {
    let response = test_router(test_config(true))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    let json: Value = serde_json::from_slice(&body).expect("body should be JSON");

    assert_eq!(
        json,
        serde_json::json!({ "error": "csrf token missing or invalid" })
    );
}

#[tokio::test]
async fn enabled_post_with_matching_cookie_and_header_passes_through() {
    let response = test_router(test_config(true))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .header(COOKIE, "csrf_token=token-123")
                .header("x-csrf-token", "token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn enabled_post_with_mismatched_cookie_and_header_is_forbidden() {
    let response = test_router(test_config(true))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .header(COOKIE, "csrf_token=cookie-token")
                .header("x-csrf-token", "header-token")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bearer_authenticated_post_bypasses_csrf() {
    let response = test_router(test_config(true))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_without_existing_cookie_issues_csrf_cookie() {
    let response = test_router(test_config(true))
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);

    let set_cookie = response
        .headers()
        .get(SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("CSRF Set-Cookie header should be present");

    assert!(set_cookie.contains("csrf_token="));
    assert!(set_cookie.contains("SameSite=Lax"));
    assert!(set_cookie.contains("Secure"));
}

#[tokio::test]
async fn get_with_empty_existing_cookie_reissues_non_empty_csrf_cookie() {
    let response = test_router(test_config(true))
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(COOKIE, "csrf_token=")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);

    let set_cookie = response
        .headers()
        .get(SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("CSRF Set-Cookie header should be present");
    let token = set_cookie
        .strip_prefix("csrf_token=")
        .and_then(|value| value.split_once(';'))
        .map(|(token, _)| token)
        .expect("CSRF Set-Cookie should include a token before attributes");

    assert!(!token.is_empty());
}

#[tokio::test]
async fn exempt_post_without_token_passes_through() {
    let response = test_router(test_config(true))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/exempt")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn mcp_without_ambient_credentials_reaches_the_next_layer() {
    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        let router = Router::new()
            .route(
                "/mcp",
                axum::routing::any(|| async { StatusCode::UNAUTHORIZED }),
            )
            .layer(from_fn_with_state(test_config(true), csrf_middleware));
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/mcp")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn mcp_with_any_cookie_still_requires_csrf() {
    for cookie in [
        "session=test-session",
        "csrf_token=token",
        "unrelated=value",
        "",
        "malformed",
    ] {
        let response = test_router(test_config(true))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/mcp")
                    .header(COOKIE, cookie)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "cookie: {cookie:?}"
        );
    }
}

#[tokio::test]
async fn mcp_with_client_certificate_still_requires_csrf() {
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::URI(
        rcgen::Ia5String::try_from("spiffe://example.test/client").expect("URI SAN"),
    )];
    let key = rcgen::KeyPair::generate().expect("key");
    let certificate = params.self_signed(&key).expect("certificate");
    let identity = crate::auth::identity_from_certificate(
        certificate.der(),
        crate::auth::ClientCertIdentitySource::Spiffe,
    )
    .expect("identity");
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .body(Body::empty())
        .expect("request");
    request.extensions_mut().insert(identity);
    let response = test_router(test_config(true))
        .oneshot(request)
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mcp_route_is_not_csrf_exempt_even_if_listed() {
    let mut config = test_config(true);
    config
        .exempt_paths
        .push(protected_resource::MCP_RESOURCE_PATH.to_owned());

    let response = test_router(config)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(protected_resource::MCP_RESOURCE_PATH)
                .header(COOKIE, "session=test-session")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("MCP request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
