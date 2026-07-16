//! CSRF protection for GreenGateway control-plane endpoints.
//!
//! This middleware implements the double-submit-cookie pattern for the
//! gateway's own state-changing admin/control-plane endpoints. Proxied
//! passthrough traffic is out of scope here and will be governed by policy.
//! Today the gateway exposes only `GET /health`, `GET /version`, and
//! `GET /metrics`; those probe paths are exempt, so this layer is dormant for
//! current production traffic. It becomes active when state-changing gateway
//! endpoints land.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{
    header::{COOKIE, SET_COOKIE},
    HeaderMap, HeaderValue, Method, StatusCode,
};
use serde::Serialize;

use crate::{auth::protected_resource, config::Config};

use super::bearer::bearer_token;

#[derive(Clone, Debug)]
pub struct CsrfConfig {
    pub enabled: bool,
    pub cookie_name: String,
    pub cookie_domain: Option<String>,
    pub header_name: String,
    pub exempt_paths: Vec<String>,
    pub mcp_route_paths: Vec<String>,
}

#[derive(Serialize)]
struct CsrfForbiddenBody {
    error: &'static str,
}

impl CsrfConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            enabled: config.csrf_enabled,
            cookie_name: config.csrf_cookie_name.clone(),
            cookie_domain: config.csrf_cookie_domain.clone(),
            header_name: config.csrf_header_name.clone(),
            exempt_paths: config.csrf_exempt_paths.clone(),
            mcp_route_paths: protected_resource::mcp_route_paths(config),
        }
    }
}

pub async fn csrf_middleware(
    State(config): State<CsrfConfig>,
    request: Request,
    next: Next,
) -> Response {
    if !config.enabled {
        return next.run(request).await;
    }

    let path = request.uri().path();
    let is_mcp_route = config
        .mcp_route_paths
        .iter()
        .any(|route_path| route_path == path);
    if !is_mcp_route
        && config
            .exempt_paths
            .iter()
            .any(|exempt_path| exempt_path == path)
    {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let existing = first_cookie_value(request.headers(), &config.cookie_name);

    if is_state_changing(&method) {
        if bearer_auth_present(&request) {
            return next.run(request).await;
        }

        let cookie_tokens = all_cookie_values(request.headers(), &config.cookie_name);
        let header_token = request
            .headers()
            .get(config.header_name.as_str())
            .and_then(header_value_to_str);

        if !csrf_token_matches(&cookie_tokens, header_token) {
            let reason = csrf_failure_reason(&cookie_tokens, header_token);
            tracing::warn!(
                method = %method,
                path = path,
                reason = reason,
                "CSRF validation failed"
            );
            return csrf_forbidden();
        }
    }

    let mut response = next.run(request).await;

    if !is_state_changing(&method) && existing.as_deref().is_none_or(str::is_empty) {
        let token = uuid::Uuid::new_v4().to_string();
        match set_cookie_header_value(&config, &token) {
            Ok(value) => {
                response.headers_mut().append(SET_COOKIE, value);
            }
            Err(err) => {
                tracing::error!(error = %err, "failed to build CSRF Set-Cookie header");
            }
        }
    }

    response
}

fn csrf_token_matches(cookie_tokens: &[String], header_token: Option<&str>) -> bool {
    match header_token {
        Some(header_token) if !header_token.is_empty() => cookie_tokens
            .iter()
            .any(|cookie_token| !cookie_token.is_empty() && cookie_token == header_token),
        _ => false,
    }
}

fn csrf_failure_reason(cookie_tokens: &[String], header_token: Option<&str>) -> &'static str {
    if cookie_tokens.iter().all(|token| token.is_empty()) {
        "missing_csrf_cookie"
    } else if header_token.is_none_or(str::is_empty) {
        "missing_csrf_header"
    } else {
        "csrf_token_mismatch"
    }
}

fn csrf_forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(CsrfForbiddenBody {
            error: "csrf token missing or invalid",
        }),
    )
        .into_response()
}

fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn bearer_auth_present(request: &Request) -> bool {
    bearer_token(request.headers()).is_some()
}

fn first_cookie_value(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    all_cookie_values(headers, cookie_name).into_iter().next()
}

fn all_cookie_values(headers: &HeaderMap, cookie_name: &str) -> Vec<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(header_value_to_str)
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .filter(|(name, _)| name.trim() == cookie_name)
        .map(|(_, value)| value.trim().to_owned())
        .collect()
}

fn header_value_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

fn set_cookie_header_value(
    config: &CsrfConfig,
    token: &str,
) -> Result<HeaderValue, http::header::InvalidHeaderValue> {
    let mut cookie = format!("{}={token}; Path=/; SameSite=Lax", config.cookie_name);

    if let Some(domain) = &config.cookie_domain {
        cookie.push_str("; Domain=");
        cookie.push_str(domain);
    }

    cookie.push_str("; Secure");
    HeaderValue::from_str(&cookie)
}

#[cfg(test)]
mod tests {
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
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("MCP request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
