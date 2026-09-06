//! CSRF protection for GreenGateway state-changing requests.
//!
//! This middleware implements the double-submit-cookie pattern. It is layered
//! over the whole router rather than over the admin surface alone, so proxied
//! passthrough traffic is in scope too: any `POST`/`PUT`/`PATCH`/`DELETE` on a
//! non-exempt path is rejected unless it carries a bearer credential or a
//! matching cookie/header token pair. Exempt paths are compared for equality
//! and default to the probe routes, so a deployment whose proxied clients
//! authenticate with anything other than a bearer token has to echo the token
//! or turn the layer off with `CSRF_ENABLED=false`.
//! MCP requests without cookies or a verified client certificate also proceed
//! to authentication so OAuth clients can receive their initial challenge.

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

use crate::{
    auth::{protected_resource, VerifiedClientIdentity},
    config::Config,
};

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

        // An MCP OAuth client starts without credentials and needs auth's 401
        // challenge. Only bypass when neither form of ambient credential is
        // present; even empty or malformed Cookie headers remain protected.
        if is_mcp_route
            && !request.headers().contains_key(COOKIE)
            && request
                .extensions()
                .get::<VerifiedClientIdentity>()
                .is_none()
        {
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
#[path = "csrf_tests.rs"]
mod tests;
