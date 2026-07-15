//! Header hardening middleware.
//!
//! Goals:
//! - Strip spoofable identity headers coming from the client.
//! - Add baseline security headers to every HTTP response.
//!
//! This middleware should run near the edge so downstream layers cannot be
//! confused by attacker-controlled identity metadata.

use axum::{extract::Request, middleware::Next, response::Response};

/// Request headers that must never be trusted from untrusted clients.
///
/// These are stripped to prevent privilege escalation via header spoofing,
/// including identity, authorization, proxy-auth, and method/URL override
/// metadata.
///
/// Note: `x-forwarded-for` and `x-real-ip` are intentionally preserved because
/// canonical client-IP extraction accepts them only when the direct connection
/// peer belongs to an explicitly configured trusted proxy CIDR. The
/// reverse-proxy fallback removes both before upstream egress and emits
/// gateway-controlled values instead.
///
/// `x-forwarded-host` and `x-forwarded-proto` are stripped because spoofed
/// values can poison URL generation, auth redirects, and cookie domains.
const SPOOFABLE_REQUEST_HEADERS: &[&str] = &[
    // Forwarded routing metadata that can influence URL generation.
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
    // User and organization identity claims injected by auth gateways.
    "x-user-id",
    "x-user",
    "x-user-email",
    "x-email",
    "x-org-id",
    "x-org",
    "x-roles",
    "x-role",
    "x-permissions",
    "x-session-id",
    "x-auth-user",
    "x-auth-email",
    "x-auth-roles",
    "x-forwarded-user",
    "x-forwarded-email",
    "x-forwarded-roles",
    // Reverse-proxy, SSO, OAuth2 Proxy, and mTLS identity assertions.
    "x-remote-user",
    "x-authenticated-user",
    "x-auth-request-user",
    "x-auth-request-email",
    "x-auth-request-groups",
    "x-forwarded-client-cert",
    "x-ssl-client-cert",
    // Authorization scopes, groups, and tenant claims.
    "x-groups",
    "x-group",
    "x-scope",
    "x-scopes",
    "x-tenant-id",
    // Method and URL overrides that can bypass scoped authorization.
    "x-http-method-override",
    "x-original-url",
    "x-rewrite-url",
    // Upstream proxy credentials.
    "proxy-authorization",
];

pub async fn header_hardening_middleware(mut req: Request, next: Next) -> Response {
    for &header in SPOOFABLE_REQUEST_HEADERS {
        req.headers_mut().remove(header);
    }

    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers
        .entry("x-content-type-options")
        .or_insert("nosniff".parse().expect("static header value should parse"));
    headers
        .entry("x-frame-options")
        .or_insert("DENY".parse().expect("static header value should parse"));
    headers.entry("referrer-policy").or_insert(
        "no-referrer"
            .parse()
            .expect("static header value should parse"),
    );
    headers.entry("permissions-policy").or_insert(
        "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
            .parse()
            .expect("static header value should parse"),
    );
    headers.entry("cross-origin-resource-policy").or_insert(
        "same-site"
            .parse()
            .expect("static header value should parse"),
    );
    headers.entry("content-security-policy").or_insert(
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
            .parse()
            .expect("static header value should parse"),
    );

    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{header, Request, StatusCode},
        middleware::from_fn,
        response::IntoResponse,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn strips_spoofed_headers_before_handler() {
        async fn echo_header(headers: http::HeaderMap) -> &'static str {
            let spoofed_headers = [
                "x-user-id",
                "x-remote-user",
                "x-tenant-id",
                "x-original-url",
            ];

            if spoofed_headers
                .iter()
                .any(|header| headers.contains_key(*header))
            {
                "present"
            } else {
                "missing"
            }
        }

        let response = Router::new()
            .route("/", get(echo_header))
            .layer(from_fn(header_hardening_middleware))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("x-user-id", "attacker")
                    .header("x-remote-user", "attacker")
                    .header("x-tenant-id", "attacker")
                    .header("x-original-url", "/admin")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        assert_eq!(&body[..], b"missing");
    }

    #[tokio::test]
    async fn adds_baseline_security_headers() {
        let response = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(from_fn(header_hardening_middleware))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        let headers = response.headers();

        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert_eq!(
            headers["permissions-policy"],
            "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        );
        assert_eq!(headers["cross-origin-resource-policy"], "same-site");
        assert_eq!(
            headers["content-security-policy"],
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        );
    }

    #[tokio::test]
    async fn does_not_overwrite_explicit_security_header() {
        async fn explicit_frame_options() -> impl IntoResponse {
            ([(header::X_FRAME_OPTIONS, "SAMEORIGIN")], "ok")
        }

        let response = Router::new()
            .route("/", get(explicit_frame_options))
            .layer(from_fn(header_hardening_middleware))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.headers()["x-frame-options"], "SAMEORIGIN");
    }
}
