use super::*;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderName, HeaderValue, Request, StatusCode},
    middleware::from_fn,
    response::IntoResponse,
    routing::get,
    Router,
};
use tower::ServiceExt;

/// Runs the middleware over a handler that emits `upstream_headers`, the way
/// a proxied response carries whatever the upstream chose to send.
async fn hardened_response(upstream_headers: &'static [(&'static str, &'static str)]) -> Response {
    async fn handler(
        State(upstream_headers): State<&'static [(&'static str, &'static str)]>,
    ) -> impl IntoResponse {
        let mut headers = HeaderMap::new();
        for (name, value) in upstream_headers {
            headers.append(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }

        (headers, "ok")
    }

    Router::new()
        .route("/", get(handler))
        .with_state(upstream_headers)
        .layer(from_fn(header_hardening_middleware))
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete")
}

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

/// Every mTLS assertion header a common terminator emits, named one at a
/// time.
///
/// GreenGateway does not read any of these -- a certificate identity here
/// comes only from a handshake this process terminated -- but an upstream
/// behind it may, and an upstream that trusts its front proxy is exactly
/// the reader they are aimed at. Each is asserted individually so that
/// dropping one from the list fails here rather than being masked by the
/// others.
#[tokio::test]
async fn strips_every_client_certificate_assertion_header() {
    const ASSERTION_HEADERS: &[&str] = &[
        "x-forwarded-client-cert",
        "x-ssl-client-cert",
        "ssl-client-cert",
        "ssl-client-verify",
        "ssl-client-subject-dn",
        "ssl-client-issuer-dn",
        "x-ssl-client-verify",
        "x-ssl-client-s-dn",
        "x-ssl-client-i-dn",
        "x-ssl-client-subject-dn",
        "x-ssl-client-issuer-dn",
        "x-ssl-client-fingerprint",
        "x-ssl-client-serial",
        "x-client-cert",
        "x-client-verify",
        "x-client-dn",
        "x-client-subject-dn",
        "x-client-fingerprint",
        "x-forwarded-tls-client-cert",
        "x-forwarded-tls-client-cert-info",
        "x-spiffe-id",
    ];

    async fn echo_surviving_headers(headers: http::HeaderMap) -> String {
        headers
            .keys()
            .map(http::HeaderName::as_str)
            .filter(|name| *name != "host")
            .collect::<Vec<_>>()
            .join(",")
    }

    for header in ASSERTION_HEADERS {
        let response = Router::new()
            .route("/", get(echo_surviving_headers))
            .layer(from_fn(header_hardening_middleware))
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(*header, "spiffe://gateway.test/ns/payments/sa/admin")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let surviving = String::from_utf8_lossy(&body);
        assert!(
            !surviving.contains(header),
            "{header} reached the handler; a caller must not be able to assert a \
                 certificate identity the gateway did not verify. Surviving headers: {surviving}"
        );
    }
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
async fn keeps_upstream_framing_restriction() {
    let response = hardened_response(&[("x-frame-options", "SAMEORIGIN")]).await;

    assert_eq!(response.headers()["x-frame-options"], "SAMEORIGIN");
}

#[tokio::test]
async fn overwrites_upstream_content_type_options() {
    let response = hardened_response(&[("x-content-type-options", "sniff")]).await;

    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn replaces_framing_directive_browsers_ignore() {
    let response = hardened_response(&[("x-frame-options", "ALLOWALL")]).await;

    assert_eq!(response.headers()["x-frame-options"], "DENY");
}

#[tokio::test]
async fn replaces_conflicting_framing_directives() {
    let response = hardened_response(&[
        ("x-frame-options", "SAMEORIGIN"),
        ("x-frame-options", "ALLOWALL"),
    ])
    .await;

    let framing = response
        .headers()
        .get_all("x-frame-options")
        .iter()
        .map(|value| value.to_str().expect("header value should be ASCII"))
        .collect::<Vec<_>>();
    assert_eq!(framing, vec!["DENY"]);
}

#[tokio::test]
async fn keeps_upstream_content_security_policy() {
    let response = hardened_response(&[("content-security-policy", "default-src 'self'")]).await;

    assert_eq!(
        response.headers()["content-security-policy"],
        "default-src 'self'"
    );
}
