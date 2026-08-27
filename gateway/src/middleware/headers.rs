//! Header hardening middleware.
//!
//! Goals:
//! - Strip spoofable identity headers coming from the client.
//! - Add baseline security headers to every HTTP response.
//!
//! This middleware should run near the edge so downstream layers cannot be
//! confused by attacker-controlled identity metadata.
//!
//! Response headers fall into two classes. A *floor* is a guarantee the gateway
//! makes about its own origin, so it is written even when the response already
//! carries a value: a proxied upstream must not be able to lower it. A
//! *default* is a policy only the application behind the route can size, so an
//! explicit value from the route wins and the baseline covers the responses
//! that express nothing.

use axum::{extract::Request, middleware::Next, response::Response};
use http::HeaderMap;

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
    // Client-certificate assertions, in every spelling the common TLS
    // terminators use: nginx (`ssl-client-*`), HAProxy and Traefik
    // (`x-forwarded-tls-client-cert*`), and the hand-rolled `x-client-*` pairs
    // that appear in front of internal services. GreenGateway never reads any
    // of these -- a certificate identity here can only come from a handshake
    // this process terminated -- but an upstream behind it very well might, and
    // an upstream that trusts its front proxy is exactly the reader these
    // headers are aimed at. Stripping them means a caller cannot borrow the
    // gateway's position in the topology to assert an identity it did not
    // authenticate as.
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

    // Floor: `nosniff` is the only value this header has ever meant, so a
    // response carrying anything else is not expressing a policy, it is
    // removing one. MIME confusion lands on the gateway's origin, not the
    // upstream's, so the gateway keeps the decision.
    headers.insert(
        "x-content-type-options",
        "nosniff".parse().expect("static header value should parse"),
    );

    // Floor: framing binds the gateway's origin, where the admin session and
    // CSRF cookies live, so an upstream cannot hand its own responses to an
    // attacker's frame. An upstream that restricts framing itself keeps its
    // value, and one that genuinely wants to be framed says so with
    // `frame-ancestors`, which browsers honour over `x-frame-options`.
    if !restricts_framing(headers) {
        headers.insert(
            "x-frame-options",
            "DENY".parse().expect("static header value should parse"),
        );
    }

    // The rest are defaults. `referrer-policy` trades privacy against apps that
    // need `Referer` for their own checks, `permissions-policy` gates features a
    // proxied app may legitimately use, and `cross-origin-resource-policy`
    // decides who may embed the route's own resources. The admin UI is the
    // in-tree proof for `content-security-policy`: it serves its own because the
    // baseline `default-src 'none'` would refuse to load its bundle, and every
    // proxied app with a UI is in the same position.
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

/// Whether the response already restricts framing with a directive a browser
/// acts on.
///
/// Browsers honour only `DENY` and `SAMEORIGIN`, and ignore the header entirely
/// when it repeats. Everything else -- `ALLOWALL`, the obsolete `ALLOW-FROM`, a
/// typo -- leaves the response framable, so the gateway reads it as no policy
/// rather than as the application's choice.
fn restricts_framing(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all("x-frame-options").iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }

    value.to_str().is_ok_and(|value| {
        let value = value.trim();
        value.eq_ignore_ascii_case("deny") || value.eq_ignore_ascii_case("sameorigin")
    })
}

#[cfg(test)]
mod tests {
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
    async fn hardened_response(
        upstream_headers: &'static [(&'static str, &'static str)],
    ) -> Response {
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
        let response =
            hardened_response(&[("content-security-policy", "default-src 'self'")]).await;

        assert_eq!(
            response.headers()["content-security-policy"],
            "default-src 'self'"
        );
    }
}
