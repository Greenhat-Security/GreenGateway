//! Explicit browser-session delegation for a fixed, trusted HTTPS API.
//! Authentication remains the middleware's authority; arbitrary inbound cookies
//! and claimed identity headers never become upstream authority.

use http::{header, HeaderMap, HeaderValue, Method};

use crate::{
    auth,
    middleware::auth::{safe_cookie_token, safe_cookie_value, ValidatedCookieSession},
};

#[derive(Clone, Debug)]
pub(super) struct CookieSessionPolicy {
    pub session_cookie_name: String,
    pub csrf_cookie_name: String,
    pub upstream_csrf_cookie_name: String,
    pub csrf_header_name: String,
}

/// Called before body reads, admission, credential resolution or upstream I/O.
pub(super) fn delegated_cookie(
    parts: &http::request::Parts,
    policy: &CookieSessionPolicy,
) -> Result<HeaderValue, &'static str> {
    let session = parts
        .extensions
        .get::<ValidatedCookieSession>()
        .ok_or("validated_cookie_session_required")?;
    if !parts
        .extensions
        .get::<auth::Principal>()
        .is_some_and(|principal| principal.auth_method == auth::AuthMethod::Cookie)
        || parts.headers.contains_key(header::AUTHORIZATION)
        || session.cookie_name() != policy.session_cookie_name
    {
        return Err("validated_cookie_session_required");
    }
    if !matches!(
        parts.method,
        Method::GET
            | Method::HEAD
            | Method::OPTIONS
            | Method::POST
            | Method::PUT
            | Method::PATCH
            | Method::DELETE
    ) {
        return Err("session_delegation_method_rejected");
    }
    let upstream_base = policy
        .upstream_csrf_cookie_name
        .strip_prefix("__Secure-")
        .or_else(|| policy.upstream_csrf_cookie_name.strip_prefix("__Host-"))
        .unwrap_or(&policy.upstream_csrf_cookie_name);
    let session_base = policy
        .session_cookie_name
        .strip_prefix("__Secure-")
        .or_else(|| policy.session_cookie_name.strip_prefix("__Host-"))
        .unwrap_or(&policy.session_cookie_name);
    if upstream_base == session_base
        || !safe_cookie_token(&policy.upstream_csrf_cookie_name)
        || policy.csrf_cookie_name == policy.session_cookie_name
        || !safe_cookie_token(&policy.csrf_cookie_name)
    {
        return Err("session_delegation_configuration_invalid");
    }
    let csrf = unique_cookie(&parts.headers, &policy.csrf_cookie_name)?;
    let mut headers = parts.headers.get_all(&policy.csrf_header_name).iter();
    let csrf_header = headers
        .next()
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| "session_delegation_csrf_invalid")?;
    if headers.next().is_some() {
        return Err("session_delegation_csrf_invalid");
    }
    let mutation = matches!(
        parts.method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if mutation && (csrf.is_none() || csrf_header != csrf) {
        return Err("session_delegation_csrf_invalid");
    }
    // A supplied token must remain unambiguous even for a safe method.
    if csrf_header.is_some() && csrf_header != csrf {
        return Err("session_delegation_csrf_invalid");
    }
    let mut cookie = match csrf {
        Some(value) => HeaderValue::from_str(&format!(
            "{}; {}={value}",
            session
                .cookie_header()
                .to_str()
                .map_err(|_| "validated_cookie_session_required")?,
            policy.upstream_csrf_cookie_name
        ))
        .map_err(|_| "session_delegation_csrf_invalid")?,
        None => session.cookie_header().clone(),
    };
    cookie.set_sensitive(true);
    Ok(cookie)
}

fn unique_cookie<'a>(
    headers: &'a HeaderMap,
    expected: &str,
) -> Result<Option<&'a str>, &'static str> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        let header = header
            .to_str()
            .map_err(|_| "session_delegation_csrf_invalid")?;
        for cookie in header.split(';') {
            let Some((name, value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if name.trim() == expected {
                if found.is_some() || !safe_cookie_value(value) {
                    return Err("session_delegation_csrf_invalid");
                }
                found = Some(value);
            }
        }
    }
    Ok(found)
}

/// Strip untrusted claimed identity as well as all ambient credentials, then
/// install only middleware-validated session material after route transforms.
pub(super) fn inject(headers: &mut HeaderMap, cookie: &HeaderValue) {
    let untrusted = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            // attempt_headers has already replaced this one with the
            // gateway's canonical client IP; never retain caller identity.
            name != "x-forwarded-for" && crate::config::cookie_session_identity_header(name)
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in untrusted {
        headers.remove(name);
    }
    headers.remove(header::AUTHORIZATION);
    headers.insert(header::COOKIE, cookie.clone());
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::{to_bytes, Body},
        middleware::from_fn_with_state,
        response::{IntoResponse, Response},
        routing::any,
        Router,
    };
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        audit::{sink::tests::CaptureSink, AuditLog},
        auth::{
            AuthError, AuthMethod, Principal, PrincipalDirectory, SessionCredential,
            SessionValidator,
        },
        client_ip::ClientIpPolicy,
        config::AuthMode,
        middleware::auth::{auth_middleware, AuthState},
    };

    struct Validator;

    #[test]
    fn origin_admission_header_is_operator_owned_and_cannot_replace_user_identity() {
        let inbound = HeaderMap::from_iter([
            (
                http::HeaderName::from_static("x-pm-origin-key"),
                HeaderValue::from_static("untrusted"),
            ),
            (
                http::HeaderName::from_static("x-user-id"),
                HeaderValue::from_static("spoofed"),
            ),
            (
                http::HeaderName::from_static("x-role"),
                HeaderValue::from_static("admin"),
            ),
            (
                header::AUTHORIZATION,
                HeaderValue::from_static("Bearer untrusted"),
            ),
        ]);
        let policy = super::super::RouteRequestHeaderPolicy {
            add_request_headers: vec![(
                http::HeaderName::from_static("x-pm-origin-key"),
                HeaderValue::from_static("fixture-origin-header"),
            )],
            strip_request_headers: vec![],
            cookie_session: None,
        };
        let mut headers =
            super::super::forward::attempt_headers(&inbound, "203.0.113.7", &policy, &[]);
        let mut cookie = HeaderValue::from_static("session=fixture");
        cookie.set_sensitive(true);
        inject(&mut headers, &cookie);
        assert_eq!(headers["x-pm-origin-key"], "fixture-origin-header");
        assert_eq!(headers[header::COOKIE], "session=fixture");
        assert_eq!(headers["x-forwarded-for"], "203.0.113.7");
        assert!(!headers.contains_key("x-user-id"));
        assert!(!headers.contains_key("x-role"));
        assert!(!headers.contains_key(header::AUTHORIZATION));
    }

    #[test]
    fn greenpm_sample_rules_bind_exact_operations_and_cookie_provider_to_the_route() {
        let fragment: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/examples/greenpm-session-rules.json"
        ))
        .unwrap();
        let policy = crate::rbac::Policy::validate_json_value(serde_json::json!({
            "schema_version": "0.1.0", "id": "greenpm-example", "default_action": "deny",
            "rules": fragment["rules"], "roles": {}, "routes": []
        }))
        .unwrap();
        let matcher = crate::rbac::RuleMatcher::new(&policy.rules);
        let mut principal = Principal {
            user_id: "fixture-user".into(),
            issuer: Some("provider:greenhat-session".into()),
            email: None,
            org_id: None,
            roles: vec![],
            session_id: "fixture-session-id".into(),
            auth_method: AuthMethod::Cookie,
        };
        let dispatch = crate::rbac::RuleDispatchContext::classified_with_route_id(
            Some("greenpm-module-access"),
            None,
            Some("/api/me/module-access"),
            None,
        );
        assert_eq!(
            matcher
                .evaluate_with_dispatch("GET", "/api/me/module-access", Some(&principal), dispatch)
                .unwrap()
                .action,
            crate::rbac::RuleAction::Allow
        );
        for (method, path) in [
            ("POST", "/api/me/module-access"),
            ("GET", "/api/me/module-access/unreviewed"),
        ] {
            assert_eq!(
                matcher
                    .evaluate_with_dispatch(method, path, Some(&principal), dispatch)
                    .unwrap()
                    .action,
                crate::rbac::RuleAction::Deny
            );
        }
        principal.auth_method = AuthMethod::Bearer;
        assert_eq!(
            matcher
                .evaluate_with_dispatch("GET", "/api/me/module-access", Some(&principal), dispatch)
                .unwrap()
                .action,
            crate::rbac::RuleAction::Deny
        );
        principal.auth_method = AuthMethod::Cookie;
        principal.issuer = Some("provider:other".into());
        assert_eq!(
            matcher
                .evaluate_with_dispatch("GET", "/api/me/module-access", Some(&principal), dispatch)
                .unwrap()
                .action,
            crate::rbac::RuleAction::Deny
        );
        assert!(matcher
            .evaluate_with_dispatch(
                "GET",
                "/api/me/module-access",
                Some(&principal),
                crate::rbac::RuleDispatchContext::contextless()
            )
            .is_none());
    }

    #[test]
    fn greenpm_assignment_and_personal_feed_require_exact_operation_and_session_route() {
        let fragment: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/examples/greenpm-session-rules.json"
        ))
        .unwrap();
        let policy = crate::rbac::Policy::validate_json_value(serde_json::json!({
            "schema_version": "0.1.0", "id": "greenpm-example", "default_action": "deny",
            "rules": fragment["rules"], "roles": {}, "routes": []
        }))
        .unwrap();
        let matcher = crate::rbac::RuleMatcher::new(&policy.rules);
        let principal = Principal {
            user_id: "fixture-user".into(),
            issuer: Some("provider:greenhat-session".into()),
            email: None,
            org_id: None,
            roles: vec![],
            session_id: "fixture-session-id".into(),
            auth_method: AuthMethod::Cookie,
        };
        let owned = crate::rbac::RuleDispatchContext::classified_with_route_id(
            Some("greenpm-owned"),
            None,
            Some("/api/greenpm-owned"),
            None,
        );
        let allows = |method, path, actor, dispatch| {
            matcher
                .evaluate_with_dispatch(method, path, actor, dispatch)
                .is_some_and(|decision| decision.action == crate::rbac::RuleAction::Allow)
        };
        let mut bearer = principal.clone();
        bearer.auth_method = AuthMethod::Bearer;
        let mut other_provider = principal.clone();
        other_provider.issuer = Some("provider:other".into());
        for (method, path) in [
            ("PATCH", "/api/greenpm-owned/tasks/fixture-task/assignee"),
            ("PATCH", "/api/greenpm-owned/tasks/fixture-task/move"),
            ("GET", "/api/greenpm-owned/my-tasks"),
        ] {
            assert!(allows(method, path, Some(&principal), owned));
            assert!(!allows(method, path, None, owned));
            assert!(!allows(
                method,
                path,
                Some(&principal),
                crate::rbac::RuleDispatchContext::contextless()
            ));
            let wrong_route = crate::rbac::RuleDispatchContext::classified_with_route_id(
                Some("greenpm-legacy"),
                None,
                Some("/api/exponential"),
                None,
            );
            assert!(!allows(method, path, Some(&principal), wrong_route));
            assert!(!allows(method, path, Some(&bearer), owned));
            assert!(!allows(method, path, Some(&other_provider), owned));
        }
        for (method, path) in [
            ("GET", "/api/greenpm-owned/tasks/fixture-task/assignee"),
            ("GET", "/api/greenpm-owned/tasks/fixture-task/move"),
            ("DELETE", "/api/greenpm-owned/tasks/fixture-task/move"),
            ("PATCH", "/api/greenpm-owned/tasks/fixture-task/move/extra"),
            ("DELETE", "/api/greenpm-owned/tasks/fixture-task/assignee"),
            ("POST", "/api/greenpm-owned/my-tasks"),
            ("PATCH", "/api/greenpm-owned/tasks/fixture-task"),
            (
                "PATCH",
                "/api/greenpm-owned/tasks/fixture-task/assignee/extra",
            ),
            ("GET", "/api/greenpm-owned/my-tasks/other-user"),
        ] {
            assert!(
                !allows(method, path, Some(&principal), owned),
                "{method} {path}"
            );
        }
    }

    #[async_trait::async_trait]
    impl SessionValidator for Validator {
        async fn validate_session(
            &self,
            credential: &SessionCredential,
        ) -> Result<Principal, AuthError> {
            let (value, auth_method) = match credential {
                SessionCredential::Cookie(value) => (value, AuthMethod::Cookie),
                SessionCredential::Bearer(value) => (value, AuthMethod::Bearer),
                SessionCredential::ClientCertificate(_) => {
                    return Err(AuthError::InvalidSession("unsupported".into()))
                }
            };
            match value.as_str() {
                "revoked" => return Err(AuthError::InvalidSession("revoked".into())),
                "unavailable" => return Err(AuthError::Upstream("unavailable".into())),
                _ => {}
            }
            Ok(Principal {
                user_id: value.clone(),
                issuer: Some("fixture".into()),
                email: None,
                org_id: None,
                roles: vec!["member".into()],
                session_id: "independent-id".into(),
                auth_method,
            })
        }
        fn supports_cookie(&self) -> bool {
            true
        }
        fn supports_bearer(&self) -> bool {
            true
        }
    }

    async fn forward(request: Request<Body>) -> Response {
        forward_with_csrf_name(request, "csrf_token").await
    }

    async fn legacy_forward(request: Request<Body>) -> Response {
        forward_with_csrf_name(request, "gh_api_csrf").await
    }

    async fn forward_with_csrf_name(request: Request<Body>, upstream_name: &str) -> Response {
        let (parts, _) = request.into_parts();
        let policy = CookieSessionPolicy {
            session_cookie_name: "session".into(),
            csrf_cookie_name: "csrf_token".into(),
            upstream_csrf_cookie_name: upstream_name.into(),
            csrf_header_name: "x-csrf-token".into(),
        };
        match delegated_cookie(&parts, &policy) {
            Ok(cookie) => {
                let mut headers = super::super::forward::attempt_headers(
                    &parts.headers,
                    "203.0.113.7",
                    &super::super::RouteRequestHeaderPolicy::default(),
                    &[],
                );
                inject(&mut headers, &cookie);
                assert!(!headers.contains_key("authorization"));
                assert!(!headers.contains_key("x-user-id"));
                assert!(!headers.contains_key("x-greenhat-user"));
                assert!(headers[header::COOKIE].is_sensitive());
                headers[header::COOKIE]
                    .to_str()
                    .unwrap()
                    .to_owned()
                    .into_response()
            }
            Err(reason) => super::super::forward::cookie_session_rejected(reason),
        }
    }

    fn router() -> Router {
        let state = AuthState {
            validator: Some(Arc::new(Validator)),
            admin_sessions: None,
            mode: AuthMode::Required,
            cookie_name: "session".into(),
            exempt_paths: vec![],
            audit: AuditLog::new(Arc::new(CaptureSink::new())),
            principal_directory: PrincipalDirectory::disabled(),
            client_ip_policy: ClientIpPolicy::default(),
            mcp_route_paths: vec![],
            mcp_resource: None,
            mcp_resource_metadata_url: None,
        };
        Router::new()
            .route("/api/project", any(forward))
            .route("/api/legacy", any(legacy_forward))
            .layer(from_fn_with_state(state, auth_middleware))
    }

    #[tokio::test]
    async fn authenticated_cookie_delegation_keeps_two_users_separate_and_only_forwards_allowlisted_cookies(
    ) {
        for user in ["alice", "bob%2Fencoded"] {
            let request = Request::builder()
                .method(Method::PATCH)
                .uri("/api/project")
                .header(
                    header::COOKIE,
                    format!("session={user}; csrf_token=csrf-fixture; unrelated=discard"),
                )
                .header("x-csrf-token", "csrf-fixture")
                .header("x-user-id", "spoofed")
                .header("x-greenhat-user", "spoofed")
                .body(Body::empty())
                .unwrap();
            let response = router().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                to_bytes(response.into_body(), 4096).await.unwrap(),
                format!("session={user}; csrf_token=csrf-fixture")
            );
        }
    }

    #[tokio::test]
    async fn authenticated_cookie_delegation_rejects_missing_revoked_mixed_ambiguous_and_unsafe_requests(
    ) {
        let cases = [
            ("GET", None, None, None, StatusCode::UNAUTHORIZED),
            (
                "GET",
                Some("session=revoked"),
                None,
                None,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "GET",
                Some("session=unavailable"),
                None,
                None,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                "GET",
                Some("session=alice"),
                Some("Bearer agent"),
                None,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "GET",
                Some("session=alice; session =alice"),
                None,
                None,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "GET",
                Some("session=alice; __Secure-session=alice"),
                None,
                None,
                StatusCode::UNAUTHORIZED,
            ),
            (
                "PATCH",
                Some("session=alice"),
                None,
                None,
                StatusCode::FORBIDDEN,
            ),
            (
                "PATCH",
                Some("session=alice; csrf_token=csrf-fixture"),
                None,
                Some("wrong"),
                StatusCode::FORBIDDEN,
            ),
            (
                "PATCH",
                Some("session=alice; csrf_token=csrf-fixture; csrf_token =csrf-fixture"),
                None,
                Some("csrf-fixture"),
                StatusCode::FORBIDDEN,
            ),
            (
                "TRACE",
                Some("session=alice"),
                None,
                None,
                StatusCode::METHOD_NOT_ALLOWED,
            ),
        ];
        for (method, cookie, bearer, csrf, expected) in cases {
            let mut builder = Request::builder().method(method).uri("/api/project");
            if let Some(cookie) = cookie {
                builder = builder.header(header::COOKIE, cookie);
            }
            if let Some(bearer) = bearer {
                builder = builder.header(header::AUTHORIZATION, bearer);
            }
            if let Some(csrf) = csrf {
                builder = builder.header("x-csrf-token", csrf);
            }
            let response = router()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                expected,
                "method={method} expected={expected}"
            );
        }
    }

    #[tokio::test]
    async fn authenticated_cookie_delegation_bootstrap_get_needs_no_csrf_but_duplicate_headers_fail_closed(
    ) {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/api/project")
                    .header(header::COOKIE, "session=alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 4096).await.unwrap(),
            "session=alice"
        );
        let response = router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/project")
                    .header(header::COOKIE, "session=alice; csrf_token=csrf-fixture")
                    .header("x-csrf-token", "csrf-fixture")
                    .header("x-csrf-token", "csrf-fixture")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    #[tokio::test]
    async fn upstream_csrf_translation_validates_canonical_pair_and_never_trusts_legacy_cookie() {
        for method in [Method::PATCH, Method::POST, Method::DELETE] {
            let request = Request::builder()
                .method(method)
                .uri("/api/legacy")
                .header(
                    header::COOKIE,
                    "session=alice; csrf_token=canonical-fixture; gh_api_csrf=untrusted-fixture",
                )
                .header("x-csrf-token", "canonical-fixture")
                .body(Body::empty())
                .unwrap();
            let response = router().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                to_bytes(response.into_body(), 4096).await.unwrap(),
                "session=alice; gh_api_csrf=canonical-fixture"
            );
        }
        for (cookies, token) in [
            (
                "session=alice; gh_api_csrf=legacy-fixture",
                "legacy-fixture",
            ),
            (
                "session=alice; csrf_token=canonical-fixture; gh_api_csrf=legacy-fixture",
                "legacy-fixture",
            ),
            ("session=alice; csrf_token=one; csrf_token=two", "one"),
        ] {
            let response = router()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/legacy")
                        .header(header::COOKIE, cookies)
                        .header("x-csrf-token", token)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/api/legacy")
                    .header(header::COOKIE, "session=alice")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 4096).await.unwrap(),
            "session=alice"
        );
    }
}
