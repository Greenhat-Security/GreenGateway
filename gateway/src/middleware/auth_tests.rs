use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body},
    middleware::from_fn_with_state,
    routing::{any, get},
    Extension, Router,
};
use http::{
    header::{AUTHORIZATION, WWW_AUTHENTICATE},
    Method,
};
use serde_json::Value;
use tower::ServiceExt;

use super::*;
use crate::{
    audit::{sink::tests::CaptureSink, AuditSink},
    auth::AuthMethod,
};

#[derive(Clone)]
struct MockValidator {
    outcome: MockOutcome,
    supports_cookie: bool,
    supports_bearer: bool,
}

#[derive(Clone)]
enum MockOutcome {
    Principal(Principal),
    InvalidSession(&'static str),
    Upstream(&'static str),
}

#[async_trait::async_trait]
impl SessionValidator for MockValidator {
    async fn validate_session(
        &self,
        _credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        match &self.outcome {
            MockOutcome::Principal(principal) => Ok(principal.clone()),
            MockOutcome::InvalidSession(reason) => {
                Err(AuthError::InvalidSession((*reason).to_owned()))
            }
            MockOutcome::Upstream(reason) => Err(AuthError::Upstream((*reason).to_owned())),
        }
    }

    fn supports_cookie(&self) -> bool {
        self.supports_cookie
    }

    fn supports_bearer(&self) -> bool {
        self.supports_bearer
    }
}

fn test_router(state: AuthState) -> Router {
    async fn ok() -> &'static str {
        "ok"
    }

    async fn principal(Extension(principal): Extension<Principal>) -> Json<Value> {
        Json(json!({ "user_id": principal.user_id }))
    }

    Router::new()
        .route("/health", get(ok))
        .route("/version", get(ok))
        .route("/metrics", get(ok))
        .route("/admin", get(ok))
        .route("/admin/assets/app.js", get(ok))
        .route("/admin/mcp", any(ok))
        .route("/admin/mcp/assets", any(ok))
        .route("/administrator", get(ok))
        .route("/admin-panel", get(ok))
        .route("/protected", get(principal).options(ok))
        .layer(from_fn_with_state(state, auth_middleware))
}

fn test_state(validator: Option<Arc<dyn SessionValidator>>) -> (AuthState, CaptureSink) {
    test_state_with_mode(AuthMode::Required, validator)
}

fn test_state_with_mode(
    mode: AuthMode,
    validator: Option<Arc<dyn SessionValidator>>,
) -> (AuthState, CaptureSink) {
    test_state_with_mode_and_mcp_route_paths(
        mode,
        validator,
        &[protected_resource::MCP_RESOURCE_PATH],
    )
}

fn test_state_with_mcp_route_paths(
    validator: Option<Arc<dyn SessionValidator>>,
    mcp_route_paths: &[&str],
) -> (AuthState, CaptureSink) {
    test_state_with_mode_and_mcp_route_paths(AuthMode::Required, validator, mcp_route_paths)
}

fn test_state_with_mode_and_mcp_route_paths(
    mode: AuthMode,
    validator: Option<Arc<dyn SessionValidator>>,
    mcp_route_paths: &[&str],
) -> (AuthState, CaptureSink) {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);

    (
        AuthState {
            validator,
            mode,
            cookie_name: "session".to_owned(),
            exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ],
            audit,
            principal_directory: PrincipalDirectory::disabled(),
            client_ip_policy: ClientIpPolicy::default(),
            mcp_route_paths: mcp_route_paths
                .iter()
                .map(|path| (*path).to_owned())
                .collect(),
            mcp_resource: None,
            mcp_resource_metadata_url: None,
        },
        capture,
    )
}

fn validator(outcome: MockOutcome) -> Arc<dyn SessionValidator> {
    Arc::new(MockValidator {
        outcome,
        supports_cookie: true,
        supports_bearer: true,
    })
}

fn validator_without_bearer() -> Arc<dyn SessionValidator> {
    Arc::new(MockValidator {
        outcome: MockOutcome::Principal(test_principal()),
        supports_cookie: true,
        supports_bearer: false,
    })
}

fn test_principal() -> Principal {
    Principal {
        user_id: "user-123".to_owned(),
        issuer: None,
        email: Some("user@example.com".to_owned()),
        org_id: Some("org-456".to_owned()),
        roles: vec!["member".to_owned()],
        session_id: "session-789".to_owned(),
        auth_method: AuthMethod::Bearer,
    }
}

#[tokio::test]
async fn exempt_path_returns_ok_without_credential_and_emits_no_auth_event() {
    let (state, capture) = test_state(None);

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(capture.events().is_empty());
}

#[tokio::test]
async fn default_probe_exempt_paths_return_ok_without_credential() {
    let (state, capture) = test_state(None);
    let router = test_router(state);

    for path in ["/health", "/version", "/metrics"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    assert!(capture.events().is_empty());
}

#[tokio::test]
async fn admin_exempt_path_matches_subpaths_but_not_lookalikes() {
    let (state, capture) = test_state(None);
    let router = test_router(state);

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/assets/app.js")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(capture.events().is_empty());

    for path in ["/administrator", "/admin-panel"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn mcp_alias_under_exempt_prefix_requires_authentication() {
    let (state, capture) = test_state_with_mcp_route_paths(None, &["/mcp", "/admin/mcp"]);

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/admin/mcp")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("MCP alias request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("missing_credential"));
    assert_eq!(event.payload["path"], json!("/admin/mcp"));
}

#[tokio::test]
async fn mcp_alias_under_exempt_prefix_rejects_junk_bearer() {
    let (state, capture) = test_state_with_mcp_route_paths(
        Some(validator(MockOutcome::InvalidSession("invalid bearer"))),
        &["/mcp", "/admin/mcp"],
    );

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/admin/mcp")
                .header(AUTHORIZATION, "Bearer junk")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("MCP alias request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("invalid bearer"));
    assert_eq!(event.payload["path"], json!("/admin/mcp"));
}

#[tokio::test]
async fn mcp_alias_non_mcp_subpath_stays_exempt() {
    let (state, capture) = test_state_with_mcp_route_paths(None, &["/mcp", "/admin/mcp"]);

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/admin/mcp/assets")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("non-MCP subpath request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(capture.events().is_empty());
}

#[tokio::test]
async fn bare_options_to_non_exempt_path_requires_authentication() {
    let (state, capture) = test_state(None);

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/protected")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static("Bearer"))
    );
    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("missing_credential"));
    assert_eq!(event.payload["path"], json!("/protected"));
}

#[tokio::test]
async fn missing_credential_returns_unauthorized_and_emits_failure() {
    let (state, capture) = test_state(Some(validator(MockOutcome::Principal(test_principal()))));

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static("Bearer"))
    );
    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("missing_credential"));
    assert_eq!(event.payload["path"], json!("/protected"));
    assert!(event.actor.is_none());
}

#[tokio::test]
async fn explicit_required_mode_blocks_missing_credential_like_default() {
    let (state, capture) = test_state_with_mode(
        AuthMode::Required,
        Some(validator(MockOutcome::Principal(test_principal()))),
    );

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/administrator")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static("Bearer"))
    );
    assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);

    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("missing_credential"));
}

#[tokio::test]
async fn observe_mode_missing_credential_forwards_and_tags_failure() {
    let (state, capture) = test_state_with_mode(
        AuthMode::Observe,
        Some(validator(MockOutcome::Principal(test_principal()))),
    );

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/administrator")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    let outcome = response
        .extensions()
        .get::<AuthOutcome>()
        .cloned()
        .expect("response should carry auth outcome");
    assert!(!outcome.authenticated);
    assert!(outcome.principal.is_none());
    assert_eq!(outcome.reason.as_deref(), Some("missing_credential"));
    assert_eq!(body_string(response).await, "ok");

    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("missing_credential"));
    assert_eq!(event.payload["path"], json!("/administrator"));
    assert!(event.actor.is_none());
}

#[tokio::test]
async fn valid_bearer_credential_injects_principal_and_emits_success() {
    let (state, capture) = test_state(Some(validator(MockOutcome::Principal(test_principal()))));

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_json(response).await;
    assert_eq!(body, json!({ "user_id": "user-123" }));

    let event = captured_event(&capture, AUTH_SUCCESS).await;
    assert!(event.actor.is_some());
    assert_eq!(event.payload["auth_mode"], json!("bearer_token"));
    assert_eq!(event.payload["user_id"], json!("user-123"));
}

#[tokio::test]
async fn observe_mode_valid_bearer_credential_injects_principal_and_emits_success() {
    let (state, capture) = test_state_with_mode(
        AuthMode::Observe,
        Some(validator(MockOutcome::Principal(test_principal()))),
    );

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let outcome = response
        .extensions()
        .get::<AuthOutcome>()
        .cloned()
        .expect("response should carry auth outcome");
    assert!(outcome.authenticated);
    assert_eq!(
        outcome
            .principal
            .as_ref()
            .map(|principal| principal.user_id.as_str()),
        Some("user-123")
    );
    assert!(outcome.reason.is_none());
    let body = to_json(response).await;
    assert_eq!(body, json!({ "user_id": "user-123" }));

    let event = captured_event(&capture, AUTH_SUCCESS).await;
    assert!(event.actor.is_some());
    assert_eq!(event.payload["auth_mode"], json!("bearer_token"));
    assert_eq!(event.payload["user_id"], json!("user-123"));
}

#[tokio::test]
async fn invalid_credential_returns_unauthorized_without_leaking_internal_reason() {
    let (state, capture) = test_state(Some(validator(MockOutcome::InvalidSession(
        "expired refresh window",
    ))));

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_string(response).await;
    assert_eq!(body, r#"{"error":"unauthorized"}"#);
    assert!(!body.contains("expired refresh window"));

    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("expired refresh window"));
}

#[tokio::test]
async fn observe_mode_invalid_credential_forwards_without_leaking_internal_reason() {
    let (state, capture) = test_state_with_mode(
        AuthMode::Observe,
        Some(validator(MockOutcome::InvalidSession(
            "expired refresh window",
        ))),
    );

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/administrator")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    let outcome = response
        .extensions()
        .get::<AuthOutcome>()
        .cloned()
        .expect("response should carry auth outcome");
    assert!(!outcome.authenticated);
    assert!(outcome.principal.is_none());
    assert_eq!(outcome.reason.as_deref(), Some("expired refresh window"));
    let body = body_string(response).await;
    assert_eq!(body, "ok");
    assert!(!body.contains("expired refresh window"));

    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("expired refresh window"));
}

#[tokio::test]
async fn unsupported_credential_type_fails_closed_and_emits_reason() {
    let (state, capture) = test_state(Some(validator_without_bearer()));

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("bearer_auth_unsupported"));
}

#[tokio::test]
async fn missing_validator_with_auth_enabled_fails_closed_and_emits_reason() {
    let (state, capture) = test_state(None);

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(event.payload["reason"], json!("no_validator_configured"));
}

#[tokio::test]
async fn upstream_validator_error_is_prefixed_in_audit_event() {
    let (state, capture) = test_state(Some(validator(MockOutcome::Upstream("jwks fetch failed"))));

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let event = captured_event(&capture, AUTH_FAILURE).await;
    assert_eq!(
        event.payload["reason"],
        json!("upstream_error: jwks fetch failed")
    );
}

#[tokio::test]
async fn unverifiable_credential_answers_service_unavailable_without_a_challenge() {
    let (state, _capture) = test_state(Some(validator(MockOutcome::Upstream("jwks fetch failed"))));

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    // The credential was never judged, so nothing tells the caller to
    // discard it and re-mint against the provider that is already failing.
    assert!(response.headers().get(WWW_AUTHENTICATE).is_none());
    assert_eq!(
        response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    assert_eq!(
        body_string(response).await,
        json!({ "error": "service unavailable" }).to_string()
    );
}

#[tokio::test]
async fn unverifiable_and_rejected_credentials_are_told_apart_only_by_failure_class() {
    // The 503 branch is selected by the validator's failure class alone. A
    // credential the gateway judged and refused still gets the permanent
    // answer, so the split never becomes an oracle for whether a particular
    // credential exists or is well formed.
    for (outcome, expected_status) in [
        (
            MockOutcome::InvalidSession("expired"),
            StatusCode::UNAUTHORIZED,
        ),
        (
            MockOutcome::Upstream("introspection timed out"),
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        for token in ["Bearer well-formed-token", "Bearer ~~~"] {
            let (state, _capture) = test_state(Some(validator(outcome.clone())));
            let response = test_router(state)
                .oneshot(
                    Request::builder()
                        .uri("/protected")
                        .header(AUTHORIZATION, token)
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("request should complete");

            assert_eq!(response.status(), expected_status, "{token}");
        }
    }
}

#[tokio::test]
async fn unverifiable_credential_is_forwarded_in_observe_mode() {
    let (state, _capture) = test_state_with_mode(
        AuthMode::Observe,
        Some(validator(MockOutcome::Upstream("jwks fetch failed"))),
    );

    let response = test_router(state)
        .oneshot(
            Request::builder()
                .uri("/administrator")
                .header(AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

async fn captured_event(capture: &CaptureSink, event_type: &str) -> AuditEvent {
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == event_type)
    });

    capture
        .events()
        .into_iter()
        .find(|event| event.event_type == event_type)
        .expect("event should be captured")
}

fn assert_eventually(timeout: Duration, condition: impl Fn() -> bool) {
    let started = Instant::now();

    while started.elapsed() < timeout {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(
        condition(),
        "condition did not become true within {timeout:?}"
    );
}

async fn to_json(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
        .expect("body should be JSON")
}

async fn body_string(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .expect("body should be UTF-8")
}
