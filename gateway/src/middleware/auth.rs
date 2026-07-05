//! Global authentication middleware.
//!
//! This ports the issue #5 request-path auth scope and folds in the planned
//! auth audit events scope now that the audit pipeline is available.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{
    header::{COOKIE, USER_AGENT, WWW_AUTHENTICATE},
    HeaderMap, HeaderValue, StatusCode,
};
use serde::Serialize;
use serde_json::json;

use crate::{
    audit::{AuditEvent, AuditLog},
    auth::{
        actor_from_principal, AuthError, Principal, PrincipalDirectory, SessionCredential,
        SessionValidator,
    },
    client_ip::{canonical_client_ip, request_id},
    config::{AuthMode, Config},
    path_match::path_prefix_matches,
};

use super::{bearer::bearer_token, decision::AuthOutcome};

const AUTH_SUCCESS: &str = "auth.success";
const AUTH_FAILURE: &str = "auth.failure";

#[derive(Clone)]
pub struct AuthState {
    pub validator: Option<Arc<dyn SessionValidator>>,
    pub mode: AuthMode,
    pub cookie_name: String,
    pub exempt_paths: Vec<String>,
    pub audit: AuditLog,
    pub principal_directory: PrincipalDirectory,
    pub trust_proxy_headers: bool,
}

#[derive(Serialize)]
struct UnauthorizedBody {
    error: &'static str,
}

struct AuditContext {
    request_id: String,
    source_ip: String,
    user_agent: Option<String>,
    path: String,
}

impl AuthState {
    pub fn from_config(
        config: &Config,
        validator: Option<Arc<dyn SessionValidator>>,
        audit: AuditLog,
        principal_directory: PrincipalDirectory,
    ) -> Self {
        Self {
            validator,
            mode: config.auth_mode,
            cookie_name: config.auth_cookie_name.clone(),
            exempt_paths: config.auth_exempt_paths.clone(),
            audit,
            principal_directory,
            trust_proxy_headers: config.trust_proxy_headers,
        }
    }
}

pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_owned();
    if state
        .exempt_paths
        .iter()
        .any(|exempt_path| path_prefix_matches(&path, exempt_path))
    {
        return next.run(req).await;
    }

    let audit = audit_context(&req, path, state.trust_proxy_headers);
    let Some(credential) = extract_credential(req.headers(), &state.cookie_name) else {
        return auth_failure_response(&state, &audit, "missing_credential", req, next).await;
    };

    let Some(validator) = state.validator.as_ref().map(Arc::clone) else {
        return auth_failure_response(&state, &audit, "no_validator_configured", req, next).await;
    };

    match &credential {
        SessionCredential::Cookie(_) if !validator.supports_cookie() => {
            return auth_failure_response(&state, &audit, "cookie_auth_unsupported", req, next)
                .await;
        }
        SessionCredential::Bearer(_) if !validator.supports_bearer() => {
            return auth_failure_response(&state, &audit, "bearer_auth_unsupported", req, next)
                .await;
        }
        _ => {}
    }

    match validator.validate_session(&credential).await {
        Ok(principal) => {
            emit_success(&state, &audit, &credential, &principal);
            req.extensions_mut().insert(principal.clone());
            state.principal_directory.observe(&principal);
            let mut response = next.run(req).await;
            response.extensions_mut().insert(AuthOutcome {
                principal: Some(principal),
                authenticated: true,
                reason: None,
            });
            response
        }
        Err(AuthError::InvalidSession(reason)) => {
            auth_failure_response(&state, &audit, reason, req, next).await
        }
        Err(AuthError::Upstream(reason)) => {
            let reason = format!("upstream_error: {reason}");
            auth_failure_response(&state, &audit, reason, req, next).await
        }
    }
}

fn audit_context(req: &Request, path: String, trust_proxy_headers: bool) -> AuditContext {
    AuditContext {
        request_id: request_id(req.headers(), req.extensions()),
        source_ip: canonical_client_ip(req.headers(), req.extensions(), trust_proxy_headers),
        user_agent: header_to_trimmed_string(req.headers().get(USER_AGENT)),
        path,
    }
}

pub fn extract_credential(headers: &HeaderMap, cookie_name: &str) -> Option<SessionCredential> {
    bearer_token(headers)
        .map(|token| SessionCredential::Bearer(token.to_owned()))
        .or_else(|| {
            session_cookie(headers, cookie_name)
                .map(|cookie| SessionCredential::Cookie(cookie.to_owned()))
        })
}

fn session_cookie<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    if cookie_name.is_empty() {
        return None;
    }

    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(header_value_to_str)
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(name, value)| {
            let value = value.trim();
            (name.trim() == cookie_name && !value.is_empty()).then_some(value)
        })
}

fn emit_success(
    state: &AuthState,
    context: &AuditContext,
    credential: &SessionCredential,
    principal: &Principal,
) {
    state.audit.emit(with_optional_user_agent(
        AuditEvent::new(
            AUTH_SUCCESS,
            &context.request_id,
            &context.source_ip,
            Some(actor_from_principal(principal)),
            json!({
                "path": &context.path,
                "auth_mode": auth_mode(credential),
                "user_id": &principal.user_id,
            }),
        ),
        context.user_agent.as_deref(),
    ));
}

fn emit_failure(state: &AuthState, context: &AuditContext, reason: &str) {
    state.audit.emit(with_optional_user_agent(
        AuditEvent::new(
            AUTH_FAILURE,
            &context.request_id,
            &context.source_ip,
            None,
            json!({
                "path": &context.path,
                "reason": reason,
            }),
        ),
        context.user_agent.as_deref(),
    ));
}

async fn auth_failure_response(
    state: &AuthState,
    context: &AuditContext,
    reason: impl Into<String>,
    req: Request,
    next: Next,
) -> Response {
    let reason = reason.into();
    emit_failure(state, context, &reason);

    match state.mode {
        AuthMode::Required => unauthorized_with_auth_outcome(reason),
        AuthMode::Observe => forward_with_auth_outcome(req, next, reason).await,
    }
}

async fn forward_with_auth_outcome(req: Request, next: Next, reason: String) -> Response {
    let mut response = next.run(req).await;
    response.extensions_mut().insert(AuthOutcome {
        principal: None,
        authenticated: false,
        reason: Some(reason),
    });
    response
}

fn auth_mode(credential: &SessionCredential) -> &'static str {
    match credential {
        SessionCredential::Cookie(_) => "session_cookie",
        SessionCredential::Bearer(_) => "bearer_token",
    }
}

fn with_optional_user_agent(event: AuditEvent, user_agent: Option<&str>) -> AuditEvent {
    match user_agent {
        Some(user_agent) => event.with_user_agent(user_agent),
        None => event,
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Bearer")],
        Json(UnauthorizedBody {
            error: "unauthorized",
        }),
    )
        .into_response()
}

fn unauthorized_with_auth_outcome(reason: impl Into<String>) -> Response {
    let mut response = unauthorized();
    response.extensions_mut().insert(AuthOutcome {
        principal: None,
        authenticated: false,
        reason: Some(reason.into()),
    });
    response
}

fn header_to_trimmed_string(value: Option<&HeaderValue>) -> Option<String> {
    value
        .and_then(header_value_to_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn header_value_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use axum::{
        body::{to_bytes, Body},
        middleware::from_fn_with_state,
        routing::get,
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
                trust_proxy_headers: false,
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
        let (state, capture) =
            test_state(Some(validator(MockOutcome::Principal(test_principal()))));

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
        let (state, capture) =
            test_state(Some(validator(MockOutcome::Principal(test_principal()))));

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
        let (state, capture) =
            test_state(Some(validator(MockOutcome::Upstream("jwks fetch failed"))));

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
        assert_eq!(
            event.payload["reason"],
            json!("upstream_error: jwks fetch failed")
        );
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
}
