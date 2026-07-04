//! Per-request observation audit event middleware.

use std::time::{Duration, Instant};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use serde_json::{json, Map, Value};

use crate::{
    audit::{AuditEvent, AuditLog},
    auth::actor_from_principal,
    client_ip::{canonical_client_ip, request_id},
    config::Config,
};

use super::decision::{AuthOutcome, PolicyDecision, PolicyDecisionOutcome, UpstreamOutcome};

const HTTP_REQUEST_OBSERVED: &str = "http.request_observed";

#[derive(Clone)]
pub struct ObservationState {
    pub audit: AuditLog,
    pub trust_proxy_headers: bool,
}

impl ObservationState {
    pub fn from_config(config: &Config, audit: AuditLog) -> Self {
        Self {
            audit,
            trust_proxy_headers: config.trust_proxy_headers,
        }
    }
}

pub async fn observation_middleware(
    State(state): State<ObservationState>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let request_id = request_id(req.headers(), req.extensions());
    let source_ip = canonical_client_ip(req.headers(), req.extensions(), state.trust_proxy_headers);

    let response = next.run(req).await;
    let status = response.status().as_u16();
    let latency_ms = duration_millis(start.elapsed());
    let auth_outcome = response.extensions().get::<AuthOutcome>();
    let policy_decision = response.extensions().get::<PolicyDecision>();
    let upstream_outcome = response.extensions().get::<UpstreamOutcome>();
    let actor = auth_outcome
        .and_then(|outcome| outcome.principal.as_ref())
        .map(actor_from_principal);

    state.audit.emit(AuditEvent::new(
        HTTP_REQUEST_OBSERVED,
        &request_id,
        &source_ip,
        actor,
        observation_payload(
            &method,
            &path,
            status,
            latency_ms,
            auth_outcome,
            policy_decision,
            upstream_outcome,
        ),
    ));

    response
}

fn observation_payload(
    method: &str,
    path: &str,
    status: u16,
    latency_ms: u64,
    auth_outcome: Option<&AuthOutcome>,
    policy_decision: Option<&PolicyDecision>,
    upstream_outcome: Option<&UpstreamOutcome>,
) -> Value {
    let mut payload = Map::new();
    payload.insert("method".to_owned(), json!(method));
    payload.insert("path".to_owned(), json!(path));
    payload.insert("status".to_owned(), json!(status));
    payload.insert("latency_ms".to_owned(), json!(latency_ms));
    payload.insert(
        "auth_outcome".to_owned(),
        json!(auth_outcome_label(auth_outcome)),
    );

    if let Some(outcome) = auth_outcome {
        if !outcome.authenticated {
            if let Some(reason) = outcome.reason.as_deref() {
                payload.insert("auth_reason".to_owned(), json!(reason));
            }
        }
    }

    payload.insert(
        "policy_decision".to_owned(),
        json!(policy_decision_label(policy_decision)),
    );

    if let Some(decision) = policy_decision {
        payload.insert("policy_reason".to_owned(), json!(decision.reason));

        if let Some(permission) = decision.permission.as_deref() {
            payload.insert("permission".to_owned(), json!(permission));
        }

        if let Some(path_prefix) = decision.path_prefix.as_deref() {
            payload.insert("path_prefix".to_owned(), json!(path_prefix));
        }

        if let Some(matched_rule_id) = decision.matched_rule_id.as_deref() {
            payload.insert("matched_rule_id".to_owned(), json!(matched_rule_id));
        }
    }

    if let Some(outcome) = upstream_outcome {
        payload.insert("upstream_latency_ms".to_owned(), json!(outcome.latency_ms));

        if let Some(status) = outcome.status {
            payload.insert("upstream_status".to_owned(), json!(status));
        }
    }

    Value::Object(payload)
}

fn auth_outcome_label(auth_outcome: Option<&AuthOutcome>) -> &'static str {
    match auth_outcome {
        Some(outcome) if outcome.authenticated => "authenticated",
        Some(_) => "anonymous_or_failed",
        None => "not_evaluated",
    }
}

fn policy_decision_label(policy_decision: Option<&PolicyDecision>) -> &'static str {
    match policy_decision {
        Some(decision) => match decision.outcome {
            PolicyDecisionOutcome::Allowed => "allowed",
            PolicyDecisionOutcome::Denied => "denied",
            PolicyDecisionOutcome::WouldDeny => "would_deny",
        },
        None => "not_evaluated",
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::Arc,
        time::{Duration, Instant},
    };

    use axum::{
        body::Body,
        middleware::{from_fn, from_fn_with_state},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use http::{header::AUTHORIZATION, Method, Request, StatusCode};
    use serde_json::json;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        audit::{sink::tests::CaptureSink, AuditSink},
        auth::{AuthError, AuthMethod, Principal, SessionCredential, SessionValidator},
        middleware::{auth, rbac},
        rbac::{
            policy::{EgressPolicy, RoleEntry},
            DefaultAction, EnforcementMode, Policy, PrincipalMatcher, RouteRule, Rule, RuleAction,
        },
    };

    #[derive(Clone)]
    enum FakeAuthLayer {
        Success(Principal),
        Failure(&'static str),
    }

    #[derive(Clone)]
    enum FakePolicyLayer {
        Allowed,
        Denied,
        WouldDeny,
    }

    #[derive(Clone)]
    struct MockValidator {
        outcome: Result<Principal, &'static str>,
    }

    #[async_trait::async_trait]
    impl SessionValidator for MockValidator {
        async fn validate_session(
            &self,
            _credential: &SessionCredential,
        ) -> Result<Principal, AuthError> {
            self.outcome
                .clone()
                .map_err(|reason| AuthError::InvalidSession(reason.to_owned()))
        }
    }

    #[tokio::test]
    async fn observation_only_emits_not_evaluated_event() {
        let (state, capture) = test_observation_state();

        let response = observation_router(state)
            .oneshot(request(Method::GET, "/", "request-observed-only"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(capture.events().len(), 1);
        assert_eq!(event.request_id, "request-observed-only");
        assert_eq!(event.payload["method"], json!("GET"));
        assert_eq!(event.payload["path"], json!("/"));
        assert_eq!(event.payload["status"], json!(200));
        assert!(event.payload["latency_ms"].as_u64().is_some());
        assert_eq!(event.payload["auth_outcome"], json!("not_evaluated"));
        assert_eq!(event.payload["policy_decision"], json!("not_evaluated"));
        assert!(event.actor.is_none());
    }

    #[tokio::test]
    async fn observed_authenticated_marker_populates_actor() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakeAuthLayer::Success(test_principal(&["reader"])),
                fake_auth_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-authenticated"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(
            event.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    #[tokio::test]
    async fn observed_upstream_marker_is_reported() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn(fake_upstream_layer))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-upstream"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["upstream_latency_ms"], json!(42));
        assert_eq!(event.payload["upstream_status"], json!(201));
    }

    #[tokio::test]
    async fn observed_failed_auth_marker_still_emits_rejection_event() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakeAuthLayer::Failure("missing_credential"),
                fake_auth_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-auth-failed"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["status"], json!(401));
        assert_eq!(event.payload["auth_outcome"], json!("anonymous_or_failed"));
        assert_eq!(event.payload["auth_reason"], json!("missing_credential"));
        assert!(event.actor.is_none());
    }

    #[tokio::test]
    async fn observed_allowed_policy_marker_is_reported() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakePolicyLayer::Allowed,
                fake_policy_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-policy-allowed"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["policy_decision"], json!("allowed"));
        assert_eq!(event.payload["policy_reason"], json!("matched_rule"));
        assert_eq!(event.payload["permission"], json!("data:read"));
        assert!(event.payload.get("matched_rule_id").is_none());
    }

    #[tokio::test]
    async fn observed_denied_policy_marker_still_emits_rejection_event() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakePolicyLayer::Denied,
                fake_policy_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-policy-denied"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["status"], json!(403));
        assert_eq!(event.payload["policy_decision"], json!("denied"));
        assert_eq!(event.payload["policy_reason"], json!("missing_permission"));
        assert_eq!(event.payload["permission"], json!("data:read"));
        assert!(event.payload.get("matched_rule_id").is_none());
    }

    #[tokio::test]
    async fn observed_would_deny_policy_marker_is_distinct_from_allowed() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakePolicyLayer::WouldDeny,
                fake_policy_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-policy-would-deny"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["status"], json!(200));
        assert_eq!(event.payload["policy_decision"], json!("would_deny"));
        assert_eq!(event.payload["policy_reason"], json!("missing_permission"));
        assert_eq!(event.payload["permission"], json!("data:read"));
        assert_eq!(event.payload["path_prefix"], json!("/data"));
        assert!(event.payload.get("matched_rule_id").is_none());
    }

    #[tokio::test]
    async fn observation_correlates_with_real_auth_and_rbac_allowed_events() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy(
                DefaultAction::Deny,
                &[("reader", &["data:read"])],
                &[route(&["GET"], "/data", "data:read")],
            ),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data/items")
                    .header(crate::REQUEST_ID_HEADER, "request-real-allowed")
                    .header(AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 3);
        let events = capture.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == HTTP_REQUEST_OBSERVED)
                .count(),
            1
        );
        for event_type in ["auth.success", "authz.allowed", HTTP_REQUEST_OBSERVED] {
            let event = events
                .iter()
                .find(|event| event.event_type == event_type)
                .expect("expected event should be captured");
            assert_eq!(event.request_id, "request-real-allowed");
        }

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(observed.payload["policy_decision"], json!("allowed"));
        assert_eq!(observed.payload["permission"], json!("data:read"));
        assert!(observed.payload.get("matched_rule_id").is_none());
        assert_eq!(
            observed.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    #[tokio::test]
    async fn observation_correlates_with_real_direct_rule_decision() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy_with_rules(
                DefaultAction::Deny,
                &[("reader", &["data:read"])],
                &[],
                &[direct_rule(
                    Some("allow-data-item"),
                    &["GET"],
                    "/data/items",
                    RuleAction::Allow,
                )],
            ),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data/items")
                    .header(crate::REQUEST_ID_HEADER, "request-real-direct-rule")
                    .header(AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 3);
        let events = capture.events();
        let authz = events
            .iter()
            .find(|event| event.event_type == "authz.allowed")
            .expect("authz allowed event should be captured");
        assert_eq!(authz.payload["matched_rule_id"], json!("allow-data-item"));
        assert!(authz.payload.get("permission").is_none());
        assert!(authz.payload.get("path_prefix").is_none());

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(observed.payload["policy_decision"], json!("allowed"));
        assert_eq!(observed.payload["policy_reason"], json!("matched_rule"));
        assert_eq!(
            observed.payload["matched_rule_id"],
            json!("allow-data-item")
        );
        assert!(observed.payload.get("permission").is_none());
        assert!(observed.payload.get("path_prefix").is_none());
    }

    #[tokio::test]
    async fn observation_correlates_with_real_default_allow_decision() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy(DefaultAction::Allow, &[], &[]),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data/items")
                    .header(crate::REQUEST_ID_HEADER, "request-real-default-allow")
                    .header(AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 3);
        let events = capture.events();
        let authz = events
            .iter()
            .find(|event| event.event_type == "authz.allowed")
            .expect("authz allowed event should be captured");
        assert_eq!(authz.payload["reason"], json!("default_allow"));
        assert_eq!(authz.request_id, "request-real-default-allow");

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(observed.payload["policy_decision"], json!("allowed"));
        assert_eq!(observed.payload["policy_reason"], json!("default_allow"));
        assert!(observed.payload.get("permission").is_none());
        assert!(observed.payload.get("matched_rule_id").is_none());
        assert_eq!(
            observed.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    #[tokio::test]
    async fn observation_correlates_with_real_shadow_would_deny_decision() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy_with_enforcement(
                DefaultAction::Deny,
                EnforcementMode::Shadow,
                &[("reader", &["data:read"])],
                &[route(&["GET"], "/data", "admin:read")],
            ),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data/items")
                    .header(crate::REQUEST_ID_HEADER, "request-real-shadow-would-deny")
                    .header(AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 3);
        let events = capture.events();
        for event_type in ["auth.success", "authz.would_deny", HTTP_REQUEST_OBSERVED] {
            let event = events
                .iter()
                .find(|event| event.event_type == event_type)
                .expect("expected event should be captured");
            assert_eq!(event.request_id, "request-real-shadow-would-deny");
        }

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(observed.payload["policy_decision"], json!("would_deny"));
        assert_eq!(
            observed.payload["policy_reason"],
            json!("missing_permission")
        );
        assert_eq!(observed.payload["permission"], json!("admin:read"));
        assert_eq!(observed.payload["path_prefix"], json!("/data"));
        assert!(observed.payload.get("matched_rule_id").is_none());
        assert_eq!(
            observed.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    #[tokio::test]
    async fn observation_correlates_with_real_auth_failure_event() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy(
                DefaultAction::Deny,
                &[("reader", &["data:read"])],
                &[route(&["GET"], "/data", "data:read")],
            ),
        );

        let response = router
            .oneshot(request(Method::GET, "/data/items", "request-real-denied"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 2);
        let events = capture.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == HTTP_REQUEST_OBSERVED)
                .count(),
            1
        );
        for event_type in ["auth.failure", HTTP_REQUEST_OBSERVED] {
            let event = events
                .iter()
                .find(|event| event.event_type == event_type)
                .expect("expected event should be captured");
            assert_eq!(event.request_id, "request-real-denied");
        }

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["status"], json!(401));
        assert_eq!(
            observed.payload["auth_outcome"],
            json!("anonymous_or_failed")
        );
        assert_eq!(observed.payload["auth_reason"], json!("missing_credential"));
        assert_eq!(observed.payload["policy_decision"], json!("not_evaluated"));
        assert!(observed.actor.is_none());
    }

    fn observation_router(state: ObservationState) -> Router {
        base_router().layer(from_fn_with_state(state, observation_middleware))
    }

    fn base_router() -> Router {
        async fn ok() -> &'static str {
            "ok"
        }

        Router::new().route("/", get(ok))
    }

    async fn fake_auth_layer(
        State(outcome): State<FakeAuthLayer>,
        req: Request<Body>,
        next: Next,
    ) -> Response {
        match outcome {
            FakeAuthLayer::Success(principal) => {
                let mut response = next.run(req).await;
                response.extensions_mut().insert(AuthOutcome {
                    principal: Some(principal),
                    authenticated: true,
                    reason: None,
                });
                response
            }
            FakeAuthLayer::Failure(reason) => {
                let mut response = StatusCode::UNAUTHORIZED.into_response();
                response.extensions_mut().insert(AuthOutcome {
                    principal: None,
                    authenticated: false,
                    reason: Some(reason.to_owned()),
                });
                response
            }
        }
    }

    async fn fake_policy_layer(
        State(decision): State<FakePolicyLayer>,
        req: Request<Body>,
        next: Next,
    ) -> Response {
        match decision {
            FakePolicyLayer::Allowed => {
                let mut response = next.run(req).await;
                response.extensions_mut().insert(PolicyDecision {
                    outcome: PolicyDecisionOutcome::Allowed,
                    reason: "matched_rule",
                    permission: Some("data:read".to_owned()),
                    path_prefix: Some("/data".to_owned()),
                    matched_rule_id: None,
                });
                response
            }
            FakePolicyLayer::Denied => {
                let mut response = StatusCode::FORBIDDEN.into_response();
                response.extensions_mut().insert(PolicyDecision {
                    outcome: PolicyDecisionOutcome::Denied,
                    reason: "missing_permission",
                    permission: Some("data:read".to_owned()),
                    path_prefix: Some("/data".to_owned()),
                    matched_rule_id: None,
                });
                response
            }
            FakePolicyLayer::WouldDeny => {
                let mut response = next.run(req).await;
                response.extensions_mut().insert(PolicyDecision {
                    outcome: PolicyDecisionOutcome::WouldDeny,
                    reason: "missing_permission",
                    permission: Some("data:read".to_owned()),
                    path_prefix: Some("/data".to_owned()),
                    matched_rule_id: None,
                });
                response
            }
        }
    }

    async fn fake_upstream_layer(req: Request<Body>, next: Next) -> Response {
        let mut response = next.run(req).await;
        response
            .extensions_mut()
            .insert(crate::middleware::decision::UpstreamOutcome {
                latency_ms: 42,
                status: Some(201),
            });
        response
    }

    fn auth_rbac_observation_router(
        audit: AuditLog,
        validator: Arc<dyn SessionValidator>,
        policy: Policy,
    ) -> Router {
        async fn ok() -> &'static str {
            "ok"
        }

        Router::new()
            .route("/data/items", get(ok))
            .layer(from_fn_with_state(
                rbac::RbacState::new(policy, Vec::new(), false, audit.clone()),
                rbac::rbac_middleware,
            ))
            .layer(from_fn_with_state(
                auth::AuthState {
                    validator: Some(validator),
                    mode: crate::config::AuthMode::Required,
                    cookie_name: "session".to_owned(),
                    exempt_paths: Vec::new(),
                    audit: audit.clone(),
                    trust_proxy_headers: false,
                },
                auth::auth_middleware,
            ))
            .layer(from_fn_with_state(
                ObservationState {
                    audit,
                    trust_proxy_headers: false,
                },
                observation_middleware,
            ))
    }

    fn test_observation_state() -> (ObservationState, CaptureSink) {
        let (audit, capture) = test_audit_log();
        (
            ObservationState {
                audit,
                trust_proxy_headers: false,
            },
            capture,
        )
    }

    fn test_audit_log() -> (AuditLog, CaptureSink) {
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        (audit, capture)
    }

    fn validator(outcome: Result<Principal, &'static str>) -> Arc<dyn SessionValidator> {
        Arc::new(MockValidator { outcome })
    }

    fn test_policy(
        default_action: DefaultAction,
        roles: &[(&str, &[&str])],
        routes: &[RouteRule],
    ) -> Policy {
        test_policy_with_enforcement(default_action, EnforcementMode::Enforce, roles, routes)
    }

    fn test_policy_with_rules(
        default_action: DefaultAction,
        roles: &[(&str, &[&str])],
        routes: &[RouteRule],
        rules: &[Rule],
    ) -> Policy {
        let mut policy = test_policy(default_action, roles, routes);
        policy.rules = rules.to_vec();
        policy
    }

    fn test_policy_with_enforcement(
        default_action: DefaultAction,
        enforcement_mode: EnforcementMode,
        roles: &[(&str, &[&str])],
        routes: &[RouteRule],
    ) -> Policy {
        Policy {
            schema_version: "0.1.0".to_owned(),
            id: Some("test-policy".to_owned()),
            default_action,
            enforcement_mode,
            roles: roles
                .iter()
                .map(|(role, permissions)| {
                    (
                        (*role).to_owned(),
                        RoleEntry {
                            permissions: permissions
                                .iter()
                                .map(|permission| (*permission).to_owned())
                                .collect(),
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
            routes: routes.to_vec(),
            rules: Vec::new(),
            egress: EgressPolicy::default(),
            rate_limits: Vec::new(),
        }
    }

    fn route(methods: &[&str], path_prefix: &str, permission: &str) -> RouteRule {
        RouteRule {
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            path_prefix: path_prefix.to_owned(),
            permission: permission.to_owned(),
            enforcement_mode: None,
        }
    }

    fn direct_rule(id: Option<&str>, methods: &[&str], path: &str, action: RuleAction) -> Rule {
        Rule {
            id: id.map(str::to_owned),
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            path: path.to_owned(),
            principal: PrincipalMatcher::default(),
            action,
        }
    }

    fn test_principal(roles: &[&str]) -> Principal {
        Principal {
            user_id: "user-123".to_owned(),
            email: Some("user@example.test".to_owned()),
            org_id: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: "session-123".to_owned(),
            auth_method: AuthMethod::Bearer,
        }
    }

    async fn one_observation_event(capture: &CaptureSink) -> AuditEvent {
        assert_eventually(Duration::from_secs(1), || {
            capture
                .events()
                .iter()
                .filter(|event| event.event_type == HTTP_REQUEST_OBSERVED)
                .count()
                == 1
        });

        capture
            .events()
            .into_iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured")
    }

    fn request(method: Method, uri: &str, request_id: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(crate::REQUEST_ID_HEADER, request_id)
            .body(Body::empty())
            .expect("request should build")
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
}
