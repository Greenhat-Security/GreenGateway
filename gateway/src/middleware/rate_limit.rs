//! Token-bucket rate limiting middleware.

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
    time::Instant,
};

use arc_swap::ArcSwap;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{
    header::{HeaderValue, COOKIE},
    Extensions, HeaderMap, Method, StatusCode,
};
use serde::Serialize;

use crate::{
    auth,
    client_ip::canonical_client_ip,
    config::Config,
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
    rbac::{
        rule::{method_matches, path_pattern_matches},
        Policy, RateLimitRule,
    },
};

#[derive(Clone)]
pub struct RateLimitState {
    read: RateLimiter,
    write: RateLimiter,
    policy: Arc<ArcSwap<RateLimitPolicyState>>,
    trust_proxy_headers: bool,
    session_cookie_name: String,
}

#[derive(Clone)]
pub struct RateLimiter {
    // Known limitation: buckets are never evicted, so this HashMap can grow
    // one entry per unique key for the lifetime of the process. Future work
    // should add TTL sweeping or an LRU/size cap. This is acceptable for now
    // with default IP keying and the current single-node scope.
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
    rps: f64,
    burst: f64,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

struct RateLimitPolicyState {
    overrides: Vec<RateLimitOverride>,
}

struct RateLimitOverride {
    rule: RateLimitRule,
    limiter: RateLimiter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane {
    Read,
    Write,
}

#[derive(Serialize)]
struct TooManyRequestsBody {
    error: &'static str,
}

impl RateLimitState {
    pub fn from_config_and_policy(config: &Config, policy: Option<&Policy>) -> Self {
        Self {
            read: RateLimiter::new(config.rate_limit_read_rps, config.rate_limit_read_burst),
            write: RateLimiter::new(config.rate_limit_write_rps, config.rate_limit_write_burst),
            policy: Arc::new(ArcSwap::from_pointee(RateLimitPolicyState::from_policy(
                policy,
            ))),
            trust_proxy_headers: config.trust_proxy_headers,
            session_cookie_name: config.session_cookie_name.clone(),
        }
    }

    pub(crate) fn replace_policy(&self, policy: &Policy) {
        self.policy
            .store(Arc::new(RateLimitPolicyState::from_policy(Some(policy))));
    }

    fn limiter_for(
        &self,
        lane: Lane,
        method: &Method,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> RateLimiter {
        let policy = self.policy.load();
        if let Some(limiter) = policy.matching_limiter(method.as_str(), path, principal) {
            return limiter;
        }

        match lane {
            Lane::Read => self.read.clone(),
            Lane::Write => self.write.clone(),
        }
    }
}

impl RateLimiter {
    pub fn new(rps: f64, burst: u32) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            rps,
            burst: f64::from(burst),
        }
    }

    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = match self.buckets.lock() {
            Ok(buckets) => buckets,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "rate_limit",
                    "lock" => "buckets"
                )
                .increment(1);
                tracing::error!("rate limiter bucket lock poisoned; recovering");
                poisoned.into_inner()
            }
        };

        let bucket = buckets.entry(key.to_owned()).or_insert(TokenBucket {
            tokens: self.burst,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();

        bucket.tokens = (bucket.tokens + (elapsed * self.rps)).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl RateLimitPolicyState {
    fn from_policy(policy: Option<&Policy>) -> Self {
        Self {
            overrides: policy
                .map(|policy| {
                    policy
                        .rate_limits
                        .iter()
                        .cloned()
                        .map(RateLimitOverride::new)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn matching_limiter(
        &self,
        method: &str,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> Option<RateLimiter> {
        self.overrides
            .iter()
            .find(|override_rule| override_rule.matches(method, path, principal))
            .map(|override_rule| override_rule.limiter.clone())
    }
}

impl RateLimitOverride {
    fn new(rule: RateLimitRule) -> Self {
        let limiter = RateLimiter::new(rule.requests_per_second, rule.burst);

        Self { rule, limiter }
    }

    fn matches(&self, method: &str, path: &str, principal: Option<&auth::Principal>) -> bool {
        self.rule.principal.matches(principal)
            && method_matches(&self.rule.methods, method)
            && self
                .rule
                .path
                .as_ref()
                .is_none_or(|pattern| path_pattern_matches(pattern, path))
    }
}

pub async fn rate_limit_request(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response {
    let lane = lane_for(req.method());
    let client_ip = canonical_client_ip(req.headers(), req.extensions(), state.trust_proxy_headers);
    let key = rate_limit_key(
        req.extensions(),
        req.headers(),
        &state.session_cookie_name,
        &client_ip,
    );
    let limiter = state.limiter_for(
        lane,
        req.method(),
        req.uri().path(),
        req.extensions().get::<auth::Principal>(),
    );

    if !limiter.check(&key) {
        tracing::warn!(
            client_ip = %client_ip,
            lane = lane.as_str(),
            path = req.uri().path(),
            "rate limit exceeded"
        );
        return too_many_requests();
    }

    next.run(req).await
}

fn rate_limit_key(
    extensions: &Extensions,
    headers: &HeaderMap,
    session_cookie_name: &str,
    client_ip: &str,
) -> String {
    if let Some(principal) = extensions.get::<auth::Principal>() {
        return format!("principal:{}", principal.user_id);
    }

    if let Some(session) = session_cookie(headers, session_cookie_name) {
        // DefaultHasher is sufficient for a non-cryptographic rate-limit fingerprint.
        return format!("session:{:016x}", hash_str(session));
    }

    format!("ip:{client_ip}")
}

fn session_cookie<'a>(headers: &'a HeaderMap, session_cookie_name: &str) -> Option<&'a str> {
    if session_cookie_name.is_empty() {
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
            (name.trim() == session_cookie_name && !value.is_empty()).then_some(value)
        })
}

fn header_value_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

fn hash_str(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn lane_for(method: &Method) -> Lane {
    if matches!(*method, Method::GET | Method::HEAD) {
        Lane::Read
    } else {
        Lane::Write
    }
}

impl Lane {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

fn too_many_requests() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(TooManyRequestsBody {
            error: "too many requests",
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        panic::AssertUnwindSafe,
        path::{Path, PathBuf},
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use axum::{
        body::Body,
        middleware::{from_fn, from_fn_with_state},
        routing::any,
        Router,
    };
    use serde_json::Value;
    use tower::ServiceExt;

    use crate::{
        audit::{sink::tests::CaptureSink, AuditLog, AuditSink},
        auth::{AuthMethod, Principal},
        middleware::rbac::{reload_policy_from_file, RbacState},
        rbac::{
            DefaultAction, EgressPolicy, EnforcementMode, Policy, PrincipalMatcher, RateLimitRule,
        },
    };

    fn test_state(read_burst: u32, write_burst: u32) -> RateLimitState {
        test_state_with_rate_limits(0.0, read_burst, 0.0, write_burst, Vec::new())
    }

    fn test_state_with_rate_limits(
        read_rps: f64,
        read_burst: u32,
        write_rps: f64,
        write_burst: u32,
        rate_limits: Vec<RateLimitRule>,
    ) -> RateLimitState {
        RateLimitState {
            read: RateLimiter::new(read_rps, read_burst),
            write: RateLimiter::new(write_rps, write_burst),
            policy: Arc::new(ArcSwap::from_pointee(RateLimitPolicyState {
                overrides: rate_limits
                    .into_iter()
                    .map(RateLimitOverride::new)
                    .collect(),
            })),
            trust_proxy_headers: false,
            session_cookie_name: String::new(),
        }
    }

    fn test_state_with_session_cookie(session_cookie_name: &str) -> RateLimitState {
        RateLimitState {
            read: RateLimiter::new(0.0, 1),
            write: RateLimiter::new(0.0, 1),
            policy: Arc::new(ArcSwap::from_pointee(RateLimitPolicyState {
                overrides: Vec::new(),
            })),
            trust_proxy_headers: false,
            session_cookie_name: session_cookie_name.to_owned(),
        }
    }

    fn test_router(state: RateLimitState) -> Router {
        async fn ok() -> &'static str {
            "ok"
        }

        Router::new()
            .fallback(any(ok))
            .layer(from_fn_with_state(state, rate_limit_request))
            .layer(from_fn(inject_test_principal))
    }

    async fn inject_test_principal(mut req: Request, next: Next) -> Response {
        if let Some(user_id) = req
            .headers()
            .get("x-test-principal")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
        {
            req.extensions_mut().insert(test_principal(&user_id));
        }

        next.run(req).await
    }

    #[test]
    fn fresh_limiter_allows_burst_then_throttles() {
        let limiter = RateLimiter::new(0.0, 2);

        assert!(limiter.check("key"));
        assert!(limiter.check("key"));
        assert!(!limiter.check("key"));
    }

    #[test]
    fn exhausted_limiter_refills_over_time() {
        let limiter = RateLimiter::new(1000.0, 1);

        assert!(limiter.check("key"));
        assert!(!limiter.check("key"));
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check("key"));
    }

    #[test]
    fn recovers_from_poisoned_bucket_lock() {
        let limiter = RateLimiter::new(0.0, 1);
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = limiter
                .buckets
                .lock()
                .expect("lock should not be poisoned yet");
            panic!("poison the bucket lock");
        }));

        assert!(result.is_err());
        assert!(limiter.check("key"));
    }

    #[tokio::test]
    async fn read_and_write_lanes_are_independent() {
        let router = test_router(test_state(1, 1));

        let response = router
            .clone()
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

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        let response = router
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
    }

    #[tokio::test]
    async fn rejection_returns_structured_json_body() {
        let router = test_router(test_state(1, 1));

        let response = router
            .clone()
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

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        let json: Value = serde_json::from_slice(&body).expect("body should be JSON");

        assert_eq!(json, serde_json::json!({ "error": "too many requests" }));
    }

    #[tokio::test]
    async fn per_principal_override_selection_uses_matching_principal() {
        let router = test_router(test_state_with_rate_limits(
            100.0,
            100,
            100.0,
            100,
            vec![rate_limit_rule(
                &["user-a"],
                &["GET"],
                Some("/data"),
                0.000_001,
                1,
            )],
        ));

        assert_eq!(
            request_status(&router, Method::GET, "/data", Some("user-a"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/data", Some("user-a"), None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            request_status(&router, Method::GET, "/data", Some("user-b"), None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn per_endpoint_override_selection_uses_method_and_path_pattern() {
        let router = test_router(test_state_with_rate_limits(
            100.0,
            100,
            100.0,
            100,
            vec![rate_limit_rule(
                &[],
                &["GET"],
                Some("/api/widgets/{id}"),
                0.000_001,
                1,
            )],
        ));

        assert_eq!(
            request_status(&router, Method::GET, "/api/widgets/123", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/api/widgets/123", None, None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            request_status(&router, Method::POST, "/api/widgets/123", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/api/widgets/123/details", None, None).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn first_matching_rate_limit_override_wins() {
        let router = test_router(test_state_with_rate_limits(
            100.0,
            100,
            100.0,
            100,
            vec![
                rate_limit_rule(&[], &["GET"], Some("/first/**"), 0.000_001, 2),
                rate_limit_rule(&[], &["GET"], Some("/first/**"), 0.000_001, 1),
            ],
        ));

        assert_eq!(
            request_status(&router, Method::GET, "/first/item", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/first/item", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/first/item", None, None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn falls_back_to_global_env_lanes_when_no_rate_limit_override_matches() {
        let router = test_router(test_state_with_rate_limits(
            0.0,
            1,
            0.0,
            1,
            vec![rate_limit_rule(
                &[],
                &["GET"],
                Some("/matched-only"),
                100.0,
                100,
            )],
        ));

        assert_eq!(
            request_status(&router, Method::GET, "/unmatched", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/unmatched", None, None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn principal_first_keying_gives_shared_ip_principals_independent_buckets() {
        let router = test_router(test_state(1, 1));

        assert_eq!(
            request_status(&router, Method::GET, "/keyed", Some("user-a"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/keyed", Some("user-a"), None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            request_status(&router, Method::GET, "/keyed", Some("user-b"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/keyed", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/keyed", None, None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn unauthenticated_session_cookie_keying_still_uses_configured_cookie() {
        let router = test_router(test_state_with_session_cookie("gateway_session"));

        assert_eq!(
            request_status(
                &router,
                Method::GET,
                "/session",
                None,
                Some("gateway_session=one"),
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(
                &router,
                Method::GET,
                "/session",
                None,
                Some("gateway_session=one"),
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            request_status(
                &router,
                Method::GET,
                "/session",
                None,
                Some("gateway_session=two"),
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn policy_reload_updates_rate_limit_overrides() {
        let initial_policy = policy_with_rate_limits(vec![rate_limit_rule(
            &[],
            &["GET"],
            Some("/reload"),
            0.000_001,
            1,
        )]);
        let file = TempPolicyFile::new(&policy_json(&initial_policy));
        let rate_limit_state =
            test_state_with_rate_limits(100.0, 100, 100.0, 100, initial_policy.rate_limits.clone());
        let rbac_state = RbacState::new(initial_policy, Vec::new(), false, test_audit_log())
            .with_rate_limit_state(rate_limit_state.clone());
        let router = test_router(rate_limit_state);

        assert_eq!(
            request_status(&router, Method::GET, "/reload", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/reload", None, None).await,
            StatusCode::TOO_MANY_REQUESTS
        );

        let updated_policy = policy_with_rate_limits(vec![rate_limit_rule(
            &[],
            &["GET"],
            Some("/reload"),
            0.000_001,
            2,
        )]);
        file.write(&policy_json(&updated_policy));
        reload_policy_from_file(&rbac_state, file.path()).expect("valid reload should succeed");

        assert_eq!(
            request_status(&router, Method::GET, "/reload", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/reload", None, None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/reload", None, None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_complete_during_rate_limit_policy_swaps() {
        let old_policy = policy_with_rate_limits(vec![rate_limit_rule(
            &[],
            &["GET"],
            Some("/swap/**"),
            1_000_000.0,
            1_000_000,
        )]);
        let new_policy = policy_with_rate_limits(vec![rate_limit_rule(
            &[],
            &["GET"],
            Some("/swap/**"),
            500_000.0,
            1_000_000,
        )]);
        let file = TempPolicyFile::new(&policy_json(&old_policy));
        let rate_limit_state =
            test_state_with_rate_limits(100.0, 100, 100.0, 100, old_policy.rate_limits.clone());
        let rbac_state = RbacState::new(old_policy, Vec::new(), false, test_audit_log())
            .with_rate_limit_state(rate_limit_state.clone());
        let router = test_router(rate_limit_state);

        let reload_state = rbac_state.clone();
        let reload_path = file.path().to_owned();
        let old_policy_json = policy_json(&policy_with_rate_limits(vec![rate_limit_rule(
            &[],
            &["GET"],
            Some("/swap/**"),
            1_000_000.0,
            1_000_000,
        )]));
        let new_policy_json = policy_json(&new_policy);
        let reload_task = tokio::spawn(async move {
            for iteration in 0..100 {
                let policy_json = if iteration % 2 == 0 {
                    &new_policy_json
                } else {
                    &old_policy_json
                };
                fs::write(&reload_path, policy_json)
                    .unwrap_or_else(|err| panic!("failed to write reload policy: {err}"));
                reload_policy_from_file(&reload_state, &reload_path)
                    .expect("valid reload policy should be accepted");
                tokio::task::yield_now().await;
            }
        });

        let mut request_tasks = Vec::new();
        for _ in 0..500 {
            let router = router.clone();
            request_tasks.push(tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    request_status(&router, Method::GET, "/swap/item", None, None),
                )
                .await
                .expect("request should not hang")
            }));
        }

        for task in request_tasks {
            assert_eq!(
                task.await.expect("request task should join"),
                StatusCode::OK
            );
        }

        reload_task.await.expect("reload task should join");
    }

    #[test]
    fn session_cookie_key_uses_configured_cookie_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            "other=ignored; gateway_session=secret; later=value"
                .parse()
                .unwrap(),
        );

        assert_eq!(
            rate_limit_key(
                &Extensions::new(),
                &headers,
                "gateway_session",
                "203.0.113.20"
            ),
            format!("session:{:016x}", hash_str("secret"))
        );
    }

    #[test]
    fn principal_key_takes_precedence_over_session_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "gateway_session=secret".parse().unwrap());
        let mut extensions = Extensions::new();
        extensions.insert(test_principal("user-123"));

        assert_eq!(
            rate_limit_key(&extensions, &headers, "gateway_session", "203.0.113.20"),
            "principal:user-123"
        );
    }

    #[test]
    fn empty_session_cookie_config_falls_back_to_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "gateway_session=secret".parse().unwrap());

        assert_eq!(
            rate_limit_key(&Extensions::new(), &headers, "", "203.0.113.20"),
            "ip:203.0.113.20"
        );
    }

    async fn request_status(
        router: &Router,
        method: Method,
        path: &str,
        principal_id: Option<&str>,
        cookie: Option<&str>,
    ) -> StatusCode {
        let mut request = Request::builder().method(method).uri(path);

        if let Some(principal_id) = principal_id {
            request = request.header("x-test-principal", principal_id);
        }

        if let Some(cookie) = cookie {
            request = request.header(COOKIE, cookie);
        }

        router
            .clone()
            .oneshot(request.body(Body::empty()).expect("request should build"))
            .await
            .expect("request should complete")
            .status()
    }

    fn rate_limit_rule(
        principal_ids: &[&str],
        methods: &[&str],
        path: Option<&str>,
        requests_per_second: f64,
        burst: u32,
    ) -> RateLimitRule {
        RateLimitRule {
            principal: PrincipalMatcher {
                principal_ids: principal_ids
                    .iter()
                    .map(|principal_id| (*principal_id).to_owned())
                    .collect(),
                ..PrincipalMatcher::default()
            },
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            path: path.map(str::to_owned),
            requests_per_second,
            burst,
        }
    }

    fn policy_with_rate_limits(rate_limits: Vec<RateLimitRule>) -> Policy {
        Policy {
            schema_version: "0.1.0".to_owned(),
            id: Some("rate-limit-test".to_owned()),
            default_action: DefaultAction::Allow,
            enforcement_mode: EnforcementMode::Enforce,
            roles: HashMap::new(),
            routes: Vec::new(),
            rules: Vec::new(),
            egress: EgressPolicy::default(),
            rate_limits,
        }
    }

    fn test_principal(user_id: &str) -> Principal {
        Principal {
            user_id: user_id.to_owned(),
            email: Some(format!("{user_id}@example.test")),
            org_id: None,
            roles: vec!["member".to_owned()],
            session_id: format!("{user_id}-session"),
            auth_method: AuthMethod::Bearer,
        }
    }

    fn test_audit_log() -> AuditLog {
        let capture = CaptureSink::new();
        AuditLog::new(Arc::new(capture) as Arc<dyn AuditSink>)
    }

    fn policy_json(policy: &Policy) -> String {
        serde_json::to_string(policy).expect("policy should serialize")
    }

    struct TempPolicyFile {
        path: PathBuf,
    }

    impl TempPolicyFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-rate-limit-policy-{}-{}.json",
                std::process::id(),
                unique_suffix()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, contents: &str) {
            fs::write(&self.path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", self.path.display()));
        }
    }

    impl Drop for TempPolicyFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn unique_suffix() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default()
    }
}
