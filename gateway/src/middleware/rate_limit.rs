//! Token-bucket rate limiting middleware.

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{
    header::{HeaderValue, COOKIE},
    HeaderMap, Method, StatusCode,
};
use serde::Serialize;

use crate::{client_ip::canonical_client_ip, config::Config};

pub const LOCK_POISON_RECOVERIES_TOTAL: &str = "lock_poison_recoveries_total";

#[derive(Clone)]
pub struct RateLimitState {
    read: RateLimiter,
    write: RateLimiter,
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
    pub fn from_config(config: &Config) -> Self {
        Self {
            read: RateLimiter::new(config.rate_limit_read_rps, config.rate_limit_read_burst),
            write: RateLimiter::new(config.rate_limit_write_rps, config.rate_limit_write_burst),
            trust_proxy_headers: config.trust_proxy_headers,
            session_cookie_name: config.session_cookie_name.clone(),
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
                metrics::counter!(LOCK_POISON_RECOVERIES_TOTAL).increment(1);
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

pub async fn rate_limit_request(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response {
    let lane = lane_for(req.method());
    let client_ip = canonical_client_ip(req.headers(), req.extensions(), state.trust_proxy_headers);
    let key = rate_limit_key(req.headers(), &state.session_cookie_name, &client_ip);
    let limiter = match lane {
        Lane::Read => &state.read,
        Lane::Write => &state.write,
    };

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

fn rate_limit_key(headers: &HeaderMap, session_cookie_name: &str, client_ip: &str) -> String {
    // Auth lands in issue #5. Principal extension keying should be checked here
    // before falling back to session-cookie keying.
    if let Some(session) = session_cookie(headers, session_cookie_name) {
        // Security footgun: this keys on an unvalidated, client-controlled
        // cookie value. Enabling SESSION_COOKIE_NAME before an upstream auth
        // layer validates the session cookie lets a client mint unlimited
        // buckets and bypass rate limiting. Only enable session keying once
        // sessions are validated; auth lands in issue #5, and cookie-session
        // validation lands in a later issue.
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
    use std::{panic::AssertUnwindSafe, time::Duration};

    use super::*;
    use axum::{body::Body, middleware::from_fn_with_state, routing::get, Router};
    use serde_json::Value;
    use tower::ServiceExt;

    fn test_state(read_burst: u32, write_burst: u32) -> RateLimitState {
        RateLimitState {
            read: RateLimiter::new(0.0, read_burst),
            write: RateLimiter::new(0.0, write_burst),
            trust_proxy_headers: false,
            session_cookie_name: String::new(),
        }
    }

    fn test_router(state: RateLimitState) -> Router {
        async fn ok() -> &'static str {
            "ok"
        }

        Router::new()
            .route("/", get(ok).post(ok))
            .layer(from_fn_with_state(state, rate_limit_request))
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
            rate_limit_key(&headers, "gateway_session", "203.0.113.20"),
            format!("session:{:016x}", hash_str("secret"))
        );
    }

    #[test]
    fn empty_session_cookie_config_falls_back_to_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, "gateway_session=secret".parse().unwrap());

        assert_eq!(
            rate_limit_key(&headers, "", "203.0.113.20"),
            "ip:203.0.113.20"
        );
    }
}
