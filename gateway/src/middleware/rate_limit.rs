//! Token-bucket rate limiting middleware.

use std::{
    collections::{hash_map::RandomState, HashMap, VecDeque},
    hash::BuildHasher,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{Method, StatusCode};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    auth,
    client_ip::{canonical_client_ip, ClientIpPolicy},
    config::Config,
    metrics::{
        LOCK_POISON_RECOVERIES_TOTAL, RATE_LIMIT_BUCKETS, RATE_LIMIT_BUCKET_EVICTIONS_TOTAL,
    },
    rbac::{
        matcher::{method_matches, path_pattern_matches},
        Policy, RateLimitRule,
    },
};

#[derive(Clone)]
pub struct RateLimitState {
    read: RateLimiter,
    write: RateLimiter,
    policy: Arc<ArcSwap<RateLimitPolicyState>>,
    client_ip_policy: ClientIpPolicy,
    bucket_capacity: usize,
    bucket_idle_ttl: Duration,
    /// Cluster mode's shared limiter (issue #241, PR 10). When set, every
    /// request the local buckets allow is then decided by the authority,
    /// so one configured burst permits that many requests across the
    /// cluster; the local buckets remain the per-replica emergency bound
    /// and never replace shared enforcement. None in standalone mode.
    #[cfg(feature = "postgres")]
    shared: Option<Arc<crate::storage::PostgresRateLimitStore>>,
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    read_limit: LaneLimit,
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    write_limit: LaneLimit,
}

/// A configured limit as the shared store decides it.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
struct LaneLimit {
    requests_per_second: f64,
    burst: u32,
}

/// The shared decision a request still needs after the local buckets
/// allowed it: none in standalone mode, the authority's in cluster mode.
enum SharedGate {
    None,
    #[cfg(feature = "postgres")]
    Authority {
        store: Arc<crate::storage::PostgresRateLimitStore>,
        lane: crate::storage::SharedLane,
        key: String,
        limit: LaneLimit,
    },
}

/// One rate limiter's bucket storage: bounded, and biased towards keeping the
/// buckets of keys that are actually being used.
///
/// The bound is a hard ceiling on distinct tracked keys; when a new key arrives
/// while the store is full, one existing bucket is evicted. The eviction rule
/// is second-chance (the clock algorithm): a bucket that has been used since
/// the last scan gets one reprieve, a bucket idle beyond the configured TTL is
/// evicted first regardless of use, and everything else is evicted in scan
/// order. That keeps a spray of throwaway identities from displacing the
/// buckets of active callers, which matters because eviction resets the
/// evicted key's allowance -- a fresh bucket is a fresh burst.
///
/// Keys are stored as 64-bit hashes, never as the key strings: a rate-limit
/// key can carry caller-influenced text (a principal's `user_id` comes from a
/// token claim with no length bound of its own), and the store's memory must
/// be bounded by the entry count, not by the length of the longest identity an
/// attacker can persuade an identity provider to mint. Hashing with a
/// per-process random seed also means no offline-precomputable key collisions.
/// A 64-bit hash collision merges two callers into one bucket -- the failure
/// mode is two callers sharing a limit, never a caller escaping one.
///
/// There is deliberately no background sweep. The ceiling alone bounds memory;
/// the clock recycles idle buckets exactly when capacity is needed, and a sweep
/// task would add lifecycle surface to free memory that is already bounded.
struct BucketStore {
    map: HashMap<u64, TokenBucket>,
    /// Second-chance scan order: insertion order, with referenced buckets
    /// demoted to the back when they earn a reprieve.
    hand: VecDeque<u64>,
    capacity: usize,
    idle_ttl: Duration,
    /// Keys are hashed with a per-process random seed held in the shared store
    /// so every clone of the limiter agrees on a key's hash: a per-clone seed
    /// would give one key two buckets in the one shared map.
    hasher: RandomState,
    label: &'static str,
    /// Live buckets summed across every store sharing this counter. The two
    /// global lanes each have one store, so theirs equals their own size;
    /// every policy rule's store shares one counter, because a gauge is an
    /// absolute set -- per-store gauges under one label would report whichever
    /// store last changed, not the lane's total.
    live_buckets: Arc<AtomicUsize>,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    referenced: bool,
}

struct RateLimitPolicyState {
    overrides: Vec<RateLimitOverride>,
}

struct RateLimitOverride {
    rule: RateLimitRule,
    limiter: RateLimiter,
    /// SHA-256 of the rule's canonical JSON: the shared store keys the
    /// rule's buckets by it, so editing a rule retires its buckets.
    fingerprint: Arc<str>,
}

/// The policy rule a request matched: its local limiter, and what the
/// shared store needs to decide the same request.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
struct PolicyMatch {
    limiter: RateLimiter,
    fingerprint: Arc<str>,
    limit: LaneLimit,
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
            read: RateLimiter::new(
                config.rate_limit_read_rps,
                config.rate_limit_read_burst,
                config.rate_limit_max_buckets,
                config.rate_limit_bucket_idle_ttl(),
                "read",
                Arc::new(AtomicUsize::new(0)),
            ),
            write: RateLimiter::new(
                config.rate_limit_write_rps,
                config.rate_limit_write_burst,
                config.rate_limit_max_buckets,
                config.rate_limit_bucket_idle_ttl(),
                "write",
                Arc::new(AtomicUsize::new(0)),
            ),
            policy: Arc::new(ArcSwap::from_pointee(RateLimitPolicyState::from_policy(
                policy,
                config.rate_limit_max_buckets,
                config.rate_limit_bucket_idle_ttl(),
            ))),
            client_ip_policy: ClientIpPolicy::from_config(config),
            bucket_capacity: config.rate_limit_max_buckets,
            bucket_idle_ttl: config.rate_limit_bucket_idle_ttl(),
            #[cfg(feature = "postgres")]
            shared: None,
            read_limit: LaneLimit {
                requests_per_second: config.rate_limit_read_rps,
                burst: config.rate_limit_read_burst,
            },
            write_limit: LaneLimit {
                requests_per_second: config.rate_limit_write_rps,
                burst: config.rate_limit_write_burst,
            },
        }
    }

    /// Cluster mode: decide every locally-allowed request at the shared
    /// store as well.
    #[cfg(feature = "postgres")]
    pub(crate) fn with_shared_store(
        mut self,
        store: Arc<crate::storage::PostgresRateLimitStore>,
    ) -> Self {
        self.shared = Some(store);
        self
    }

    /// The shared gate for a global lane, when the store is configured.
    fn shared_global_gate(&self, lane: Lane, key: &str) -> SharedGate {
        #[cfg(feature = "postgres")]
        if let Some(store) = &self.shared {
            return SharedGate::Authority {
                store: Arc::clone(store),
                lane: match lane {
                    Lane::Read => crate::storage::SharedLane::Read,
                    Lane::Write => crate::storage::SharedLane::Write,
                },
                key: key.to_owned(),
                limit: match lane {
                    Lane::Read => self.read_limit,
                    Lane::Write => self.write_limit,
                },
            };
        }
        let _ = (lane, key);
        SharedGate::None
    }

    /// The shared gate for a matched policy rule: keyed by the rule's
    /// fingerprint and the principal, so an edited rule starts fresh
    /// buckets and two rules never share one.
    fn shared_policy_gate(&self, matched: &PolicyMatch, principal_key: &str) -> SharedGate {
        #[cfg(feature = "postgres")]
        if let Some(store) = &self.shared {
            return SharedGate::Authority {
                store: Arc::clone(store),
                lane: crate::storage::SharedLane::Policy,
                key: format!("rule:{}:{principal_key}", matched.fingerprint),
                limit: matched.limit,
            };
        }
        let _ = (matched, principal_key);
        SharedGate::None
    }

    pub(crate) fn replace_policy(&self, policy: &Policy) {
        self.policy
            .store(Arc::new(RateLimitPolicyState::from_policy(
                Some(policy),
                self.bucket_capacity,
                self.bucket_idle_ttl,
            )));
    }

    fn global_limiter(&self, lane: Lane) -> RateLimiter {
        match lane {
            Lane::Read => self.read.clone(),
            Lane::Write => self.write.clone(),
        }
    }

    fn policy_limiter(
        &self,
        method: &Method,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> Option<PolicyMatch> {
        let policy = self.policy.load();
        policy.matching_limiter(method.as_str(), path, principal)
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<BucketStore>>,
    rps: f64,
    burst: f64,
}

impl RateLimiter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rps: f64,
        burst: u32,
        bucket_capacity: usize,
        bucket_idle_ttl: Duration,
        label: &'static str,
        live_buckets: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(BucketStore::new(
                bucket_capacity,
                bucket_idle_ttl,
                label,
                live_buckets,
            ))),
            rps,
            burst: f64::from(burst),
        }
    }

    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    /// The limiter's decision for `key` at a given instant, so the store's
    /// eviction rules can be tested against synthetic time instead of sleeps.
    fn check_at(&self, key: &str, now: Instant) -> bool {
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
        let hashed = buckets.hash_of(key);

        if let Some(bucket) = buckets.map.get_mut(&hashed) {
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();

            bucket.tokens = (bucket.tokens + (elapsed * self.rps)).min(self.burst);
            bucket.last_refill = now;
            bucket.referenced = true;

            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                true
            } else {
                false
            }
        } else {
            if buckets.map.len() >= buckets.capacity {
                buckets.evict_one(now);
            }
            let mut bucket = TokenBucket {
                // A fresh bucket starts full and spends its first token
                // immediately, through the same comparison the long-lived
                // path uses -- which keeps a misconfigured zero burst
                // denying the very first request, exactly as the unbounded
                // implementation did.
                tokens: self.burst,
                last_refill: now,
                // Unreferenced on purpose: a bucket earns its eviction
                // reprieve by being checked *again* after insertion, so a
                // spray of one-shot identities -- each checked exactly once
                // -- never protects itself, and active keys do.
                referenced: false,
            };
            let allowed = bucket.tokens >= 1.0;
            if allowed {
                bucket.tokens -= 1.0;
            }
            buckets.map.insert(hashed, bucket);
            buckets.hand.push_back(hashed);
            buckets.live_buckets.fetch_add(1, Ordering::Relaxed);
            buckets.report_gauge();
            allowed
        }
    }
}

impl BucketStore {
    fn new(
        capacity: usize,
        idle_ttl: Duration,
        label: &'static str,
        live_buckets: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            map: HashMap::new(),
            hand: VecDeque::new(),
            capacity,
            idle_ttl,
            hasher: RandomState::new(),
            label,
            live_buckets,
        }
    }

    /// A key's bucket identity, stable for the life of the process.
    fn hash_of(&self, key: &str) -> u64 {
        self.hasher.hash_one(key)
    }

    /// Evicts one bucket, second-chance: idle-beyond-TTL first, then the first
    /// not-referenced-since-the-last-scan, demoting referenced ones as it goes.
    fn evict_one(&mut self, now: Instant) {
        // One full rotation clears every `referenced` bit, so a second pass
        // must find a victim; the outer bound guarantees forward progress even
        // if that reasoning ever breaks.
        let scans_available = self.hand.len().saturating_mul(2);
        for _ in 0..scans_available {
            let Some(candidate) = self.hand.pop_front() else {
                break;
            };
            let Some(bucket) = self.map.get_mut(&candidate) else {
                // Hand and map are maintained together; skip rather than panic
                // if that invariant is ever broken.
                continue;
            };
            let idle = now.saturating_duration_since(bucket.last_refill);
            if idle >= self.idle_ttl {
                self.map.remove(&candidate);
                self.live_buckets.fetch_sub(1, Ordering::Relaxed);
                self.report_eviction("ttl");
                return;
            }
            if bucket.referenced {
                bucket.referenced = false;
                self.hand.push_back(candidate);
                continue;
            }
            self.map.remove(&candidate);
            self.live_buckets.fetch_sub(1, Ordering::Relaxed);
            self.report_eviction("capacity");
            return;
        }
        // Every bucket was hot within the TTL: progress beats perfect fairness.
        while let Some(candidate) = self.hand.pop_front() {
            if self.map.remove(&candidate).is_some() {
                self.live_buckets.fetch_sub(1, Ordering::Relaxed);
                self.report_eviction("capacity");
                return;
            }
        }
    }

    fn report_eviction(&self, reason: &'static str) {
        ::metrics::counter!(
            RATE_LIMIT_BUCKET_EVICTIONS_TOTAL,
            "limiter" => self.label,
            "reason" => reason
        )
        .increment(1);
        self.report_gauge();
    }

    fn report_gauge(&self) {
        ::metrics::gauge!(RATE_LIMIT_BUCKETS, "limiter" => self.label)
            .set(self.live_buckets.load(Ordering::Relaxed) as f64);
    }
}

impl RateLimitPolicyState {
    fn from_policy(
        policy: Option<&Policy>,
        bucket_capacity: usize,
        bucket_idle_ttl: Duration,
    ) -> Self {
        // One counter shared by every rule's store, so the policy lane's
        // gauge is the sum across rules rather than whichever store happened
        // to change last. Rebuilt on policy replace, alongside the stores.
        let live_buckets = Arc::new(AtomicUsize::new(0));
        Self {
            overrides: policy
                .map(|policy| {
                    policy
                        .rate_limits
                        .iter()
                        .cloned()
                        .map(|rule| {
                            RateLimitOverride::new(
                                rule,
                                bucket_capacity,
                                bucket_idle_ttl,
                                Arc::clone(&live_buckets),
                            )
                        })
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
    ) -> Option<PolicyMatch> {
        self.overrides
            .iter()
            .find(|override_rule| override_rule.matches(method, path, principal))
            .map(|override_rule| PolicyMatch {
                limiter: override_rule.limiter.clone(),
                fingerprint: Arc::clone(&override_rule.fingerprint),
                limit: LaneLimit {
                    requests_per_second: override_rule.rule.requests_per_second,
                    burst: override_rule.rule.burst,
                },
            })
    }
}

impl RateLimitOverride {
    fn new(
        rule: RateLimitRule,
        bucket_capacity: usize,
        bucket_idle_ttl: Duration,
        live_buckets: Arc<AtomicUsize>,
    ) -> Self {
        // Every policy-rule limiter reports under the one `policy` label: rule
        // sets change across reloads, and a per-rule label would mint and
        // abandon time series with every policy edit. The gauge is the shared
        // counter, so it reports the lane's total, not one rule's store.
        let limiter = RateLimiter::new(
            rule.requests_per_second,
            rule.burst,
            bucket_capacity,
            bucket_idle_ttl,
            "policy",
            live_buckets,
        );

        let fingerprint = Arc::<str>::from(rule_fingerprint(&rule));
        Self {
            rule,
            limiter,
            fingerprint,
        }
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
    let path = req.uri().path().to_owned();
    let client_ip = canonical_client_ip(req.headers(), req.extensions(), &state.client_ip_policy);
    let key = format!("ip:{client_ip}");
    let limiter = state.global_limiter(lane);
    let shared = state.shared_global_gate(lane, &key);

    check_rate_limit(limiter, &key, &client_ip, lane, &path, shared, req, next).await
}

pub async fn policy_rate_limit_request(
    State(state): State<RateLimitState>,
    req: Request,
    next: Next,
) -> Response {
    let lane = lane_for(req.method());
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let client_ip = canonical_client_ip(req.headers(), req.extensions(), &state.client_ip_policy);
    let Some(principal) = req.extensions().get::<auth::Principal>() else {
        return next.run(req).await;
    };
    let Some(matched) = state.policy_limiter(&method, &path, Some(principal)) else {
        return next.run(req).await;
    };
    let key = principal_rate_limit_key(principal);
    let shared = state.shared_policy_gate(&matched, &key);

    check_rate_limit(
        matched.limiter,
        &key,
        &client_ip,
        lane,
        &path,
        shared,
        req,
        next,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn check_rate_limit(
    limiter: RateLimiter,
    key: &str,
    client_ip: &str,
    lane: Lane,
    path: &str,
    shared: SharedGate,
    req: Request,
    next: Next,
) -> Response {
    // The local buckets first: the per-replica emergency bound, and a
    // denial here spends no authority round trip.
    if !limiter.check(key) {
        tracing::warn!(
            client_ip = %client_ip,
            lane = lane.as_str(),
            path,
            "rate limit exceeded"
        );
        return too_many_requests();
    }
    match shared {
        SharedGate::None => {}
        #[cfg(feature = "postgres")]
        SharedGate::Authority {
            store,
            lane: shared_lane,
            key: shared_key,
            limit,
        } => {
            use crate::metrics::RATE_LIMIT_SHARED_DECISIONS_TOTAL;
            use crate::storage::{SharedDecision, SharedLimit};
            let decision = store
                .decide(
                    shared_lane,
                    &shared_key,
                    SharedLimit {
                        requests_per_second: limit.requests_per_second,
                        burst: limit.burst,
                    },
                )
                .await;
            match decision {
                Ok(SharedDecision::Allowed) => {
                    ::metrics::counter!(
                        RATE_LIMIT_SHARED_DECISIONS_TOTAL,
                        "lane" => shared_lane.as_str(),
                        "outcome" => "allowed"
                    )
                    .increment(1);
                }
                Ok(SharedDecision::Denied) => {
                    ::metrics::counter!(
                        RATE_LIMIT_SHARED_DECISIONS_TOTAL,
                        "lane" => shared_lane.as_str(),
                        "outcome" => "denied"
                    )
                    .increment(1);
                    tracing::warn!(
                        client_ip = %client_ip,
                        lane = shared_lane.as_str(),
                        path,
                        "shared rate limit exceeded"
                    );
                    return too_many_requests();
                }
                Err(error) => {
                    // Fail closed: an authority that cannot be consulted is
                    // a 503 with zero upstream attempts, never a silent
                    // allow and never a 429.
                    ::metrics::counter!(
                        RATE_LIMIT_SHARED_DECISIONS_TOTAL,
                        "lane" => shared_lane.as_str(),
                        "outcome" => "unavailable"
                    )
                    .increment(1);
                    tracing::error!(
                        lane = shared_lane.as_str(),
                        path,
                        error = %error,
                        "shared rate limiter unavailable; refusing the request"
                    );
                    return limiter_unavailable();
                }
            }
        }
    }

    next.run(req).await
}

/// The shared store's key for a policy rule: SHA-256 of its canonical
/// JSON, so any edit -- matcher, rate, or burst -- retires its buckets.
fn rule_fingerprint(rule: &RateLimitRule) -> String {
    let canonical = serde_json::to_vec(rule).unwrap_or_default();
    hex::encode(Sha256::digest(canonical))
}

#[derive(Serialize)]
struct LimiterUnavailableBody {
    error: &'static str,
}

#[cfg_attr(not(feature = "postgres"), allow(dead_code))]
fn limiter_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(LimiterUnavailableBody {
            error: "rate limiter unavailable",
        }),
    )
        .into_response()
}

fn principal_rate_limit_key(principal: &auth::Principal) -> String {
    let issuer = principal.issuer.as_deref().unwrap_or("");
    let auth_method = crate::rbac::rule::auth_method_policy_value(&principal.auth_method);
    format!(
        "principal:{}:{issuer}:{auth_method}:{}",
        issuer.len(),
        principal.user_id
    )
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
        extract::ConnectInfo,
        middleware::{from_fn, from_fn_with_state},
        routing::any,
        Router,
    };
    use http::header::COOKIE;
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

    /// Bucket-store shape for behaviour tests: generous enough that ordinary
    /// lane tests never touch it, small enough to be irrelevant to timing.
    const TEST_BUCKET_CAPACITY: usize = 1024;
    const TEST_BUCKET_TTL: Duration = Duration::from_secs(600);

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
        let policy = policy_with_rate_limits(rate_limits);
        let policy_state =
            RateLimitPolicyState::from_policy(Some(&policy), TEST_BUCKET_CAPACITY, TEST_BUCKET_TTL);
        RateLimitState {
            read: RateLimiter::new(
                read_rps,
                read_burst,
                TEST_BUCKET_CAPACITY,
                TEST_BUCKET_TTL,
                "read",
                Arc::new(AtomicUsize::new(0)),
            ),
            write: RateLimiter::new(
                write_rps,
                write_burst,
                TEST_BUCKET_CAPACITY,
                TEST_BUCKET_TTL,
                "write",
                Arc::new(AtomicUsize::new(0)),
            ),
            policy: Arc::new(ArcSwap::from_pointee(policy_state)),
            client_ip_policy: ClientIpPolicy::default(),
            bucket_capacity: TEST_BUCKET_CAPACITY,
            bucket_idle_ttl: TEST_BUCKET_TTL,
            #[cfg(feature = "postgres")]
            shared: None,
            read_limit: LaneLimit {
                requests_per_second: read_rps,
                burst: read_burst,
            },
            write_limit: LaneLimit {
                requests_per_second: write_rps,
                burst: write_burst,
            },
        }
    }

    fn test_router(state: RateLimitState) -> Router {
        async fn ok() -> &'static str {
            "ok"
        }

        Router::new()
            .fallback(any(ok))
            .layer(from_fn_with_state(state, rate_limit_request))
    }

    fn test_router_with_policy_layer(state: RateLimitState) -> Router {
        async fn ok() -> &'static str {
            "ok"
        }

        Router::new()
            .fallback(any(ok))
            .layer(from_fn_with_state(state.clone(), policy_rate_limit_request))
            .layer(from_fn(inject_test_principal))
            .layer(from_fn_with_state(state, rate_limit_request))
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
        let limiter = RateLimiter::new(
            0.0,
            2,
            TEST_BUCKET_CAPACITY,
            TEST_BUCKET_TTL,
            "read",
            Arc::new(AtomicUsize::new(0)),
        );

        assert!(limiter.check("key"));
        assert!(limiter.check("key"));
        assert!(!limiter.check("key"));
    }

    #[test]
    fn exhausted_limiter_refills_over_time() {
        let limiter = RateLimiter::new(
            1000.0,
            1,
            TEST_BUCKET_CAPACITY,
            TEST_BUCKET_TTL,
            "read",
            Arc::new(AtomicUsize::new(0)),
        );

        assert!(limiter.check("key"));
        assert!(!limiter.check("key"));
        std::thread::sleep(Duration::from_millis(5));
        assert!(limiter.check("key"));
    }

    #[test]
    fn recovers_from_poisoned_bucket_lock() {
        let limiter = RateLimiter::new(
            0.0,
            1,
            TEST_BUCKET_CAPACITY,
            TEST_BUCKET_TTL,
            "read",
            Arc::new(AtomicUsize::new(0)),
        );
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

    fn store_len(limiter: &RateLimiter) -> usize {
        limiter.buckets.lock().expect("bucket lock").map.len()
    }

    /// The store's size is bounded by its capacity no matter how many distinct
    /// keys an attacker rotates through -- the property the unbounded HashMap
    /// this replaces could not make.
    #[test]
    fn bucket_storage_is_bounded_at_the_configured_capacity() {
        let limiter = RateLimiter::new(
            0.0,
            10,
            4,
            TEST_BUCKET_TTL,
            "read",
            Arc::new(AtomicUsize::new(0)),
        );

        for index in 0..10 {
            limiter.check(&format!("attacker-identity-{index}"));
        }

        assert_eq!(
            store_len(&limiter),
            4,
            "ten distinct keys must not leave more buckets than the capacity"
        );
    }

    /// An active key's bucket survives a spray of throwaway identities, and
    /// that survival is observable in the key's allowance: the hot key was
    /// exhausted before the spray and is still exhausted after it. Had it been
    /// evicted, its next check would start a fresh bucket and succeed.
    ///
    /// Second-chance protects a key for one full rotation of the scan hand --
    /// which is the same protection LRU gives, for a key checked at least once
    /// per rotation. The spray here stays within one rotation of a
    /// capacity-four store; the boundary itself is pinned by the next test.
    #[test]
    fn a_hot_key_survives_a_cold_spray() {
        let limiter = RateLimiter::new(
            0.0,
            1,
            4,
            TEST_BUCKET_TTL,
            "read",
            Arc::new(AtomicUsize::new(0)),
        );

        assert!(limiter.check("hot"));
        assert!(!limiter.check("hot"), "the hot key starts exhausted");

        for index in 0..6 {
            limiter.check(&format!("throwaway-{index}"));
        }

        assert!(
            !limiter.check("hot"),
            "the hot key's bucket must survive the spray; success here would mean it was evicted and given a fresh burst"
        );
    }

    /// The honest boundary of that protection: a spray larger than the whole
    /// capacity displaces even active keys, because every entry in any bounded
    /// store is displaced by enough newcomers. An evicted active key's next
    /// request starts a fresh bucket -- a fresh burst. That is the documented
    /// approximation limit of the ceiling, and the reason
    /// `rate_limit_buckets` pinned at capacity with `capacity` evictions
    /// climbing is the signal to raise `RATE_LIMIT_MAX_BUCKETS`: the working
    /// set, legitimate or not, no longer fits.
    #[test]
    fn a_spray_larger_than_the_capacity_recycles_even_active_keys() {
        let limiter = RateLimiter::new(
            0.0,
            1,
            4,
            TEST_BUCKET_TTL,
            "read",
            Arc::new(AtomicUsize::new(0)),
        );

        assert!(limiter.check("hot"));
        assert!(!limiter.check("hot"), "the hot key starts exhausted");

        for index in 0..12 {
            limiter.check(&format!("throwaway-{index}"));
        }

        assert!(
            limiter.check("hot"),
            "beyond a full rotation the hot key is recycled and starts a fresh burst -- the documented limit, not a defect"
        );
    }

    /// A bucket idle beyond the TTL is evicted in preference to a fresher one,
    /// even though both carry the second-chance `referenced` bit. The scenario
    /// is built so plain second-chance cannot produce the same outcome: `hot`
    /// sits *ahead* of `idle` in scan order, so without the TTL rule the scan
    /// demotes both and then evicts `hot` -- with the TTL rule, `idle` is the
    /// victim because its last activity is older. Which key kept its bucket is
    /// observable in whose next check succeeds. Synthetic instants rather than
    /// sleeps: the TTL is a comparison, not a timer.
    #[test]
    fn idle_beyond_ttl_buckets_are_evicted_before_fresher_ones() {
        let limiter = RateLimiter::new(
            0.0,
            1,
            2,
            Duration::from_millis(180),
            "read",
            Arc::new(AtomicUsize::new(0)),
        );
        let t0 = Instant::now();
        let t_mid = t0 + Duration::from_millis(50);
        let t_late = t0 + Duration::from_millis(200);

        // `hot` is created first (ahead in scan order), used again to earn the
        // second-chance reprieve, and touched once more at t_mid so its last
        // activity is only 150ms before t_late.
        assert!(limiter.check_at("hot", t0));
        assert!(!limiter.check_at("hot", t0), "hot starts exhausted");
        assert!(!limiter.check_at("hot", t_mid));
        // `idle` is created second and also earns the reprieve, but its last
        // activity stays at t0 -- the full 200ms before t_late, beyond the
        // 180ms TTL.
        assert!(limiter.check_at("idle", t0));
        assert!(!limiter.check_at("idle", t0), "idle starts exhausted");

        // Capacity pressure with both buckets referenced.
        assert!(limiter.check_at("newcomer", t_late));

        assert!(
            !limiter.check_at("hot", t_late),
            "the fresher bucket must survive; success here would mean the TTL rule did not protect it"
        );
        assert!(
            limiter.check_at("idle", t_late),
            "the idle-beyond-TTL bucket must have been evicted: its next check starts a fresh one and succeeds"
        );
    }

    /// A burst of zero denies the very first request, exactly as the
    /// unbounded implementation did. A fresh bucket starts full and spends
    /// through the common path, so a misconfigured zero burst fails closed
    /// rather than admitting one request per key.
    #[test]
    fn a_zero_burst_denies_the_first_request() {
        let limiter = RateLimiter::new(
            0.0,
            0,
            TEST_BUCKET_CAPACITY,
            TEST_BUCKET_TTL,
            "read",
            Arc::new(AtomicUsize::new(0)),
        );

        assert!(
            !limiter.check("key"),
            "a zero burst must not admit anything"
        );
        assert!(!limiter.check("key"));
    }

    /// When every bucket holds the second-chance reprieve, a newcomer still
    /// evicts exactly one and the store stays at its ceiling: the scan clears
    /// reprieves for one full rotation and takes the first key on the second
    /// pass. This pins the second-pass path -- and the hand/map agreement it
    /// depends on -- which no other test reaches.
    #[test]
    fn an_all_referenced_store_still_evicts_exactly_one() {
        let limiter = RateLimiter::new(
            0.0,
            1,
            2,
            TEST_BUCKET_TTL,
            "read",
            Arc::new(AtomicUsize::new(0)),
        );

        // Both keys earn the reprieve with a second check each.
        assert!(limiter.check("one"));
        assert!(!limiter.check("one"));
        assert!(limiter.check("two"));
        assert!(!limiter.check("two"));

        // Capacity pressure against two referenced, fresh buckets.
        assert!(limiter.check("newcomer"));

        assert_eq!(
            store_len(&limiter),
            2,
            "eviction must make room without exceeding the ceiling, whatever every bucket's state"
        );
        // Exactly one of the originals was recycled: it gets a fresh burst.
        let recycled = limiter.check("one") || limiter.check("two");
        assert!(
            recycled,
            "exactly one evicted key must be re-admitted with a fresh burst"
        );
    }

    /// The policy lane's gauge is the sum across every rule's store, not
    /// whichever store changed last: all policy stores share one live-bucket
    /// counter. Without that, two rules with 2 and 3 buckets report 3.
    #[test]
    fn policy_lane_gauge_sums_across_rule_stores() {
        let recorder = crate::audit::sink::tests::CountingRecorder::default();
        ::metrics::with_local_recorder(&recorder, || {
            let shared = Arc::new(AtomicUsize::new(0));
            let first =
                RateLimiter::new(0.0, 10, 8, TEST_BUCKET_TTL, "policy", Arc::clone(&shared));
            let second =
                RateLimiter::new(0.0, 10, 8, TEST_BUCKET_TTL, "policy", Arc::clone(&shared));

            first.check("a");
            first.check("b");
            second.check("c");
            second.check("d");
            second.check("e");
        });

        assert_eq!(
            recorder.gauge_value(crate::metrics::RATE_LIMIT_BUCKETS, &[("limiter", "policy")]),
            Some(5.0),
            "the policy gauge must report the lane total (2 + 3), not the last store to change"
        );
    }

    /// Both eviction reasons are counted on the documented counter, with the
    /// limiter as a static label.
    #[test]
    fn evictions_are_counted_by_reason_on_the_documented_metric() {
        let recorder = crate::audit::sink::tests::CountingRecorder::default();
        ::metrics::with_local_recorder(&recorder, || {
            let limiter = RateLimiter::new(
                0.0,
                1,
                1,
                Duration::from_millis(100),
                "read",
                Arc::new(AtomicUsize::new(0)),
            );
            let t0 = Instant::now();

            // Capacity eviction: the store is full; `first` was checked once,
            // holds no reprieve, and is evicted without any demotion round.
            assert!(limiter.check_at("first", t0));
            assert!(limiter.check_at("second", t0));

            // TTL eviction: `second` sits idle past the TTL before pressure.
            let t1 = t0 + Duration::from_millis(200);
            assert!(limiter.check_at("third", t1));
        });

        assert_eq!(
            recorder.count(
                crate::metrics::RATE_LIMIT_BUCKET_EVICTIONS_TOTAL,
                &[("limiter", "read"), ("reason", "capacity")]
            ),
            1,
            "the capacity eviction must be counted once"
        );
        assert_eq!(
            recorder.count(
                crate::metrics::RATE_LIMIT_BUCKET_EVICTIONS_TOTAL,
                &[("limiter", "read"), ("reason", "ttl")]
            ),
            1,
            "the TTL eviction must be counted once"
        );
    }

    /// The live bucket count is reported on the documented gauge, which is
    /// what tells an operator the ceiling is doing its job.
    #[test]
    fn bucket_count_is_reported_on_the_documented_gauge() {
        let recorder = crate::audit::sink::tests::CountingRecorder::default();
        ::metrics::with_local_recorder(&recorder, || {
            let limiter = RateLimiter::new(
                0.0,
                10,
                2,
                TEST_BUCKET_TTL,
                "read",
                Arc::new(AtomicUsize::new(0)),
            );

            limiter.check("one");
            limiter.check("two");
            limiter.check("three");
        });

        assert_eq!(
            recorder.gauge_value(crate::metrics::RATE_LIMIT_BUCKETS, &[("limiter", "read")]),
            Some(2.0),
            "three keys against a capacity of two must leave exactly two buckets"
        );
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
    async fn attacker_prepended_forwarded_ips_cannot_rotate_pre_auth_limit_key() {
        let mut state = test_state(1, 1);
        state.client_ip_policy = ClientIpPolicy::from_trusted_proxy_cidrs(vec!["10.0.0.0/8"
            .parse()
            .expect("test CIDR should parse")]);
        let router = test_router(state);

        let request = |spoofed_ip: &str| {
            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/")
                .header("x-forwarded-for", format!("{spoofed_ip}, 198.51.100.10"))
                .body(Body::empty())
                .expect("request should build");
            request.extensions_mut().insert(ConnectInfo(
                "10.0.0.6:12345"
                    .parse::<std::net::SocketAddr>()
                    .expect("test peer should parse"),
            ));
            request
        };

        let first = router
            .clone()
            .oneshot(request("192.0.2.1"))
            .await
            .expect("first request should complete");
        assert_eq!(first.status(), StatusCode::OK);

        let second = router
            .oneshot(request("192.0.2.2"))
            .await
            .expect("second request should complete");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn per_principal_override_selection_uses_matching_principal() {
        let router = test_router_with_policy_layer(test_state_with_rate_limits(
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
        let router = test_router_with_policy_layer(test_state_with_rate_limits(
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
            request_status(
                &router,
                Method::GET,
                "/api/widgets/123",
                Some("user-a"),
                None
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(
                &router,
                Method::GET,
                "/api/widgets/123",
                Some("user-a"),
                None
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            request_status(
                &router,
                Method::POST,
                "/api/widgets/123",
                Some("user-a"),
                None
            )
            .await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(
                &router,
                Method::GET,
                "/api/widgets/123/details",
                Some("user-a"),
                None
            )
            .await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn first_matching_rate_limit_override_wins() {
        let router = test_router_with_policy_layer(test_state_with_rate_limits(
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
            request_status(&router, Method::GET, "/first/item", Some("user-a"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/first/item", Some("user-a"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/first/item", Some("user-a"), None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn falls_back_to_global_env_lanes_when_no_rate_limit_override_matches() {
        let router = test_router_with_policy_layer(test_state_with_rate_limits(
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
        let router = test_router_with_policy_layer(test_state_with_rate_limits(
            100.0,
            100,
            100.0,
            100,
            vec![rate_limit_rule(&[], &["GET"], Some("/keyed"), 0.000_001, 1)],
        ));

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
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn rotating_unauthenticated_cookies_does_not_reset_global_ip_bucket() {
        let router = test_router(test_state(1, 1));

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
                Some("gateway_session=two"),
            )
            .await,
            StatusCode::TOO_MANY_REQUESTS
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
        let router = test_router_with_policy_layer(rate_limit_state);

        assert_eq!(
            request_status(&router, Method::GET, "/reload", Some("user-a"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/reload", Some("user-a"), None).await,
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
            request_status(&router, Method::GET, "/reload", Some("user-a"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/reload", Some("user-a"), None).await,
            StatusCode::OK
        );
        assert_eq!(
            request_status(&router, Method::GET, "/reload", Some("user-a"), None).await,
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
        let rate_limit_state = test_state_with_rate_limits(
            1_000_000.0,
            1_000_000,
            1_000_000.0,
            1_000_000,
            old_policy.rate_limits.clone(),
        );
        let rbac_state = RbacState::new(old_policy, Vec::new(), false, test_audit_log())
            .with_rate_limit_state(rate_limit_state.clone());
        let router = test_router_with_policy_layer(rate_limit_state);

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
                    request_status(&router, Method::GET, "/swap/item", Some("user-a"), None),
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
    fn principal_key_includes_issuer_auth_method_and_user_id() {
        assert_eq!(
            principal_rate_limit_key(&test_principal("user-123")),
            "principal:0::bearer_token:user-123"
        );
    }

    #[test]
    fn principal_key_separates_colliding_subjects_by_issuer_and_auth_method() {
        let mut first = test_principal("shared-subject");
        first.issuer = Some("https://idp-a.example.test/".to_owned());
        let mut second = test_principal("shared-subject");
        second.issuer = Some("https://idp-b.example.test/".to_owned());
        let mut cookie = first.clone();
        cookie.auth_method = auth::AuthMethod::Cookie;

        assert_ne!(
            principal_rate_limit_key(&first),
            principal_rate_limit_key(&second)
        );
        assert_ne!(
            principal_rate_limit_key(&first),
            principal_rate_limit_key(&cookie)
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
            tools: HashMap::new(),
        }
    }

    fn test_principal(user_id: &str) -> Principal {
        Principal {
            user_id: user_id.to_owned(),
            issuer: None,
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
