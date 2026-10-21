//! Frozen pre-cutover policy rate-lane selection from 5fdf2b6, only for
//! differential tests: the `policy_rate_limit_request` middleware, guard
//! included, and the `matching_limiter` selector it consulted. Never compiled
//! into the serving binary; do not update its decision semantics.
//!
//! It runs over the same override stores the live stage builds, so the two can
//! be compared bucket for bucket.

use super::*;
use crate::rbac::{
    matcher::{method_matches, path_pattern_matches},
    Policy,
};

impl RateLimitState {
    fn legacy_policy_limiter(
        &self,
        method: &Method,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> Option<PolicyMatch> {
        let policy = self.policy.load();
        policy.legacy_matching_limiter(method.as_str(), path, principal)
    }
}

impl RateLimitPolicyState {
    /// The pre-cutover selector over a policy's overrides, without an RBAC
    /// state, for comparing the kernel against it directly.
    pub(crate) fn legacy_for_selection_parity(policy: &Policy) -> Self {
        let live_buckets = Arc::new(AtomicUsize::new(0));
        Self {
            selector: None,
            overrides: policy
                .rate_limits
                .iter()
                .cloned()
                .map(|rule| {
                    RateLimitOverride::new(
                        rule,
                        1,
                        Duration::from_secs(1),
                        Arc::clone(&live_buckets),
                    )
                })
                .collect(),
        }
    }

    /// The limit the first matching override declares, without touching a
    /// limiter or a bucket.
    pub(crate) fn legacy_selected_override_limit(
        &self,
        method: &str,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> Option<(usize, f64, u32)> {
        self.overrides
            .iter()
            .enumerate()
            .find(|(_, override_rule)| override_rule.legacy_matches(method, path, principal))
            .map(|(index, override_rule)| {
                (
                    index,
                    override_rule.rule.requests_per_second,
                    override_rule.rule.burst,
                )
            })
    }

    fn legacy_matching_limiter(
        &self,
        method: &str,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> Option<PolicyMatch> {
        self.overrides
            .iter()
            .find(|override_rule| override_rule.legacy_matches(method, path, principal))
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
    fn legacy_matches(
        &self,
        method: &str,
        path: &str,
        principal: Option<&auth::Principal>,
    ) -> bool {
        self.rule.principal.matches(principal)
            && method_matches(&self.rule.methods, method)
            && self
                .rule
                .path
                .as_ref()
                .is_none_or(|pattern| path_pattern_matches(pattern, path))
    }
}

/// The pre-cutover policy stage, guard included: a request with no principal
/// returns before the selector is consulted.
pub(crate) async fn legacy_policy_rate_limit_request(
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
    let Some(matched) = state.legacy_policy_limiter(&method, &path, Some(principal)) else {
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

/// The override the frozen selector picks for a request, as the frozen stage
/// would consult it: `None` for an anonymous caller, before any rule is read.
/// Reported as its fingerprint and limit, which is what the stage acts on.
pub(crate) fn legacy_selection(
    state: &RateLimitState,
    method: &Method,
    path: &str,
    principal: Option<&auth::Principal>,
) -> Option<(Arc<str>, f64, u32)> {
    let principal = principal?;
    state
        .legacy_policy_limiter(method, path, Some(principal))
        .map(|matched| {
            (
                matched.fingerprint,
                matched.limit.requests_per_second,
                matched.limit.burst,
            )
        })
}
