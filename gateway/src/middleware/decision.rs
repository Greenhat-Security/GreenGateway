use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use serde::Serialize;

/// The stable reason a request carries when it is refused because a
/// security decision it depended on could not be durably recorded under
/// `AUDIT_DURABILITY=required` (issue #425). It is the response's `reason`,
/// the observation's `auth_reason` or `policy_reason`, and nothing else: the
/// store's error never crosses the response boundary.
pub const AUDIT_UNAVAILABLE_REASON: &str = "audit_unavailable";

#[derive(Serialize)]
struct AuditUnavailableBody {
    error: &'static str,
    reason: &'static str,
}

/// `503 {"error":"audit unavailable","reason":"audit_unavailable"}`: the
/// gateway made a decision it cannot evidence, so it does not act on it.
/// The same answer from the authentication and authorization stages, so a
/// client and an operator see one outage, not two.
pub fn audit_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(AuditUnavailableBody {
            error: "audit unavailable",
            reason: AUDIT_UNAVAILABLE_REASON,
        }),
    )
        .into_response()
}

#[derive(Clone, Debug)]
pub struct AuthOutcome {
    pub principal: Option<crate::auth::Principal>,
    pub authenticated: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDecisionOutcome {
    Allowed,
    Denied,
    WouldDeny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub outcome: PolicyDecisionOutcome,
    pub reason: &'static str,
    pub permission: Option<String>,
    pub path_prefix: Option<String>,
    pub matched_rule_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UpstreamOutcome {
    pub latency_ms: u64,
    pub status: Option<u16>,
    pub pool_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub attempts: Vec<UpstreamAttemptOutcome>,
    pub retry_exhausted: bool,
    pub stream_terminal_pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamAttemptOutcome {
    pub endpoint_id: String,
    pub result: String,
    pub duration_ms: u64,
}
