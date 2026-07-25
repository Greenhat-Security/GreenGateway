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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamAttemptOutcome {
    pub endpoint_id: String,
    pub result: String,
    pub duration_ms: u64,
}
