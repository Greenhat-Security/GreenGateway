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

#[derive(Clone, Debug)]
pub struct PolicyDecision {
    pub outcome: PolicyDecisionOutcome,
    pub reason: &'static str,
    pub permission: Option<String>,
    pub path_prefix: Option<String>,
}
