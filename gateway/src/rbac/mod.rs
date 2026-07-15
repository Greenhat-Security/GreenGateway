pub mod engine;
pub mod matcher;
pub mod policy;
pub mod policy_history;
pub mod rule;

pub use engine::PolicyEngine;
#[allow(unused_imports)]
// Public direct-rule matcher API is available for tests and future admin APIs.
pub use matcher::{RuleDecision, RuleDispatchContext, RuleMatcher};
pub use policy::{DefaultAction, EgressPolicy, EnforcementMode, Policy, RateLimitRule, RouteRule};
#[allow(unused_imports)]
// Public policy-history API is used by the admin control plane and rollback workflow.
pub use policy_history::{PolicyHistoryListFilters, PolicyHistoryPage, PolicyHistoryStore};
#[allow(unused_imports)]
// Public rule API is available for policy construction and future admin APIs.
pub use rule::{PrincipalMatcher, Rule, RuleAction, RuleDispatchKind, RuleDispatchMatcher};
