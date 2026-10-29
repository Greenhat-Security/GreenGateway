pub mod conditions;
pub mod engine;
pub mod identity_mappings;
pub mod matcher;
pub mod policy;
pub mod policy_conversion;
pub mod policy_document;
pub mod policy_history;
pub mod rule;

pub use engine::PolicyEngine;
#[allow(unused_imports)]
// The direct-rule matcher backs the shared policy evaluator (`policy_eval`),
// its only serving consumer; tests and the frozen oracles also name it.
pub use matcher::{RuleDecision, RuleDispatchContext, RuleMatcher};
pub use policy::{DefaultAction, EgressPolicy, EnforcementMode, Policy, RateLimitRule, RouteRule};
#[allow(unused_imports)]
// Public policy-history API is used by the admin control plane and rollback workflow.
pub use policy_history::{PolicyHistoryListFilters, PolicyHistoryPage, PolicyHistoryStore};
#[allow(unused_imports)]
// Public rule API is available for policy construction and future admin APIs.
pub use rule::{PrincipalMatcher, Rule, RuleAction, RuleDispatchKind, RuleDispatchMatcher};
