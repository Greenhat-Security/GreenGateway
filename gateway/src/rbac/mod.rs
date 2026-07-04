pub mod engine;
pub mod matcher;
pub mod policy;
pub mod rule;

pub use engine::PolicyEngine;
#[allow(unused_imports)]
// Public direct-rule matcher API is available for tests and future admin APIs.
pub use matcher::{RuleDecision, RuleMatcher};
pub use policy::{DefaultAction, EgressPolicy, EnforcementMode, Policy, RateLimitRule, RouteRule};
#[allow(unused_imports)]
// Public rule API is available for policy construction and future admin APIs.
pub use rule::{PrincipalMatcher, Rule, RuleAction};
