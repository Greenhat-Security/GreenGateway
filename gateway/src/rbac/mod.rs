pub mod engine;
pub mod policy;
pub mod rule;

pub use engine::PolicyEngine;
pub use policy::{DefaultAction, EgressPolicy, EnforcementMode, Policy, RateLimitRule, RouteRule};
#[allow(unused_imports)]
// Public rule API is consumed by follow-up matcher and integration PRs.
pub use rule::{PrincipalMatcher, Rule, RuleAction};
