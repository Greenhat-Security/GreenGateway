pub mod engine;
pub mod matcher;
pub mod policy;
pub mod rule;

pub use engine::PolicyEngine;
#[allow(unused_imports)]
// Public direct-rule matcher API is wired into live request handling in a follow-up PR.
pub use matcher::{RuleDecision, RuleMatcher};
pub use policy::{DefaultAction, EgressPolicy, EnforcementMode, Policy, RouteRule};
#[allow(unused_imports)]
// Public rule API is consumed by follow-up matcher and integration PRs.
pub use rule::{PrincipalMatcher, Rule, RuleAction};
