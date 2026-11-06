//! The RBAC policy document the gateway enforces (issue #243's policy v0 and
//! v1): its model and its validating parse, shared by the gateway and
//! `ggctl` (issue #242).
//!
//! - [`policy`]: the document, [`Policy::validate_json_value`] and
//!   [`Policy::from_source`];
//! - [`policy_document`]: the schema dispatch, policy v1's closed
//!   vocabulary, the structured diagnostics and the canonical digests;
//! - [`rule`], [`conditions`] and [`identity_mappings`]: direct rules, their
//!   typed conditions and the identity mappings, with their validation;
//! - `path_pattern`: the capture-segment grammar a rule path is checked
//!   against.
//!
//! Everything here is a function of the document it is given: nothing reads
//! a file, a clock or the network. Loading, persisting and watching a policy
//! file, its history, and evaluating a policy against a request stay in the
//! gateway, whose `rbac` modules re-export these.

pub mod conditions;
pub mod identity_mappings;
mod path_pattern;
pub mod policy;
pub mod policy_document;
pub mod rule;

pub use path_pattern::find_malformed_capture_segment;
pub use policy::{DefaultAction, EgressPolicy, EnforcementMode, Policy, RateLimitRule, RouteRule};
pub use rule::{PrincipalMatcher, Rule, RuleAction, RuleDispatchKind, RuleDispatchMatcher};
