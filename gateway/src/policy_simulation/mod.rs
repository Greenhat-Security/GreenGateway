//! Synthetic whole-policy simulation (issue #243, slice 10).
//!
//! A simulation evaluates operator-supplied hypothetical cases -- the typed
//! HTTP, tool, rendered-tool and rate-override contexts a `policy-tests.v1`
//! case states, without an expectation -- against the active policy and a
//! candidate, and explains each decision at a requested trace level.
//!
//! The pieces:
//!
//! - [`request`] parses the strict, exact-version `policy-simulation.v1`
//!   request: the pinned base ETag, the candidate source, the trace level,
//!   the projections and the cases. Cases go through the test-suite parser
//!   ([`crate::policy_testing::suite`]), so a simulated case and a test case
//!   with the same facts are the same question.
//! - [`edits`] applies explicit, position-aware edits (`insert`, `replace`,
//!   `move`, `delete`, `set`) to the pinned base. There is no append in an
//!   unstated position: every edit names where it lands.
//! - [`run`] decides every case through the compiled evaluator the live
//!   adapters call ([`crate::policy_eval`]), under each requested projection,
//!   for the candidate and -- when the candidate differs from it -- for the
//!   base, and renders the results.
//!
//! ## Projections
//!
//! `as_authored` evaluates the policy as written. `enforce_all_shadow`
//! evaluates a hypothetical in which every shadow became enforcing: each
//! direct `shadow` rule a `deny`, the global enforcement mode `enforce`, and
//! every per-route `shadow` override `enforce`. The projection is an
//! in-memory copy compiled for the run; nothing is rewritten, stored or
//! activated. It is the question "what would block if I promoted every
//! shadow", and it never previews an intended allow.
//!
//! ## No side effects
//!
//! The run is pure: it reads two policies and the cases and returns values.
//! It performs no I/O, takes no lock, emits no audit event or metric, reads
//! or charges no rate bucket, acquires no tool permit, resolves no name and
//! contacts no upstream; the only record a simulation leaves is the one
//! `policy.simulation_run` audit event the admin endpoint emits after it.

pub(crate) mod edits;
pub(crate) mod request;
pub(crate) mod run;
#[cfg(test)]
mod tests;

use crate::rbac::{EnforcementMode, Policy, RuleAction};

/// The only request schema this module implements.
pub(crate) const SIMULATION_SCHEMA_VERSION: &str = "policy-simulation.v1";
/// The schema of the result document.
pub(crate) const RESULT_SCHEMA_VERSION: &str = "policy-simulation-results.v1";
/// The media type the request digest is framed with.
pub(crate) const SIMULATION_MEDIA_TYPE: &str =
    "application/vnd.greengateway.policy-simulation+json";

/// How much of each decision a result explains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraceLevel {
    /// Outcome only: logical decision, enforcement, effective action, reason
    /// and completeness.
    Terminal,
    /// The outcome and the policy element that decided it.
    Matched,
    /// The outcome, the element, and the evaluator's own stage steps.
    Full,
}

impl TraceLevel {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Matched => "matched",
            Self::Full => "full",
        }
    }
}

/// A non-mutating view of a policy a simulation evaluates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Projection {
    /// The policy as written.
    AsAuthored,
    /// Every shadow treated as enforcing; see the module documentation.
    EnforceAllShadow,
}

impl Projection {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::AsAuthored => "as_authored",
            Self::EnforceAllShadow => "enforce_all_shadow",
        }
    }

    /// The policy this projection evaluates, as a new value.
    pub(crate) fn apply(self, policy: &Policy) -> Policy {
        match self {
            Self::AsAuthored => policy.clone(),
            Self::EnforceAllShadow => enforce_all_shadow(policy),
        }
    }
}

/// `policy` with every shadow made enforcing.
///
/// A route keeps its own override, now `enforce`, rather than losing it, so a
/// trace still says whether the route's mode was its own or inherited. Rule
/// order, identifiers and every other field are untouched, so a position in
/// the projection names the same element as in the policy it came from. The
/// change touches only enum values that policy validation does not constrain,
/// so the projection is valid exactly when the policy is.
fn enforce_all_shadow(policy: &Policy) -> Policy {
    let mut projected = policy.clone();
    projected.enforcement_mode = EnforcementMode::Enforce;
    for route in &mut projected.routes {
        if route.enforcement_mode.is_some() {
            route.enforcement_mode = Some(EnforcementMode::Enforce);
        }
    }
    for rule in &mut projected.rules {
        if rule.action == RuleAction::Shadow {
            rule.action = RuleAction::Deny;
        }
    }
    projected
}
