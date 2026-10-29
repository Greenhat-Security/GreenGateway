//! Synthetic policy tests (issue #243, slice 11).
//!
//! A test suite is a strict, exact-version `policy-tests.v1` document of
//! operator-authored cases: a typed hypothetical HTTP request, tool question,
//! rendered tool request or rate-override question, with explicit identity
//! facts, and the decision the author expects. [`suite`] parses and bounds
//! it, [`runner`] decides every case through the shared evaluator
//! ([`crate::policy_eval`]) -- the same compiled kernel the live adapters call
//! -- and [`report`] renders the result as stable JSON, SARIF 2.1.0 or JUnit
//! XML.
//!
//! ## What a pass means
//!
//! A passing case says that the policy, as the evaluator decides it, gives the
//! expected answer for the stated facts. It says nothing about the stages
//! outside the policy verdict -- authentication, request validation, rate
//! capacity, egress, transport, the upstream -- which every report lists in
//! `not_evaluated`. An evaluator refusal and an undecided answer are their own
//! outcomes, `error` and `incomplete`, and neither ever counts as a pass; nor
//! can an empty suite, which the parser refuses.
//!
//! ## What is not here yet
//!
//! Suites are submitted with each run. Storing a suite beside the policy with a
//! strong ETag, requiring one before activation, isolated rate-bucket
//! sequences on a virtual clock and the `ggctl policy test` command are later
//! slices; the runner is application-state free so that command can link it.

pub(crate) mod report;
pub(crate) mod runner;
pub(crate) mod suite;
#[cfg(test)]
mod tests;

use std::time::Instant;

use crate::{
    policy_eval::{CompileError, CompiledPolicy, PolicyAuthority},
    rbac::Policy,
};

/// The stages no case's verdict covers, in every lane. Listed in every report
/// so that a passing run cannot be read as a request that would succeed.
pub(crate) const NOT_EVALUATED: &[&str] = &[
    "authentication",
    "csrf",
    "request_admission",
    "request_schema",
    "management_permissions",
    "tool_registry",
    "registry_visibility",
    "composite_grant",
    "http_rendering",
    "mutable_capacity",
    "leases",
    "credentials",
    "egress",
    "dns",
    "transport",
    "upstream_execution",
    "gateway_build_identity",
];

/// Why a run produced no report. Neither is a partial answer.
#[derive(Debug)]
pub(crate) enum RunError {
    /// The policy under test did not compile.
    Compile(CompileError),
    /// The run passed its deadline before every case was decided.
    DeadlineExceeded,
}

/// Compile `policy` and run `suite` against it, deciding no case once
/// `deadline` has passed. Compiling counts against the deadline, since the
/// caller sets it before this starts.
///
/// Compilation goes through [`CompiledPolicy::from_validated_policy`], the
/// constructor the live install paths use, so the policy is judged exactly as
/// an installed snapshot of it would be.
pub(crate) fn run_against_policy(
    policy: Policy,
    authority: PolicyAuthority,
    suite: &suite::Suite,
    deadline: Instant,
) -> Result<runner::RunOutcome, RunError> {
    let under_test = {
        let rule_ids_source = policy.clone();
        let compiled =
            CompiledPolicy::from_validated_policy(policy, authority).map_err(RunError::Compile)?;
        runner::PolicyUnderTest::new(compiled, &rule_ids_source)
    };
    runner::run_suite(&under_test, suite, deadline)
        .map_err(|runner::DeadlineExceeded| RunError::DeadlineExceeded)
}
