//! `ggctl doctor --env FILE`: the offline checks on an environment file.
//!
//! Two required checks come from reading the file (`environment.file`) and
//! compiling it with the gateway's own configuration compiler
//! (`environment.compiler`), and one piece of advice from the grammar
//! (`environment.duplicate_keys`). Environment mode has no deployment
//! profile, so the rest evaluates what the compiled plan configures against
//! ADR-0008's production profile as advice: each such check is `warning`
//! severity, so it can warn and never fails the doctor. Only invariants the
//! plan itself shows are evaluated; the policy invariants (default deny,
//! enforce mode, no wildcard role) live in the document `POLICY_FILE` names,
//! which an offline check of the environment file does not read, so that
//! check is `skipped` whenever a policy file is set.

use std::time::{Duration, Instant};

use gateway_config::compiler::{AuditDurability, AuthMode, ConfigPlan};

use super::{CheckRecord, Reason, Status};
use crate::{env::EnvRead, report::ReportDiagnostic};

/// The checks of an environment file, in the order they are reported.
pub(crate) const CHECKS: &[&str] = &[
    "environment.file",
    "environment.duplicate_keys",
    "environment.compiler",
    "production.authentication",
    "production.policy",
    "production.csrf",
    "production.private_egress",
    "production.audit_durability",
    "production.client_secrets",
];

/// A production-profile invariant the compiled plan shows: whether `plan`
/// keeps it, and the reason when it does not.
struct Advice {
    id: &'static str,
    evaluate: fn(&ConfigPlan) -> (Status, Reason),
}

const ADVICE: &[Advice] = &[
    Advice {
        id: "production.authentication",
        evaluate: |plan| {
            let identity = &plan.identity;
            keeps(
                identity.auth_enabled && identity.auth_mode == AuthMode::Required,
                Reason::AuthenticationNotRequired,
            )
        },
    },
    Advice {
        id: "production.policy",
        evaluate: |plan| match plan.storage.policy_file {
            Some(_) => (Status::Skipped, Reason::PolicyNotRead),
            None => (Status::Warning, Reason::PolicyNotConfigured),
        },
    },
    Advice {
        id: "production.csrf",
        evaluate: |plan| keeps(plan.identity.csrf_enabled, Reason::CsrfDisabled),
    },
    Advice {
        id: "production.private_egress",
        evaluate: |plan| {
            keeps(
                plan.egress.egress_deny_private_ips,
                Reason::PrivateEgressAllowed,
            )
        },
    },
    Advice {
        id: "production.audit_durability",
        evaluate: |plan| {
            keeps(
                plan.runtime.audit_durability == AuditDurability::Required,
                Reason::AuditBestEffort,
            )
        },
    },
    Advice {
        id: "production.client_secrets",
        evaluate: |plan| {
            keeps(
                plan.identity
                    .auth_providers
                    .iter()
                    .all(|provider| provider.client_secret.is_none()),
                Reason::InlineClientSecret,
            )
        },
    },
];

fn keeps(kept: bool, otherwise: Reason) -> (Status, Reason) {
    if kept {
        (Status::Pass, Reason::Passed)
    } else {
        (Status::Warning, otherwise)
    }
}

/// The first of the file's diagnostics that `matches`.
fn first(read: &EnvRead, matches: impl Fn(&ReportDiagnostic) -> bool) -> Option<&ReportDiagnostic> {
    read.diagnostics
        .iter()
        .find(|diagnostic| matches(diagnostic))
}

/// Every check of an environment file, in [`CHECKS`] order. `took` is how
/// long reading and compiling the file took, which the checks drawn from
/// that one run all report.
pub(crate) fn checks(read: &EnvRead, took: Duration) -> Vec<CheckRecord> {
    let mut checks = Vec::with_capacity(CHECKS.len());
    let file_problem = first(read, |diagnostic| {
        diagnostic.code() != "env.duplicate_key" && diagnostic.code().starts_with("env.")
    });
    checks.push(match file_problem {
        Some(diagnostic) => {
            CheckRecord::from_diagnostic(CHECKS[0], true, Status::Fail, diagnostic, took)
        }
        None => CheckRecord::new(CHECKS[0], true, Status::Pass, Reason::Passed, took),
    });
    let duplicate = first(read, |diagnostic| diagnostic.code() == "env.duplicate_key");
    checks.push(match (&read.file, duplicate) {
        (None, _) => CheckRecord::new(CHECKS[1], false, Status::Skipped, Reason::Incomplete, took),
        (Some(_), Some(diagnostic)) => {
            CheckRecord::from_diagnostic(CHECKS[1], false, Status::Warning, diagnostic, took)
        }
        (Some(_), None) => CheckRecord::new(CHECKS[1], false, Status::Pass, Reason::Passed, took),
    });
    let refused = first(read, |diagnostic| {
        diagnostic.code().starts_with("config.") || diagnostic.code().starts_with("source.")
    });
    checks.push(match (&read.compiled, refused) {
        (Some(Ok(_)), _) => CheckRecord::new(CHECKS[2], true, Status::Pass, Reason::Passed, took),
        (Some(Err(_)), Some(diagnostic)) => {
            CheckRecord::from_diagnostic(CHECKS[2], true, Status::Fail, diagnostic, took)
        }
        // A refusal always carries at least one diagnostic; were it ever
        // to carry none, the check still fails rather than passing.
        (Some(Err(_)), None) => {
            CheckRecord::new(CHECKS[2], true, Status::Fail, Reason::Incomplete, took)
        }
        (None, _) => CheckRecord::new(CHECKS[2], true, Status::Skipped, Reason::Incomplete, took),
    });
    for advice in ADVICE {
        let started = Instant::now();
        let (status, reason) = match read.plan() {
            Some(plan) => (advice.evaluate)(plan),
            // Advice about a configuration the gateway would refuse, or a
            // file with a line no reader can apply, would be advice about
            // something that is not what the file configures.
            None => (Status::Skipped, Reason::Incomplete),
        };
        checks.push(CheckRecord::new(
            advice.id,
            false,
            status,
            reason,
            started.elapsed(),
        ));
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_advice_follows_the_check_list() {
        let ids: Vec<_> = ADVICE.iter().map(|advice| advice.id).collect();
        assert_eq!(ids, CHECKS[3..]);
    }
}
