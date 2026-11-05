//! The required policy test suite (issue #243): with
//! `POLICY_TESTS_REQUIRED=true`, a policy change is activated only when the
//! stored `policy-tests.v1` suite (`admin_policy_tests`) passes against it.
//!
//! Every publication the policy API makes asks [`admit_required_policy_tests`]
//! inside its commit precondition: under the policy write lock, after the
//! cross-resource checks, before anything is written. That is
//! `commit_policy_mutation`, which `PUT .../policy`, rollback, rule create,
//! update (a promotion or disable bound to a shadow review included), delete
//! and reorder, a draft publication and a standalone suggestion acceptance
//! commit through, and the cluster-mode suggestion acceptance, which commits
//! inside the suggestion's transaction.
//!
//! The rules the gate keeps:
//!
//! - **Fail closed.** A publication goes ahead only when a suite is stored,
//!   verifies, and every one of its cases passed against the candidate. No
//!   suite, a stored suite that no longer verifies, a failed, refused or
//!   undecided case, a run that decided fewer cases than the suite holds, a
//!   candidate that did not compile and a run past its deadline all refuse it,
//!   and nothing is written. An evaluator error is never a pass.
//! - **The runner a test run uses.** The suite runs through
//!   `policy_testing::run_against_policy` against the candidate exactly as it
//!   would be committed, with the synthetic resources a run reads
//!   ([`synthetic_resources`]), on a blocking thread and within a run's
//!   five-second budget ([`POLICY_TEST_RUN_DEADLINE`]). The write lock
//!   serializes it with every other publication on this replica, so at most
//!   one gate evaluation runs per replica at a time.
//! - **Counts only.** A refusal answers `422 policy_tests_required_failed`
//!   (`503 policy_tests_unavailable` when the suite store cannot be read) with
//!   the cause, the stored suite's version and ETag and the five summary
//!   counts, and is audited as `policy.publication_refused` with the same.
//!   Neither ever carries a case id, a fixture value or a matched element.
//! - **Storing a suite is never gated.** `PUT .../policy/tests` stores a suite
//!   the active policy fails, and reports what the gate would answer
//!   ([`report_required_tests`]), so an operator can always store the suite
//!   the next policy must pass.
//!
//! The suite is read once per publication. In cluster mode another replica
//! can replace it between that read and the policy commit; the
//! `policy.changed` record names the suite version that admitted the change.
//! Bundle activation (#242) has no runtime path in this build, so there is
//! nothing there to gate yet.
use super::*;

use policy_testing::runner::{RunStatus, Summary};
use storage::policy_tests::PolicyTestSuiteRecord;

/// The stable reason of a publication the required suite did not admit.
pub(super) const POLICY_TESTS_REQUIRED_FAILED_REASON: &str = "policy_tests_required_failed";
/// The stable reason of a publication refused because the suite store could
/// not be read: the same reason the suite routes answer then.
pub(super) const POLICY_TESTS_UNAVAILABLE_REASON: &str = "policy_tests_unavailable";
/// What `PUT .../policy/tests` reports, with the gate on: what the gate would
/// answer for the active policy under the suite just stored.
pub(super) const POLICY_TESTS_ACTIVE_STATUS_HEADER: &str =
    "x-greengateway-policy-tests-active-status";

/// Why the required suite did not admit a policy. Each has a stable code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequiredTestsCause {
    /// No suite is stored.
    SuiteMissing,
    /// The stored suite does not verify: a row edited out of band, or a
    /// suite this build no longer accepts.
    SuiteInvalid,
    /// No suite store is configured, or it could not be read.
    SuiteUnavailable,
    /// At least one case's expectation did not hold.
    Failed,
    /// At least one case could not be decided, or the run decided fewer
    /// cases than the suite holds.
    Incomplete,
    /// The evaluator refused at least one case.
    Error,
    /// The run did not finish within its deadline.
    DeadlineExceeded,
    /// The policy did not compile, could not be read, or the evaluation did
    /// not complete.
    EvaluationFailed,
}

impl RequiredTestsCause {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::SuiteMissing => "suite_missing",
            Self::SuiteInvalid => "suite_invalid",
            Self::SuiteUnavailable => "suite_unavailable",
            Self::Failed => "failed",
            Self::Incomplete => "incomplete",
            Self::Error => "error",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::EvaluationFailed => "evaluation_failed",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::SuiteUnavailable => POLICY_TESTS_UNAVAILABLE_REASON,
            _ => POLICY_TESTS_REQUIRED_FAILED_REASON,
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::SuiteUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    fn commit_refusal(self) -> PolicyCommitRefusal {
        match self {
            Self::SuiteUnavailable => PolicyCommitRefusal::RequiredTestsUnavailable,
            _ => PolicyCommitRefusal::RequiredTestsFailed,
        }
    }
}

/// The stored suite a gate decision read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RequiredSuite {
    pub(super) version: i64,
    pub(super) etag: String,
}

/// What the required suite said about one policy: passed, or the cause it
/// did not, with the counts of a run that completed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RequiredTestsRun {
    suite: Option<RequiredSuite>,
    summary: Option<Summary>,
    cause: Option<RequiredTestsCause>,
}

impl RequiredTestsRun {
    fn refused(suite: Option<RequiredSuite>, cause: RequiredTestsCause) -> Self {
        Self {
            suite,
            summary: None,
            cause: Some(cause),
        }
    }

    /// `passed`, or the refusal cause.
    pub(super) fn status(&self) -> &'static str {
        self.cause.map_or("passed", RequiredTestsCause::as_str)
    }

    /// The suite and the count of cases that passed, when every case did.
    fn passed(&self) -> Option<RequiredTestsPassed> {
        match (self.cause, &self.suite, &self.summary) {
            (None, Some(suite), Some(summary)) => Some(RequiredTestsPassed {
                suite: suite.clone(),
                total: summary.total,
            }),
            _ => None,
        }
    }

    /// The decision in counts: the cause, the suite's version and ETag, and
    /// the five summary counts of a run that completed (`null` otherwise).
    pub(super) fn to_json(&self) -> Value {
        json!({
            "status": self.status(),
            "suite_version": self.suite.as_ref().map(|suite| suite.version),
            "suite_etag": self.suite.as_ref().map(|suite| suite.etag.as_str()),
            "summary": self.summary,
        })
    }

    fn refusal_response(&self, cause: RequiredTestsCause) -> Response {
        let error = match cause {
            RequiredTestsCause::SuiteUnavailable => {
                "the stored policy test suite this deployment requires could not be read; nothing was written"
            }
            _ => "the stored policy test suite this deployment requires did not pass against this policy; nothing was written",
        };
        (
            cause.status(),
            Json(json!({
                "error": error,
                "reason": cause.reason(),
                "required_tests": self.to_json(),
            })),
        )
            .into_response()
    }
}

/// A publication the required suite admitted, for its `policy.changed`
/// record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RequiredTestsPassed {
    suite: RequiredSuite,
    total: usize,
}

impl RequiredTestsPassed {
    pub(super) fn to_json(&self) -> Value {
        json!({
            "suite_version": self.suite.version,
            "suite_etag": self.suite.etag,
            "total": self.total,
            "passed": self.total,
        })
    }
}

/// How a run of the stored suite ended, before it is judged.
pub(super) enum RequiredRunEnd {
    Completed(Summary),
    DeadlineExceeded,
    EvaluationFailed,
}

/// Judge one run of a suite of `case_count` cases. Passed only when the
/// runner's own status is `passed` and every case of the suite was decided
/// and passed: a run that decided fewer cases than the suite holds is
/// incomplete, whatever its status says.
pub(super) fn required_tests_verdict(
    suite: RequiredSuite,
    end: RequiredRunEnd,
    case_count: usize,
) -> RequiredTestsRun {
    let summary = match end {
        RequiredRunEnd::Completed(summary) => summary,
        RequiredRunEnd::DeadlineExceeded => {
            return RequiredTestsRun::refused(Some(suite), RequiredTestsCause::DeadlineExceeded)
        }
        RequiredRunEnd::EvaluationFailed => {
            return RequiredTestsRun::refused(Some(suite), RequiredTestsCause::EvaluationFailed)
        }
    };
    let every_case_passed =
        case_count > 0 && summary.total == case_count && summary.passed == case_count;
    let cause = match summary.status() {
        RunStatus::Error => Some(RequiredTestsCause::Error),
        RunStatus::Incomplete => Some(RequiredTestsCause::Incomplete),
        RunStatus::Failed => Some(RequiredTestsCause::Failed),
        RunStatus::Passed if every_case_passed => None,
        RunStatus::Passed => Some(RequiredTestsCause::Incomplete),
    };
    RequiredTestsRun {
        suite: Some(suite),
        summary: Some(summary),
        cause,
    }
}

/// The stored suite, or why there is none to run.
async fn required_suite(
    state: &PolicyAdminState,
) -> Result<PolicyTestSuiteRecord, RequiredTestsCause> {
    let Some(store) = state.test_suite_store.as_ref() else {
        tracing::error!("policy tests are required, but no policy test suite store is configured");
        return Err(RequiredTestsCause::SuiteUnavailable);
    };
    match store.active().await {
        Ok(Some(record)) => Ok(record),
        Ok(None) => Err(RequiredTestsCause::SuiteMissing),
        Err(error) if error.kind() == storage::RepositoryErrorKind::InvalidData => {
            tracing::error!(
                error = %error,
                "the stored policy test suite does not verify; publication is refused"
            );
            Err(RequiredTestsCause::SuiteInvalid)
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "the stored policy test suite could not be read; publication is refused"
            );
            Err(RequiredTestsCause::SuiteUnavailable)
        }
    }
}

/// Run `record`'s suite against `policy` and judge it. The policy is judged
/// as a candidate is, with no live revision.
async fn run_required_suite(
    rbac_state: &middleware::rbac::RbacState,
    record: PolicyTestSuiteRecord,
    policy: rbac::Policy,
) -> RequiredTestsRun {
    let suite_binding = RequiredSuite {
        version: record.version,
        etag: record.etag.clone(),
    };
    let case_count = record.case_count();
    let suite = record.suite;
    let resources = synthetic_resources(rbac_state);
    // The deadline starts before compilation, so compiling counts against
    // it, as it does for a test run.
    let run = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + POLICY_TEST_RUN_DEADLINE;
        policy_testing::run_against_policy(
            policy,
            policy_eval::PolicyAuthority::Standalone,
            &suite,
            &resources,
            deadline,
        )
    })
    .await;
    let end = match run {
        Ok(Ok(outcome)) => RequiredRunEnd::Completed(outcome.summary),
        Ok(Err(policy_testing::RunError::DeadlineExceeded)) => RequiredRunEnd::DeadlineExceeded,
        Ok(Err(policy_testing::RunError::Compile(error))) => {
            tracing::error!(error = ?error, "a policy under required tests could not be compiled");
            RequiredRunEnd::EvaluationFailed
        }
        Err(error) => {
            tracing::error!(error = %error, "a required policy test run did not complete");
            RequiredRunEnd::EvaluationFailed
        }
    };
    required_tests_verdict(suite_binding, end, case_count)
}

/// Refuse a publication the required suite does not admit, before any
/// authority sees it. `Ok(None)` when tests are not required; `Ok(Some)`
/// names the suite that admitted the candidate. A refusal is audited as
/// `policy.publication_refused` with its code and counts, and nothing is
/// written.
pub(super) async fn admit_required_policy_tests(
    request: PublicationRequest<'_>,
    live_etag: &str,
    candidate: &rbac::Policy,
    diff_summary: &Value,
    resource_snapshot_digest: Option<&str>,
) -> Result<Option<RequiredTestsPassed>, PolicyMutationFailure> {
    if !request.state.policy_tests_required {
        return Ok(None);
    }
    let run = match required_suite(request.state).await {
        Ok(record) => run_required_suite(request.rbac_state, record, candidate.clone()).await,
        Err(cause) => RequiredTestsRun::refused(None, cause),
    };
    if let Some(passed) = run.passed() {
        return Ok(Some(passed));
    }
    // A run that names no cause always carries its suite and counts; one
    // that does not is refused, never read as a pass.
    let run = if run.cause.is_some() {
        run
    } else {
        tracing::error!("a required policy test pass carried no suite or counts");
        RequiredTestsRun::refused(run.suite, RequiredTestsCause::EvaluationFailed)
    };
    Err(refuse(
        request,
        live_etag,
        diff_summary,
        resource_snapshot_digest,
        &run,
    ))
}

fn refuse(
    request: PublicationRequest<'_>,
    live_etag: &str,
    diff_summary: &Value,
    resource_snapshot_digest: Option<&str>,
    run: &RequiredTestsRun,
) -> PolicyMutationFailure {
    let cause = run.cause.unwrap_or(RequiredTestsCause::EvaluationFailed);
    emit_policy_publication_refused(
        request.state,
        request.parts,
        request.principal,
        PolicyPublicationRefusal {
            action: diff_summary.get("action").and_then(Value::as_str),
            codes: &[cause.reason()],
            policy_etag: live_etag,
            resource_snapshot_digest,
            required_tests: Some(run.to_json()),
        },
    );
    PolicyMutationFailure::Refused(
        cause.commit_refusal(),
        Box::new(run.refusal_response(cause)),
    )
}

/// With tests required, what the gate would answer for the active policy
/// under `record`: reported when a suite is stored, never a reason to
/// refuse storing it. `None` when tests are not required.
pub(super) async fn report_required_tests(
    state: &PolicyAdminState,
    record: PolicyTestSuiteRecord,
) -> Option<RequiredTestsRun> {
    if !state.policy_tests_required {
        return None;
    }
    let suite = RequiredSuite {
        version: record.version,
        etag: record.etag.clone(),
    };
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Some(RequiredTestsRun::refused(
            Some(suite),
            RequiredTestsCause::EvaluationFailed,
        ));
    };
    let Ok(active) = authoritative_policy(state, rbac_state).await else {
        return Some(RequiredTestsRun::refused(
            Some(suite),
            RequiredTestsCause::EvaluationFailed,
        ));
    };
    Some(run_required_suite(rbac_state, record, active).await)
}
