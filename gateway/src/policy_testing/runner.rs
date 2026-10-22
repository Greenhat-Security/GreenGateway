//! Decides every case of a suite through the shared evaluator.
//!
//! The runner builds the same typed contexts the live adapters build and asks
//! the same [`CompiledPolicy`] methods: `evaluate` for HTTP, `evaluate_tool` for
//! the tool lane and rendered tool requests, and `select_rate_lane` for rate
//! overrides. It never matches a rule itself, so a test can only ever report
//! what production decides for the same facts.
//!
//! The run is pure. It reads the compiled policy and the suite and returns a
//! report; it performs no I/O, takes no lock, emits no audit event, and
//! touches no rate bucket, tool permit or upstream. Fixture values live only
//! in the suite while the run reads them: the report carries case ids,
//! expectations and stable outcome codes, never a path, host, subject, role or
//! tool name a case supplied.

use serde::Serialize;

use super::suite::{
    Case, CaseInput, CaseKind, DecisionExpectation, MatchedExpectation, RateExpectation, Suite,
    SyntheticPrincipal, SyntheticTarget,
};
use crate::{
    policy_eval::{
        tools::{ToolEvaluationContext, ToolLimitation, ToolReason, TOOL_CONTEXT_VERSION},
        CompiledPolicy, EvaluationError, HostFact, HttpTarget, Limitation, LogicalDecision,
        PolicyEffect, PolicyEvaluationContext, PrincipalFact, PrincipalIdentity, RateLaneOutcome,
        Reason, RuleReference, CONTEXT_VERSION,
    },
    rbac::Policy,
};

/// A policy compiled for a run, with the effective identifier of each direct
/// rule so a matched rule can be reported the way every policy API names it.
///
/// Built from one `Policy` value, so the identifiers and the compiled rules
/// cannot come from two different documents.
pub(crate) struct PolicyUnderTest {
    compiled: CompiledPolicy,
    rule_ids: Vec<String>,
}

impl PolicyUnderTest {
    pub(crate) fn new(compiled: CompiledPolicy, policy: &Policy) -> Self {
        Self {
            compiled,
            rule_ids: policy
                .rules
                .iter()
                .enumerate()
                // The effective id the hit-count, rule and history APIs use.
                .map(|(index, rule)| rule.id.clone().unwrap_or_else(|| index.to_string()))
                .collect(),
        }
    }

    fn rule_id(&self, index: usize) -> Option<&str> {
        self.rule_ids.get(index).map(String::as_str)
    }
}

/// The outcome of one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CaseStatus {
    /// Every stated expectation held.
    Passed,
    /// The evaluator decided, and at least one expectation did not hold.
    Failed,
    /// The evaluator could not decide. Never a pass, whatever was expected.
    Incomplete,
    /// The evaluator refused the case. Never a pass, and never retried.
    Error,
}

impl CaseStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Incomplete => "incomplete",
            Self::Error => "error",
        }
    }
}

/// The outcome of a whole run: `passed` only when every case passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunStatus {
    Passed,
    Failed,
    Incomplete,
    Error,
}

impl RunStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Incomplete => "incomplete",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    pub(crate) total: usize,
    pub(crate) passed: usize,
    pub(crate) failed: usize,
    pub(crate) incomplete: usize,
    pub(crate) errors: usize,
}

impl Summary {
    /// The worst outcome present, worst first: an evaluator error, then an
    /// undecided case, then a failed expectation.
    pub(crate) fn status(&self) -> RunStatus {
        if self.errors > 0 {
            RunStatus::Error
        } else if self.incomplete > 0 {
            RunStatus::Incomplete
        } else if self.failed > 0 || self.passed != self.total || self.total == 0 {
            // An empty run is refused before it starts; `total == 0` here can
            // only be a bug, and a bug must not read as a pass.
            RunStatus::Failed
        } else {
            RunStatus::Passed
        }
    }
}

/// A reference to the policy element that decided, in report form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MatchedView {
    None,
    Rule(String),
    Route(usize),
}

/// What a case expected, echoed in report form. Expectations are the
/// author's assertions, not fixture inputs, so they are safe to repeat.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ExpectedView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) logical: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) effect: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) matched: Option<MatchedView>,
    /// For a rate case: the override position expected to govern, or `null`
    /// for none. Absent on every other kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rate_override: Option<Option<usize>>,
}

/// What the evaluator answered, in stable codes only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ActualView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) logical: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) effect: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) matched: Option<MatchedView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rate_override: Option<Option<usize>>,
    pub(crate) complete: bool,
    pub(crate) limitation: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CaseResult {
    pub(crate) id: String,
    pub(crate) pointer: String,
    pub(crate) kind: CaseKind,
    pub(crate) status: CaseStatus,
    pub(crate) expected: ExpectedView,
    /// Absent exactly when the evaluator refused the case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) actual: Option<ActualView>,
    /// The expectations that did not hold, by name, in a fixed order.
    pub(crate) mismatches: Vec<&'static str>,
    /// The evaluator's refusal, as a stable code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<&'static str>,
}

pub(crate) struct RunOutcome {
    pub(crate) summary: Summary,
    pub(crate) cases: Vec<CaseResult>,
}

impl RunOutcome {
    pub(crate) fn status(&self) -> RunStatus {
        self.summary.status()
    }
}

/// Run every case of `suite` against `policy`, in suite order.
pub(crate) fn run_suite(policy: &PolicyUnderTest, suite: &Suite) -> RunOutcome {
    let mut summary = Summary::default();
    let mut cases = Vec::with_capacity(suite.cases.len());
    for case in &suite.cases {
        let result = run_case(policy, case);
        summary.total += 1;
        match result.status {
            CaseStatus::Passed => summary.passed += 1,
            CaseStatus::Failed => summary.failed += 1,
            CaseStatus::Incomplete => summary.incomplete += 1,
            CaseStatus::Error => summary.errors += 1,
        }
        cases.push(result);
    }
    RunOutcome { summary, cases }
}

fn principal_fact(principal: &SyntheticPrincipal) -> PrincipalFact {
    match principal {
        SyntheticPrincipal::Anonymous => PrincipalFact::Anonymous,
        SyntheticPrincipal::Authenticated(principal) => {
            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
        }
    }
}

fn run_case(policy: &PolicyUnderTest, case: &Case) -> CaseResult {
    let compiled = &policy.compiled;
    match &case.input {
        CaseInput::Http {
            request,
            principal,
            expect,
        } => {
            let (target, dispatch) = match &request.target {
                SyntheticTarget::Contextless => (HttpTarget::Contextless, None),
                SyntheticTarget::McpAlias { canonical_path } => (
                    HttpTarget::McpAlias {
                        canonical_path: canonical_path.clone(),
                    },
                    None,
                ),
                SyntheticTarget::ProxyDispatch(facts) => {
                    (HttpTarget::ProxyDispatch, Some(facts.clone()))
                }
            };
            let context = PolicyEvaluationContext {
                version: CONTEXT_VERSION,
                snapshot: compiled.snapshot(),
                method: Some(request.method.clone()),
                path: Some(request.path.clone()),
                principal: principal_fact(principal),
                target,
                // A synthetic request states its host, so it is never the
                // uncaptured `Missing`: no host is a request without one.
                request_host: request
                    .host
                    .clone()
                    .map_or(HostFact::Absent, HostFact::Present),
                dispatch,
            };
            let expected = expected_decision(expect, Reason::as_str);
            match compiled.evaluate(&context) {
                Ok(evaluation) => {
                    let matched = matched_view(policy, evaluation.matched());
                    let mismatches = compare_decision(
                        expect,
                        evaluation.logical(),
                        evaluation.effect(),
                        evaluation.reason() == Reason::Incomplete,
                        |reason| evaluation.reason() == *reason,
                        &matched,
                    );
                    let actual = ActualView {
                        logical: Some(logical_code(evaluation.logical())),
                        effect: Some(effect_code(evaluation.effect())),
                        reason: Some(evaluation.reason().as_str()),
                        matched: Some(matched),
                        rate_override: None,
                        complete: evaluation.is_complete(),
                        limitation: evaluation.limitation().map(limitation_code),
                    };
                    decided(
                        case,
                        expected,
                        actual,
                        evaluation.is_complete()
                            && evaluation.logical() != LogicalDecision::Indeterminate,
                        mismatches,
                    )
                }
                Err(error) => refused(case, expected, error),
            }
        }
        CaseInput::Tool {
            operation,
            tool_name,
            principal,
            expect,
        } => evaluate_tool_case(
            policy,
            case,
            ToolEvaluationContext {
                version: TOOL_CONTEXT_VERSION,
                snapshot: compiled.snapshot(),
                operation: *operation,
                tool_name: Some(tool_name.clone()),
                principal: principal_fact(principal),
                method: None,
                path: None,
            },
            expect,
        ),
        CaseInput::ToolHttp {
            tool_name,
            method,
            path,
            principal,
            expect,
        } => evaluate_tool_case(
            policy,
            case,
            ToolEvaluationContext {
                version: TOOL_CONTEXT_VERSION,
                snapshot: compiled.snapshot(),
                operation: crate::policy_eval::tools::ToolOperation::RenderedHttp,
                tool_name: Some(tool_name.clone()),
                principal: principal_fact(principal),
                method: Some(method.clone()),
                path: Some(path.clone()),
            },
            expect,
        ),
        CaseInput::Rate {
            method,
            path,
            principal,
            expect,
        } => {
            // The live rate adapter's context exactly: selection reads method,
            // path and principal, and states routing and host as uncaptured
            // rather than claim the request had none.
            let context = PolicyEvaluationContext {
                version: CONTEXT_VERSION,
                snapshot: compiled.snapshot(),
                method: Some(method.clone()),
                path: Some(path.clone()),
                principal: principal_fact(principal),
                target: HttpTarget::Missing,
                request_host: HostFact::Missing,
                dispatch: None,
            };
            let expected_override = match expect {
                RateExpectation::NoOverride => None,
                RateExpectation::Override(index) => Some(*index),
            };
            let expected = ExpectedView {
                logical: None,
                effect: None,
                reason: None,
                matched: None,
                rate_override: Some(expected_override),
            };
            match compiled.select_rate_lane(&context) {
                Ok(selection) => {
                    let (selected, limitation) = match selection.outcome() {
                        RateLaneOutcome::NoOverride => (Some(None), None),
                        RateLaneOutcome::Override { index, .. } => (Some(Some(index)), None),
                        RateLaneOutcome::Indeterminate(limitation) => (None, Some(limitation)),
                    };
                    let actual = ActualView {
                        logical: None,
                        effect: None,
                        reason: None,
                        matched: None,
                        rate_override: selected,
                        complete: selected.is_some(),
                        limitation: limitation.map(limitation_code),
                    };
                    let mismatches = if selected == Some(expected_override) {
                        Vec::new()
                    } else {
                        vec!["rate_override"]
                    };
                    decided(case, expected, actual, selected.is_some(), mismatches)
                }
                Err(error) => refused(case, expected, error),
            }
        }
    }
}

fn evaluate_tool_case(
    policy: &PolicyUnderTest,
    case: &Case,
    context: ToolEvaluationContext,
    expect: &DecisionExpectation<ToolReason>,
) -> CaseResult {
    let expected = expected_decision(expect, ToolReason::as_str);
    match policy.compiled.evaluate_tool(&context) {
        Ok(evaluation) => {
            let matched = matched_view(policy, evaluation.matched());
            let mismatches = compare_decision(
                expect,
                evaluation.logical(),
                evaluation.effect(),
                evaluation.reason() == ToolReason::Incomplete,
                |reason| evaluation.reason() == *reason,
                &matched,
            );
            let actual = ActualView {
                logical: Some(logical_code(evaluation.logical())),
                effect: Some(effect_code(evaluation.effect())),
                reason: Some(evaluation.reason().as_str()),
                matched: Some(matched),
                rate_override: None,
                complete: evaluation.is_complete(),
                limitation: evaluation.limitation().map(tool_limitation_code),
            };
            decided(
                case,
                expected,
                actual,
                evaluation.is_complete() && evaluation.logical() != LogicalDecision::Indeterminate,
                mismatches,
            )
        }
        Err(error) => refused(case, expected, error),
    }
}

/// The expectations of a decision that did not hold, in a fixed order.
fn compare_decision<R>(
    expect: &DecisionExpectation<R>,
    logical: LogicalDecision,
    effect: PolicyEffect,
    incomplete: bool,
    reason_matches: impl Fn(&R) -> bool,
    matched: &MatchedView,
) -> Vec<&'static str> {
    let mut mismatches = Vec::new();
    if incomplete || logical != expect.logical {
        mismatches.push("logical");
    }
    if expect.effect.is_some_and(|expected| expected != effect) {
        mismatches.push("effect");
    }
    if expect
        .reason
        .as_ref()
        .is_some_and(|expected| !reason_matches(expected))
    {
        mismatches.push("reason");
    }
    if expect
        .matched
        .as_ref()
        .is_some_and(|expected| !matched_equals(expected, matched))
    {
        mismatches.push("matched");
    }
    mismatches
}

fn matched_equals(expected: &MatchedExpectation, actual: &MatchedView) -> bool {
    match (expected, actual) {
        (MatchedExpectation::None, MatchedView::None) => true,
        (MatchedExpectation::Rule(expected), MatchedView::Rule(actual)) => expected == actual,
        (MatchedExpectation::Route(expected), MatchedView::Route(actual)) => expected == actual,
        _ => false,
    }
}

fn decided(
    case: &Case,
    expected: ExpectedView,
    actual: ActualView,
    complete: bool,
    mismatches: Vec<&'static str>,
) -> CaseResult {
    // An undecided answer is incomplete whatever it was compared with: a
    // missing fact must never be able to satisfy an expectation.
    let status = if !complete {
        CaseStatus::Incomplete
    } else if mismatches.is_empty() {
        CaseStatus::Passed
    } else {
        CaseStatus::Failed
    };
    CaseResult {
        id: case.id.clone(),
        pointer: case.pointer.clone(),
        kind: case.input.kind(),
        status,
        expected,
        actual: Some(actual),
        mismatches,
        error: None,
    }
}

fn refused(case: &Case, expected: ExpectedView, error: EvaluationError) -> CaseResult {
    CaseResult {
        id: case.id.clone(),
        pointer: case.pointer.clone(),
        kind: case.input.kind(),
        status: CaseStatus::Error,
        expected,
        actual: None,
        mismatches: Vec::new(),
        error: Some(evaluation_error_code(error)),
    }
}

fn expected_decision<R>(
    expect: &DecisionExpectation<R>,
    reason_code: fn(R) -> &'static str,
) -> ExpectedView
where
    R: Copy,
{
    ExpectedView {
        logical: Some(logical_code(expect.logical)),
        effect: expect.effect.map(effect_code),
        reason: expect.reason.map(reason_code),
        matched: expect.matched.as_ref().map(|matched| match matched {
            MatchedExpectation::None => MatchedView::None,
            MatchedExpectation::Rule(id) => MatchedView::Rule(id.clone()),
            MatchedExpectation::Route(index) => MatchedView::Route(*index),
        }),
        rate_override: None,
    }
}

fn matched_view(policy: &PolicyUnderTest, matched: Option<RuleReference>) -> MatchedView {
    match matched {
        None => MatchedView::None,
        Some(RuleReference::Direct(index)) => match policy.rule_id(index) {
            Some(id) => MatchedView::Rule(id.to_owned()),
            // The compiled rules and the ids come from one policy, so an
            // index outside it is impossible; report the position rather
            // than invent a name.
            None => MatchedView::Rule(index.to_string()),
        },
        Some(RuleReference::Route(index)) => MatchedView::Route(index),
    }
}

pub(crate) fn logical_code(logical: LogicalDecision) -> &'static str {
    match logical {
        LogicalDecision::Allow => "allow",
        LogicalDecision::Deny => "deny",
        LogicalDecision::Indeterminate => "indeterminate",
    }
}

pub(crate) fn effect_code(effect: PolicyEffect) -> &'static str {
    match effect {
        PolicyEffect::Allow => "allow",
        PolicyEffect::Block => "block",
        PolicyEffect::Observe => "observe",
    }
}

/// The trace's stable limitation codes, matching the evaluator's own
/// serialization of [`Limitation`].
fn limitation_code(limitation: Limitation) -> &'static str {
    match limitation {
        Limitation::MissingMethod => "missing_method",
        Limitation::MissingPath => "missing_path",
        Limitation::MissingPrincipalFact => "missing_principal_fact",
        Limitation::MissingDispatchFact => "missing_dispatch_fact",
        Limitation::MissingHostFact => "missing_host_fact",
    }
}

/// The tool lane's stable limitation codes, matching its serialization of
/// [`ToolLimitation`].
fn tool_limitation_code(limitation: ToolLimitation) -> &'static str {
    match limitation {
        ToolLimitation::ToolName => "missing_tool_name",
        ToolLimitation::Principal => "missing_principal_fact",
        ToolLimitation::Method => "missing_method",
        ToolLimitation::Path => "missing_path",
    }
}

pub(crate) fn evaluation_error_code(error: EvaluationError) -> &'static str {
    match error {
        EvaluationError::UnsupportedContextVersion => "unsupported_context_version",
        EvaluationError::SnapshotMismatch => "snapshot_mismatch",
        EvaluationError::MalformedPath => "malformed_path",
        EvaluationError::ContextTooLarge => "context_too_large",
        EvaluationError::InvalidPrincipal => "invalid_principal",
        EvaluationError::InvalidHost => "invalid_host",
        EvaluationError::InconsistentContext => "inconsistent_context",
        EvaluationError::InternalInvariant => "internal_invariant",
        EvaluationError::TraceEncoding => "trace_encoding",
        EvaluationError::TraceTooLarge => "trace_too_large",
    }
}
