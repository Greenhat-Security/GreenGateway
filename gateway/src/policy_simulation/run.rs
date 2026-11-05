//! Decides every simulated case through the shared evaluator and renders the
//! results.
//!
//! Each case becomes the context a live adapter builds -- through the same
//! builders the policy test runner uses -- and is asked of the same
//! [`CompiledPolicy`] methods, with the facts a live lane captures for the
//! case's principal (`case_facts`): `evaluate_with_stages` (which *is*
//! `evaluate_with_facts`, with a collecting sink) for HTTP,
//! `evaluate_tool_with_facts` for the tool lanes and
//! `select_rate_lane_with_facts` for rate overrides, each with a collecting
//! sink. An isolated rate sequence runs on a fresh bucket for the selected
//! lane, and an egress case is asked of the static egress lane, both through
//! [`crate::policy_testing::synthetic`]. Nothing here matches a rule.
//!
//! Results carry case ids, stable codes, element positions and, for an admin
//! who already holds `admin:policy:read`, the matched element's stable `id`
//! and a route's permission -- bounded in length -- and never a value a case
//! supplied: no path, host, address, subject, role, origin or tool name.

use std::time::Instant;

use serde_json::{json, Map, Value};

use super::{Projection, TraceLevel};
use crate::{
    policy_eval::{
        stages::{
            DirectAction, HostUse, HttpStage, IdentityCheck, PermissionCheck, RateStage, ToolEntry,
            ToolRules, ToolStage, UpstreamBinding, MAX_HTTP_STAGES, MAX_RATE_STAGES,
            MAX_TOOL_STAGES,
        },
        tools::{ToolEvaluationContext, ToolOperation, ToolReason},
        CompileError, CompiledPolicy, EvaluationError, LogicalDecision, PolicyAuthority,
        PolicyEffect, PolicyFacts, RateLaneOutcome, Reason, RuleReference,
    },
    policy_testing::{
        runner::{
            case_facts, evaluation_error_code, http_context, limitation_code, logical_code,
            rate_context, step_codes, tool_context, tool_limitation_code,
        },
        suite::{CaseContext, EgressCase, StepOutcome, SyntheticCase},
        synthetic::{
            egress_limitation, egress_reason, evaluate_egress, run_sequence, EgressAnswer,
            SequenceRun, SyntheticResources, MISSING_EGRESS_CONTROLS,
            MISSING_RATE_LANE_CONFIGURATION,
        },
    },
    rbac::{EnforcementMode, Policy, RuleAction},
};

/// Most stage steps one simulation returns across all its evaluations. Each
/// HTTP, tool or rate evaluation returns one step per stage of its lane; past
/// this budget the steps of further evaluations are omitted and the result
/// says so.
pub(crate) const MAX_TRACE_STAGES: usize = 4096;
/// Longest authored element id or route permission a result repeats, in
/// bytes.
/// A longer one is reported by position only, and marked as omitted.
pub(crate) const MAX_ECHOED_POLICY_STRING_BYTES: usize = 128;

/// The order the HTTP lane runs its stages in, as a full trace lists them.
const HTTP_STAGE_NAMES: &[&str] = &[
    "facts",
    "request_host",
    "direct_rules",
    "upstream_host_binding",
    "routes",
    "default",
];
/// The order a tool operation runs its stages in.
const TOOL_STAGE_NAMES: &[&str] = &["facts", "tool_entry", "tool_identity", "tool_rules"];
/// The order a rendered tool request runs its stages in: it is decided by
/// the direct HTTP rules alone.
const RENDERED_TOOL_STAGE_NAMES: &[&str] = &["facts", "rendered_http_rules"];
/// The order the rate lane runs its stages in.
const RATE_STAGE_NAMES: &[&str] = &["facts", "anonymous_bypass", "rate_overrides"];

/// A policy compiled for a simulation, with the authored strings a matched
/// element is reported by. Built from one `Policy` value, so the strings and
/// the compiled rules cannot come from two different documents.
pub(crate) struct SimulatedPolicy {
    compiled: CompiledPolicy,
    rule_ids: Vec<Option<String>>,
    rule_actions: Vec<RuleAction>,
    route_ids: Vec<Option<String>>,
    route_permissions: Vec<String>,
    rate_override_ids: Vec<Option<String>>,
}

impl SimulatedPolicy {
    /// Compile through [`CompiledPolicy::from_validated_policy`], the
    /// constructor every live install path uses.
    pub(crate) fn compile(
        policy: Policy,
        authority: PolicyAuthority,
    ) -> Result<Self, CompileError> {
        let rule_ids = policy.rules.iter().map(|rule| rule.id.clone()).collect();
        let rule_actions = policy
            .rules
            .iter()
            .map(|rule| rule.action.clone())
            .collect();
        let route_ids = policy.routes.iter().map(|route| route.id.clone()).collect();
        let route_permissions = policy
            .routes
            .iter()
            .map(|route| route.permission.clone())
            .collect();
        let rate_override_ids = policy
            .rate_limits
            .iter()
            .map(|rule| rule.id.clone())
            .collect();
        Ok(Self {
            compiled: CompiledPolicy::from_validated_policy(policy, authority)?,
            rule_ids,
            rule_actions,
            route_ids,
            route_permissions,
            rate_override_ids,
        })
    }
}

/// The policies one projection evaluates: the candidate, and the base when
/// the candidate is not the base itself.
pub(crate) struct ProjectedPair {
    pub(crate) projection: Projection,
    pub(crate) candidate: SimulatedPolicy,
    pub(crate) base: Option<SimulatedPolicy>,
}

/// Compile each projection of the candidate, and of the base when the
/// candidate differs from it (`candidate` is `None` when it is the base).
///
/// The base keeps the authority it was read under; a candidate is
/// hypothetical and is bound to no revision.
pub(crate) fn compile_pairs(
    base: &Policy,
    authority: PolicyAuthority,
    candidate: Option<&Policy>,
    projections: &[Projection],
) -> Result<Vec<ProjectedPair>, CompileError> {
    projections
        .iter()
        .map(|projection| {
            let base_policy = SimulatedPolicy::compile(projection.apply(base), authority)?;
            Ok(match candidate {
                None => ProjectedPair {
                    projection: *projection,
                    candidate: base_policy,
                    base: None,
                },
                Some(candidate) => ProjectedPair {
                    projection: *projection,
                    candidate: SimulatedPolicy::compile(
                        projection.apply(candidate),
                        PolicyAuthority::Standalone,
                    )?,
                    base: Some(base_policy),
                },
            })
        })
        .collect()
}

/// Why a simulation produced no result. None of these is a partial answer.
#[derive(Debug)]
pub(crate) enum SimulationError {
    /// A case the evaluator refused as malformed or out of bounds, with its
    /// pointer and the evaluator's stable code.
    CaseRefused { pointer: String, code: &'static str },
    /// The evaluator reported an invariant failure.
    Internal(&'static str),
    /// The run passed its deadline before every case was decided.
    DeadlineExceeded,
}

/// A completed simulation.
pub(crate) struct SimulationOutcome {
    pub(crate) cases: Vec<Value>,
    pub(crate) summary: Value,
    pub(crate) stages_truncated: bool,
}

/// A decision in the result's vocabulary.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Outcome {
    logical: &'static str,
    enforcement: &'static str,
    effective_action: &'static str,
    reason: &'static str,
}

/// What a decision is compared by: the outcome, not the element positions,
/// which an insert before them shifts without changing anything.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Key {
    /// An HTTP or tool decision.
    Decision(Outcome),
    /// An egress verdict, counted apart: admitting a destination is not
    /// forwarding a request.
    Egress(Outcome),
    /// A rate selection. The limits decide every step of a sequence on the
    /// lane, so comparing them compares the sequence too.
    Rate {
        selected: &'static str,
        requests_per_second: Option<f64>,
        burst: Option<u32>,
    },
}

struct Evaluated {
    view: Value,
    key: Key,
}

/// The stage steps a simulation may still return, and whether it has run
/// out. Shared by every lane, so one budget bounds a whole result.
struct StageBudget {
    remaining: usize,
    truncated: bool,
}

impl StageBudget {
    /// Insert the `count` stage steps `render` builds into `view`, or mark
    /// them omitted when the budget cannot hold them all: an evaluation's
    /// stages are listed whole or not at all.
    fn insert(
        &mut self,
        view: &mut Map<String, Value>,
        count: usize,
        render: impl FnOnce() -> Vec<Value>,
    ) {
        if count <= self.remaining {
            self.remaining -= count;
            view.insert("stages".to_owned(), Value::Array(render()));
        } else {
            self.truncated = true;
            view.insert("stages_truncated".to_owned(), json!(true));
        }
    }
}

/// Running counts for one projection's summary.
#[derive(Default)]
struct Counts {
    would_forward: usize,
    would_block: usize,
    unknown: usize,
    shadowed: usize,
    rate_override: usize,
    no_rate_override: usize,
    rate_unknown: usize,
    egress_allow: usize,
    egress_deny: usize,
    egress_unknown: usize,
    changed_from_base: usize,
}

impl Counts {
    fn add(&mut self, key: &Key) {
        match key {
            Key::Decision(outcome) => {
                match outcome.effective_action {
                    "would_forward" => self.would_forward += 1,
                    "would_block" => self.would_block += 1,
                    _ => self.unknown += 1,
                }
                if outcome.enforcement == "shadowed" {
                    self.shadowed += 1;
                }
            }
            Key::Egress(outcome) => match outcome.logical {
                "allow" => self.egress_allow += 1,
                "deny" => self.egress_deny += 1,
                _ => self.egress_unknown += 1,
            },
            Key::Rate { selected, .. } => match *selected {
                "override" => self.rate_override += 1,
                "no_override" => self.no_rate_override += 1,
                _ => self.rate_unknown += 1,
            },
        }
    }
}

/// Decide every case under every projection.
///
/// Pure: reads the compiled policies, the cases and the synthetic
/// resources, and returns values.
pub(crate) fn simulate(
    pairs: &[ProjectedPair],
    cases: &[SyntheticCase],
    trace: TraceLevel,
    resources: &SyntheticResources,
    deadline: Instant,
) -> Result<SimulationOutcome, SimulationError> {
    let mut budget = StageBudget {
        remaining: MAX_TRACE_STAGES,
        truncated: false,
    };
    let mut counts: Vec<Counts> = pairs.iter().map(|_| Counts::default()).collect();
    let mut projection_changed = 0usize;
    let mut rendered = Vec::with_capacity(cases.len());
    for case in cases {
        // A cooperative bound on CPU time: cases are cheap, but a run is
        // never allowed to occupy a blocking thread without limit.
        if Instant::now() > deadline {
            return Err(SimulationError::DeadlineExceeded);
        }
        let mut results = Vec::with_capacity(pairs.len());
        let mut candidate_keys = Vec::with_capacity(pairs.len());
        for (pair, counts) in pairs.iter().zip(counts.iter_mut()) {
            let candidate = evaluate_case(&pair.candidate, case, trace, resources, &mut budget)?;
            counts.add(&candidate.key);
            candidate_keys.push(candidate.key);
            let mut result = Map::new();
            result.insert("projection".to_owned(), json!(pair.projection.as_str()));
            if let Some(base) = &pair.base {
                let base = evaluate_case(base, case, trace, resources, &mut budget)?;
                let changed = base.key != candidate.key;
                if changed {
                    counts.changed_from_base += 1;
                }
                result.insert("base".to_owned(), base.view);
                result.insert("changed".to_owned(), json!(changed));
            }
            result.insert("candidate".to_owned(), candidate.view);
            results.push(Value::Object(result));
        }
        let mut entry = Map::new();
        entry.insert("id".to_owned(), json!(case.id));
        entry.insert("pointer".to_owned(), json!(case.pointer));
        entry.insert("kind".to_owned(), json!(case.context.kind().as_str()));
        entry.insert("results".to_owned(), Value::Array(results));
        if candidate_keys.len() > 1 {
            // Whether promoting every shadow changes this case's answer.
            let changed = candidate_keys.windows(2).any(|pair| pair[0] != pair[1]);
            if changed {
                projection_changed += 1;
            }
            entry.insert("projection_changed".to_owned(), json!(changed));
        }
        rendered.push(Value::Object(entry));
    }
    let mut projections = Map::new();
    for (pair, counts) in pairs.iter().zip(&counts) {
        let mut view = json!({
            "would_forward": counts.would_forward,
            "would_block": counts.would_block,
            "unknown": counts.unknown,
            "shadowed": counts.shadowed,
            "rate_override": counts.rate_override,
            "no_rate_override": counts.no_rate_override,
            "rate_unknown": counts.rate_unknown,
            "egress_allow": counts.egress_allow,
            "egress_deny": counts.egress_deny,
            "egress_unknown": counts.egress_unknown,
        });
        if pair.base.is_some() {
            if let Some(view) = view.as_object_mut() {
                view.insert(
                    "changed_from_base".to_owned(),
                    json!(counts.changed_from_base),
                );
            }
        }
        projections.insert(pair.projection.as_str().to_owned(), view);
    }
    let mut summary = Map::new();
    summary.insert("cases".to_owned(), json!(cases.len()));
    summary.insert("projections".to_owned(), Value::Object(projections));
    if pairs.len() > 1 {
        summary.insert("projection_changed".to_owned(), json!(projection_changed));
    }
    Ok(SimulationOutcome {
        cases: rendered,
        summary: Value::Object(summary),
        stages_truncated: budget.truncated,
    })
}

fn evaluate_case(
    policy: &SimulatedPolicy,
    case: &SyntheticCase,
    trace: TraceLevel,
    resources: &SyntheticResources,
    budget: &mut StageBudget,
) -> Result<Evaluated, SimulationError> {
    let compiled = &policy.compiled;
    let refused = |error: EvaluationError| refusal(case, error);
    match &case.context {
        CaseContext::Http { request, principal } => {
            let context = http_context(compiled.snapshot(), request, principal);
            let mut stages = Vec::with_capacity(MAX_HTTP_STAGES);
            let evaluation = compiled
                .evaluate_with_stages(
                    &context,
                    &case_facts(compiled, principal, &case.facts),
                    &mut stages,
                )
                .map_err(refused)?;
            let outcome = decision_outcome(
                evaluation.logical(),
                evaluation.effect(),
                evaluation.reason().as_str(),
            );
            let mut view = decision_view(
                "http",
                None,
                &outcome,
                evaluation.is_complete(),
                evaluation.limitation().map(limitation_code),
            );
            if trace != TraceLevel::Terminal {
                let matched = evaluation
                    .matched()
                    .map(|element| element_view(policy, element, Some(evaluation.reason())));
                view.insert("matched".to_owned(), matched.unwrap_or(Value::Null));
                let observation = evaluation
                    .observation()
                    .map(|element| element_view(policy, element, None));
                view.insert("observation".to_owned(), observation.unwrap_or(Value::Null));
            }
            if trace == TraceLevel::Full {
                // Every stage is listed, reached or not, so each evaluation
                // returns exactly one step per stage name.
                let indeterminate = evaluation.logical() == LogicalDecision::Indeterminate;
                budget.insert(&mut view, HTTP_STAGE_NAMES.len(), || {
                    ordered_stages(
                        HTTP_STAGE_NAMES,
                        &stages,
                        indeterminate,
                        stage_name,
                        |stage| stage_view(policy, stage),
                    )
                });
            }
            Ok(Evaluated {
                view: Value::Object(view),
                key: Key::Decision(outcome),
            })
        }
        CaseContext::Tool {
            operation,
            tool_name,
            principal,
        } => {
            let context = tool_context(compiled.snapshot(), *operation, tool_name, principal, None);
            let facts = case_facts(compiled, principal, &case.facts);
            tool_evaluated(policy, *operation, &context, &facts, trace, budget).map_err(refused)
        }
        CaseContext::ToolHttp {
            tool_name,
            method,
            path,
            principal,
        } => {
            let context = tool_context(
                compiled.snapshot(),
                ToolOperation::RenderedHttp,
                tool_name,
                principal,
                Some((method, path)),
            );
            let facts = case_facts(compiled, principal, &case.facts);
            tool_evaluated(
                policy,
                ToolOperation::RenderedHttp,
                &context,
                &facts,
                trace,
                budget,
            )
            .map_err(refused)
        }
        CaseContext::Rate {
            method,
            path,
            principal,
            sequence,
        } => {
            let context = rate_context(compiled.snapshot(), method, path, principal);
            let mut stages = Vec::with_capacity(MAX_RATE_STAGES);
            let selection = compiled
                .select_rate_lane_with_facts(
                    &context,
                    &case_facts(compiled, principal, &case.facts),
                    &mut stages,
                )
                .map_err(refused)?;
            let mut view = Map::new();
            view.insert("lane".to_owned(), json!("rate_selection"));
            let (key, selected) = match selection.outcome() {
                RateLaneOutcome::NoOverride => {
                    view.insert("rate_override".to_owned(), Value::Null);
                    (
                        Key::Rate {
                            selected: "no_override",
                            requests_per_second: None,
                            burst: None,
                        },
                        "no_override",
                    )
                }
                RateLaneOutcome::Override { index, limit } => {
                    let mut selected = Map::new();
                    selected.insert("position".to_owned(), json!(index));
                    if trace != TraceLevel::Terminal {
                        insert_id(
                            &mut selected,
                            policy
                                .rate_override_ids
                                .get(index)
                                .and_then(Option::as_deref),
                        );
                        selected.insert(
                            "requests_per_second".to_owned(),
                            json!(limit.requests_per_second()),
                        );
                        selected.insert("burst".to_owned(), json!(limit.burst()));
                    }
                    view.insert("rate_override".to_owned(), Value::Object(selected));
                    (
                        Key::Rate {
                            selected: "override",
                            requests_per_second: Some(limit.requests_per_second()),
                            burst: Some(limit.burst()),
                        },
                        "override",
                    )
                }
                RateLaneOutcome::Indeterminate(limitation) => {
                    view.insert("limitation".to_owned(), json!(limitation_code(limitation)));
                    (
                        Key::Rate {
                            selected: "indeterminate",
                            requests_per_second: None,
                            burst: None,
                        },
                        "indeterminate",
                    )
                }
            };
            view.insert("selected".to_owned(), json!(selected));
            let mut complete = selected != "indeterminate";
            if let Some(sequence) = sequence {
                let run = run_sequence(selection.outcome(), method, sequence, resources);
                if matches!(run, SequenceRun::LaneConfigurationUnavailable) {
                    // The selection decided, so this is the only limitation.
                    complete = false;
                    view.insert(
                        "limitation".to_owned(),
                        json!(MISSING_RATE_LANE_CONFIGURATION),
                    );
                }
                view.insert("sequence".to_owned(), sequence_view(run, trace));
            }
            view.insert("complete".to_owned(), json!(complete));
            if trace == TraceLevel::Full {
                let indeterminate = selected == "indeterminate";
                budget.insert(&mut view, RATE_STAGE_NAMES.len(), || {
                    ordered_stages(
                        RATE_STAGE_NAMES,
                        &stages,
                        indeterminate,
                        rate_stage_name,
                        |stage| rate_stage_view(policy, stage),
                    )
                });
            }
            Ok(Evaluated {
                view: Value::Object(view),
                key,
            })
        }
        CaseContext::Egress { egress } => {
            let answer = evaluate_egress(egress, resources).map_err(refused)?;
            Ok(egress_evaluated(answer, egress, trace))
        }
    }
}

fn tool_evaluated(
    policy: &SimulatedPolicy,
    operation: ToolOperation,
    context: &ToolEvaluationContext,
    facts: &PolicyFacts,
    trace: TraceLevel,
    budget: &mut StageBudget,
) -> Result<Evaluated, EvaluationError> {
    let mut stages = Vec::with_capacity(MAX_TOOL_STAGES);
    let evaluation = policy
        .compiled
        .evaluate_tool_with_facts(context, facts, &mut stages)?;
    let outcome = decision_outcome(
        evaluation.logical(),
        evaluation.effect(),
        ToolReason::as_str(evaluation.reason()),
    );
    let mut view = decision_view(
        "tool",
        Some(operation_code(operation)),
        &outcome,
        evaluation.is_complete(),
        evaluation.limitation().map(tool_limitation_code),
    );
    if trace != TraceLevel::Terminal {
        let matched = evaluation
            .matched()
            .map(|element| element_view(policy, element, None));
        view.insert("matched".to_owned(), matched.unwrap_or(Value::Null));
    }
    if trace == TraceLevel::Full {
        let rendered = operation == ToolOperation::RenderedHttp;
        let names = if rendered {
            RENDERED_TOOL_STAGE_NAMES
        } else {
            TOOL_STAGE_NAMES
        };
        let indeterminate = evaluation.logical() == LogicalDecision::Indeterminate;
        budget.insert(&mut view, names.len(), || {
            ordered_stages(
                names,
                &stages,
                indeterminate,
                |stage| tool_stage_name(stage, rendered),
                |stage| tool_stage_view(policy, stage, rendered),
            )
        });
    }
    Ok(Evaluated {
        view: Value::Object(view),
        key: Key::Decision(outcome),
    })
}

/// An egress case's result. The lane names no policy element, so a
/// `matched` trace adds only the ordinal of the hypothetical address that
/// decided -- never the address.
fn egress_evaluated(answer: EgressAnswer, egress: &EgressCase, trace: TraceLevel) -> Evaluated {
    let (outcome, mut view) = match answer {
        EgressAnswer::ControlsUnavailable => {
            let outcome = decision_outcome(
                LogicalDecision::Indeterminate,
                PolicyEffect::Block,
                "incomplete",
            );
            let view = decision_view(
                "egress",
                None,
                &outcome,
                false,
                Some(MISSING_EGRESS_CONTROLS),
            );
            (outcome, view)
        }
        EgressAnswer::Decided(evaluation) => {
            let outcome = decision_outcome(
                evaluation.logical(),
                evaluation.effect(),
                egress_reason(evaluation.outcome()),
            );
            let mut view = decision_view(
                "egress",
                None,
                &outcome,
                evaluation.is_complete(),
                egress_limitation(&evaluation),
            );
            if trace != TraceLevel::Terminal {
                match evaluation.outcome() {
                    crate::policy_eval::egress::EgressOutcome::Allow { pinned } => {
                        view.insert("pinned_address".to_owned(), json!(pinned));
                    }
                    crate::policy_eval::egress::EgressOutcome::Deny(
                        crate::policy_eval::egress::EgressDenial::NonGlobalAddress { index },
                    ) => {
                        view.insert("refused_address".to_owned(), json!(index));
                    }
                    _ => {}
                }
            }
            (outcome, view)
        }
    };
    view.insert(
        "resolution".to_owned(),
        json!(if egress.hypothetical_addresses.is_some() {
            "hypothetical"
        } else {
            "none"
        }),
    );
    Evaluated {
        view: Value::Object(view),
        key: Key::Egress(outcome),
    }
}

/// An isolated sequence's result: the lane and key class it modelled, that
/// its bucket started empty on a virtual clock, and each step's outcome. A
/// `matched` trace adds the limits the bucket was built from.
fn sequence_view(run: SequenceRun, trace: TraceLevel) -> Value {
    match run {
        SequenceRun::Ran { lane, limit, steps } => {
            let allowed = steps
                .iter()
                .filter(|step| **step == StepOutcome::Allowed)
                .count();
            let mut view = Map::new();
            view.insert("lane".to_owned(), json!(lane.as_str()));
            view.insert("key_class".to_owned(), json!(lane.key_class()));
            view.insert("bucket".to_owned(), json!("isolated_empty"));
            view.insert("clock".to_owned(), json!("virtual"));
            if trace != TraceLevel::Terminal {
                view.insert(
                    "requests_per_second".to_owned(),
                    json!(limit.requests_per_second),
                );
                view.insert("burst".to_owned(), json!(limit.burst));
            }
            view.insert("steps".to_owned(), json!(step_codes(&steps)));
            view.insert("allowed".to_owned(), json!(allowed));
            view.insert("limited".to_owned(), json!(steps.len() - allowed));
            view.insert("complete".to_owned(), json!(true));
            Value::Object(view)
        }
        // The selection's own limitation says why there was no lane.
        SequenceRun::Undecided => json!({ "complete": false }),
        SequenceRun::LaneConfigurationUnavailable => json!({
            "complete": false,
            "limitation": MISSING_RATE_LANE_CONFIGURATION,
        }),
    }
}

fn refusal(case: &SyntheticCase, error: EvaluationError) -> SimulationError {
    match error {
        // The case's own facts, refused by the evaluator's bounds. The parser
        // applies the same predicates, so this is not expected to happen; when
        // it does it is the caller's input, never a pass or an empty result.
        EvaluationError::MalformedPath
        | EvaluationError::ContextTooLarge
        | EvaluationError::InvalidPrincipal
        | EvaluationError::InvalidHost
        | EvaluationError::InconsistentContext => SimulationError::CaseRefused {
            pointer: case.pointer.clone(),
            code: evaluation_error_code(error),
        },
        EvaluationError::UnsupportedContextVersion
        | EvaluationError::SnapshotMismatch
        | EvaluationError::InternalInvariant
        | EvaluationError::TraceEncoding
        | EvaluationError::TraceTooLarge => SimulationError::Internal(evaluation_error_code(error)),
    }
}

/// The outcome in the result's vocabulary. The logical decision, whether a
/// denial is enforced or only observed, and what the request would meet are
/// three separate answers, so a shadowed deny is never read as an allow.
/// The enforcement and effective action a decision states: kept apart from
/// the logical outcome, so a shadowed deny is never read as an allow.
/// Historical replay reports its decisions in the same vocabulary.
pub(crate) fn enforcement_and_effect(
    logical: LogicalDecision,
    effect: PolicyEffect,
) -> (&'static str, &'static str) {
    match (logical, effect) {
        // Undecided: no enforcement to describe, and no promise either way.
        (LogicalDecision::Indeterminate, _) => ("not_applicable", "unknown"),
        (_, PolicyEffect::Allow) => ("not_applicable", "would_forward"),
        (_, PolicyEffect::Observe) => ("shadowed", "would_forward"),
        (_, PolicyEffect::Block) => ("enforced", "would_block"),
    }
}

fn decision_outcome(
    logical: LogicalDecision,
    effect: PolicyEffect,
    reason: &'static str,
) -> Outcome {
    let (enforcement, effective_action) = enforcement_and_effect(logical, effect);
    Outcome {
        logical: logical_code(logical),
        enforcement,
        effective_action,
        reason,
    }
}

fn decision_view(
    lane: &'static str,
    operation: Option<&'static str>,
    outcome: &Outcome,
    complete: bool,
    limitation: Option<&'static str>,
) -> Map<String, Value> {
    let mut view = Map::new();
    view.insert("lane".to_owned(), json!(lane));
    if let Some(operation) = operation {
        view.insert("operation".to_owned(), json!(operation));
    }
    view.insert("logical".to_owned(), json!(outcome.logical));
    view.insert("enforcement".to_owned(), json!(outcome.enforcement));
    view.insert(
        "effective_action".to_owned(),
        json!(outcome.effective_action),
    );
    view.insert("reason".to_owned(), json!(outcome.reason));
    view.insert("complete".to_owned(), json!(complete));
    if let Some(limitation) = limitation {
        view.insert("limitation".to_owned(), json!(limitation));
    }
    view
}

fn operation_code(operation: ToolOperation) -> &'static str {
    match operation {
        ToolOperation::Invocation => "invocation",
        ToolOperation::Visibility => "visibility",
        ToolOperation::PolicyEligibility => "eligibility",
        ToolOperation::CompositeLeaf => "composite_leaf",
        ToolOperation::RenderedHttp => "rendered_http",
    }
}

/// A policy element by position, with its bounded authored name. A route's
/// permission check is reported from the evaluator's own reason.
fn element_view(policy: &SimulatedPolicy, element: RuleReference, reason: Option<Reason>) -> Value {
    match element {
        RuleReference::Direct(position) => rule_view(policy, position),
        RuleReference::Route(position) => {
            let mut view = route_view(policy, position);
            if let (Some(reason), Some(map)) = (reason, view.as_object_mut()) {
                map.insert(
                    "permission_granted".to_owned(),
                    json!(reason == Reason::MatchedRule),
                );
            }
            view
        }
    }
}

fn rule_view(policy: &SimulatedPolicy, position: usize) -> Value {
    let mut view = Map::new();
    view.insert("kind".to_owned(), json!("rule"));
    view.insert("position".to_owned(), json!(position));
    if let Some(action) = policy.rule_actions.get(position) {
        view.insert(
            "action".to_owned(),
            json!(action_code(&DirectAction::from(action))),
        );
    }
    insert_id(
        &mut view,
        policy.rule_ids.get(position).and_then(Option::as_deref),
    );
    Value::Object(view)
}

/// An element's stable id when it has one, or a marker when it is longer
/// than a result repeats.
fn insert_id(view: &mut Map<String, Value>, id: Option<&str>) {
    match id {
        Some(id) if id.len() <= MAX_ECHOED_POLICY_STRING_BYTES => {
            view.insert("id".to_owned(), json!(id));
        }
        Some(_) => {
            view.insert("id_omitted".to_owned(), json!(true));
        }
        None => {}
    }
}

fn route_view(policy: &SimulatedPolicy, position: usize) -> Value {
    let mut view = Map::new();
    view.insert("kind".to_owned(), json!("route"));
    view.insert("position".to_owned(), json!(position));
    insert_id(
        &mut view,
        policy.route_ids.get(position).and_then(Option::as_deref),
    );
    match policy.route_permissions.get(position) {
        Some(permission) if permission.len() <= MAX_ECHOED_POLICY_STRING_BYTES => {
            view.insert("permission".to_owned(), json!(permission));
        }
        Some(_) => {
            view.insert("permission_omitted".to_owned(), json!(true));
        }
        None => {}
    }
    Value::Object(view)
}

fn rate_override_view(policy: &SimulatedPolicy, position: usize) -> Value {
    let mut view = Map::new();
    view.insert("kind".to_owned(), json!("rate_override"));
    view.insert("position".to_owned(), json!(position));
    insert_id(
        &mut view,
        policy
            .rate_override_ids
            .get(position)
            .and_then(Option::as_deref),
    );
    Value::Object(view)
}

fn action_code(action: &DirectAction) -> &'static str {
    match action {
        DirectAction::Allow => "allow",
        DirectAction::Deny => "deny",
        DirectAction::Shadow => "shadow",
    }
}

fn mode_code(mode: EnforcementMode) -> &'static str {
    match mode {
        EnforcementMode::Enforce => "enforce",
        EnforcementMode::Shadow => "shadow",
    }
}

/// Every stage of a lane in evaluation order: the ones the evaluator
/// recorded, as it recorded them, and the ones it did not reach -- `skipped`
/// after a decision, `unknown` after an indeterminate answer.
fn ordered_stages<S>(
    names: &[&'static str],
    stages: &[S],
    indeterminate: bool,
    name_of: impl Fn(&S) -> &'static str,
    view_of: impl Fn(&S) -> Value,
) -> Vec<Value> {
    names
        .iter()
        .map(
            |name| match stages.iter().find(|stage| name_of(stage) == *name) {
                Some(stage) => view_of(stage),
                None => json!({
                    "stage": name,
                    "status": if indeterminate { "unknown" } else { "skipped" },
                }),
            },
        )
        .collect()
}

fn stage_name(stage: &HttpStage) -> &'static str {
    match stage {
        HttpStage::Facts(_) => "facts",
        HttpStage::RequestHost(_) => "request_host",
        HttpStage::DirectRules(_) => "direct_rules",
        HttpStage::UpstreamBinding(_) => "upstream_host_binding",
        HttpStage::Routes(_) => "routes",
        HttpStage::HostPolicyRequired | HttpStage::Default(_) => "default",
    }
}

fn stage_view(policy: &SimulatedPolicy, stage: &HttpStage) -> Value {
    let name = stage_name(stage);
    match stage {
        HttpStage::Facts(None) => json!({ "stage": name, "status": "matched" }),
        HttpStage::Facts(Some(limitation)) => json!({
            "stage": name,
            "status": "unknown",
            "limitation": limitation_code(*limitation),
        }),
        HttpStage::RequestHost(host) => match host {
            HostUse::SelectedUpstream => {
                json!({ "stage": name, "status": "matched", "host": "selected_upstream" })
            }
            HostUse::Request => json!({ "stage": name, "status": "matched", "host": "request" }),
            HostUse::Absent => json!({ "stage": name, "status": "matched", "host": "absent" }),
            HostUse::NotRequired => json!({ "stage": name, "status": "not_applicable" }),
            HostUse::Missing => json!({
                "stage": name,
                "status": "unknown",
                "limitation": "missing_host_fact",
            }),
        },
        HttpStage::DirectRules(None) => json!({ "stage": name, "status": "no_match" }),
        HttpStage::DirectRules(Some(direct)) => json!({
            "stage": name,
            "status": "matched",
            "element": rule_view(policy, direct.rule),
            "action": action_code(&direct.action),
        }),
        HttpStage::UpstreamBinding(UpstreamBinding::NotSelected) => {
            json!({ "stage": name, "status": "not_applicable" })
        }
        HttpStage::UpstreamBinding(UpstreamBinding::DenyOnly(None)) => {
            json!({ "stage": name, "status": "no_match", "deny_only": true })
        }
        HttpStage::UpstreamBinding(UpstreamBinding::DenyOnly(Some(rule))) => json!({
            "stage": name,
            "status": "matched",
            "deny_only": true,
            "element": rule_view(policy, *rule),
        }),
        HttpStage::Routes(None) => json!({ "stage": name, "status": "no_match" }),
        HttpStage::Routes(Some(route)) => json!({
            "stage": name,
            "status": "matched",
            "element": route_view(policy, route.route),
            "permission": match route.permission {
                PermissionCheck::Granted => "granted",
                PermissionCheck::Missing => "missing",
                PermissionCheck::NoPrincipal => "no_principal",
            },
            "enforcement_mode": mode_code(route.mode),
            "mode_inherited": route.mode_inherited,
        }),
        HttpStage::HostPolicyRequired => json!({
            "stage": name,
            "status": "not_applicable",
            "reason": Reason::HostPolicyRequired.as_str(),
        }),
        HttpStage::Default(default) => json!({
            "stage": name,
            "status": "matched",
            "default_action": if default.allow { "allow" } else { "deny" },
            "enforcement_mode": mode_code(default.mode),
        }),
    }
}

fn tool_stage_name(stage: &ToolStage, rendered: bool) -> &'static str {
    match stage {
        ToolStage::Facts(_) => "facts",
        ToolStage::Entry(_) => "tool_entry",
        ToolStage::Identity(_) => "tool_identity",
        ToolStage::Rules(_) if rendered => "rendered_http_rules",
        ToolStage::Rules(_) => "tool_rules",
    }
}

fn tool_stage_view(policy: &SimulatedPolicy, stage: &ToolStage, rendered: bool) -> Value {
    let name = tool_stage_name(stage, rendered);
    match stage {
        ToolStage::Facts(None) => json!({ "stage": name, "status": "matched" }),
        ToolStage::Facts(Some(limitation)) => json!({
            "stage": name,
            "status": "unknown",
            "limitation": tool_limitation_code(*limitation),
        }),
        ToolStage::Entry(ToolEntry::Absent) => json!({ "stage": name, "status": "no_match" }),
        ToolStage::Entry(ToolEntry::Disabled) => {
            json!({ "stage": name, "status": "matched", "enabled": false })
        }
        ToolStage::Entry(ToolEntry::Enabled) => {
            json!({ "stage": name, "status": "matched", "enabled": true })
        }
        ToolStage::Identity(IdentityCheck::Admitted) => {
            json!({ "stage": name, "status": "matched" })
        }
        ToolStage::Identity(IdentityCheck::Refused) => {
            json!({ "stage": name, "status": "no_match" })
        }
        ToolStage::Rules(ToolRules::NoMatch) => json!({ "stage": name, "status": "no_match" }),
        ToolStage::Rules(ToolRules::Matched(direct)) => json!({
            "stage": name,
            "status": "matched",
            "element": rule_view(policy, direct.rule),
            "action": action_code(&direct.action),
        }),
        ToolStage::Rules(ToolRules::Undetermined) => json!({
            "stage": name,
            "status": "unknown",
            "limitation": "missing_matcher_fact",
        }),
    }
}

fn rate_stage_name(stage: &RateStage) -> &'static str {
    match stage {
        RateStage::Facts(_) => "facts",
        RateStage::AnonymousBypass(_) => "anonymous_bypass",
        RateStage::Overrides(_) => "rate_overrides",
    }
}

fn rate_stage_view(policy: &SimulatedPolicy, stage: &RateStage) -> Value {
    let name = rate_stage_name(stage);
    match stage {
        RateStage::Facts(None) => json!({ "stage": name, "status": "matched" }),
        RateStage::Facts(Some(limitation)) => json!({
            "stage": name,
            "status": "unknown",
            "limitation": limitation_code(*limitation),
        }),
        RateStage::AnonymousBypass(true) => json!({ "stage": name, "status": "matched" }),
        RateStage::AnonymousBypass(false) => {
            json!({ "stage": name, "status": "not_applicable" })
        }
        RateStage::Overrides(None) => json!({ "stage": name, "status": "no_match" }),
        RateStage::Overrides(Some(position)) => json!({
            "stage": name,
            "status": "matched",
            "element": rate_override_view(policy, *position),
        }),
    }
}
