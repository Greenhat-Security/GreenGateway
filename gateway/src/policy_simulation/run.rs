//! Decides every simulated case through the shared evaluator and renders the
//! results.
//!
//! Each case becomes the context a live adapter builds -- through the same
//! builders the policy test runner uses -- and is asked of the same
//! [`CompiledPolicy`] methods: `evaluate_with_stages` (which *is* `evaluate`,
//! with a collecting sink) for HTTP, `evaluate_tool` for the tool lanes and
//! `select_rate_lane` for rate overrides. Nothing here matches a rule.
//!
//! Results carry case ids, stable codes, element positions and, for an admin
//! who already holds `admin:policy:read`, the matched element's stable `id`
//! and a route's permission -- bounded in length -- and never a value a case
//! supplied: no path, host, subject, role, origin or tool name.

use std::time::Instant;

use serde_json::{json, Map, Value};

use super::{Projection, TraceLevel};
use crate::{
    policy_eval::{
        stages::{
            DirectAction, HostUse, HttpStage, PermissionCheck, UpstreamBinding, MAX_HTTP_STAGES,
        },
        tools::{ToolOperation, ToolReason},
        CompileError, CompiledPolicy, EvaluationError, LogicalDecision, PolicyAuthority,
        PolicyEffect, RateLaneOutcome, Reason, RuleReference,
    },
    policy_testing::{
        runner::{
            evaluation_error_code, http_context, limitation_code, logical_code, rate_context,
            tool_context, tool_limitation_code,
        },
        suite::{CaseContext, SyntheticCase},
    },
    rbac::{EnforcementMode, Policy, RuleAction},
};

/// Most stage steps one simulation returns across all its evaluations. Each
/// HTTP evaluation returns one step per stage; past this budget the steps of
/// further evaluations are omitted and the result says so.
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

/// What a decision is compared by: the outcome, not the element positions,
/// which an insert before them shifts without changing anything.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Key {
    Decision {
        logical: &'static str,
        enforcement: &'static str,
        effective_action: &'static str,
        reason: &'static str,
    },
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
    changed_from_base: usize,
}

impl Counts {
    fn add(&mut self, key: &Key) {
        match key {
            Key::Decision {
                effective_action,
                enforcement,
                ..
            } => {
                match *effective_action {
                    "would_forward" => self.would_forward += 1,
                    "would_block" => self.would_block += 1,
                    _ => self.unknown += 1,
                }
                if *enforcement == "shadowed" {
                    self.shadowed += 1;
                }
            }
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
/// Pure: reads the compiled policies and the cases, and returns values.
pub(crate) fn simulate(
    pairs: &[ProjectedPair],
    cases: &[SyntheticCase],
    trace: TraceLevel,
    deadline: Instant,
) -> Result<SimulationOutcome, SimulationError> {
    let mut budget = MAX_TRACE_STAGES;
    let mut stages_truncated = false;
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
            let candidate = evaluate_case(
                &pair.candidate,
                case,
                trace,
                &mut budget,
                &mut stages_truncated,
            )?;
            counts.add(&candidate.key);
            candidate_keys.push(candidate.key);
            let mut result = Map::new();
            result.insert("projection".to_owned(), json!(pair.projection.as_str()));
            if let Some(base) = &pair.base {
                let base = evaluate_case(base, case, trace, &mut budget, &mut stages_truncated)?;
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
        stages_truncated,
    })
}

fn evaluate_case(
    policy: &SimulatedPolicy,
    case: &SyntheticCase,
    trace: TraceLevel,
    budget: &mut usize,
    truncated: &mut bool,
) -> Result<Evaluated, SimulationError> {
    let compiled = &policy.compiled;
    let refused = |error: EvaluationError| refusal(case, error);
    match &case.context {
        CaseContext::Http { request, principal } => {
            let context = http_context(compiled.snapshot(), request, principal);
            let mut stages = Vec::with_capacity(MAX_HTTP_STAGES);
            let evaluation = compiled
                .evaluate_with_stages(&context, &mut stages)
                .map_err(refused)?;
            let key = decision_key(
                evaluation.logical(),
                evaluation.effect(),
                evaluation.reason().as_str(),
            );
            let mut view = decision_view(
                "http",
                None,
                &key,
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
                if HTTP_STAGE_NAMES.len() <= *budget {
                    *budget -= HTTP_STAGE_NAMES.len();
                    view.insert(
                        "stages".to_owned(),
                        Value::Array(stage_views(
                            policy,
                            &stages,
                            evaluation.logical() == LogicalDecision::Indeterminate,
                        )),
                    );
                } else {
                    *truncated = true;
                    view.insert("stages_truncated".to_owned(), json!(true));
                }
            }
            Ok(Evaluated {
                view: Value::Object(view),
                key,
            })
        }
        CaseContext::Tool {
            operation,
            tool_name,
            principal,
        } => {
            let context = tool_context(compiled.snapshot(), *operation, tool_name, principal, None);
            tool_evaluated(policy, *operation, &context, trace).map_err(refused)
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
            tool_evaluated(policy, ToolOperation::RenderedHttp, &context, trace).map_err(refused)
        }
        CaseContext::Rate {
            method,
            path,
            principal,
        } => {
            let context = rate_context(compiled.snapshot(), method, path, principal);
            let selection = compiled.select_rate_lane(&context).map_err(refused)?;
            let mut view = Map::new();
            view.insert("lane".to_owned(), json!("rate_selection"));
            let key = match selection.outcome() {
                RateLaneOutcome::NoOverride => {
                    view.insert("rate_override".to_owned(), Value::Null);
                    Key::Rate {
                        selected: "no_override",
                        requests_per_second: None,
                        burst: None,
                    }
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
                    Key::Rate {
                        selected: "override",
                        requests_per_second: Some(limit.requests_per_second()),
                        burst: Some(limit.burst()),
                    }
                }
                RateLaneOutcome::Indeterminate(limitation) => {
                    view.insert("limitation".to_owned(), json!(limitation_code(limitation)));
                    Key::Rate {
                        selected: "indeterminate",
                        requests_per_second: None,
                        burst: None,
                    }
                }
            };
            if let Key::Rate { selected, .. } = key {
                view.insert("selected".to_owned(), json!(selected));
                view.insert("complete".to_owned(), json!(selected != "indeterminate"));
            }
            Ok(Evaluated {
                view: Value::Object(view),
                key,
            })
        }
    }
}

fn tool_evaluated(
    policy: &SimulatedPolicy,
    operation: ToolOperation,
    context: &crate::policy_eval::tools::ToolEvaluationContext,
    trace: TraceLevel,
) -> Result<Evaluated, EvaluationError> {
    let evaluation = policy.compiled.evaluate_tool(context)?;
    let key = decision_key(
        evaluation.logical(),
        evaluation.effect(),
        ToolReason::as_str(evaluation.reason()),
    );
    let mut view = decision_view(
        "tool",
        Some(operation_code(operation)),
        &key,
        evaluation.is_complete(),
        evaluation.limitation().map(tool_limitation_code),
    );
    if trace != TraceLevel::Terminal {
        let matched = evaluation
            .matched()
            .map(|element| element_view(policy, element, None));
        view.insert("matched".to_owned(), matched.unwrap_or(Value::Null));
    }
    Ok(Evaluated {
        view: Value::Object(view),
        key,
    })
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
fn decision_key(logical: LogicalDecision, effect: PolicyEffect, reason: &'static str) -> Key {
    let (enforcement, effective_action) = match (logical, effect) {
        // Undecided: no enforcement to describe, and no promise either way.
        (LogicalDecision::Indeterminate, _) => ("not_applicable", "unknown"),
        (_, PolicyEffect::Allow) => ("not_applicable", "would_forward"),
        (_, PolicyEffect::Observe) => ("shadowed", "would_forward"),
        (_, PolicyEffect::Block) => ("enforced", "would_block"),
    };
    Key::Decision {
        logical: logical_code(logical),
        enforcement,
        effective_action,
        reason,
    }
}

fn decision_view(
    lane: &'static str,
    operation: Option<&'static str>,
    key: &Key,
    complete: bool,
    limitation: Option<&'static str>,
) -> Map<String, Value> {
    let mut view = Map::new();
    view.insert("lane".to_owned(), json!(lane));
    if let Some(operation) = operation {
        view.insert("operation".to_owned(), json!(operation));
    }
    if let Key::Decision {
        logical,
        enforcement,
        effective_action,
        reason,
    } = key
    {
        view.insert("logical".to_owned(), json!(logical));
        view.insert("enforcement".to_owned(), json!(enforcement));
        view.insert("effective_action".to_owned(), json!(effective_action));
        view.insert("reason".to_owned(), json!(reason));
    }
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

/// Every HTTP stage in evaluation order: the ones the evaluator recorded, as
/// it recorded them, and the ones it did not reach -- `skipped` after a
/// decision, `unknown` after an indeterminate answer.
fn stage_views(policy: &SimulatedPolicy, stages: &[HttpStage], indeterminate: bool) -> Vec<Value> {
    HTTP_STAGE_NAMES
        .iter()
        .map(
            |name| match stages.iter().find(|stage| stage_name(stage) == *name) {
                Some(stage) => stage_view(policy, stage),
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
