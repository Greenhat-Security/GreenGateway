//! The whole-policy impact comparison (issue #243, slice 14): what a candidate
//! changes, record by record, against the base it was written against, and
//! how the gateway's recorded results compare with that base today.
//!
//! A replay job ([`super::job`]) decides every replayable record under the
//! candidate. This module decides it again under the pinned base, through the
//! same kernel functions in [`super::evaluate`], and sorts each pair of
//! answers into a transition with a stable code. It never matches a rule, a
//! route or a tool entry itself.
//!
//! ## Three values, two comparisons
//!
//! - **Recorded**: what the gateway's policy stage recorded when the request
//!   was served, under the evaluator and resources it ran then.
//! - **Base**: the pinned base policy, decided again now.
//! - **Candidate**: the candidate, decided again by the same evaluator.
//!
//! Base against candidate is the impact of the change, per projection.
//! Recorded against base says how far the base, decided today, is from what
//! was recorded -- a policy or resource that changed since, or a record that
//! was never a policy verdict. The two are kept apart: a difference between
//! recorded and base says nothing about the candidate, and a v1 record cannot
//! say whether the policy, the configuration or the evaluator changed.
//!
//! ## Transitions
//!
//! | Code | Base and candidate |
//! | --- | --- |
//! | `newly_allowed` | deny, then allow |
//! | `enforcement_only_change` | the same logical decision with a different effect: a deny enforced in one and shadowed in the other |
//! | `newly_denied` | allow, then deny (enforced or shadowed) |
//! | `attribution_only_change` | the same decision and effect, decided by a different element or reason, or with a different shadow observation |
//! | `unchanged_deny`, `unchanged_allow` | the same decision, effect, reason, element and observation |
//! | `indeterminate` | either policy could not answer, for want of a fact |
//! | `unsupported_context` | the kernel refused the record's facts |
//!
//! Every decided pair also states its forwarding change -- `newly_forwarded`
//! when the base would block and the candidate would forward,
//! `newly_blocked` for the reverse -- so a deny that became shadowed is never
//! read as unchanged. Rows are ordered by that priority: newly allowed first,
//! and within a transition, newly forwarded first.
//!
//! Elements are compared by identity, not position: two rules, routes or rate
//! overrides are the same element when they carry the same stable id, or --
//! for entries without one, as a 0.x document allows -- the same content. An
//! insert ahead of an element moves it without changing it.
//!
//! ## Privacy projection
//!
//! A comparison holds counts keyed by codes from closed sets, and names
//! policy elements by position in the policy that decided, with the element's
//! authored id when it has one of at most
//! [`MAX_ECHOED_POLICY_STRING_BYTES`], and a tool entry by its name in that
//! policy's own tool map. It never repeats a value only a record carries: a
//! recorded rule id, permission, path prefix or reason is compared and never
//! copied (a recorded reason is rendered only as the code from the closed set
//! it matched), and a tool a record names that the policy does not list is
//! `no_tool_entry`, never its name.
//!
//! ## Bounds
//!
//! Every map is keyed by closed sets of codes and by element pairs, whose
//! number is bounded by the policies, not the window. Rendered rows are
//! capped per lane and projection; the records in rows past a cap are
//! counted as omitted, never silently dropped, and every transition count
//! stays complete.

use std::{cmp::Reverse, collections::BTreeMap};

use serde_json::{json, Map, Value};

use super::{
    evaluate::{evaluate_http, evaluate_tool, select_rate_lane, HttpReplayOutcome},
    job::ReplayStop,
    HttpFacts, RecordedPolicy, RecordedResult, ReplaySource, ToolFacts,
};
use crate::{
    policy_eval::{
        tools::ToolReason, CompileError, CompiledPolicy, EvaluationError, LogicalDecision,
        PolicyAuthority, PolicyEffect, RateLaneOutcome, Reason, RuleReference,
    },
    policy_simulation::{
        run::{enforcement_and_effect, MAX_ECHOED_POLICY_STRING_BYTES},
        Projection,
    },
    policy_testing::runner::{evaluation_error_code, logical_code, tool_limitation_code},
    rbac::{Policy, RateLimitRule, RouteRule, Rule},
};

/// Most transition-matrix rows a lane renders per projection, and most rows
/// a recorded comparison renders per lane.
pub(crate) const MAX_IMPACT_MATRIX_ROWS: usize = 64;
/// Most changed-element rows a lane renders per projection.
pub(crate) const MAX_IMPACT_ELEMENT_ROWS: usize = 32;
/// The one sentence a historical result may use to say a candidate allowed
/// nothing new, and only when it holds; see [`ProjectionTally::statement`].
const NO_NEWLY_ALLOWED_TEXT: &str = "No newly allowed decisions were observed among";

pub(crate) const EVALUATOR_FAILED: ReplayStop = ReplayStop::Failed("evaluator_failed");

/// The HTTP reasons that are a policy verdict. A recorded reason outside this
/// set -- `policy_evaluation_incomplete`, a revision-check code -- is what the
/// gateway recorded for a request its policy stage did not answer.
const HTTP_VERDICT_REASONS: [Reason; 6] = [
    Reason::MatchedRule,
    Reason::MissingPermission,
    Reason::MissingPrincipal,
    Reason::DefaultAllow,
    Reason::DefaultDeny,
    Reason::HostPolicyRequired,
];
/// The tool admission reasons that are a policy verdict. A refused name or an
/// evaluation the runtime could not complete is not.
const TOOL_VERDICT_REASONS: [ToolReason; 4] = [
    ToolReason::UnknownTool,
    ToolReason::Disabled,
    ToolReason::RoleNotAllowed,
    ToolReason::MatchedRule,
];

/// An evaluator error, sorted into the two answers a run gives one: the
/// record's facts were refused (a stable code, counted), or the run itself
/// is broken (`None`: the job fails, and nothing it counted is an answer).
///
/// Exhaustive on purpose: a new error is a decision this function must make.
fn refusal_code(error: EvaluationError) -> Option<&'static str> {
    match error {
        EvaluationError::MalformedPath
        | EvaluationError::ContextTooLarge
        | EvaluationError::InvalidPrincipal
        | EvaluationError::InvalidHost
        | EvaluationError::InconsistentContext => Some(evaluation_error_code(error)),
        EvaluationError::UnsupportedContextVersion
        | EvaluationError::SnapshotMismatch
        | EvaluationError::InternalInvariant
        | EvaluationError::TraceEncoding
        | EvaluationError::TraceTooLarge => None,
    }
}

/// One policy a job decides records under, compiled once through the
/// constructor every live install path uses, with its tool names in sorted
/// order so a tool entry has a stable position.
pub(crate) struct ReplayPolicy {
    compiled: CompiledPolicy,
    tool_names: Vec<String>,
}

impl ReplayPolicy {
    pub(crate) fn compile(policy: Policy) -> Result<Self, CompileError> {
        let compiled = CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)?;
        let mut tool_names: Vec<String> = compiled.tool_entries().keys().cloned().collect();
        tool_names.sort_unstable();
        Ok(Self {
            compiled,
            tool_names,
        })
    }

    fn tool_position(&self, name: &str) -> Option<usize> {
        self.tool_names
            .binary_search_by(|listed| listed.as_str().cmp(name))
            .ok()
    }
}

/// The candidate and the base under one projection.
struct PolicyPair {
    candidate: ReplayPolicy,
    /// `None` when the candidate is the base itself: one compiled policy
    /// answers for both.
    base: Option<ReplayPolicy>,
}

impl PolicyPair {
    fn compile(
        base: &Policy,
        candidate: Option<&Policy>,
        projection: Projection,
    ) -> Result<Self, CompileError> {
        Ok(match candidate {
            None => Self {
                candidate: ReplayPolicy::compile(projection.apply(base))?,
                base: None,
            },
            Some(candidate) => Self {
                candidate: ReplayPolicy::compile(projection.apply(candidate))?,
                base: Some(ReplayPolicy::compile(projection.apply(base))?),
            },
        })
    }

    fn base(&self) -> &ReplayPolicy {
        self.base.as_ref().unwrap_or(&self.candidate)
    }
}

/// Every policy one job decides under: the candidate and the base as
/// authored, which the job always needs, and both under the shadow
/// projection when the job asked for it. Projections are in-memory copies
/// compiled for the job; nothing is rewritten, stored or activated.
pub(crate) struct ReplayPolicies {
    as_authored: PolicyPair,
    enforce_all_shadow: Option<PolicyPair>,
    projections: Vec<Projection>,
}

impl ReplayPolicies {
    /// `candidate` is `None` when the candidate is the base itself.
    pub(crate) fn compile(
        base: &Policy,
        candidate: Option<&Policy>,
        projections: &[Projection],
    ) -> Result<Self, CompileError> {
        let enforce_all_shadow = if projections.contains(&Projection::EnforceAllShadow) {
            Some(PolicyPair::compile(
                base,
                candidate,
                Projection::EnforceAllShadow,
            )?)
        } else {
            None
        };
        Ok(Self {
            as_authored: PolicyPair::compile(base, candidate, Projection::AsAuthored)?,
            enforce_all_shadow,
            projections: projections.to_vec(),
        })
    }
}

/// One policy's answer for one replayed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Answer {
    Decided(Decided),
    /// The policy could not answer for want of a fact: the stable limitation
    /// code.
    Indeterminate(&'static str),
    /// The kernel refused the record's facts: the stable refusal code.
    Refused(&'static str),
}

/// A decided answer, with the element that decided it in the policy that
/// decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Decided {
    pub(crate) logical: LogicalDecision,
    pub(crate) effect: PolicyEffect,
    pub(crate) reason: &'static str,
    pub(crate) element: Element,
    /// The direct rule that recorded a would-deny observation without
    /// deciding.
    pub(crate) observation: Option<usize>,
}

impl Decided {
    /// The answer in the result's vocabulary, which keeps the logical
    /// decision, its enforcement and the effective action apart.
    pub(crate) fn state(&self) -> State {
        let (enforcement, effective_action) = enforcement_and_effect(self.logical, self.effect);
        State {
            logical: logical_code(self.logical),
            enforcement,
            effective_action,
            reason: self.reason,
        }
    }
}

/// A decided outcome as a result states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct State {
    pub(crate) logical: &'static str,
    pub(crate) enforcement: &'static str,
    pub(crate) effective_action: &'static str,
    pub(crate) reason: &'static str,
}

impl State {
    fn render(self) -> Value {
        json!({
            "logical": self.logical,
            "enforcement": self.enforcement,
            "effective_action": self.effective_action,
            "reason": self.reason,
        })
    }
}

/// The policy element that decided, by position in the policy that decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Element {
    Rule(usize),
    Route(usize),
    /// The policy's default action.
    Default,
    /// A selected upstream that no host-bound route authorized.
    HostBinding,
    /// The invoked tool's entry, by position among the policy's tool names
    /// in sorted order.
    ToolEntry(usize),
    /// The invoked tool has no entry in the policy.
    NoToolEntry,
}

/// Which rate-limit override one policy selects for a record. Selection
/// only: whether a bucket had capacity is never reconstructed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum RateAnswer {
    NoOverride,
    Override {
        position: usize,
        requests_per_second: f64,
        burst: u32,
    },
    Indeterminate(&'static str),
    Refused(&'static str),
}

/// Decide a recorded HTTP request under `policy`.
///
/// Fails the run, rather than answering, when the kernel breaks its own
/// contract: an error that is not a refusal of the record's facts, an
/// observation that is not a direct rule, or a decision without the element
/// its reason implies.
pub(crate) fn http_answer(policy: &ReplayPolicy, facts: &HttpFacts) -> Result<Answer, ReplayStop> {
    let decision = match evaluate_http(&policy.compiled, facts) {
        Ok(HttpReplayOutcome::Decided(decision)) => decision,
        Ok(HttpReplayOutcome::Indeterminate(limitation)) => {
            return Ok(Answer::Indeterminate(limitation.as_str()))
        }
        Err(error) => {
            return refusal_code(error)
                .map(Answer::Refused)
                .ok_or(EVALUATOR_FAILED)
        }
    };
    let element = match (decision.matched, decision.reason) {
        (Some(RuleReference::Direct(position)), _) => Element::Rule(position),
        (Some(RuleReference::Route(position)), _) => Element::Route(position),
        (None, Reason::DefaultAllow | Reason::DefaultDeny) => Element::Default,
        (None, Reason::HostPolicyRequired) => Element::HostBinding,
        (None, _) => return Err(EVALUATOR_FAILED),
    };
    let observation = match decision.observation {
        None => None,
        Some(RuleReference::Direct(position)) => Some(position),
        Some(RuleReference::Route(_)) => return Err(EVALUATOR_FAILED),
    };
    Ok(Answer::Decided(Decided {
        logical: decision.logical,
        effect: decision.effect,
        reason: decision.reason.as_str(),
        element,
        observation,
    }))
}

/// Decide a recorded tool invocation's admission under `policy`.
pub(crate) fn tool_answer(policy: &ReplayPolicy, facts: &ToolFacts) -> Result<Answer, ReplayStop> {
    let evaluation = match evaluate_tool(&policy.compiled, facts) {
        Ok(evaluation) => evaluation,
        Err(error) => {
            return refusal_code(error)
                .map(Answer::Refused)
                .ok_or(EVALUATOR_FAILED)
        }
    };
    if !evaluation.is_complete() || evaluation.logical() == LogicalDecision::Indeterminate {
        // An unanswered evaluation always names what it lacked; one that
        // does not is the kernel breaking its own contract.
        let limitation = evaluation.limitation().ok_or(EVALUATOR_FAILED)?;
        return Ok(Answer::Indeterminate(tool_limitation_code(limitation)));
    }
    let element = match (evaluation.matched(), evaluation.reason()) {
        (Some(RuleReference::Direct(position)), _) => Element::Rule(position),
        (Some(RuleReference::Route(_)), _) => return Err(EVALUATOR_FAILED),
        (None, ToolReason::UnknownTool) => Element::NoToolEntry,
        // Every other invocation answer read the tool's entry.
        (None, _) => Element::ToolEntry(
            policy
                .tool_position(&facts.tool_name)
                .ok_or(EVALUATOR_FAILED)?,
        ),
    };
    Ok(Answer::Decided(Decided {
        logical: evaluation.logical(),
        effect: evaluation.effect(),
        reason: evaluation.reason().as_str(),
        element,
        observation: None,
    }))
}

/// Which override `policy` selects for a recorded request.
pub(crate) fn rate_answer(
    policy: &ReplayPolicy,
    facts: &HttpFacts,
) -> Result<RateAnswer, ReplayStop> {
    match select_rate_lane(&policy.compiled, facts) {
        Ok(selection) => Ok(match selection.outcome() {
            RateLaneOutcome::NoOverride => RateAnswer::NoOverride,
            RateLaneOutcome::Override { index, limit } => RateAnswer::Override {
                position: index,
                requests_per_second: limit.requests_per_second(),
                burst: limit.burst(),
            },
            RateLaneOutcome::Indeterminate(limitation) => {
                RateAnswer::Indeterminate(limitation.as_str())
            }
        }),
        Err(error) => refusal_code(error)
            .map(RateAnswer::Refused)
            .ok_or(EVALUATOR_FAILED),
    }
}

/// A policy entry's stable id, when it has one.
trait StableId: PartialEq {
    fn stable_id(&self) -> Option<&str>;
}

impl StableId for Rule {
    fn stable_id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

impl StableId for RouteRule {
    fn stable_id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

impl StableId for RateLimitRule {
    fn stable_id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

/// Whether two entries are the same element: the same stable id, or, for two
/// entries without one, the same content. Never by position.
fn same_entry<T: StableId>(base: Option<&T>, candidate: Option<&T>) -> bool {
    match (base, candidate) {
        (Some(base), Some(candidate)) => match (base.stable_id(), candidate.stable_id()) {
            (Some(base_id), Some(candidate_id)) => base_id == candidate_id,
            (None, None) => base == candidate,
            _ => false,
        },
        _ => false,
    }
}

fn same_element(pair: &PolicyPair, base: Element, candidate: Element) -> bool {
    let (from, to) = (pair.base(), &pair.candidate);
    match (base, candidate) {
        (Element::Rule(base), Element::Rule(candidate)) => same_entry(
            from.compiled.direct_rules().get(base),
            to.compiled.direct_rules().get(candidate),
        ),
        (Element::Route(base), Element::Route(candidate)) => same_entry(
            from.compiled.routes().get(base),
            to.compiled.routes().get(candidate),
        ),
        (Element::ToolEntry(base), Element::ToolEntry(candidate)) => {
            match (from.tool_names.get(base), to.tool_names.get(candidate)) {
                (Some(base), Some(candidate)) => base == candidate,
                _ => false,
            }
        }
        (Element::Default, Element::Default)
        | (Element::HostBinding, Element::HostBinding)
        | (Element::NoToolEntry, Element::NoToolEntry) => true,
        _ => false,
    }
}

fn same_observation(pair: &PolicyPair, base: Option<usize>, candidate: Option<usize>) -> bool {
    match (base, candidate) {
        (None, None) => true,
        (Some(base), Some(candidate)) => same_entry(
            pair.base().compiled.direct_rules().get(base),
            pair.candidate.compiled.direct_rules().get(candidate),
        ),
        _ => false,
    }
}

/// How one record's answer changed from the base to the candidate. Declared
/// in rendering priority: the change an operator must review first, first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Transition {
    NewlyAllowed,
    EnforcementOnlyChange,
    NewlyDenied,
    AttributionOnlyChange,
    UnchangedDeny,
    UnchangedAllow,
    Indeterminate,
    UnsupportedContext,
}

impl Transition {
    const ALL: [Self; 8] = [
        Self::NewlyAllowed,
        Self::EnforcementOnlyChange,
        Self::NewlyDenied,
        Self::AttributionOnlyChange,
        Self::UnchangedDeny,
        Self::UnchangedAllow,
        Self::Indeterminate,
        Self::UnsupportedContext,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NewlyAllowed => "newly_allowed",
            Self::EnforcementOnlyChange => "enforcement_only_change",
            Self::NewlyDenied => "newly_denied",
            Self::AttributionOnlyChange => "attribution_only_change",
            Self::UnchangedDeny => "unchanged_deny",
            Self::UnchangedAllow => "unchanged_allow",
            Self::Indeterminate => "indeterminate",
            Self::UnsupportedContext => "unsupported_context",
        }
    }

    fn is_change(self) -> bool {
        matches!(
            self,
            Self::NewlyAllowed
                | Self::EnforcementOnlyChange
                | Self::NewlyDenied
                | Self::AttributionOnlyChange
        )
    }

    fn is_compared(self) -> bool {
        !matches!(self, Self::Indeterminate | Self::UnsupportedContext)
    }

    /// The transition between two decided answers.
    fn between(pair: &PolicyPair, base: &Decided, candidate: &Decided) -> Self {
        match (base.logical, candidate.logical) {
            (LogicalDecision::Allow, LogicalDecision::Deny) => Self::NewlyDenied,
            (LogicalDecision::Deny, LogicalDecision::Allow) => Self::NewlyAllowed,
            _ if base.effect != candidate.effect => Self::EnforcementOnlyChange,
            _ if base.reason != candidate.reason
                || !same_element(pair, base.element, candidate.element)
                || !same_observation(pair, base.observation, candidate.observation) =>
            {
                Self::AttributionOnlyChange
            }
            (LogicalDecision::Allow, _) => Self::UnchangedAllow,
            _ => Self::UnchangedDeny,
        }
    }
}

/// Whether a decided pair changes what a request would meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Forwarding {
    /// The base would block it; the candidate would forward it.
    NewlyForwarded,
    /// The base would forward it; the candidate would block it.
    NewlyBlocked,
    Unchanged,
}

impl Forwarding {
    fn between(base: PolicyEffect, candidate: PolicyEffect) -> Self {
        match (
            base == PolicyEffect::Block,
            candidate == PolicyEffect::Block,
        ) {
            (true, false) => Self::NewlyForwarded,
            (false, true) => Self::NewlyBlocked,
            _ => Self::Unchanged,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::NewlyForwarded => "newly_forwarded",
            Self::NewlyBlocked => "newly_blocked",
            Self::Unchanged => "unchanged",
        }
    }
}

/// Every code of `all` with its count, zeros included, so an absent code is
/// never mistaken for one that was not counted.
fn code_counts<T: Copy + Ord>(
    all: &[T],
    counts: &BTreeMap<T, u64>,
    code: fn(T) -> &'static str,
) -> Value {
    let mut rendered = Map::new();
    for item in all {
        rendered.insert(
            code(*item).to_owned(),
            json!(counts.get(item).copied().unwrap_or(0)),
        );
    }
    Value::Object(rendered)
}

fn bump<K: Ord>(map: &mut BTreeMap<K, u64>, key: K) {
    *map.entry(key).or_default() += 1;
}

/// At most `max` rows, rendered in the order given; the records in the rows
/// past it are counted, never dropped silently.
fn bounded_rows<'a, K: 'a>(
    rows: impl Iterator<Item = (&'a K, u64)>,
    max: usize,
    render: impl Fn(&K, u64) -> Value,
) -> (Vec<Value>, u64) {
    let mut kept = Vec::new();
    let mut omitted = 0;
    for (key, count) in rows {
        if kept.len() < max {
            kept.push(render(key, count));
        } else {
            omitted += count;
        }
    }
    (kept, omitted)
}

fn entry_view(kind: &str, position: usize, id: Option<&str>) -> Value {
    let mut view = Map::new();
    view.insert("kind".to_owned(), json!(kind));
    view.insert("position".to_owned(), json!(position));
    match id {
        Some(id) if id.len() <= MAX_ECHOED_POLICY_STRING_BYTES => {
            view.insert("id".to_owned(), json!(id));
        }
        Some(_) => {
            view.insert("id_omitted".to_owned(), json!(true));
        }
        None => {}
    }
    Value::Object(view)
}

/// An element as a result names it: by position in `policy`, with its bounded
/// authored id, or a tool entry by its name in `policy`'s own tool map.
fn element_view(policy: &ReplayPolicy, element: Element) -> Value {
    match element {
        Element::Rule(position) => entry_view(
            "rule",
            position,
            policy
                .compiled
                .direct_rules()
                .get(position)
                .and_then(StableId::stable_id),
        ),
        Element::Route(position) => entry_view(
            "route",
            position,
            policy
                .compiled
                .routes()
                .get(position)
                .and_then(StableId::stable_id),
        ),
        Element::Default => json!({ "kind": "default" }),
        Element::HostBinding => json!({ "kind": "host_binding" }),
        Element::ToolEntry(position) => match policy.tool_names.get(position) {
            Some(name) if name.len() <= MAX_ECHOED_POLICY_STRING_BYTES => {
                json!({ "kind": "tool_entry", "tool": name })
            }
            _ => json!({ "kind": "tool_entry", "tool_omitted": true }),
        },
        Element::NoToolEntry => json!({ "kind": "no_tool_entry" }),
    }
}

fn rate_element_view(policy: &ReplayPolicy, position: Option<usize>) -> Value {
    match position {
        Some(position) => entry_view(
            "rate_override",
            position,
            policy
                .compiled
                .rate_limit_rules()
                .get(position)
                .and_then(StableId::stable_id),
        ),
        None => json!({ "kind": "no_override" }),
    }
}

/// One lane's base-to-candidate comparison under one projection.
#[derive(Default)]
struct LaneComparison {
    records: u64,
    transitions: BTreeMap<Transition, u64>,
    newly_forwarded: u64,
    newly_blocked: u64,
    matrix: BTreeMap<(Transition, Forwarding, State, State), u64>,
    /// Changed records only, by the element that decided under each policy.
    elements: BTreeMap<(Transition, Forwarding, Element, Element), u64>,
    base_limitations: BTreeMap<&'static str, u64>,
    candidate_limitations: BTreeMap<&'static str, u64>,
    refusals: BTreeMap<&'static str, u64>,
}

impl LaneComparison {
    fn observe(&mut self, pair: &PolicyPair, base: Answer, candidate: Answer) {
        self.records += 1;
        let (base, candidate) = match (base, candidate) {
            (Answer::Decided(base), Answer::Decided(candidate)) => (base, candidate),
            (Answer::Refused(code), _) | (_, Answer::Refused(code)) => {
                bump(&mut self.transitions, Transition::UnsupportedContext);
                bump(&mut self.refusals, code);
                return;
            }
            (base, candidate) => {
                bump(&mut self.transitions, Transition::Indeterminate);
                if let Answer::Indeterminate(code) = base {
                    bump(&mut self.base_limitations, code);
                }
                if let Answer::Indeterminate(code) = candidate {
                    bump(&mut self.candidate_limitations, code);
                }
                return;
            }
        };
        let transition = Transition::between(pair, &base, &candidate);
        let forwarding = Forwarding::between(base.effect, candidate.effect);
        bump(&mut self.transitions, transition);
        match forwarding {
            Forwarding::NewlyForwarded => self.newly_forwarded += 1,
            Forwarding::NewlyBlocked => self.newly_blocked += 1,
            Forwarding::Unchanged => {}
        }
        bump(
            &mut self.matrix,
            (transition, forwarding, base.state(), candidate.state()),
        );
        if transition.is_change() {
            bump(
                &mut self.elements,
                (transition, forwarding, base.element, candidate.element),
            );
        }
    }

    fn count(&self, transition: Transition) -> u64 {
        self.transitions.get(&transition).copied().unwrap_or(0)
    }

    fn compared(&self) -> u64 {
        self.transitions
            .iter()
            .filter(|(transition, _)| transition.is_compared())
            .map(|(_, count)| count)
            .sum()
    }

    fn render(&self, pair: &PolicyPair) -> Value {
        let (matrix, matrix_omitted) = bounded_rows(
            self.matrix.iter().map(|(key, count)| (key, *count)),
            MAX_IMPACT_MATRIX_ROWS,
            |(transition, forwarding, base, candidate), count| {
                json!({
                    "transition": transition.as_str(),
                    "forwarding": forwarding.as_str(),
                    "base": base.render(),
                    "candidate": candidate.render(),
                    "count": count,
                })
            },
        );
        // Most records first within a transition, so a cap keeps the
        // elements that moved the most.
        let mut elements: Vec<_> = self.elements.iter().collect();
        elements.sort_by_key(|((transition, forwarding, base, candidate), count)| {
            (
                *transition,
                *forwarding,
                Reverse(**count),
                *base,
                *candidate,
            )
        });
        let (changed_elements, changed_elements_omitted) = bounded_rows(
            elements.into_iter().map(|(key, count)| (key, *count)),
            MAX_IMPACT_ELEMENT_ROWS,
            |(transition, forwarding, base, candidate), count| {
                json!({
                    "transition": transition.as_str(),
                    "forwarding": forwarding.as_str(),
                    "base": element_view(pair.base(), *base),
                    "candidate": element_view(&pair.candidate, *candidate),
                    "count": count,
                })
            },
        );
        json!({
            "records": self.records,
            "compared": self.compared(),
            "transitions": code_counts(&Transition::ALL, &self.transitions, Transition::as_str),
            "forwarding": {
                "newly_forwarded": self.newly_forwarded,
                "newly_blocked": self.newly_blocked,
            },
            "matrix": matrix,
            "matrix_omitted": matrix_omitted,
            "changed_elements": changed_elements,
            "changed_elements_omitted": changed_elements_omitted,
            "limitations": {
                "base": self.base_limitations,
                "candidate": self.candidate_limitations,
            },
            "refusals": self.refusals,
        })
    }
}

/// Both decision lanes under one projection.
#[derive(Default)]
struct ProjectionTally {
    http: LaneComparison,
    tool: LaneComparison,
}

impl ProjectionTally {
    fn total(&self, transition: Transition) -> u64 {
        self.http.count(transition) + self.tool.count(transition)
    }

    fn compared(&self) -> u64 {
        self.http.compared() + self.tool.compared()
    }

    fn newly_forwarded(&self) -> u64 {
        self.http.newly_forwarded + self.tool.newly_forwarded
    }

    /// What the as-authored comparison establishes, as a stable code. The
    /// required sentence is given only when it holds: the result is complete,
    /// at least one record was compared, and no compared record was newly
    /// allowed or newly forwarded. It is never a statement that a policy is
    /// safe, and it covers only the records counted in it.
    fn statement(&self, complete: bool) -> Value {
        let compared = self.compared();
        let newly_allowed = self.total(Transition::NewlyAllowed);
        let newly_forwarded = self.newly_forwarded();
        if newly_allowed > 0 || newly_forwarded > 0 {
            json!({
                "code": "newly_allowed_observed",
                "newly_allowed": newly_allowed,
                "newly_forwarded": newly_forwarded,
                "replayable_events": compared,
            })
        } else if !complete {
            json!({ "code": "not_established", "reason": "incomplete" })
        } else if compared == 0 {
            json!({ "code": "not_established", "reason": "nothing_compared" })
        } else {
            json!({
                "code": "no_newly_allowed_observed",
                "replayable_events": compared,
                "text": format!("{NO_NEWLY_ALLOWED_TEXT} {compared} replayable events."),
            })
        }
    }

    /// `complete` is the job's completeness when this projection carries the
    /// statement, and `None` when it does not.
    fn render(&self, pair: &PolicyPair, complete: Option<bool>) -> Value {
        let mut view = Map::new();
        if let Some(complete) = complete {
            view.insert("statement".to_owned(), self.statement(complete));
        }
        view.insert("http".to_owned(), self.http.render(pair));
        view.insert("tool".to_owned(), self.tool.render(pair));
        Value::Object(view)
    }

    /// Counts only, for the job's completion record.
    fn summary(&self) -> Value {
        json!({
            "compared": self.compared(),
            "newly_allowed": self.total(Transition::NewlyAllowed),
            "newly_denied": self.total(Transition::NewlyDenied),
            "enforcement_only_change": self.total(Transition::EnforcementOnlyChange),
            "newly_forwarded": self.newly_forwarded(),
            "newly_blocked": self.http.newly_blocked + self.tool.newly_blocked,
            "indeterminate": self.total(Transition::Indeterminate),
            "unsupported_context": self.total(Transition::UnsupportedContext),
        })
    }
}

/// How one record's rate-override selection changed. Selection only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RateTransition {
    OverrideChanged,
    OverrideAdded,
    OverrideRemoved,
    Unchanged,
    Indeterminate,
    UnsupportedContext,
}

impl RateTransition {
    const ALL: [Self; 6] = [
        Self::OverrideChanged,
        Self::OverrideAdded,
        Self::OverrideRemoved,
        Self::Unchanged,
        Self::Indeterminate,
        Self::UnsupportedContext,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::OverrideChanged => "override_changed",
            Self::OverrideAdded => "override_added",
            Self::OverrideRemoved => "override_removed",
            Self::Unchanged => "unchanged",
            Self::Indeterminate => "indeterminate",
            Self::UnsupportedContext => "unsupported_context",
        }
    }
}

/// How a changed override's configured limits compare with the base's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LimitChange {
    Looser,
    Mixed,
    Tighter,
    Same,
}

impl LimitChange {
    const ALL: [Self; 4] = [Self::Looser, Self::Mixed, Self::Tighter, Self::Same];

    fn as_str(self) -> &'static str {
        match self {
            Self::Looser => "looser",
            Self::Mixed => "mixed",
            Self::Tighter => "tighter",
            Self::Same => "same",
        }
    }

    fn between(base: (f64, u32), candidate: (f64, u32)) -> Self {
        use std::cmp::Ordering::{Equal, Greater, Less};
        match (candidate.0.partial_cmp(&base.0), candidate.1.cmp(&base.1)) {
            (Some(Equal), Equal) => Self::Same,
            (Some(Greater | Equal), Greater | Equal) => Self::Looser,
            (Some(Less | Equal), Less | Equal) => Self::Tighter,
            // Opposite directions, or a rate that does not compare.
            _ => Self::Mixed,
        }
    }
}

/// The base-to-candidate comparison of rate-override selection. A projection
/// changes no override, so there is one, for the policies as authored.
#[derive(Default)]
struct RateComparison {
    records: u64,
    transitions: BTreeMap<RateTransition, u64>,
    limits: BTreeMap<LimitChange, u64>,
    elements: BTreeMap<(RateTransition, Option<usize>, Option<usize>), u64>,
    base_limitations: BTreeMap<&'static str, u64>,
    candidate_limitations: BTreeMap<&'static str, u64>,
    refusals: BTreeMap<&'static str, u64>,
}

impl RateComparison {
    fn observe(&mut self, pair: &PolicyPair, base: RateAnswer, candidate: RateAnswer) {
        self.records += 1;
        let transition = match (base, candidate) {
            (RateAnswer::Refused(code), _) | (_, RateAnswer::Refused(code)) => {
                bump(&mut self.refusals, code);
                RateTransition::UnsupportedContext
            }
            (RateAnswer::Indeterminate(_), _) | (_, RateAnswer::Indeterminate(_)) => {
                if let RateAnswer::Indeterminate(code) = base {
                    bump(&mut self.base_limitations, code);
                }
                if let RateAnswer::Indeterminate(code) = candidate {
                    bump(&mut self.candidate_limitations, code);
                }
                RateTransition::Indeterminate
            }
            (RateAnswer::NoOverride, RateAnswer::NoOverride) => RateTransition::Unchanged,
            (RateAnswer::NoOverride, RateAnswer::Override { .. }) => RateTransition::OverrideAdded,
            (RateAnswer::Override { .. }, RateAnswer::NoOverride) => {
                RateTransition::OverrideRemoved
            }
            (
                RateAnswer::Override {
                    position: base_position,
                    requests_per_second: base_rate,
                    burst: base_burst,
                },
                RateAnswer::Override {
                    position: candidate_position,
                    requests_per_second: candidate_rate,
                    burst: candidate_burst,
                },
            ) => {
                let limits = LimitChange::between(
                    (base_rate, base_burst),
                    (candidate_rate, candidate_burst),
                );
                let same = same_entry(
                    pair.base().compiled.rate_limit_rules().get(base_position),
                    pair.candidate
                        .compiled
                        .rate_limit_rules()
                        .get(candidate_position),
                );
                if limits == LimitChange::Same && same {
                    RateTransition::Unchanged
                } else {
                    bump(&mut self.limits, limits);
                    RateTransition::OverrideChanged
                }
            }
        };
        bump(&mut self.transitions, transition);
        if matches!(
            transition,
            RateTransition::OverrideChanged
                | RateTransition::OverrideAdded
                | RateTransition::OverrideRemoved
        ) {
            bump(
                &mut self.elements,
                (transition, base.position(), candidate.position()),
            );
        }
    }

    fn render(&self, pair: &PolicyPair) -> Value {
        let mut elements: Vec<_> = self.elements.iter().collect();
        elements.sort_by_key(|((transition, base, candidate), count)| {
            (*transition, Reverse(**count), *base, *candidate)
        });
        let (changed_elements, changed_elements_omitted) = bounded_rows(
            elements.into_iter().map(|(key, count)| (key, *count)),
            MAX_IMPACT_ELEMENT_ROWS,
            |(transition, base, candidate), count| {
                json!({
                    "transition": transition.as_str(),
                    "base": rate_element_view(pair.base(), *base),
                    "candidate": rate_element_view(&pair.candidate, *candidate),
                    "count": count,
                })
            },
        );
        let compared: u64 = self
            .transitions
            .iter()
            .filter(|(transition, _)| {
                !matches!(
                    transition,
                    RateTransition::Indeterminate | RateTransition::UnsupportedContext
                )
            })
            .map(|(_, count)| count)
            .sum();
        json!({
            "records": self.records,
            "compared": compared,
            "transitions": code_counts(
                &RateTransition::ALL,
                &self.transitions,
                RateTransition::as_str,
            ),
            "limits": code_counts(&LimitChange::ALL, &self.limits, LimitChange::as_str),
            "changed_elements": changed_elements,
            "changed_elements_omitted": changed_elements_omitted,
            "limitations": {
                "base": self.base_limitations,
                "candidate": self.candidate_limitations,
            },
            "refusals": self.refusals,
        })
    }
}

impl RateAnswer {
    fn position(self) -> Option<usize> {
        match self {
            Self::Override { position, .. } => Some(position),
            _ => None,
        }
    }
}

/// How a recorded result compares with the base's answer for the same
/// record. Declared in rendering priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RecordedComparison {
    /// The base decides differently from what was recorded.
    OutcomeDiffers,
    /// The same outcome, with a different reason or deciding element.
    AttributionDiffers,
    /// The base decides as recorded, for the reason and by the element the
    /// record names, as far as the record states them.
    Agrees,
    /// The record is not a policy verdict: the policy stage did not answer
    /// the request, and the record says why.
    RecordedNotPolicyVerdict,
    /// The base could not answer for want of a fact.
    BaseIndeterminate,
    /// The kernel refused the record's facts.
    BaseRefused,
}

impl RecordedComparison {
    const ALL: [Self; 6] = [
        Self::OutcomeDiffers,
        Self::AttributionDiffers,
        Self::Agrees,
        Self::RecordedNotPolicyVerdict,
        Self::BaseIndeterminate,
        Self::BaseRefused,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::OutcomeDiffers => "outcome_differs",
            Self::AttributionDiffers => "attribution_differs",
            Self::Agrees => "agrees",
            Self::RecordedNotPolicyVerdict => "recorded_not_policy_verdict",
            Self::BaseIndeterminate => "base_indeterminate",
            Self::BaseRefused => "base_refused",
        }
    }

    fn is_compared(self) -> bool {
        matches!(
            self,
            Self::OutcomeDiffers | Self::AttributionDiffers | Self::Agrees
        )
    }
}

/// The recorded reason as the code from the closed set of verdict reasons
/// it matches, or `None` when it is not one: the value itself is never kept.
fn verdict_reason(source: ReplaySource, reason: &str) -> Option<&'static str> {
    match source {
        ReplaySource::HttpObservation => HTTP_VERDICT_REASONS
            .into_iter()
            .map(Reason::as_str)
            .find(|code| *code == reason),
        ReplaySource::ToolAdmission | ReplaySource::ToolRuleDecision => TOOL_VERDICT_REASONS
            .into_iter()
            .map(ToolReason::as_str)
            .find(|code| *code == reason),
    }
}

/// What the live stage records for an answer with this effect: the HTTP
/// lane records the effect itself; the tool lane records an invocation that
/// policy let through -- shadow-observed or not -- as admitted.
fn recordable_policy(source: ReplaySource, effect: PolicyEffect) -> RecordedPolicy {
    match (source, effect) {
        (_, PolicyEffect::Block) => RecordedPolicy::Denied,
        (ReplaySource::HttpObservation, PolicyEffect::Allow) => RecordedPolicy::Allowed,
        (ReplaySource::HttpObservation, PolicyEffect::Observe) => RecordedPolicy::WouldDeny,
        (ReplaySource::ToolAdmission | ReplaySource::ToolRuleDecision, _) => {
            RecordedPolicy::Admitted
        }
    }
}

/// Whether the element attribution a record names is the one the base's
/// deciding element would be recorded with: a direct rule by its id, or its
/// position when it has none, exactly as the live HTTP and tool adapters
/// record it; a route by its permission and path prefix; anything else by
/// nothing.
fn attribution_matches(policy: &ReplayPolicy, element: Element, recorded: &RecordedResult) -> bool {
    match element {
        Element::Rule(position) => {
            recorded.permission.is_none()
                && recorded.path_prefix.is_none()
                && match (
                    policy.compiled.direct_rules().get(position),
                    recorded.matched_rule_id.as_deref(),
                ) {
                    (Some(rule), Some(recorded_id)) => match rule.id.as_deref() {
                        Some(id) => id == recorded_id,
                        None => recorded_id == position.to_string(),
                    },
                    _ => false,
                }
        }
        Element::Route(position) => {
            recorded.matched_rule_id.is_none()
                && policy.compiled.routes().get(position).is_some_and(|route| {
                    recorded.permission.as_deref() == Some(route.permission.as_str())
                        && recorded.path_prefix.as_deref() == Some(route.path_prefix.as_str())
                })
        }
        Element::Default | Element::HostBinding | Element::ToolEntry(_) | Element::NoToolEntry => {
            recorded.matched_rule_id.is_none()
                && recorded.permission.is_none()
                && recorded.path_prefix.is_none()
        }
    }
}

/// Compare what was recorded for a record with the base's answer for it.
///
/// A recorded reason outside the verdict set makes the record not a policy
/// verdict. Otherwise the outcome is compared and, when the record states a
/// reason, the reason and the element attribution it was recorded with --
/// none at all for a decision no element made. A record that states no
/// reason (a tool invocation policy admitted) is compared by outcome only,
/// and one that dropped an over-long attribution says so and is compared
/// without it.
pub(crate) fn compare_recorded(
    policy: &ReplayPolicy,
    base: Answer,
    recorded: &RecordedResult,
    source: ReplaySource,
) -> RecordedComparison {
    let reason = match recorded.reason.as_deref() {
        None => None,
        Some(reason) => match verdict_reason(source, reason) {
            Some(code) => Some(code),
            None => return RecordedComparison::RecordedNotPolicyVerdict,
        },
    };
    let decided = match base {
        Answer::Decided(decided) => decided,
        Answer::Indeterminate(_) => return RecordedComparison::BaseIndeterminate,
        Answer::Refused(_) => return RecordedComparison::BaseRefused,
    };
    if recordable_policy(source, decided.effect) != recorded.policy {
        return RecordedComparison::OutcomeDiffers;
    }
    let Some(reason) = reason else {
        return RecordedComparison::Agrees;
    };
    if reason != decided.reason
        || (!recorded.attribution_omitted
            && !attribution_matches(policy, decided.element, recorded))
    {
        return RecordedComparison::AttributionDiffers;
    }
    RecordedComparison::Agrees
}

/// `(comparison, recorded policy, recorded reason, base policy, base
/// reason)`: one row of a recorded comparison, all codes from closed sets.
type RecordedRow = (
    RecordedComparison,
    &'static str,
    Option<&'static str>,
    &'static str,
    &'static str,
);

/// One lane's recorded-against-base comparison. It reads the base as
/// authored, the policy the live gateway decided by.
#[derive(Default)]
struct RecordedTally {
    records: u64,
    comparisons: BTreeMap<RecordedComparison, u64>,
    /// The records the base decided and the record states as a verdict.
    matrix: BTreeMap<RecordedRow, u64>,
}

impl RecordedTally {
    fn observe(
        &mut self,
        policy: &ReplayPolicy,
        base: Answer,
        recorded: &RecordedResult,
        source: ReplaySource,
    ) {
        self.records += 1;
        let comparison = compare_recorded(policy, base, recorded, source);
        bump(&mut self.comparisons, comparison);
        if let (Answer::Decided(decided), true) = (base, comparison.is_compared()) {
            let recorded_reason = recorded
                .reason
                .as_deref()
                .and_then(|reason| verdict_reason(source, reason));
            bump(
                &mut self.matrix,
                (
                    comparison,
                    recorded.policy.as_str(),
                    recorded_reason,
                    recordable_policy(source, decided.effect).as_str(),
                    decided.reason,
                ),
            );
        }
    }

    fn render(&self) -> Value {
        let (matrix, matrix_omitted) = bounded_rows(
            self.matrix.iter().map(|(key, count)| (key, *count)),
            MAX_IMPACT_MATRIX_ROWS,
            |(comparison, recorded_policy, recorded_reason, base_policy, base_reason), count| {
                json!({
                    "comparison": comparison.as_str(),
                    "recorded": { "policy": recorded_policy, "reason": recorded_reason },
                    "base": { "policy": base_policy, "reason": base_reason },
                    "count": count,
                })
            },
        );
        json!({
            "records": self.records,
            "comparisons": code_counts(
                &RecordedComparison::ALL,
                &self.comparisons,
                RecordedComparison::as_str,
            ),
            "matrix": matrix,
            "matrix_omitted": matrix_omitted,
        })
    }
}

/// Every comparison one job keeps.
pub(crate) struct ImpactTally {
    as_authored: Option<ProjectionTally>,
    enforce_all_shadow: Option<ProjectionTally>,
    rate: RateComparison,
    recorded_http: RecordedTally,
    recorded_tool: RecordedTally,
}

impl ImpactTally {
    pub(crate) fn new(policies: &ReplayPolicies) -> Self {
        Self {
            as_authored: policies
                .projections
                .contains(&Projection::AsAuthored)
                .then(ProjectionTally::default),
            enforce_all_shadow: policies
                .enforce_all_shadow
                .as_ref()
                .map(|_| ProjectionTally::default()),
            rate: RateComparison::default(),
            recorded_http: RecordedTally::default(),
            recorded_tool: RecordedTally::default(),
        }
    }

    /// Decide a recorded HTTP request under every policy of the job and fold
    /// each comparison in. Returns the candidate's answer as authored, which
    /// the job's own counts report.
    pub(crate) fn observe_http(
        &mut self,
        policies: &ReplayPolicies,
        facts: &HttpFacts,
        recorded: &RecordedResult,
    ) -> Result<Answer, ReplayStop> {
        let pair = &policies.as_authored;
        let candidate = http_answer(&pair.candidate, facts)?;
        let base = match &pair.base {
            None => candidate,
            Some(base) => http_answer(base, facts)?,
        };
        self.recorded_http
            .observe(pair.base(), base, recorded, ReplaySource::HttpObservation);
        if let Some(tally) = &mut self.as_authored {
            tally.http.observe(pair, base, candidate);
        }
        if let (Some(projected), Some(tally)) =
            (&policies.enforce_all_shadow, &mut self.enforce_all_shadow)
        {
            let projected_candidate = http_answer(&projected.candidate, facts)?;
            let projected_base = match &projected.base {
                None => projected_candidate,
                Some(base) => http_answer(base, facts)?,
            };
            tally
                .http
                .observe(projected, projected_base, projected_candidate);
        }
        Ok(candidate)
    }

    /// Select a recorded request's rate override under the candidate and the
    /// base. Returns the candidate's selection.
    pub(crate) fn observe_rate(
        &mut self,
        policies: &ReplayPolicies,
        facts: &HttpFacts,
    ) -> Result<RateAnswer, ReplayStop> {
        let pair = &policies.as_authored;
        let candidate = rate_answer(&pair.candidate, facts)?;
        let base = match &pair.base {
            None => candidate,
            Some(base) => rate_answer(base, facts)?,
        };
        self.rate.observe(pair, base, candidate);
        Ok(candidate)
    }

    /// Decide a recorded tool invocation under every policy of the job.
    /// Returns the candidate's answer as authored.
    pub(crate) fn observe_tool(
        &mut self,
        policies: &ReplayPolicies,
        facts: &ToolFacts,
        recorded: &RecordedResult,
        source: ReplaySource,
    ) -> Result<Answer, ReplayStop> {
        let pair = &policies.as_authored;
        let candidate = tool_answer(&pair.candidate, facts)?;
        let base = match &pair.base {
            None => candidate,
            Some(base) => tool_answer(base, facts)?,
        };
        self.recorded_tool
            .observe(pair.base(), base, recorded, source);
        if let Some(tally) = &mut self.as_authored {
            tally.tool.observe(pair, base, candidate);
        }
        if let (Some(projected), Some(tally)) =
            (&policies.enforce_all_shadow, &mut self.enforce_all_shadow)
        {
            let projected_candidate = tool_answer(&projected.candidate, facts)?;
            let projected_base = match &projected.base {
                None => projected_candidate,
                Some(base) => tool_answer(base, facts)?,
            };
            tally
                .tool
                .observe(projected, projected_base, projected_candidate);
        }
        Ok(candidate)
    }

    /// The `impact` member of a job's result. `complete` is the job's own
    /// completeness, which the as-authored statement depends on.
    pub(crate) fn render(&self, policies: &ReplayPolicies, complete: bool) -> Value {
        let mut projections = Map::new();
        if let Some(tally) = &self.as_authored {
            projections.insert(
                Projection::AsAuthored.as_str().to_owned(),
                tally.render(&policies.as_authored, Some(complete)),
            );
        }
        if let (Some(tally), Some(pair)) = (&self.enforce_all_shadow, &policies.enforce_all_shadow)
        {
            projections.insert(
                Projection::EnforceAllShadow.as_str().to_owned(),
                tally.render(pair, None),
            );
        }
        json!({
            "candidate_is_base": policies.as_authored.base.is_none(),
            "projections": projections,
            "rate": self.rate.render(&policies.as_authored),
            "recorded": {
                "http": self.recorded_http.render(),
                "tool": self.recorded_tool.render(),
            },
        })
    }

    /// Counts per projection, for the job's completion record: no element,
    /// no id and no record value.
    pub(crate) fn summary(&self) -> Value {
        let mut summary = Map::new();
        if let Some(tally) = &self.as_authored {
            summary.insert(Projection::AsAuthored.as_str().to_owned(), tally.summary());
        }
        if let Some(tally) = &self.enforce_all_shadow {
            summary.insert(
                Projection::EnforceAllShadow.as_str().to_owned(),
                tally.summary(),
            );
        }
        Value::Object(summary)
    }
}
