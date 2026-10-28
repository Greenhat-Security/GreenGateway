//! A replay context, asked of the compiled policy.
//!
//! Every function here builds the kernel's own context from recorded facts and
//! calls the kernel; none of them matches a rule, a route or a destination
//! itself. The mapping is one fact to one kernel input, so a fact the record
//! states reaches the kernel unchanged and a fact it does not state reaches it
//! as missing:
//!
//! | Recorded | Kernel input |
//! | --- | --- |
//! | principal `not_recorded` / `anonymous` / `authenticated` | `PrincipalFact::Missing` / `Anonymous` / `Authenticated` |
//! | request host `not_recorded` / `absent` / `present` | `HostFact::Missing` / `Absent` / `Present` |
//! | routing `not_recorded` | `HttpTarget::Missing` |
//! | routing `local`, MCP identity `canonical` | `HttpTarget::Contextless` |
//! | routing `local`, MCP identity `alias` | `HttpTarget::McpAlias` |
//! | routing `local`, MCP identity `not_recorded` | both of the two above; see [`evaluate_http`] |
//! | routing `proxy_dispatch` | `HttpTarget::ProxyDispatch` with the recorded facts |
//! | egress destination | `EgressDestination`, with `ResolutionFact::Missing` |
//!
//! The tool lane projects the recorded principal the way the live tool runtime
//! projects an invocation's actor, through the runtime's own function
//! ([`crate::tools::runtime::principal_from_tool_actor`]), because that
//! projection -- not the HTTP lane's -- is what a tool decision was made on.

use crate::{
    audit::Actor,
    auth::{protected_resource::MCP_RESOURCE_PATH, Principal},
    policy_eval::{
        egress::{
            CompiledEgressPolicy, EgressDestination, EgressEvaluation, EgressEvaluationContext,
            ResolutionFact, EGRESS_CONTEXT_VERSION,
        },
        tools::{ToolEvaluation, ToolEvaluationContext, ToolOperation, TOOL_CONTEXT_VERSION},
        CompiledPolicy, EvaluationError, HostFact, HttpTarget, Limitation, LogicalDecision,
        PolicyEffect, PolicyEvaluationContext, PrincipalFact, PrincipalIdentity, RateLaneSelection,
        Reason, ResourceSnapshot, RuleReference, CONTEXT_VERSION,
    },
    tools::runtime::principal_from_tool_actor,
};

use super::{
    auth_method_code, EgressRecord, HostRecord, HttpFacts, McpIdentity, PrincipalRecord,
    RecordedPrincipal, RoutingRecord, ToolFacts,
};

/// What every plausible reading of an HTTP record decided, when they agree.
///
/// Not an [`crate::policy_eval::Evaluation`]: that value binds the one context
/// it answered, and a record read two ways was not that context. A decision
/// here is therefore never reusable for a live request; it is an answer about
/// the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HttpReplayDecision {
    pub(crate) logical: LogicalDecision,
    pub(crate) effect: PolicyEffect,
    pub(crate) reason: Reason,
    pub(crate) matched: Option<RuleReference>,
    pub(crate) observation: Option<RuleReference>,
    /// How many readings of the record were evaluated: two when its MCP
    /// identity was not recorded, otherwise one.
    pub(crate) readings: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpReplayOutcome {
    Decided(HttpReplayDecision),
    Indeterminate(HttpReplayLimitation),
}

/// Why a replayed HTTP record has no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpReplayLimitation {
    /// The kernel lacked a fact it needed, with its own stable code.
    Kernel(Limitation),
    /// The record does not say whether its path was an MCP alias, and the two
    /// readings decide differently.
    MissingMcpIdentity,
}

impl HttpReplayLimitation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Kernel(limitation) => limitation.as_str(),
            Self::MissingMcpIdentity => "missing_mcp_identity",
        }
    }
}

fn recorded_principal(principal: &RecordedPrincipal) -> Principal {
    Principal {
        user_id: principal.subject.clone(),
        issuer: principal.issuer.clone(),
        email: None,
        org_id: None,
        roles: principal.roles.clone(),
        session_id: String::new(),
        auth_method: principal.auth_method.clone(),
    }
}

/// The principal fact the HTTP lane, and rate-lane selection, read: the
/// authenticated principal itself, as the live HTTP adapter supplies it.
fn http_principal_fact(principal: &PrincipalRecord) -> PrincipalFact {
    match principal {
        PrincipalRecord::NotRecorded => PrincipalFact::Missing,
        PrincipalRecord::Anonymous => PrincipalFact::Anonymous,
        PrincipalRecord::Authenticated(principal) => PrincipalFact::Authenticated(
            PrincipalIdentity::from_principal(&recorded_principal(principal)),
        ),
    }
}

/// The principal fact the tool lane reads: the recorded actor projected the
/// way the tool runtime projects one. An actor the runtime does not project --
/// a client certificate, today -- is judged anonymous there, so it is here.
fn tool_principal_fact(principal: &PrincipalRecord) -> PrincipalFact {
    match principal {
        PrincipalRecord::NotRecorded => PrincipalFact::Missing,
        PrincipalRecord::Anonymous => PrincipalFact::Anonymous,
        PrincipalRecord::Authenticated(principal) => {
            let actor = Actor {
                user_id: principal.subject.clone(),
                issuer: principal.issuer.clone(),
                email: None,
                roles: (!principal.roles.is_empty()).then(|| principal.roles.clone()),
                auth_mode: auth_method_code(&principal.auth_method).to_owned(),
            };
            principal_from_tool_actor(&actor, "").map_or(PrincipalFact::Anonymous, |principal| {
                PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal))
            })
        }
    }
}

fn host_fact(host: &HostRecord) -> HostFact {
    match host {
        HostRecord::NotRecorded => HostFact::Missing,
        HostRecord::Absent => HostFact::Absent,
        HostRecord::Present(host) => HostFact::Present(host.clone()),
    }
}

impl HttpFacts {
    fn context(
        &self,
        snapshot: ResourceSnapshot,
        target: HttpTarget,
        dispatch: Option<crate::policy_eval::DispatchFacts>,
    ) -> PolicyEvaluationContext {
        PolicyEvaluationContext {
            version: CONTEXT_VERSION,
            snapshot,
            method: Some(self.method.clone()),
            path: Some(self.path.clone()),
            principal: http_principal_fact(&self.principal),
            target,
            request_host: host_fact(&self.request_host),
            dispatch,
        }
    }

    /// The HTTP contexts this record could have been decided under: one, or
    /// two when the record does not say whether its path was an MCP alias.
    ///
    /// The second reading names the gateway's one canonical MCP identity,
    /// which every MCP route alias decides under; see
    /// [`crate::auth::protected_resource::mcp_route_paths`].
    pub(crate) fn plausible_contexts(
        &self,
        snapshot: ResourceSnapshot,
    ) -> Vec<PolicyEvaluationContext> {
        match &self.routing {
            RoutingRecord::NotRecorded => vec![self.context(snapshot, HttpTarget::Missing, None)],
            RoutingRecord::Local(McpIdentity::Canonical) => {
                vec![self.context(snapshot, HttpTarget::Contextless, None)]
            }
            RoutingRecord::Local(McpIdentity::Alias { canonical_path }) => vec![self.context(
                snapshot,
                HttpTarget::McpAlias {
                    canonical_path: canonical_path.clone(),
                },
                None,
            )],
            RoutingRecord::Local(McpIdentity::NotRecorded) => vec![
                self.context(snapshot, HttpTarget::Contextless, None),
                self.context(
                    snapshot,
                    HttpTarget::McpAlias {
                        canonical_path: MCP_RESOURCE_PATH.to_owned(),
                    },
                    None,
                ),
            ],
            RoutingRecord::ProxyDispatch(facts) => {
                vec![self.context(snapshot, HttpTarget::ProxyDispatch, Some(facts.clone()))]
            }
        }
    }

    /// The live rate adapter's context exactly: selection reads method, path
    /// and principal, and states routing and host as uncaptured rather than
    /// claim the request had none.
    pub(crate) fn rate_context(&self, snapshot: ResourceSnapshot) -> PolicyEvaluationContext {
        PolicyEvaluationContext {
            version: CONTEXT_VERSION,
            snapshot,
            method: Some(self.method.clone()),
            path: Some(self.path.clone()),
            principal: http_principal_fact(&self.principal),
            target: HttpTarget::Missing,
            request_host: HostFact::Missing,
            dispatch: None,
        }
    }
}

/// Decide a recorded HTTP request under `policy`.
///
/// Each plausible reading is evaluated by [`CompiledPolicy::evaluate`]. The
/// record is decided only when every reading is decided and they agree on
/// everything a decision states -- logical outcome, effect, reason, the
/// deciding element and any observation. A reading the kernel cannot answer
/// makes the record indeterminate with the kernel's limitation; readings that
/// disagree make it indeterminate with `missing_mcp_identity`. Neither is ever
/// resolved by preferring one reading.
///
/// An evaluator error is returned as it is: the kernel refusing a recorded
/// fact means the record is not one a served request could have left, and any
/// other error is a fault in the run, never an answer about the record.
pub(crate) fn evaluate_http(
    policy: &CompiledPolicy,
    facts: &HttpFacts,
) -> Result<HttpReplayOutcome, EvaluationError> {
    let contexts = facts.plausible_contexts(policy.snapshot());
    let readings = contexts.len();
    let mut agreed: Option<HttpReplayDecision> = None;
    for context in &contexts {
        let evaluation = policy.evaluate(context)?;
        if !evaluation.is_complete() || evaluation.logical() == LogicalDecision::Indeterminate {
            let limitation = evaluation
                .limitation()
                .ok_or(EvaluationError::InternalInvariant)?;
            return Ok(HttpReplayOutcome::Indeterminate(
                HttpReplayLimitation::Kernel(limitation),
            ));
        }
        let decision = HttpReplayDecision {
            logical: evaluation.logical(),
            effect: evaluation.effect(),
            reason: evaluation.reason(),
            matched: evaluation.matched(),
            observation: evaluation.observation(),
            readings,
        };
        match agreed {
            None => agreed = Some(decision),
            Some(previous) if previous == decision => {}
            Some(_) => {
                return Ok(HttpReplayOutcome::Indeterminate(
                    HttpReplayLimitation::MissingMcpIdentity,
                ))
            }
        }
    }
    agreed
        .map(HttpReplayOutcome::Decided)
        .ok_or(EvaluationError::InternalInvariant)
}

/// Which rate-limit override `policy` would select for a recorded request.
/// Selection only, as live: whether a bucket had capacity at the time is not
/// recorded and is not reconstructed.
pub(crate) fn select_rate_lane(
    policy: &CompiledPolicy,
    facts: &HttpFacts,
) -> Result<RateLaneSelection, EvaluationError> {
    policy.select_rate_lane(&facts.rate_context(policy.snapshot()))
}

impl ToolFacts {
    /// The invocation question the live tool runtime asks at admission.
    pub(crate) fn invocation_context(&self, snapshot: ResourceSnapshot) -> ToolEvaluationContext {
        ToolEvaluationContext {
            version: TOOL_CONTEXT_VERSION,
            snapshot,
            operation: ToolOperation::Invocation,
            tool_name: Some(self.tool_name.clone()),
            principal: tool_principal_fact(&self.principal),
            method: None,
            path: None,
        }
    }
}

/// Decide a recorded tool invocation's admission under `policy`.
pub(crate) fn evaluate_tool(
    policy: &CompiledPolicy,
    facts: &ToolFacts,
) -> Result<ToolEvaluation, EvaluationError> {
    policy.evaluate_tool(&facts.invocation_context(policy.snapshot()))
}

/// Decide a recorded egress destination under `policy`, with no resolution
/// facts: v1 records none. A destination the static checks refuse is refused;
/// one they admit is indeterminate, because the addresses it resolved to could
/// still have refused it. `None` when the record states no destination.
pub(crate) fn evaluate_egress(
    policy: &CompiledEgressPolicy,
    egress: &EgressRecord,
) -> Option<Result<EgressEvaluation, EvaluationError>> {
    let EgressRecord::Destination(facts) = egress else {
        return None;
    };
    let destination = EgressDestination::from_parts(
        facts.scheme.clone(),
        facts.host.clone(),
        facts.port,
        facts.userinfo,
        facts.fragment,
    );
    Some(policy.evaluate(&EgressEvaluationContext {
        version: EGRESS_CONTEXT_VERSION,
        snapshot: policy.snapshot(),
        destination: &destination,
        resolution: ResolutionFact::Missing,
    }))
}
