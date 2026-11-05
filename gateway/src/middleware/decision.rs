//! What the request path records about a decision: the auth and policy
//! outcomes the observation middleware reads, the upstream outcome, and the
//! versioned policy decision facts a historical replay compares with (issue
//! #243).

use std::sync::Arc;

use axum::{
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::policy_eval::{
    tools::{ToolEvaluation, ToolReason, TOOL_CONTEXT_VERSION, TOOL_SEMANTICS_VERSION},
    CompiledPolicy, Evaluation, Fact, HostFact, HttpTarget, PolicyEvaluationContext, PolicyFacts,
    PrincipalFact, Reason, RuleReference, HTTP_SEMANTICS_VERSION,
};

/// The stable reason a request carries when it is refused because a
/// security decision it depended on could not be durably recorded under
/// `AUDIT_DURABILITY=required` (issue #425). It is the response's `reason`,
/// the observation's `auth_reason` or `policy_reason`, and nothing else: the
/// store's error never crosses the response boundary.
pub const AUDIT_UNAVAILABLE_REASON: &str = "audit_unavailable";

#[derive(Serialize)]
struct AuditUnavailableBody {
    error: &'static str,
    reason: &'static str,
}

/// `503 {"error":"audit unavailable","reason":"audit_unavailable"}`: the
/// gateway made a decision it cannot evidence, so it does not act on it.
/// The same answer from the authentication and authorization stages, so a
/// client and an operator see one outage, not two.
pub fn audit_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(AuditUnavailableBody {
            error: "audit unavailable",
            reason: AUDIT_UNAVAILABLE_REASON,
        }),
    )
        .into_response()
}

#[derive(Clone, Debug)]
pub struct AuthOutcome {
    pub principal: Option<crate::auth::Principal>,
    pub authenticated: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDecisionOutcome {
    Allowed,
    Denied,
    WouldDeny,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub outcome: PolicyDecisionOutcome,
    pub reason: &'static str,
    pub permission: Option<String>,
    pub path_prefix: Option<String>,
    pub matched_rule_id: Option<String>,
    /// The versioned facts of the evaluator's verdict, which the observation
    /// records as `policy_decision_facts`. `None` for a request the policy
    /// stage refused to answer, and for a decision made outside it.
    pub facts: Option<PolicyDecisionFacts>,
}

/// The exact version of the `policy_decision_facts` member. A reader
/// dispatches on it exactly; any change to what the member states is a new
/// version.
pub const POLICY_DECISION_FACTS_VERSION: &str = "policy-decision.v1";
/// The audit payload member the facts are written under, on
/// `http.request_observed`, `tool.invoke_start`, the `tool.invoke_rejected`
/// written at admission, and a tool-name rule's `authz.*` record.
pub const POLICY_DECISION_FACTS_MEMBER: &str = "policy_decision_facts";
/// Longest authored element id the facts name. A longer one is flagged
/// `id_omitted`, never cut.
pub const MAX_DECISION_ELEMENT_ID_BYTES: usize = 256;

/// The facts one policy verdict was decided with, for a later replay to tell
/// a policy or evaluator change apart from a candidate's.
///
/// They name the installed policy by its ETag and, for a v1 document, its
/// ADR-0004 semantic digest; the evaluator by its semantics and context
/// versions; which of the evaluator's inputs were available; how the request
/// was classified for routing; and the verdict's stable reason and deciding
/// element, by position in that policy with the element's authored id. They
/// hold no request value: no address, header, query, body, argument, email,
/// user agent, subject or path. The identity is computed once per installed
/// snapshot and shared, so a verdict adds one reference count and a
/// fixed-size [`EvaluationFacts`] to the request path, and no allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDecisionFacts {
    identity: Arc<PolicyDecisionIdentity>,
    evaluation: EvaluationFacts,
}

/// The identity of one installed policy snapshot, as its decision facts name
/// it. Built once, at install, from the policy the compiled instance holds.
#[derive(Debug, PartialEq, Eq)]
pub struct PolicyDecisionIdentity {
    /// The ETag the admin API reports for this policy (`crate::policy_etag`).
    etag: String,
    /// The ADR-0004 semantic digest; `None` for a 0.x document, which has no
    /// normative normalization.
    semantic_digest: Option<String>,
    /// The authored id of each direct rule and route, by position.
    rule_ids: Vec<Option<String>>,
    route_ids: Vec<Option<String>>,
}

impl PolicyDecisionIdentity {
    /// The identity of the policy `compiled` was built from, or `None` when
    /// it cannot be computed. Its decisions are then recorded without facts,
    /// as a record from before they existed is: never under a guessed
    /// identity.
    pub(crate) fn of_compiled(compiled: &CompiledPolicy) -> Option<Self> {
        let policy = compiled.engine().policy();
        let etag = match crate::policy_etag(policy) {
            Ok(etag) => etag,
            Err(error) => {
                tracing::error!(error = %error, "failed to compute an installed policy's ETag; its decisions are recorded without decision facts");
                return None;
            }
        };
        let Ok(semantic_digest) =
            crate::rbac::policy_document::accepted_policy_semantic_digest(policy)
        else {
            tracing::error!("failed to compute an installed policy's semantic digest; its decisions are recorded without decision facts");
            return None;
        };
        Some(Self {
            etag,
            semantic_digest,
            rule_ids: policy.rules.iter().map(|rule| rule.id.clone()).collect(),
            route_ids: policy.routes.iter().map(|route| route.id.clone()).collect(),
        })
    }

    #[cfg(test)]
    pub(crate) fn etag(&self) -> &str {
        &self.etag
    }
}

/// The per-verdict part of [`PolicyDecisionFacts`]: codes, versions and
/// positions only, so building one cannot allocate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvaluationFacts {
    lane: DecisionLane,
    semantics_version: &'static str,
    context_version: u16,
    facts_available: u16,
    /// HTTP only: a tool invocation is not routed.
    routing: Option<DecisionRouting>,
    reason: &'static str,
    element: DecisionElement,
}

/// Which lane decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionLane {
    Http,
    Tool,
}

impl DecisionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tool => "tool",
        }
    }
}

/// How the HTTP lane saw the request's routing: the evaluator's target,
/// without the facts it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionRouting {
    /// Routing was never classified.
    Unclassified,
    /// Classified, no proxy route selected, and the path is its own identity.
    Contextless,
    /// Classified, no proxy route selected, and the path is an MCP route
    /// alias decided under the gateway's canonical MCP path as well.
    McpAlias,
    /// Classified onto a proxy route.
    ProxyDispatch,
}

impl DecisionRouting {
    pub const ALL: [Self; 4] = [
        Self::Unclassified,
        Self::Contextless,
        Self::McpAlias,
        Self::ProxyDispatch,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Contextless => "contextless",
            Self::McpAlias => "mcp_alias",
            Self::ProxyDispatch => "proxy_dispatch",
        }
    }
}

/// The policy element that decided, by position in the policy that decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionElement {
    /// A direct rule, by position among the policy's rules.
    Rule(usize),
    /// A route, by position among the policy's routes.
    Route(usize),
    /// The policy's default action.
    Default,
    /// A selected upstream that no host-bound route authorized.
    HostBinding,
    /// The invoked tool's entry, which the record names by its tool name.
    ToolEntry,
    /// The invoked tool has no entry in the policy.
    NoToolEntry,
}

impl DecisionElement {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Rule(_) => "rule",
            Self::Route(_) => "route",
            Self::Default => "default",
            Self::HostBinding => "host_binding",
            Self::ToolEntry => "tool_entry",
            Self::NoToolEntry => "no_tool_entry",
        }
    }
}

/// The bits of `facts_available`: which of the evaluator's inputs a verdict
/// was given. A set bit is an input the evaluator had, whatever its value --
/// an anonymous principal and an absent `Host` are available -- and a clear
/// bit one it was decided without. The positions are part of
/// [`POLICY_DECISION_FACTS_VERSION`] and never reused.
pub mod facts_available {
    pub const METHOD: u16 = 1 << 0;
    pub const PATH: u16 = 1 << 1;
    pub const PRINCIPAL: u16 = 1 << 2;
    pub const ROUTING: u16 = 1 << 3;
    pub const REQUEST_HOST: u16 = 1 << 4;
    pub const TOOL_NAME: u16 = 1 << 5;
    pub const ORGANIZATION: u16 = 1 << 6;
    pub const CLIENT_ADDRESS: u16 = 1 << 7;
    pub const HEADERS: u16 = 1 << 8;
    pub const QUERY: u16 = 1 << 9;
    pub const TOOL_ARGUMENTS: u16 = 1 << 10;
    pub const CLOCK: u16 = 1 << 11;
    /// The typed-matcher facts, which every lane reads beside its context.
    pub const MATCHER_FACTS: u16 =
        ORGANIZATION | CLIENT_ADDRESS | HEADERS | QUERY | TOOL_ARGUMENTS | CLOCK;
    /// Every bit an HTTP verdict can set.
    pub const HTTP: u16 = METHOD | PATH | PRINCIPAL | ROUTING | REQUEST_HOST | MATCHER_FACTS;
    /// Every bit a tool invocation verdict can set.
    pub const TOOL: u16 = TOOL_NAME | PRINCIPAL | MATCHER_FACTS;
}

/// The typed-matcher facts a lane captured.
fn matcher_facts_available(facts: &PolicyFacts) -> u16 {
    let mut available = 0;
    for (captured, bit) in [
        (
            matches!(facts.organization, Fact::Captured(_)),
            facts_available::ORGANIZATION,
        ),
        (
            matches!(facts.source_ip, Fact::Captured(_)),
            facts_available::CLIENT_ADDRESS,
        ),
        (
            matches!(facts.headers, Fact::Captured(_)),
            facts_available::HEADERS,
        ),
        (
            matches!(facts.query, Fact::Captured(_)),
            facts_available::QUERY,
        ),
        (
            matches!(facts.tool_arguments, Fact::Captured(_)),
            facts_available::TOOL_ARGUMENTS,
        ),
        (
            matches!(facts.now, Fact::Captured(_)),
            facts_available::CLOCK,
        ),
    ] {
        if captured {
            available |= bit;
        }
    }
    available
}

impl PolicyDecisionFacts {
    /// The facts of one complete HTTP verdict, from the context and facts it
    /// was decided with. `None` without an identity, or for a verdict whose
    /// element and reason are not a pair the kernel gives: a verdict is
    /// recorded without facts rather than with a guessed element.
    pub(crate) fn http(
        identity: Option<&Arc<PolicyDecisionIdentity>>,
        input: &PolicyEvaluationContext,
        facts: &PolicyFacts,
        evaluation: &Evaluation,
    ) -> Option<Self> {
        let identity = identity?;
        let element = match (evaluation.matched(), evaluation.reason()) {
            (Some(RuleReference::Direct(position)), Reason::MatchedRule) => {
                DecisionElement::Rule(position)
            }
            (
                Some(RuleReference::Route(position)),
                Reason::MatchedRule | Reason::MissingPermission | Reason::MissingPrincipal,
            ) => DecisionElement::Route(position),
            (None, Reason::DefaultAllow | Reason::DefaultDeny) => DecisionElement::Default,
            (None, Reason::HostPolicyRequired) => DecisionElement::HostBinding,
            _ => return None,
        };
        let routing = match input.target {
            HttpTarget::Missing => DecisionRouting::Unclassified,
            HttpTarget::Contextless => DecisionRouting::Contextless,
            HttpTarget::McpAlias { .. } => DecisionRouting::McpAlias,
            HttpTarget::ProxyDispatch => DecisionRouting::ProxyDispatch,
        };
        let mut available = matcher_facts_available(facts);
        for (given, bit) in [
            (input.method.is_some(), facts_available::METHOD),
            (input.path.is_some(), facts_available::PATH),
            (
                !matches!(input.principal, PrincipalFact::Missing),
                facts_available::PRINCIPAL,
            ),
            (
                routing != DecisionRouting::Unclassified,
                facts_available::ROUTING,
            ),
            (
                !matches!(input.request_host, HostFact::Missing),
                facts_available::REQUEST_HOST,
            ),
        ] {
            if given {
                available |= bit;
            }
        }
        Some(Self {
            identity: Arc::clone(identity),
            evaluation: EvaluationFacts {
                lane: DecisionLane::Http,
                semantics_version: HTTP_SEMANTICS_VERSION,
                context_version: input.version,
                facts_available: available,
                routing: Some(routing),
                reason: evaluation.reason().as_str(),
                element,
            },
        })
    }

    /// The facts of one tool invocation verdict the tool lane answered. The
    /// invocation lane always supplies the tool name and a principal fact
    /// (anonymous or authenticated), so both are available. `None` without
    /// an identity, or for an answer whose element and reason are not a pair
    /// the kernel gives.
    pub(crate) fn tool_invocation(
        identity: Option<&Arc<PolicyDecisionIdentity>>,
        facts: &PolicyFacts,
        evaluation: &ToolEvaluation,
    ) -> Option<Self> {
        let identity = identity?;
        let element = match (evaluation.matched(), evaluation.reason()) {
            (Some(RuleReference::Direct(position)), ToolReason::MatchedRule) => {
                DecisionElement::Rule(position)
            }
            (None, ToolReason::UnknownTool) => DecisionElement::NoToolEntry,
            (None, ToolReason::Disabled | ToolReason::RoleNotAllowed | ToolReason::Allowed) => {
                DecisionElement::ToolEntry
            }
            _ => return None,
        };
        Some(Self {
            identity: Arc::clone(identity),
            evaluation: EvaluationFacts {
                lane: DecisionLane::Tool,
                semantics_version: TOOL_SEMANTICS_VERSION,
                context_version: TOOL_CONTEXT_VERSION,
                facts_available: facts_available::TOOL_NAME
                    | facts_available::PRINCIPAL
                    | matcher_facts_available(facts),
                routing: None,
                reason: evaluation.reason().as_str(),
                element,
            },
        })
    }

    /// The installed snapshot's identity these facts name.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> &Arc<PolicyDecisionIdentity> {
        &self.identity
    }

    /// The `policy-decision.v1` JSON form. Deterministic: a member is present
    /// exactly when it applies.
    pub(crate) fn to_json(&self) -> Value {
        let identity = &*self.identity;
        let evaluation = &self.evaluation;
        let mut object = Map::new();
        object.insert(
            "schema_version".to_owned(),
            json!(POLICY_DECISION_FACTS_VERSION),
        );
        object.insert("lane".to_owned(), json!(evaluation.lane.as_str()));
        object.insert("policy_etag".to_owned(), json!(identity.etag));
        if let Some(digest) = &identity.semantic_digest {
            object.insert("policy_semantic_digest".to_owned(), json!(digest));
        }
        object.insert(
            "semantics_version".to_owned(),
            json!(evaluation.semantics_version),
        );
        object.insert(
            "context_version".to_owned(),
            json!(evaluation.context_version),
        );
        object.insert(
            "facts_available".to_owned(),
            json!(evaluation.facts_available),
        );
        if let Some(routing) = evaluation.routing {
            object.insert("routing".to_owned(), json!(routing.as_str()));
        }
        object.insert("reason".to_owned(), json!(evaluation.reason));
        object.insert("element".to_owned(), self.element_json());
        Value::Object(object)
    }

    fn element_json(&self) -> Value {
        let element = self.evaluation.element;
        let mut object = Map::new();
        object.insert("kind".to_owned(), json!(element.kind()));
        let (position, ids) = match element {
            DecisionElement::Rule(position) => (position, &self.identity.rule_ids),
            DecisionElement::Route(position) => (position, &self.identity.route_ids),
            _ => return Value::Object(object),
        };
        object.insert("position".to_owned(), json!(position));
        match ids.get(position).and_then(Option::as_deref) {
            Some(id) if id.len() > MAX_DECISION_ELEMENT_ID_BYTES => {
                object.insert("id_omitted".to_owned(), json!(true));
            }
            Some(id) => {
                object.insert("id".to_owned(), json!(id));
            }
            None => {}
        }
        Value::Object(object)
    }
}

#[derive(Clone, Debug)]
pub struct UpstreamOutcome {
    pub latency_ms: u64,
    pub status: Option<u16>,
    pub pool_id: Option<String>,
    pub endpoint_id: Option<String>,
    pub attempts: Vec<UpstreamAttemptOutcome>,
    pub retry_exhausted: bool,
    pub stream_terminal_pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamAttemptOutcome {
    pub endpoint_id: String,
    pub result: String,
    pub duration_ms: u64,
}
