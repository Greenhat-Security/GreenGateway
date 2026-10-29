//! The questions the existing analysis consumers ask, answered by the shared
//! evaluator (#422 PR 4).
//!
//! Three admin consumers judged policy without it, each with its own copy of
//! part of the matching: the historical rule preview, the endpoint coverage the
//! traffic inventory reports, and the coverage check discovery suggestions use
//! to skip what the policy already decides. They now build an ordinary
//! [`PolicyEvaluationContext`] and ask the kernel, so the facts they supply are
//! validated, and refused when unanswerable, exactly as a live request's are.
//!
//! Coverage asks what the policy would decide for a representative request,
//! which is [`CompiledPolicy::evaluate`] itself. The rule preview asks
//! something narrower, and this module adds the one operation it needs:
//! [`CompiledPolicy::match_direct_rules`], the first direct rule whose own
//! predicates accept the facts. The preview judges a candidate rule alone, so
//! no earlier rule pre-empts it, and a selected virtual upstream does not
//! narrow it to denies as live evaluation does. That is the existing preview
//! contract: a historical match counter, not a simulation of the whole policy.
//! Suggestion coverage of a tool-name candidate asks only whether a tool rule
//! already decides the call, answered by [`CompiledPolicy::match_tool_rules`],
//! the tool lane's rule step without its admission.
//!
//! Like every other operation here, it demands a fact only when an answer can
//! turn on it. A missing principal or an unclassified routing context is
//! unanswerable only when an enabled HTTP rule actually reads it; otherwise
//! the answer is the same whatever the fact would have been.

use std::collections::HashMap;

use super::{
    validated_policy_digest, CompiledPolicy, DispatchFacts, EvaluationError, HttpTarget,
    Limitation, PolicyAuthority, PolicyDigest, PolicyEvaluationContext, PrincipalFact,
    UNCAPTURED_FACTS,
};
use crate::{
    auth::Principal,
    rbac::{
        matcher::{RuleDispatchContext, RuleScan},
        policy::RoleEntry,
        DefaultAction, EgressPolicy, EnforcementMode, Policy, Rule,
    },
    request_bounds::MAX_TOOL_NAME_BYTES,
};

/// The schema the candidate-rule policy is built at. It decides nothing: the
/// preview reads the rule alone, and the digest frame names its own version.
const CANDIDATE_RULE_SCHEMA_VERSION: &str = "0.1.0";

impl CompiledPolicy {
    /// Compiles a policy an analysis consumer holds, for analysis only.
    ///
    /// The snapshot binds the policy's digest and no revision. That is honest
    /// for both modes: a standalone policy has none, and the cluster callers
    /// (suggestion generation reads the active document from the control plane)
    /// hold the document without the watermark it was published at, so claiming
    /// one would invent it. Infallible because only a watermark can be refused.
    pub(crate) fn for_analysis(policy: Policy) -> Self {
        let digest = PolicyDigest::ValidatedPolicy(validated_policy_digest(&policy));
        Self::assemble(policy, digest, PolicyAuthority::Standalone)
    }

    /// One candidate rule, compiled alone, for the historical rule preview.
    ///
    /// Routes, roles and defaults are empty because the preview never reads
    /// them: it asks only [`Self::match_direct_rules`].
    pub(crate) fn for_candidate_rule(rule: Rule) -> Self {
        Self::for_analysis(Policy {
            schema_version: CANDIDATE_RULE_SCHEMA_VERSION.to_owned(),
            id: None,
            default_action: DefaultAction::default(),
            enforcement_mode: EnforcementMode::default(),
            roles: HashMap::new(),
            identity_mappings: None,
            routes: Vec::new(),
            rules: vec![rule],
            egress: EgressPolicy::default(),
            rate_limits: Vec::new(),
            tools: HashMap::new(),
        })
    }

    /// The direct rules this instance decides by, in source order, for an
    /// analysis consumer that resolves a [`super::RuleReference::Direct`]
    /// index or derives representative callers from the rules. Reading them
    /// here rather than from another copy of the policy keeps an index and the
    /// rule it names from coming from two different policies.
    pub(crate) fn direct_rules(&self) -> &[Rule] {
        &self.engine.policy().rules
    }

    /// The roles this instance grants permissions by, for an analysis consumer
    /// that asks about a representative caller of each.
    pub(crate) fn roles(&self) -> &HashMap<String, RoleEntry> {
        &self.engine.policy().roles
    }

    /// Whether this instance grants `principal` the admin `permission`: the
    /// question the admin API asks of the live policy before every admin
    /// operation, asked of this one. The policy resource checks use it to
    /// tell whether a publisher would keep the permission to publish again.
    /// In mapped-role mode it is asked of the internal roles the mappings
    /// grant ([`Self::management_principal`]), exactly as the admin API asks.
    pub(crate) fn principal_has_permission(&self, principal: &Principal, permission: &str) -> bool {
        self.engine
            .principal_has_permission(&self.management_principal(principal), permission)
    }

    /// The first enabled direct HTTP rule whose own predicates -- method, path
    /// pattern, principal and dispatch binding -- accept the supplied facts,
    /// in source order.
    ///
    /// Nothing else participates: no route, default or enforcement mode, and
    /// no host narrowing. A selected virtual upstream narrows live evaluation
    /// to direct denies (see [`Self::evaluate`]); this operation answers the
    /// rule preview's question instead, which is whether a rule's predicates
    /// match a request, not whether the rule would decide it.
    ///
    /// A missing principal or an unclassified routing context is
    /// indeterminate only when an enabled HTTP rule reads that fact. The
    /// pre-cutover preview matched such a request as though it were anonymous,
    /// or under an unknown dispatch, and so counted it as not matching a rule
    /// that constrains either -- a zero presented as an answer.
    ///
    /// An MCP alias is refused as inconsistent: its two identities decide
    /// under action-major precedence, where "the first matching rule" has no
    /// meaning, and the preview never supplies one.
    pub(crate) fn match_direct_rules(
        &self,
        context: &PolicyEvaluationContext,
    ) -> Result<DirectRuleOutcome, EvaluationError> {
        context.validate(self.snapshot)?;
        let dispatch_context = match (&context.target, context.dispatch.as_ref()) {
            (HttpTarget::McpAlias { .. }, _) => return Err(EvaluationError::InconsistentContext),
            (HttpTarget::Contextless, _) => Some(RuleDispatchContext::contextless()),
            (HttpTarget::ProxyDispatch, Some(facts)) => {
                Some(RuleDispatchContext::classified_with_route_id(
                    facts.route_id.as_deref(),
                    facts.route_host.as_deref(),
                    facts.route_path_prefix.as_deref(),
                    Some(facts.upstream_origin.as_str()),
                ))
            }
            // Routing was never classified, or a dispatch was named without
            // its facts. Either way no dispatch-bound rule can be judged.
            (HttpTarget::Missing | HttpTarget::ProxyDispatch, _) => None,
        };
        let limitation = if context.method.is_none() {
            Some(Limitation::MissingMethod)
        } else if context.path.is_none() {
            Some(Limitation::MissingPath)
        } else if matches!(context.principal, PrincipalFact::Missing)
            && self.direct_rules_read(|rule| !rule.principal.is_unconstrained())
        {
            Some(Limitation::MissingPrincipalFact)
        } else if dispatch_context.is_none()
            && self.direct_rules_read(|rule| rule.dispatch.is_some())
        {
            Some(Limitation::MissingDispatchFact)
        } else {
            None
        };
        if let Some(limitation) = limitation {
            return Ok(DirectRuleOutcome::Indeterminate(limitation));
        }
        let (Some(method), Some(path)) = (&context.method, &context.path) else {
            return Err(EvaluationError::InternalInvariant);
        };
        // Past the checks above, a missing principal or dispatch is one no
        // enabled HTTP rule reads, so any stand-in gives the same answer. These
        // are the ones that cannot match a rule that does read it.
        let effective = match &context.principal {
            PrincipalFact::Authenticated(identity) => {
                match self.effective_principal(&identity.0, &UNCAPTURED_FACTS) {
                    Some(effective) => Some(effective),
                    None => {
                        return Ok(DirectRuleOutcome::Indeterminate(
                            Limitation::MissingMatcherFact,
                        ))
                    }
                }
            }
            PrincipalFact::Anonymous | PrincipalFact::Missing => None,
        };
        let dispatch_context = dispatch_context.unwrap_or_else(RuleDispatchContext::unknown);
        Ok(direct_rule_outcome(self.match_direct(
            method.as_str(),
            path,
            None,
            effective.as_deref(),
            dispatch_context,
            false,
            &UNCAPTURED_FACTS,
        )))
    }

    /// Whether any rule that can match an HTTP request reads a fact.
    /// Disabled rules and tool-name rules never match one, so they read none.
    fn direct_rules_read(&self, reads: impl Fn(&Rule) -> bool) -> bool {
        self.direct_rules()
            .iter()
            .any(|rule| rule.enabled && rule.tool_name.is_none() && reads(rule))
    }

    /// The first enabled tool-name rule whose own predicates -- the tool name
    /// and the principal -- accept the supplied facts, in source order.
    ///
    /// This is the tool lane's rule step alone, for suggestion coverage, which
    /// asks whether a tool rule already decides a call. No tool entry,
    /// enablement or entry identity constraint participates: those are the
    /// tool lane's admission, which runs before any tool rule and is not what
    /// coverage asks. HTTP rules never match a tool name.
    ///
    /// A missing principal is indeterminate only when an enabled tool-name
    /// rule constrains it. A name longer than any policy may carry, or a
    /// principal the evaluator refuses for shape, is refused as it is on the
    /// tool lane.
    pub(crate) fn match_tool_rules(
        &self,
        tool_name: &str,
        principal: &PrincipalFact,
    ) -> Result<DirectRuleOutcome, EvaluationError> {
        if tool_name.len() > MAX_TOOL_NAME_BYTES {
            return Err(EvaluationError::ContextTooLarge);
        }
        let effective = match principal {
            PrincipalFact::Authenticated(identity) => {
                if let Err(problem) = identity.0.check_shape() {
                    return Err(if problem.is_size() {
                        EvaluationError::ContextTooLarge
                    } else {
                        EvaluationError::InvalidPrincipal
                    });
                }
                match self.effective_principal(&identity.0, &UNCAPTURED_FACTS) {
                    Some(effective) => Some(effective),
                    None => {
                        return Ok(DirectRuleOutcome::Indeterminate(
                            Limitation::MissingMatcherFact,
                        ))
                    }
                }
            }
            PrincipalFact::Missing
                if self.direct_rules().iter().any(|rule| {
                    rule.enabled && rule.tool_name.is_some() && !rule.principal.is_unconstrained()
                }) =>
            {
                return Ok(DirectRuleOutcome::Indeterminate(
                    Limitation::MissingPrincipalFact,
                ));
            }
            // No enabled tool-name rule reads a missing principal, so the
            // anonymous stand-in gives the same answer.
            PrincipalFact::Anonymous | PrincipalFact::Missing => None,
        };
        Ok(direct_rule_outcome(self.matcher.scan_tool(
            tool_name,
            effective.as_deref(),
            &UNCAPTURED_FACTS,
        )))
    }
}

/// A direct-rule scan as an analysis outcome. A rule whose conditions read a
/// fact no analysis consumer captures is indeterminate, never counted as a
/// match or a miss.
fn direct_rule_outcome(scan: RuleScan) -> DirectRuleOutcome {
    match scan {
        RuleScan::Matched(decision) => DirectRuleOutcome::Matched {
            index: decision.rule_index,
        },
        RuleScan::NoMatch => DirectRuleOutcome::NoMatch,
        RuleScan::Undetermined { .. } => {
            DirectRuleOutcome::Indeterminate(Limitation::MissingMatcherFact)
        }
    }
}

/// The routing facts an analysis consumer found recorded with a request, as
/// the kernel's target and dispatch facts.
///
/// Observations and discovery record the classified dispatch the way
/// `ProxyRouteObservationContext` carries it: an upstream origin whenever a
/// proxy dispatch was selected, with its route id, host and path prefix beside
/// it. No origin and no route facts is classified traffic without a dispatch.
/// Route facts without an origin cannot come from that context, so they are
/// refused as inconsistent rather than read as either.
///
/// The caller states separately whether routing was classified at all; an
/// unclassified request is [`HttpTarget::Missing`] and never reaches here.
pub(crate) fn recorded_dispatch(
    route_id: Option<&str>,
    route_host: Option<&str>,
    route_path_prefix: Option<&str>,
    upstream_origin: Option<&str>,
) -> Result<(HttpTarget, Option<DispatchFacts>), EvaluationError> {
    match upstream_origin {
        Some(upstream_origin) => Ok((
            HttpTarget::ProxyDispatch,
            Some(DispatchFacts {
                route_id: route_id.map(str::to_owned),
                route_host: route_host.map(str::to_owned),
                route_path_prefix: route_path_prefix.map(str::to_owned),
                upstream_origin: upstream_origin.to_owned(),
            }),
        )),
        None if route_id.is_none() && route_host.is_none() && route_path_prefix.is_none() => {
            Ok((HttpTarget::Contextless, None))
        }
        None => Err(EvaluationError::InconsistentContext),
    }
}

/// The first direct rule whose predicates accept the facts.
///
/// Unlike [`super::Evaluation`] it carries no input binding. Nothing retains or
/// reuses one -- the preview and suggestion coverage read it and move on, the
/// preview once per scanned observation -- and a binding is there to stop a
/// retained answer being applied to a different question. An analysis that
/// retains these must bind them first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DirectRuleOutcome {
    NoMatch,
    Matched {
        /// Source ordinal of the rule, including disabled and tool-name
        /// rules; resolve it through [`CompiledPolicy::direct_rules`] on the
        /// same instance.
        index: usize,
    },
    /// A fact an enabled HTTP rule reads was not supplied.
    Indeterminate(Limitation),
}

impl EvaluationError {
    /// Whether the evaluator refused the facts it was handed, rather than the
    /// question: a path, principal, host or dispatch it does not accept.
    ///
    /// An analysis consumer reading retained records reports such a record as
    /// one it could not evaluate. Every other error is the consumer's own
    /// mistake -- a context version or snapshot it built wrongly, or a broken
    /// invariant -- and is never reported as a judgement about the record: the
    /// preview fails the analysis on it, as ADR-0004 requires.
    pub(crate) fn rejects_supplied_facts(self) -> bool {
        matches!(
            self,
            Self::MalformedPath
                | Self::ContextTooLarge
                | Self::InvalidPrincipal
                | Self::InvalidHost
                | Self::InconsistentContext
        )
    }
}

impl Limitation {
    /// The stable limitation code, as the trace serializes it.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MissingMethod => "missing_method",
            Self::MissingPath => "missing_path",
            Self::MissingPrincipalFact => "missing_principal_fact",
            Self::MissingDispatchFact => "missing_dispatch_fact",
            Self::MissingHostFact => "missing_host_fact",
            Self::MissingMatcherFact => "missing_matcher_fact",
        }
    }
}

#[cfg(test)]
mod tests;
