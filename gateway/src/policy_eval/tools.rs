//! Policy-backed tool decisions. These operations deliberately do not compose
//! into a promise that a tool can execute. Registry visibility, composite grants,
//! admission, leases, HTTP rendering and transport remain adapter responsibilities.
//! No production caller until the tool cutover in #422.

use super::{
    framed_digest, validate_path, CompiledPolicy, EvaluationError, LogicalDecision, PolicyEffect,
    PrincipalFact, ResourceSnapshot, RuleReference, MAX_TRACE_BYTES,
};
use crate::{
    auth::Principal,
    rbac::{matcher::RuleDispatchContext, rule::principal_identity_matches, RuleAction},
    request_bounds::MAX_REQUEST_METHOD_BYTES,
};
use http::Method;
use serde::Serialize;
use std::fmt;

pub(crate) const TOOL_CONTEXT_VERSION: u16 = 1;
const TOOL_SEMANTICS_VERSION: &str = "gg-tool-policy-v1";
const TOOL_DOMAIN: &str = "tool_policy_v1";
// An offline work bound, not a new policy-name grammar. Before live cutover,
// #422 must reconcile this with tool-name admission (currently unbounded).
pub(crate) const MAX_TOOL_NAME_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ToolOperation {
    Invocation,
    Visibility,
    PolicyEligibility,
    /// Enablement only; the caller must already hold a composite grant.
    CompositeLeaf,
    /// Direct HTTP rules only, using unknown dispatch, after request rendering.
    RenderedHttp,
}

#[derive(Clone)]
pub(crate) struct ToolEvaluationContext {
    pub(crate) version: u16,
    pub(crate) snapshot: ResourceSnapshot,
    pub(crate) operation: ToolOperation,
    /// None means uncaptured, not a name absent from the policy.
    pub(crate) tool_name: Option<String>,
    /// The identity seen by the specific consumer, not necessarily the inbound
    /// principal: ToolRuntime currently projects its Actor through three auth
    /// modes, whereas inventory uses the authenticated Principal directly.
    pub(crate) principal: PrincipalFact,
    /// Present only for RenderedHttp; exact separated path, never a URL/query.
    pub(crate) method: Option<Method>,
    pub(crate) path: Option<String>,
}

impl fmt::Debug for ToolEvaluationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolEvaluationContext")
            .finish_non_exhaustive()
    }
}

impl ToolEvaluationContext {
    fn validate(&self, expected: ResourceSnapshot) -> Result<(), EvaluationError> {
        if self.version != TOOL_CONTEXT_VERSION {
            return Err(EvaluationError::UnsupportedContextVersion);
        }
        if self.snapshot != expected {
            return Err(EvaluationError::SnapshotMismatch);
        }
        if self
            .tool_name
            .as_ref()
            .is_some_and(|s| s.len() > MAX_TOOL_NAME_BYTES)
            || self
                .method
                .as_ref()
                .is_some_and(|m| m.as_str().len() > MAX_REQUEST_METHOD_BYTES)
        {
            return Err(EvaluationError::ContextTooLarge);
        }
        if self.operation != ToolOperation::RenderedHttp
            && (self.method.is_some() || self.path.is_some())
        {
            return Err(EvaluationError::InconsistentContext);
        }
        if let Some(path) = &self.path {
            if self.operation == ToolOperation::RenderedHttp {
                validate_rendered_http_path(path)?;
            } else {
                validate_path(path)?;
            }
        }
        if let PrincipalFact::Authenticated(identity) = &self.principal {
            if let Err(problem) = identity.0.check_shape() {
                return Err(if problem.is_size() {
                    EvaluationError::ContextTooLarge
                } else {
                    EvaluationError::InvalidPrincipal
                });
            }
        }
        // The inventory API is authenticated-only. An anonymous input is not a
        // legacy inventory decision; missing identity is separately incomplete.
        if self.operation == ToolOperation::PolicyEligibility
            && matches!(self.principal, PrincipalFact::Anonymous)
        {
            return Err(EvaluationError::InconsistentContext);
        }
        Ok(())
    }

    fn binding(&self) -> Result<ToolBinding, EvaluationError> {
        let principal = match &self.principal {
            PrincipalFact::Missing => ("missing", None),
            PrincipalFact::Anonymous => ("anonymous", None),
            PrincipalFact::Authenticated(identity) => {
                let p = &identity.0;
                let method = match p.auth_method {
                    crate::auth::AuthMethod::Bearer => "bearer",
                    crate::auth::AuthMethod::Cookie => "cookie",
                    crate::auth::AuthMethod::ServiceToken => "service_token",
                    crate::auth::AuthMethod::ClientCertificate => "client_certificate",
                };
                (
                    "authenticated",
                    Some((&p.user_id, &p.issuer, &p.roles, method)),
                )
            }
        };
        let bytes = serde_json::to_vec(&(
            TOOL_SEMANTICS_VERSION,
            self.version,
            self.operation,
            &self.tool_name,
            principal,
            self.method.as_ref().map(Method::as_str),
            &self.path,
        ))
        .map_err(|_| EvaluationError::TraceEncoding)?;
        Ok(ToolBinding {
            snapshot: self.snapshot,
            context_digest: framed_digest(
                "gg.tool-context",
                "application/json",
                TOOL_SEMANTICS_VERSION,
                &bytes,
            ),
        })
    }
}

/// Rendered paths may contain percent-encoded template arguments. The live
/// executor authorizes those exact bytes after segment encoding, so this lane
/// accepts valid escapes while retaining the same structural path guards.
/// Inbound request paths continue to use `validate_path`, which rejects `%`.
fn validate_rendered_http_path(path: &str) -> Result<(), EvaluationError> {
    if path.len() > super::MAX_REQUEST_PATH_BYTES {
        return Err(EvaluationError::ContextTooLarge);
    }
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let valid_hex = |byte: u8| byte.is_ascii_hexdigit();
            if index + 2 >= bytes.len()
                || !valid_hex(bytes[index + 1])
                || !valid_hex(bytes[index + 2])
            {
                return Err(EvaluationError::MalformedPath);
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    if !path.starts_with('/')
        || path.contains(['?', '#', '\\'])
        || bytes.iter().any(|byte| *byte <= b' ' || *byte == 127)
        || path.contains("//")
        || path.split('/').any(|segment| segment == "." || segment == "..")
    {
        return Err(EvaluationError::MalformedPath);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct ToolBinding {
    snapshot: ResourceSnapshot,
    context_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ToolReason {
    UnknownTool,
    Disabled,
    RoleNotAllowed,
    MatchedRule,
    Allowed,
    NotInPolicy,
    PolicyDisabled,
    PrincipalNotEligible,
    PolicyDenied,
    Eligible,
    NoHttpRule,
    Incomplete,
}

impl ToolReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnknownTool => "unknown_tool",
            Self::Disabled => "disabled",
            Self::RoleNotAllowed => "role_not_allowed",
            Self::MatchedRule => "matched_rule",
            Self::Allowed => "allowed",
            Self::NotInPolicy => "not_in_policy",
            Self::PolicyDisabled => "policy_disabled",
            Self::PrincipalNotEligible => "principal_not_eligible",
            Self::PolicyDenied => "policy_denied",
            Self::Eligible => "eligible",
            Self::NoHttpRule => "no_http_rule",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum ToolLimitation {
    #[serde(rename = "missing_tool_name")]
    ToolName,
    #[serde(rename = "missing_principal_fact")]
    Principal,
    #[serde(rename = "missing_method")]
    Method,
    #[serde(rename = "missing_path")]
    Path,
}

const NOT_EVALUATED: &[&str] = &[
    "authentication",
    "request_admission",
    "tool_registry",
    "registry_visibility",
    "composite_grant",
    "request_schema",
    "http_rendering",
    "other_tool_operations",
    "http_routes_and_defaults",
    "enum_source_authorization",
    "legacy_tool_fallback",
    "mutable_capacity",
    "leases",
    "credentials",
    "egress",
    "dns",
    "transport",
    "upstream_execution",
    "live_revision_freshness",
    "gateway_build_identity",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ToolEvaluation {
    binding: ToolBinding,
    domain: &'static str,
    semantics_version: &'static str,
    context_version: u16,
    operation: ToolOperation,
    not_evaluated: &'static [&'static str],
    logical: LogicalDecision,
    effect: PolicyEffect,
    reason: ToolReason,
    matched: Option<RuleReference>,
    complete: bool,
    limitation: Option<ToolLimitation>,
}

impl ToolEvaluation {
    pub(crate) fn logical(&self) -> LogicalDecision {
        self.logical
    }
    pub(crate) fn effect(&self) -> PolicyEffect {
        self.effect
    }
    pub(crate) fn reason(&self) -> ToolReason {
        self.reason
    }
    pub(crate) fn matched(&self) -> Option<RuleReference> {
        self.matched
    }
    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }
    pub(crate) fn limitation(&self) -> Option<ToolLimitation> {
        self.limitation
    }

    pub(crate) fn canonical_trace_bytes(&self) -> Result<Vec<u8>, EvaluationError> {
        let bytes = serde_json::to_vec(self).map_err(|_| EvaluationError::TraceEncoding)?;
        if bytes.len() > MAX_TRACE_BYTES {
            return Err(EvaluationError::TraceTooLarge);
        }
        Ok(bytes)
    }

    pub(crate) fn reusable_for(&self, context: &ToolEvaluationContext) -> bool {
        self.complete
            && context.validate(self.binding.snapshot).is_ok()
            && context
                .binding()
                .is_ok_and(|binding| binding == self.binding)
    }

    fn deny(mut self, reason: ToolReason) -> Self {
        self.logical = LogicalDecision::Deny;
        self.effect = PolicyEffect::Block;
        self.reason = reason;
        self
    }

    fn incomplete(mut self, limitation: ToolLimitation) -> Self {
        self.logical = LogicalDecision::Indeterminate;
        self.effect = PolicyEffect::Block;
        self.reason = ToolReason::Incomplete;
        self.complete = false;
        self.limitation = Some(limitation);
        self
    }
}

impl CompiledPolicy {
    pub(crate) fn evaluate_tool(
        &self,
        context: &ToolEvaluationContext,
    ) -> Result<ToolEvaluation, EvaluationError> {
        context.validate(self.snapshot())?;
        let mut result = ToolEvaluation {
            binding: context.binding()?,
            domain: TOOL_DOMAIN,
            semantics_version: TOOL_SEMANTICS_VERSION,
            context_version: TOOL_CONTEXT_VERSION,
            operation: context.operation,
            not_evaluated: NOT_EVALUATED,
            logical: LogicalDecision::Allow,
            effect: PolicyEffect::Allow,
            reason: ToolReason::Allowed,
            matched: None,
            complete: true,
            limitation: None,
        };
        let Some(name) = &context.tool_name else {
            return Ok(result.incomplete(ToolLimitation::ToolName));
        };
        let principal = match &context.principal {
            PrincipalFact::Missing if context.operation != ToolOperation::CompositeLeaf => {
                return Ok(result.incomplete(ToolLimitation::Principal))
            }
            PrincipalFact::Authenticated(identity) => Some(&identity.0),
            _ => None,
        };
        let preview = matches!(
            context.operation,
            ToolOperation::Visibility | ToolOperation::PolicyEligibility
        );
        let decision = if context.operation == ToolOperation::RenderedHttp {
            let Some(method) = &context.method else {
                return Ok(result.incomplete(ToolLimitation::Method));
            };
            let Some(path) = &context.path else {
                return Ok(result.incomplete(ToolLimitation::Path));
            };
            result.reason = ToolReason::NoHttpRule;
            // This is intentionally neither contextless dispatch nor the HTTP
            // route/default evaluator. It mirrors authorize_http_operation.
            self.matcher.evaluate_with_dispatch(
                method.as_str(),
                path,
                principal,
                RuleDispatchContext::unknown(),
            )
        } else {
            let Some(tool) = self.engine.policy().tools.get(name) else {
                return Ok(result.deny(if preview {
                    ToolReason::NotInPolicy
                } else {
                    ToolReason::UnknownTool
                }));
            };
            if !tool.enabled {
                return Ok(result.deny(if preview {
                    ToolReason::PolicyDisabled
                } else {
                    ToolReason::Disabled
                }));
            }
            if context.operation == ToolOperation::CompositeLeaf {
                return Ok(result);
            }
            if !tool_principal_matches(tool, principal) {
                return Ok(result.deny(if preview {
                    ToolReason::PrincipalNotEligible
                } else {
                    ToolReason::RoleNotAllowed
                }));
            }
            if preview {
                result.reason = ToolReason::Eligible;
            }
            self.matcher.evaluate_tool(name, principal)
        };
        if let Some(decision) = decision {
            result.matched = Some(RuleReference::Direct(decision.rule_index));
            if preview {
                // A shadow rule does not hide a tool, deny inventory eligibility,
                // or ask either preview consumer to emit an observation.
                if decision.action == RuleAction::Deny {
                    result = result.deny(ToolReason::PolicyDenied);
                }
            } else {
                result.reason = ToolReason::MatchedRule;
                match decision.action {
                    RuleAction::Allow => {}
                    RuleAction::Deny => result = result.deny(ToolReason::MatchedRule),
                    RuleAction::Shadow => {
                        result.logical = LogicalDecision::Deny;
                        result.effect = PolicyEffect::Observe;
                    }
                }
            }
        }
        Ok(result)
    }
}

fn tool_principal_matches(
    tool: &crate::rbac::policy::ToolPolicyEntry,
    principal: Option<&Principal>,
) -> bool {
    if tool.allowed_roles.is_empty() && tool.issuers.is_empty() && tool.auth_methods.is_empty() {
        return true;
    }
    principal.is_some_and(|principal| {
        principal_identity_matches(&tool.issuers, &tool.auth_methods, principal)
            && (tool.allowed_roles.is_empty()
                || tool
                    .allowed_roles
                    .iter()
                    .any(|role| principal.roles.contains(role)))
    })
}

#[cfg(test)]
mod tests;
