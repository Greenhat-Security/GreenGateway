//! Pure policy foundation for issue #421, PR 1. Production adapters stay in
//! middleware until #422 proves each cutover. This slice supports contextless
//! HTTP direct rules, ordinary permission routes, and defaults only.
//!
//! No runtime handle, store, audit sink, provider, resolver, or callback enters
//! this API. Principal inputs contain only policy facts, never credentials.

// The compiled API intentionally has no production caller before #422.
#![allow(dead_code)]

mod input;
#[cfg(test)]
mod tests;

use std::fmt;

use http::Method;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    auth::{AuthMethod, Principal},
    path_match::{is_unsafe_request_path, path_prefix_matches},
    rbac::{
        matcher::method_matches, policy::KNOWN_TOP_LEVEL_KEYS, DefaultAction, EnforcementMode,
        Policy, PolicyEngine, RuleAction, RuleMatcher,
    },
};

pub(crate) const CONTEXT_VERSION: u16 = 1;
pub(crate) const HTTP_SEMANTICS_VERSION: &str = "gg-http-contextless-v1";
pub(crate) const MAX_TRACE_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyAuthority {
    /// A source digest, not an invented persistent standalone revision.
    Standalone,
    /// The watermark supplied by the existing cluster admission mechanism.
    PostgreSql { security_revision: i64 },
}

/// The complete immutable resource domain for this slice is the policy itself.
/// Routing, tools, Connections and configuration are deliberately not guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ResourceSnapshot {
    source_digest: [u8; 32],
    authority: PolicyAuthority,
    context_version: u16,
    semantics_version: &'static str,
}

pub(crate) struct CompiledPolicy {
    engine: PolicyEngine,
    matcher: RuleMatcher,
    snapshot: ResourceSnapshot,
    unsupported_routing: bool,
}

impl fmt::Debug for CompiledPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledPolicy")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompileError {
    InputTooLarge,
    InvalidJson,
    UnknownField,
    UnsupportedSchema,
    InvalidPolicy,
    InvalidRevision,
}

impl CompiledPolicy {
    pub(crate) fn compile(source: &[u8], authority: PolicyAuthority) -> Result<Self, CompileError> {
        if matches!(authority, PolicyAuthority::PostgreSql { security_revision } if security_revision < 0)
        {
            return Err(CompileError::InvalidRevision);
        }
        let value = input::parse(source)?;
        let object = value.as_object().ok_or(CompileError::InvalidPolicy)?;
        if object
            .keys()
            .any(|key| !KNOWN_TOP_LEVEL_KEYS.contains(&key.as_str()))
        {
            return Err(CompileError::UnknownField);
        }
        // This new offline API has exact dispatch. The legacy parser and live
        // startup keep their existing 0.x acceptance contract unchanged.
        if object
            .get("schema_version")
            .and_then(|value| value.as_str())
            != Some("0.1.0")
        {
            return Err(CompileError::UnsupportedSchema);
        }
        // Reuse the existing normalizer and semantic validator. All top-level
        // keys have been checked, so its unknown-key warning cannot be emitted.
        let policy = Policy::validate_json_value(value).map_err(|_| CompileError::InvalidPolicy)?;
        let unsupported_routing = policy.routes.iter().any(|route| !route.hosts.is_empty())
            || policy.rules.iter().any(|rule| rule.dispatch.is_some());
        let snapshot = ResourceSnapshot {
            source_digest: framed_digest("source", "application/json", "0.1.0", source),
            authority,
            context_version: CONTEXT_VERSION,
            semantics_version: HTTP_SEMANTICS_VERSION,
        };
        Ok(Self {
            matcher: RuleMatcher::new(&policy.rules),
            engine: PolicyEngine::new(policy),
            snapshot,
            unsupported_routing,
        })
    }

    pub(crate) fn snapshot(&self) -> ResourceSnapshot {
        self.snapshot
    }

    pub(crate) fn evaluate(
        &self,
        context: &PolicyEvaluationContext,
    ) -> Result<Evaluation, EvaluationError> {
        context.validate(self.snapshot)?;
        let binding = context.binding()?;
        let missing = if context.method.is_none() {
            Some(Limitation::MissingMethod)
        } else if context.path.is_none() {
            Some(Limitation::MissingPath)
        } else if matches!(context.principal, PrincipalFact::Missing) {
            Some(Limitation::MissingPrincipalFact)
        } else {
            match context.target {
                HttpTarget::Missing => Some(Limitation::MissingDispatchFact),
                HttpTarget::Contextless => None,
                HttpTarget::ProxyDispatch | HttpTarget::McpAlias => {
                    Some(Limitation::UnsupportedTarget)
                }
            }
        };
        if let Some(limitation) = missing {
            return Ok(Evaluation::indeterminate(binding, limitation));
        }
        if self.unsupported_routing {
            return Ok(Evaluation::indeterminate(
                binding,
                Limitation::UnsupportedRoutingPolicy,
            ));
        }
        let (Some(method), Some(path)) = (&context.method, &context.path) else {
            return Err(EvaluationError::InternalInvariant);
        };
        let principal = match &context.principal {
            PrincipalFact::Authenticated(identity) => Some(&identity.0),
            PrincipalFact::Anonymous => None,
            PrincipalFact::Missing => return Err(EvaluationError::InternalInvariant),
        };
        if let Some(decision) = self.matcher.evaluate(method.as_str(), path, principal) {
            let (logical, effect) = match decision.action {
                RuleAction::Allow => (LogicalDecision::Allow, PolicyEffect::Allow),
                RuleAction::Deny => (LogicalDecision::Deny, PolicyEffect::Block),
                RuleAction::Shadow => (LogicalDecision::Deny, PolicyEffect::Observe),
            };
            return Ok(Evaluation::complete(
                binding,
                logical,
                effect,
                Reason::MatchedRule,
                Some(RuleReference::Direct(decision.rule_index)),
            ));
        }
        let policy = self.engine.policy();
        // First match in source order; the existing prefix and method matchers
        // preserve segment boundaries, wildcard methods and case folding.
        if let Some((index, route)) = policy.routes.iter().enumerate().find(|(_, route)| {
            path_prefix_matches(path, &route.path_prefix)
                && method_matches(&route.methods, method.as_str())
        }) {
            let allowed = principal.is_some_and(|principal| {
                self.engine
                    .principal_has_permission(principal, &route.permission)
            });
            let reason = if allowed {
                Reason::MatchedRule
            } else if principal.is_some() {
                Reason::MissingPermission
            } else {
                Reason::MissingPrincipal
            };
            return Ok(Evaluation::complete(
                binding,
                if allowed {
                    LogicalDecision::Allow
                } else {
                    LogicalDecision::Deny
                },
                effect(
                    allowed,
                    route.enforcement_mode.unwrap_or(policy.enforcement_mode),
                ),
                reason,
                Some(RuleReference::Route(index)),
            ));
        }
        let allowed = policy.default_action == DefaultAction::Allow;
        Ok(Evaluation::complete(
            binding,
            if allowed {
                LogicalDecision::Allow
            } else {
                LogicalDecision::Deny
            },
            effect(allowed, policy.enforcement_mode),
            if allowed {
                Reason::DefaultAllow
            } else {
                Reason::DefaultDeny
            },
            None,
        ))
    }
}

fn effect(allowed: bool, mode: EnforcementMode) -> PolicyEffect {
    if allowed {
        PolicyEffect::Allow
    } else if mode == EnforcementMode::Shadow {
        PolicyEffect::Observe
    } else {
        PolicyEffect::Block
    }
}

/// A policy-only projection. Never retain email, organization, session ID,
/// credential material, token claims, or a reference to the original principal.
#[derive(Clone)]
pub(crate) struct PrincipalIdentity(Principal);

impl PrincipalIdentity {
    pub(crate) fn from_principal(principal: &Principal) -> Self {
        Self(Principal {
            user_id: principal.user_id.clone(),
            issuer: principal.issuer.clone(),
            roles: principal.roles.clone(),
            auth_method: principal.auth_method.clone(),
            email: None,
            org_id: None,
            session_id: String::new(),
        })
    }
}

#[derive(Clone)]
pub(crate) enum PrincipalFact {
    Missing,
    Anonymous,
    Authenticated(PrincipalIdentity),
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HttpTarget {
    Missing,
    Contextless,
    ProxyDispatch,
    McpAlias,
}

#[derive(Clone)]
pub(crate) struct PolicyEvaluationContext {
    pub(crate) version: u16,
    pub(crate) snapshot: ResourceSnapshot,
    pub(crate) method: Option<Method>,
    /// Exact already-separated URI path; never query, fragment or full URL.
    pub(crate) path: Option<String>,
    pub(crate) principal: PrincipalFact,
    pub(crate) target: HttpTarget,
}

impl fmt::Debug for PolicyEvaluationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyEvaluationContext")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EvaluationError {
    UnsupportedContextVersion,
    SnapshotMismatch,
    MalformedPath,
    ContextTooLarge,
    InvalidPrincipal,
    InternalInvariant,
    TraceEncoding,
    TraceTooLarge,
}

impl PolicyEvaluationContext {
    fn validate(&self, expected: ResourceSnapshot) -> Result<(), EvaluationError> {
        if self.version != CONTEXT_VERSION {
            return Err(EvaluationError::UnsupportedContextVersion);
        }
        if self.snapshot != expected {
            return Err(EvaluationError::SnapshotMismatch);
        }
        if let Some(path) = &self.path {
            if path.len() > 8192 {
                return Err(EvaluationError::ContextTooLarge);
            }
            if !path.starts_with('/')
                || path.contains(['?', '#'])
                || path.bytes().any(|byte| byte <= b' ' || byte == 127)
                || is_unsafe_request_path(path)
            {
                return Err(EvaluationError::MalformedPath);
            }
        }
        if self
            .method
            .as_ref()
            .is_some_and(|method| method.as_str().len() > 64)
        {
            return Err(EvaluationError::ContextTooLarge);
        }
        if let PrincipalFact::Authenticated(identity) = &self.principal {
            let principal = &identity.0;
            if principal.roles.len() > 256
                || principal.user_id.len() > 4096
                || principal
                    .issuer
                    .as_ref()
                    .is_some_and(|issuer| issuer.len() > 4096)
                || principal.roles.iter().any(|role| role.len() > 256)
            {
                return Err(EvaluationError::ContextTooLarge);
            }
            if principal.user_id.is_empty() || principal.roles.iter().any(|role| role.is_empty()) {
                return Err(EvaluationError::InvalidPrincipal);
            }
        }
        Ok(())
    }

    fn binding(&self) -> Result<InputBinding, EvaluationError> {
        let principal = match &self.principal {
            PrincipalFact::Missing => ("missing", None),
            PrincipalFact::Anonymous => ("anonymous", None),
            PrincipalFact::Authenticated(identity) => {
                let principal = &identity.0;
                let method = match principal.auth_method {
                    AuthMethod::Cookie => "cookie",
                    AuthMethod::Bearer => "bearer",
                    AuthMethod::ServiceToken => "service_token",
                    AuthMethod::ClientCertificate => "client_certificate",
                };
                (
                    "authenticated",
                    Some((
                        &principal.user_id,
                        &principal.issuer,
                        &principal.roles,
                        method,
                    )),
                )
            }
        };
        let bytes = serde_json::to_vec(&(
            self.version,
            self.target,
            self.method.as_ref().map(Method::as_str),
            &self.path,
            principal,
        ))
        .map_err(|_| EvaluationError::TraceEncoding)?;
        Ok(InputBinding {
            snapshot: self.snapshot,
            context_digest: framed_digest("context", "application/json", "1", &bytes),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct InputBinding {
    snapshot: ResourceSnapshot,
    context_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LogicalDecision {
    Allow,
    Deny,
    Indeterminate,
}

/// Effect within this logical lane only. Allow/Observe never promise forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyEffect {
    Allow,
    Block,
    Observe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuleReference {
    Direct(usize),
    Route(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    MatchedRule,
    MissingPermission,
    MissingPrincipal,
    DefaultAllow,
    DefaultDeny,
    Incomplete,
}

impl Reason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MatchedRule => "matched_rule",
            Self::MissingPermission => "missing_permission",
            Self::MissingPrincipal => "missing_principal",
            Self::DefaultAllow => "default_allow",
            Self::DefaultDeny => "default_deny",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Limitation {
    MissingMethod,
    MissingPath,
    MissingPrincipalFact,
    MissingDispatchFact,
    UnsupportedTarget,
    UnsupportedRoutingPolicy,
}

pub(crate) const NOT_EVALUATED: &[&str] = &[
    "authentication",
    "csrf",
    "request_admission",
    "management_permissions",
    "mcp",
    "tools",
    "routing",
    "rate_selection",
    "mutable_capacity",
    "egress",
    "dns",
    "transport",
    "upstream_execution",
    "live_revision_freshness",
    "gateway_build_identity",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Evaluation {
    binding: InputBinding,
    domain: &'static str,
    not_evaluated: &'static [&'static str],
    logical: LogicalDecision,
    effect: PolicyEffect,
    reason: Reason,
    matched: Option<RuleReference>,
    /// Complete only for the named contextless HTTP policy domain.
    complete: bool,
    limitation: Option<Limitation>,
}

impl Evaluation {
    pub(crate) fn logical(&self) -> LogicalDecision {
        self.logical
    }

    pub(crate) fn effect(&self) -> PolicyEffect {
        self.effect
    }

    pub(crate) fn reason(&self) -> Reason {
        self.reason
    }

    pub(crate) fn matched(&self) -> Option<RuleReference> {
        self.matched
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.complete
    }

    pub(crate) fn limitation(&self) -> Option<Limitation> {
        self.limitation
    }

    fn complete(
        binding: InputBinding,
        logical: LogicalDecision,
        effect: PolicyEffect,
        reason: Reason,
        matched: Option<RuleReference>,
    ) -> Self {
        Self {
            binding,
            domain: "http_contextless_v1",
            not_evaluated: NOT_EVALUATED,
            logical,
            effect,
            reason,
            matched,
            complete: true,
            limitation: None,
        }
    }

    fn indeterminate(binding: InputBinding, limitation: Limitation) -> Self {
        Self {
            binding,
            domain: "http_contextless_v1",
            not_evaluated: NOT_EVALUATED,
            logical: LogicalDecision::Indeterminate,
            effect: PolicyEffect::Block,
            reason: Reason::Incomplete,
            matched: None,
            complete: false,
            limitation: Some(limitation),
        }
    }

    /// Fixed-schema JSON trace: only bounded enums, ordinals, digests and numeric
    /// revisions. No authored IDs, permissions, paths or identity values escape.
    /// This deterministic encoding is not the future policy semantic/JCS digest.
    pub(crate) fn canonical_trace_bytes(&self) -> Result<Vec<u8>, EvaluationError> {
        let bytes = serde_json::to_vec(self).map_err(|_| EvaluationError::TraceEncoding)?;
        if bytes.len() > MAX_TRACE_BYTES {
            return Err(EvaluationError::TraceTooLarge);
        }
        Ok(bytes)
    }

    pub(crate) fn reusable_for(&self, context: &PolicyEvaluationContext) -> bool {
        self.complete
            && context.validate(self.binding.snapshot).is_ok()
            && context
                .binding()
                .is_ok_and(|binding| binding == self.binding)
    }
}

fn framed_digest(kind: &str, media_type: &str, version: &str, payload: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"GGDIGEST\0");
    for part in [
        kind.as_bytes(),
        media_type.as_bytes(),
        version.as_bytes(),
        payload,
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}
