//! Pure policy foundation for issue #421. Production adapters stay in
//! middleware until #422 proves each cutover.
//!
//! PR 1 supported contextless HTTP direct rules, ordinary permission routes and
//! defaults. The routing lane added host-qualified routes and dispatch-scoped
//! direct rules, for both contextless requests and a classified proxy dispatch.
//! This slice adds MCP alias identities.
//!
//! ## An alias decides under a different precedence order
//!
//! An MCP endpoint reachable by a path that is not its canonical policy identity
//! has *two* identities, and both decide. They are not evaluated twice and the
//! results combined, because the combination is not expressible that way: the
//! pair uses action-major precedence -- the most restrictive action present
//! anywhere in the rulebase wins, scanned over the union of both paths -- while a
//! single identity uses rule-index-major, the first matching rule in source
//! order whatever its action.
//!
//! Those orders disagree. Given `[allow /x, deny /x]` the single identity answers
//! allow and the pair answers deny. Action-major is what stops an allow written
//! against one identity from suppressing a deny or shadow written against the
//! other, so the kernel carries both orders rather than deriving one from the
//! other; see [`CompiledPolicy::match_direct`].
//!
//! The route lane is asymmetric for the same reason, in the other direction: an
//! alias matches a route's `path_prefix` *exactly* on the request path, and only
//! then by prefix on the canonical identity. Prefix-matching the request path
//! would let an MCP endpoint mounted under a public prefix inherit that prefix's
//! weaker permission. See [`CompiledPolicy::match_route`].
//!
//! ## Host qualification is the one place a direct allow does not decide
//!
//! Direct rules otherwise run before, and win over, the route/permission model.
//! When a virtual upstream has been selected, that inverts: a direct deny still
//! blocks, but a direct allow or shadow cannot authorize the selected upstream,
//! and authorization must come from a host-bound route. Losing that asymmetry
//! would let a broad `/**` allow authorize every virtual host on the gateway,
//! so the kernel reproduces it rather than simplifying it.
//!
//! A first-matching shadow rule on such a request still records a would-deny
//! observation before the route decides. That observation is a second, separate
//! output, reported as [`Evaluation::observation`]: the kernel emits nothing
//! itself, and an adapter that dropped it would silently lose telemetry the
//! live path produces today.
//!
//! ## Selecting a rate lane is not deciding one
//!
//! [`CompiledPolicy::select_rate_lane`] answers which configured override governs
//! a request, first match in source order. It does not answer whether the request
//! fits inside that lane, and the split is the point: which lane applies is a
//! policy question and deterministic, while remaining capacity is mutable state
//! that ADR-0004 puts outside the pure verdict. The limiter, its token buckets
//! and their capacity stay where they are, and `mutable_capacity` stays listed as
//! not evaluated.
//!
//! Alias identities do not participate: the live selector matches the request
//! path only, so consulting a canonical identity here would invent a second
//! behaviour rather than mirror the existing one. An anonymous caller reaches no
//! override at all, because `policy_rate_limit_request` returns before consulting
//! the selector when a request carries no principal -- that is the live bypass
//! reproduced, and changing it is a cutover decision taken in both paths at once.
//!
//! ## Facts, not guesses
//!
//! A fact this lane needs and does not have is [`LogicalDecision::Indeterminate`]
//! with a stable limitation, never a default. The request host is a three-state
//! [`HostFact`] for that reason: a request that genuinely carried no `Host`
//! header is a different input from one whose host was never captured, and only
//! the second is unanswerable. The host fact is required only when the compiled
//! policy actually has host-qualified routes, so a caller is never asked for a
//! fact that cannot change the result.
//!
//! No runtime handle, store, audit sink, provider, resolver, or callback enters
//! this API. Principal inputs contain only policy facts, never credentials.

// No production caller until #422's adapter consumes this, at which point the
// allow comes off and each item that is still unused is annotated individually
// with the reason -- a module-level allow is why an unused addition can arrive
// unnoticed, so it should not outlive the cutover.
#![allow(dead_code)]

mod input;
#[cfg(test)]
mod tests;

use std::fmt;
use std::net::Ipv6Addr;

use http::Method;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    auth::{AuthMethod, Principal},
    path_match::{is_unsafe_request_path, path_prefix_matches},
    rbac::{
        matcher::{method_matches, path_pattern_matches, RuleDecision, RuleDispatchContext},
        policy::{RouteRule, KNOWN_TOP_LEVEL_KEYS},
        DefaultAction, EnforcementMode, Policy, PolicyEngine, RuleAction, RuleMatcher,
    },
};

/// Each lane that adds a required fact bumps this, so a context built for an
/// earlier shape is refused rather than silently reinterpreted under a later one.
pub(crate) const CONTEXT_VERSION: u16 = 3;
pub(crate) const HTTP_SEMANTICS_VERSION: &str = "gg-http-alias-v1";
pub(crate) const HTTP_DOMAIN: &str = "http_alias_v1";
pub(crate) const MAX_TRACE_BYTES: usize = 2048;
/// Frame kind for the in-memory install path's digest. Outside ADR-0004's
/// reserved `source`/`semantic` namespace on purpose; see [`PolicyDigest`].
const VALIDATED_POLICY_DIGEST_KIND: &str = "gg.validated-policy.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyAuthority {
    /// A source digest, not an invented persistent standalone revision.
    Standalone,
    /// The watermark supplied by the existing cluster admission mechanism.
    PostgreSql { security_revision: i64 },
}

/// How a compiled policy's identity was established.
///
/// The ADR requires both a source-document digest and a normalized semantic one,
/// and requires a result that lacks the digest it needs to be unreusable rather
/// than reused under a guessed value. Keeping them as distinct variants is what
/// makes that honest: the live install paths hand over an already-parsed
/// `Policy`, never the bytes it came from, and `Policy` canonicalizes as it loads
/// (issuer trailing slashes, for one), so bytes cannot be reconstructed from it.
/// Reporting a reconstruction as a source digest would quietly break the
/// guarantee that identical pinned inputs produce identical trace bytes, and the
/// break would only surface when somebody diffed an offline trace against a
/// production one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyDigest {
    /// Over the exact accepted source-document bytes.
    Source([u8; 32]),
    /// Over a deterministic encoding of the already-validated policy, for an
    /// install path that never held the source bytes.
    ///
    /// Deliberately *not* called semantic. ADR-0004 reserves that word for the
    /// RFC 8785 canonical byte sequence, says a version without normative
    /// normalization has no semantic digest, and rejects "ad hoc key sorting or
    /// implementation-dependent map iteration for digests" by name -- which is
    /// exactly what this is. Framing it as `semantic` would put a different value
    /// under the frame the real JCS digest will use, with nothing in the frame to
    /// tell the two apart: the same hazard as a fabricated source digest, in the
    /// same place, found the same way. Its own frame kind keeps that namespace
    /// free for the digest slice that earns it.
    ValidatedPolicy([u8; 32]),
}

/// The complete immutable resource domain for this slice is the policy itself.
/// Routing, tools, Connections and configuration are deliberately not guessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ResourceSnapshot {
    digest: PolicyDigest,
    authority: PolicyAuthority,
    context_version: u16,
    semantics_version: &'static str,
}

pub(crate) struct CompiledPolicy {
    engine: PolicyEngine,
    matcher: RuleMatcher,
    snapshot: ResourceSnapshot,
    /// Whether any route is host-qualified. Only then does the request host
    /// change a result, and only then is the caller asked to supply it.
    host_qualified_routes: bool,
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
        validate_authority(authority)?;
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
        Ok(Self::assemble(
            policy,
            PolicyDigest::Source(framed_digest("source", "application/json", "0.1.0", source)),
            authority,
        ))
    }

    /// Compiles a policy the gateway has already parsed and validated.
    ///
    /// The live install paths hold a `Policy`, not the document it came from, so
    /// this is how the kernel becomes reachable from them. It deliberately does
    /// not reuse [`Self::compile`]: that path has exact `0.1.0` schema dispatch
    /// and rejects unknown top-level keys, which is right for an offline caller
    /// handed arbitrary bytes but would fail-close policies this gateway accepts
    /// today. Narrowing what production accepts is not a change to smuggle in as
    /// a side effect of reusing a constructor.
    ///
    /// Fallible only in the authority. Every rejection `compile` performs is a
    /// judgement about untrusted bytes and this caller has none -- but the
    /// authority is not bytes, it is a caller-supplied watermark, so it is
    /// checked here exactly as it is there.
    pub(crate) fn from_validated_policy(
        policy: Policy,
        authority: PolicyAuthority,
    ) -> Result<Self, CompileError> {
        // The policy is already validated; the authority is not. It is a caller
        // supplied integer, and `policy_active.security_revision` carries no
        // database CHECK, so a corrupt or out-of-band-edited row reaches here as
        // a negative watermark. `compile` already refuses that, and the adapter
        // this constructor exists for must not be the one path that accepts it:
        // the result would be a complete allow bound to an invalid revision.
        validate_authority(authority)?;
        let digest = PolicyDigest::ValidatedPolicy(validated_policy_digest(&policy));
        Ok(Self::assemble(policy, digest, authority))
    }

    fn assemble(policy: Policy, digest: PolicyDigest, authority: PolicyAuthority) -> Self {
        let host_qualified_routes = policy.routes.iter().any(|route| !route.hosts.is_empty());
        let snapshot = ResourceSnapshot {
            digest,
            authority,
            context_version: CONTEXT_VERSION,
            semantics_version: HTTP_SEMANTICS_VERSION,
        };
        Self {
            matcher: RuleMatcher::new(&policy.rules),
            engine: PolicyEngine::new(policy),
            snapshot,
            host_qualified_routes,
        }
    }

    pub(crate) fn snapshot(&self) -> ResourceSnapshot {
        self.snapshot
    }

    /// First deciding direct rule, over one path identity or an alias pair.
    ///
    /// The two cases use **different precedence orders**, and neither is a
    /// special case of the other:
    ///
    /// - One identity is *rule-index-major*: the first rule in source order that
    ///   matches, whatever its action.
    /// - An alias pair is *action-major*: the most restrictive action present
    ///   anywhere in the rulebase wins -- deny, then shadow, then allow -- each
    ///   scanned over the union of both identities.
    ///
    /// They disagree, and not only in theory. Given `[allow /x, deny /x]` the
    /// single-identity order answers allow and the pair answers deny. Action-major
    /// is what stops an allow written against one identity from suppressing a deny
    /// or shadow written against the other, which is the whole reason an alias
    /// evaluates as a pair rather than twice. Collapsing them into one rule would
    /// silently change one of the two.
    ///
    /// Narrowing to denies composes with either: the action set shrinks to
    /// `[deny]`, and over a single action the two orders coincide.
    fn match_direct(
        &self,
        method: &str,
        path: &str,
        canonical_path: Option<&str>,
        principal: Option<&Principal>,
        dispatch_context: RuleDispatchContext<'_>,
        denies_only: bool,
    ) -> Option<RuleDecision> {
        match canonical_path {
            Some(canonical) => self.matcher.evaluate_equivalent_paths_with_dispatch(
                method,
                &[canonical, path],
                principal,
                dispatch_context,
                denies_only,
            ),
            None if denies_only => self.matcher.evaluate_denies_with_dispatch(
                method,
                path,
                principal,
                dispatch_context,
            ),
            None => self
                .matcher
                .evaluate_with_dispatch(method, path, principal, dispatch_context),
        }
    }

    /// Which configured rate-limit override governs a request.
    ///
    /// First match in source order over method, path pattern and principal --
    /// the same three predicates the live selector uses, over the same matchers,
    /// so the pattern syntax and method folding cannot drift apart from it.
    ///
    /// Selection only, and the distinction is the point: which lane applies is a
    /// policy question and deterministic, while whether this request fits inside
    /// that lane is mutable state. ADR-0004 puts dynamic rate capacity outside
    /// the pure verdict, so the limiter, its buckets and their capacity stay
    /// exactly where they are. An allow here is not a statement that a request
    /// will be admitted.
    ///
    /// Alias identities do not apply: the live selector matches the request path
    /// only, so reading a canonical identity here would invent a second
    /// behaviour rather than mirror one.
    ///
    /// An anonymous caller reaches no override at all. That is the live bypass,
    /// not a simplification: `policy_rate_limit_request` returns before consulting
    /// the selector when a request carries no `Principal`, so it only ever selects
    /// for an authenticated one. Passing `None` to the matcher here instead would
    /// let an unconstrained override match, and simulation and replay would report
    /// a lane governing traffic that live never rate-limits. Changing that is a
    /// deliberate decision for the cutover, in both paths at once.
    pub(crate) fn select_rate_lane(
        &self,
        context: &PolicyEvaluationContext,
    ) -> Result<RateLaneSelection, EvaluationError> {
        context.validate(self.snapshot)?;
        let binding = context.binding()?;
        // A fact this lane matches on that was not supplied is an incomplete
        // result, not an evaluator error: ordinary replay over retained data is
        // missing facts routinely, and failing the run would turn "we did not
        // record that" into "the analysis is broken".
        let limitation = if context.method.is_none() {
            Some(Limitation::MissingMethod)
        } else if context.path.is_none() {
            Some(Limitation::MissingPath)
        } else if matches!(context.principal, PrincipalFact::Missing) {
            // A rule may constrain the principal, so not knowing it is not the
            // same as there being none.
            Some(Limitation::MissingPrincipalFact)
        } else {
            None
        };
        if let Some(limitation) = limitation {
            return Ok(RateLaneSelection {
                binding,
                outcome: RateLaneOutcome::Indeterminate(limitation),
            });
        }
        let (Some(method), Some(path)) = (&context.method, &context.path) else {
            return Err(EvaluationError::InternalInvariant);
        };
        let principal = match &context.principal {
            PrincipalFact::Authenticated(identity) => &identity.0,
            // The live bypass, above.
            PrincipalFact::Anonymous => {
                return Ok(RateLaneSelection {
                    binding,
                    outcome: RateLaneOutcome::NoOverride,
                })
            }
            PrincipalFact::Missing => return Err(EvaluationError::InternalInvariant),
        };
        let selected = self
            .engine
            .policy()
            .rate_limits
            .iter()
            .enumerate()
            .find(|(_, rule)| {
                rule.principal.matches(Some(principal))
                    && method_matches(&rule.methods, method.as_str())
                    && rule
                        .path
                        .as_ref()
                        .is_none_or(|pattern| path_pattern_matches(pattern, path))
            });
        Ok(RateLaneSelection {
            binding,
            outcome: match selected {
                Some((index, rule)) => RateLaneOutcome::Override {
                    index,
                    limit: RateLimit {
                        requests_per_second: rule.requests_per_second,
                        burst: rule.burst,
                    },
                },
                None => RateLaneOutcome::NoOverride,
            },
        })
    }

    /// First matching route, over one path identity or an alias pair.
    ///
    /// For a single identity this is prefix matching in source order. For an
    /// alias it is deliberately asymmetric: an **exact** `path_prefix` match on
    /// the request path, and only then a **prefix** match on the canonical
    /// identity. The request path is never prefix-matched.
    ///
    /// That asymmetry is load-bearing. An MCP endpoint mounted under a public
    /// prefix -- `/base/mcp` where a `/base` route grants something weaker --
    /// must not inherit the broad route's permission by prefix. Prefix-matching
    /// the request path would hand `/base/mcp` the `/base` permission and quietly
    /// widen who may reach the MCP endpoint.
    fn match_route(
        &self,
        method: &str,
        path: &str,
        canonical_path: Option<&str>,
        host: Option<&str>,
        host_binding_required: bool,
    ) -> Option<(usize, &RouteRule)> {
        let routes = &self.engine.policy().routes;
        let admissible = |route: &RouteRule| {
            method_matches(&route.methods, method)
                && route_host_matches(&route.hosts, host, host_binding_required)
        };
        match canonical_path {
            Some(canonical) => routes
                .iter()
                .enumerate()
                .find(|(_, route)| route.path_prefix == path && admissible(route))
                .or_else(|| {
                    routes.iter().enumerate().find(|(_, route)| {
                        path_prefix_matches(canonical, &route.path_prefix) && admissible(route)
                    })
                }),
            // The existing prefix and method matchers preserve segment
            // boundaries, wildcard methods and case folding.
            None => routes.iter().enumerate().find(|(_, route)| {
                path_prefix_matches(path, &route.path_prefix) && admissible(route)
            }),
        }
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
            match &context.target {
                HttpTarget::Missing => Some(Limitation::MissingDispatchFact),
                HttpTarget::Contextless | HttpTarget::McpAlias { .. } => None,
                HttpTarget::ProxyDispatch if context.dispatch.is_none() => {
                    Some(Limitation::MissingDispatchFact)
                }
                HttpTarget::ProxyDispatch => None,
            }
        };
        if let Some(limitation) = missing {
            return Ok(Evaluation::indeterminate(binding, limitation));
        }
        let (Some(method), Some(path)) = (&context.method, &context.path) else {
            return Err(EvaluationError::InternalInvariant);
        };
        let principal = match &context.principal {
            PrincipalFact::Authenticated(identity) => Some(&identity.0),
            PrincipalFact::Anonymous => None,
            PrincipalFact::Missing => return Err(EvaluationError::InternalInvariant),
        };

        let dispatch = context.dispatch.as_ref();
        // A selected virtual upstream, which production identifies by the route
        // carrying a bound host. Its presence, not the mere existence of a
        // classified dispatch, is what makes a route's host binding mandatory.
        let required_host = dispatch.and_then(|facts| facts.route_host.as_deref());
        let host_binding_required = required_host.is_some();
        // The host routes are matched against: the selected upstream's when one
        // was chosen, otherwise the request's own.
        let effective_host = match (required_host, &context.request_host) {
            (Some(host), _) => Some(host),
            (None, HostFact::Present(host)) => Some(host.as_str()),
            (None, HostFact::Absent) => None,
            (None, HostFact::Missing) => {
                // Only unanswerable when a route could actually turn on it.
                if self.host_qualified_routes {
                    return Ok(Evaluation::indeterminate(
                        binding,
                        Limitation::MissingHostFact,
                    ));
                }
                None
            }
        };
        let dispatch_context = match (&context.target, dispatch) {
            (HttpTarget::Contextless | HttpTarget::McpAlias { .. }, _) => {
                RuleDispatchContext::contextless()
            }
            (HttpTarget::ProxyDispatch, Some(facts)) => {
                RuleDispatchContext::classified_with_route_id(
                    facts.route_id.as_deref(),
                    facts.route_host.as_deref(),
                    facts.route_path_prefix.as_deref(),
                    Some(facts.upstream_origin.as_str()),
                )
            }
            _ => return Err(EvaluationError::InternalInvariant),
        };
        // The canonical policy identity, when this request reached an MCP
        // endpoint by another path. Both identities decide together.
        let canonical_path = match &context.target {
            HttpTarget::McpAlias { canonical_path } => Some(canonical_path.as_str()),
            _ => None,
        };

        // Direct rules first, except that a selected upstream narrows them to
        // denies: an allow or shadow must not authorize a virtual host. The
        // first match is still computed, because a shadow among the rules an
        // upstream-bound request skips is still recorded as a would-deny.
        let first_direct = self.match_direct(
            method.as_str(),
            path,
            canonical_path,
            principal,
            dispatch_context,
            false,
        );
        let observation = first_direct.as_ref().and_then(|decision| {
            (host_binding_required && decision.action == RuleAction::Shadow)
                .then_some(RuleReference::Direct(decision.rule_index))
        });
        let deciding_direct = if host_binding_required {
            self.match_direct(
                method.as_str(),
                path,
                canonical_path,
                principal,
                dispatch_context,
                true,
            )
        } else {
            first_direct
        };
        if let Some(decision) = deciding_direct {
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
                observation,
            ));
        }
        let policy = self.engine.policy();
        if let Some((index, route)) = self.match_route(
            method.as_str(),
            path,
            canonical_path,
            effective_host,
            host_binding_required,
        ) {
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
                observation,
            ));
        }
        // A selected upstream that no host-bound route authorizes is refused
        // outright. The policy default does not apply and shadow enforcement
        // does not soften it: `default_action: allow` must not become blanket
        // authorization for every virtual host the gateway can reach, and a
        // gateway in shadow mode must not forward to one on that basis.
        if host_binding_required {
            return Ok(Evaluation::complete(
                binding,
                LogicalDecision::Deny,
                PolicyEffect::Block,
                Reason::HostPolicyRequired,
                None,
                observation,
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
            observation,
        ))
    }
}

/// Whether a value is a host with its port and brackets already removed, the
/// form `upstream_route::request_host_without_port` produces.
///
/// Colons cannot simply be refused. That helper strips the brackets from
/// `[2001:db8::1]:8443` and returns `2001:db8::1`, so rejecting every colon
/// would make the kernel unable to answer for an IPv6-addressed request at all
/// -- including one whose policy has no host-qualified routes and for which the
/// host could not have changed the decision. A bare IPv6 literal is recognized
/// by parsing it, rather than by guessing at colon counts.
fn is_bare_host(host: &str) -> bool {
    if host.is_empty() || host.contains('/') {
        return false;
    }
    if host.contains(':') {
        return host.parse::<Ipv6Addr>().is_ok();
    }
    true
}

/// Whether a route's host binding admits this request.
///
/// An unbound route serves any host, but only while no virtual upstream was
/// selected: once one is, an unbound route can no longer authorize it. Bound
/// routes compare ASCII-case-insensitively, matching how hosts are compared
/// everywhere else.
fn route_host_matches(
    hosts: &[String],
    request_host: Option<&str>,
    binding_required: bool,
) -> bool {
    if hosts.is_empty() {
        return !binding_required;
    }
    request_host.is_some_and(|request_host| {
        hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(request_host))
    })
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HttpTarget {
    /// Routing was never classified for this request, so a dispatch-scoped rule
    /// would silently not apply. Unanswerable rather than answered permissively.
    Missing,
    Contextless,
    ProxyDispatch,
    /// An MCP endpoint reached by a path that is not its canonical policy
    /// identity. Both identities decide together; see [`AliasPrecedence`].
    ///
    /// The canonical path lives in the variant so that naming this target
    /// without supplying the second identity is not expressible. A separate
    /// optional field would be meaningful for exactly one target, which is the
    /// shape a later caller forgets to populate.
    McpAlias {
        canonical_path: String,
    },
}

/// The request host, distinguishing "no `Host` header" from "never captured".
///
/// Collapsing the two would let an uncaptured host be answered as though the
/// request had none, which for a host-qualified route is the difference between
/// no match and an unanswerable question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostFact {
    Missing,
    Absent,
    Present(String),
}

/// Trusted routing facts established before policy evaluation.
///
/// Every field is supplied by the caller. The kernel resolves nothing: it does
/// not parse an origin, consult routing tables, or select an upstream.
///
/// The shape mirrors `ProxyRouteObservationContext`, which is the single place
/// production establishes these, deliberately closely. Two earlier differences
/// both turned out to be ways to fail open:
///
/// - A separate `required_host` field. Production derives the required host from
///   `route_host` alone -- `authorization_context()` yields one exactly when
///   `route_host` is set -- so carrying it twice let a caller supply the route
///   host without it, leaving host binding unenforced and a broad allow or a
///   permissive default free to authorize a virtual upstream. The host binding
///   is now derived here too, so the two cannot disagree.
/// - An optional `upstream_origin`. A classified dispatch always has one, and
///   making it optional created a dispatch with no identity at all, which
///   `kind: contextless` rules match -- so a contextless-only allow could
///   authorize what the caller labeled a proxy dispatch. It is required, as it
///   is in production.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DispatchFacts {
    pub(crate) route_id: Option<String>,
    /// The route's bound host. Its presence is what makes a virtual upstream
    /// selected, and therefore a route's own host binding mandatory.
    pub(crate) route_host: Option<String>,
    pub(crate) route_path_prefix: Option<String>,
    pub(crate) upstream_origin: String,
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
    /// Host header value without port, as the routing lane compares it.
    pub(crate) request_host: HostFact,
    /// Required when `target` is [`HttpTarget::ProxyDispatch`], and rejected on
    /// any other target rather than ignored: facts that would change the answer
    /// must never be silently discarded because a tag disagrees with them.
    pub(crate) dispatch: Option<DispatchFacts>,
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
    InvalidHost,
    InconsistentContext,
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
            validate_path(path)?;
        }
        // The canonical identity is a path that decides, matched against direct
        // rules and routes exactly as the request path is, so it is checked
        // exactly as the request path is. Validating only the first identity
        // would let a malformed or oversized second one reach matching, produce
        // a complete decision -- an allow, under a permissive default -- and
        // escape the bound the context size limit exists to impose.
        if let HttpTarget::McpAlias { canonical_path } = &self.target {
            validate_path(canonical_path)?;
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
        if let HostFact::Present(host) = &self.request_host {
            if host.len() > 4096 {
                return Err(EvaluationError::ContextTooLarge);
            }
            if !is_bare_host(host) {
                return Err(EvaluationError::InvalidHost);
            }
        }
        if let Some(facts) = &self.dispatch {
            // Dispatch facts on a target that does not evaluate them would be
            // read by one and ignored by the other, and `route_host` is exactly
            // the fact whose loss turns a refusal into an allow.
            if self.target != HttpTarget::ProxyDispatch {
                return Err(EvaluationError::InconsistentContext);
            }
            for value in [
                facts.route_id.as_deref(),
                facts.route_host.as_deref(),
                facts.route_path_prefix.as_deref(),
                Some(facts.upstream_origin.as_str()),
            ]
            .into_iter()
            .flatten()
            {
                if value.len() > 4096 {
                    return Err(EvaluationError::ContextTooLarge);
                }
            }
            // A classified dispatch always has an origin; an empty one would
            // leave it with no identity, which `kind: contextless` rules match.
            if facts.upstream_origin.is_empty() {
                return Err(EvaluationError::InconsistentContext);
            }
            if facts
                .route_host
                .as_ref()
                .is_some_and(|host| !is_bare_host(host))
            {
                return Err(EvaluationError::InvalidHost);
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
        let host = match &self.request_host {
            HostFact::Missing => ("missing", None),
            HostFact::Absent => ("absent", None),
            HostFact::Present(host) => ("present", Some(host)),
        };
        // Every routing fact binds the result. A dispatch that differs in any
        // field is a different question, so a prior answer cannot be reused.
        let dispatch = self.dispatch.as_ref().map(|facts| {
            (
                &facts.route_id,
                &facts.route_host,
                &facts.route_path_prefix,
                &facts.upstream_origin,
            )
        });
        let bytes = serde_json::to_vec(&(
            self.version,
            &self.target,
            self.method.as_ref().map(Method::as_str),
            &self.path,
            principal,
            host,
            dispatch,
        ))
        .map_err(|_| EvaluationError::TraceEncoding)?;
        Ok(InputBinding {
            snapshot: self.snapshot,
            context_digest: framed_digest(
                "context",
                "application/json",
                &CONTEXT_VERSION.to_string(),
                &bytes,
            ),
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
    /// A virtual upstream was selected and no host-bound route authorized it.
    HostPolicyRequired,
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
            Self::HostPolicyRequired => "host_policy_required",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Why an evaluation could not complete, as a stable code.
///
/// Every variant now shares the `Missing` prefix, because every one of them is a
/// fact that was not supplied -- the kernel has no "unsupported" limitation left
/// to report since every target is evaluated. The names are not free to change:
/// they serialize into the trace as the stable limitation codes ADR-0004
/// requires, so dropping the prefix to satisfy a naming lint would edit a
/// published contract for cosmetic reasons.
#[allow(
    clippy::enum_variant_names,
    reason = "variant names are the stable limitation codes in the trace"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Limitation {
    MissingMethod,
    MissingPath,
    MissingPrincipalFact,
    MissingDispatchFact,
    MissingHostFact,
}

pub(crate) const NOT_EVALUATED: &[&str] = &[
    "authentication",
    "csrf",
    "request_admission",
    "management_permissions",
    "mcp",
    "tools",
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
    /// A rule that recorded a would-deny observation without deciding: a
    /// first-matching shadow on a request bound to a virtual upstream. Separate
    /// from `matched`, which is the rule that actually decided.
    observation: Option<RuleReference>,
    /// Complete only for the named HTTP routing policy domain.
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

    /// The would-deny observation this evaluation also produced, if any. An
    /// adapter that ignores it loses telemetry the live path records today.
    pub(crate) fn observation(&self) -> Option<RuleReference> {
        self.observation
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
        observation: Option<RuleReference>,
    ) -> Self {
        Self {
            binding,
            domain: HTTP_DOMAIN,
            not_evaluated: NOT_EVALUATED,
            logical,
            effect,
            reason,
            matched,
            observation,
            complete: true,
            limitation: None,
        }
    }

    fn indeterminate(binding: InputBinding, limitation: Limitation) -> Self {
        Self {
            binding,
            domain: HTTP_DOMAIN,
            not_evaluated: NOT_EVALUATED,
            logical: LogicalDecision::Indeterminate,
            effect: PolicyEffect::Block,
            reason: Reason::Incomplete,
            matched: None,
            observation: None,
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

/// Rejects a path that is not an exact, already-separated request path.
///
/// Shared by every path identity in a context. A check that covered only the
/// first one would be a check the others are missing, and each of them decides.
fn validate_path(path: &str) -> Result<(), EvaluationError> {
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
    Ok(())
}

/// Rejects an authority that cannot be a real watermark.
///
/// Shared by both constructors on purpose: a revision check that lives in only
/// one of them is a revision check the other path is missing.
fn validate_authority(authority: PolicyAuthority) -> Result<(), CompileError> {
    match authority {
        PolicyAuthority::PostgreSql { security_revision } if security_revision < 0 => {
            Err(CompileError::InvalidRevision)
        }
        _ => Ok(()),
    }
}

/// Digest over a deterministic encoding of an already-validated policy.
///
/// `Policy::roles` is a `HashMap`, so serializing it straight to JSON gives a
/// different byte string per process and a digest that identifies nothing. Object
/// keys are therefore sorted explicitly rather than trusting `serde_json::Map` to
/// be ordered -- it is a `BTreeMap` only while nothing in the dependency graph
/// turns on `preserve_order`, which is a feature-unification accident away from
/// being false and would fail silently if it happened.
///
/// This is deterministic, not canonical in the ADR's sense: key order here is
/// byte-wise UTF-8 where JCS mandates UTF-16 code units, and numbers defer to
/// serde_json rather than ECMAScript shortest-representation. Both differences are
/// reachable with operator-authored keys, so this cannot be relabelled JCS later
/// by adding a validation step -- it is a different algorithm, which is why it
/// carries its own frame kind.
fn validated_policy_digest(policy: &Policy) -> [u8; 32] {
    let mut payload = Vec::new();
    match serde_json::to_value(policy) {
        Ok(value) => write_canonical(&value, &mut payload),
        // A policy that will not serialize cannot be given a stable identity, and
        // a constant would make two different policies share one. Make the digest
        // unique to this failure instead, so nothing can be reused across it.
        Err(error) => {
            payload.extend_from_slice(b"unserializable\0");
            payload.extend_from_slice(error.to_string().as_bytes());
        }
    }
    framed_digest(
        VALIDATED_POLICY_DIGEST_KIND,
        "application/json",
        "0.1.0",
        &payload,
    )
}

/// Writes `value` with object keys in sorted order.
fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_scalar(&Value::String((*key).clone()), out);
                out.push(b':');
                match map.get(*key) {
                    Some(member) => write_canonical(member, out),
                    // Unreachable: the key came from this map.
                    None => out.extend_from_slice(b"null"),
                }
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => write_json_scalar(scalar, out),
    }
}

fn write_json_scalar(value: &Value, out: &mut Vec<u8>) {
    match serde_json::to_string(value) {
        Ok(text) => out.extend_from_slice(text.as_bytes()),
        // Scalars do not fail to serialize; a marker still keeps the digest
        // defined rather than silently dropping a field.
        Err(_) => out.extend_from_slice(b"\"\\u0000unencodable\""),
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

/// Which configured rate-limit override governs a request, and the limit it
/// declares.
///
/// Selection only. The limiter, its token buckets, their capacity and every
/// decision about whether *this* request fits within the limit stay where they
/// are: those are mutable state, and ADR-0004 puts dynamic rate capacity outside
/// the pure verdict. A selection is a statement about policy, not about whether
/// a request will be admitted -- `NOT_EVALUATED` keeps listing `mutable_capacity`
/// for exactly that reason.
/// It carries its input binding for the same reason [`Evaluation`] does. A bare
/// index and a pair of numbers are indistinguishable from the same index and
/// numbers produced under a replacement policy, so a selection retained or
/// serialized across a reload could be applied with stale rates and nothing in
/// the value would say so. Validating the context before producing the value
/// protects the production of it, not its later use.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub(crate) struct RateLaneSelection {
    binding: InputBinding,
    outcome: RateLaneOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RateLaneOutcome {
    /// No configured override governs this request: either none matched, or the
    /// caller is anonymous and the live path never consults an override for one.
    NoOverride,
    Override {
        /// First match in source order.
        index: usize,
        /// What that override declares. Policy data, not a live budget.
        limit: RateLimit,
    },
    /// A fact this lane matches on was not supplied. Not an evaluator error:
    /// replay over retained data is routinely missing facts, and failing the run
    /// would turn "we did not record that" into "the analysis is broken".
    Indeterminate(Limitation),
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub(crate) struct RateLimit {
    requests_per_second: f64,
    burst: u32,
}

impl RateLaneSelection {
    pub(crate) fn outcome(&self) -> RateLaneOutcome {
        self.outcome
    }

    /// The override index, for a selection that found one.
    pub(crate) fn matched(&self) -> Option<usize> {
        match self.outcome {
            RateLaneOutcome::Override { index, .. } => Some(index),
            _ => None,
        }
    }

    pub(crate) fn limit(&self) -> Option<RateLimit> {
        match self.outcome {
            RateLaneOutcome::Override { limit, .. } => Some(limit),
            _ => None,
        }
    }

    pub(crate) fn limitation(&self) -> Option<Limitation> {
        match self.outcome {
            RateLaneOutcome::Indeterminate(limitation) => Some(limitation),
            _ => None,
        }
    }

    /// Whether this selection may be applied to `context`.
    ///
    /// An indeterminate selection is never reusable: it is the absence of an
    /// answer, and reusing it would hand a caller a stale "no lane" where the
    /// facts may since have arrived.
    pub(crate) fn reusable_for(&self, context: &PolicyEvaluationContext) -> bool {
        !matches!(self.outcome, RateLaneOutcome::Indeterminate(_))
            && context.validate(self.binding.snapshot).is_ok()
            && context
                .binding()
                .is_ok_and(|binding| binding == self.binding)
    }
}

impl RateLimit {
    pub(crate) fn requests_per_second(&self) -> f64 {
        self.requests_per_second
    }

    pub(crate) fn burst(&self) -> u32 {
        self.burst
    }
}
