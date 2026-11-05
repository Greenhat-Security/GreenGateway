//! Conservative structural policy analysis (issue #243, slice 15).
//!
//! The analyzer reads one policy and reports what is provably wrong with its
//! structure, or risky about its defaults: elements that can never decide a
//! request because an earlier one always does, or decide only part of what
//! they match; rules and routes whose written intent never applies, or
//! applies differently to MCP alias requests and selected virtual upstreams;
//! tool-name rules their tool's entry contradicts; grants broader than they
//! look; rate overrides looser than their global lane; egress entries that
//! admit more than the web; and, through the publication's own cross-resource
//! checks, references other resources contradict and a change that leaves
//! nobody able to write the policy. Each finding names the element by
//! section, JSON Pointer, position and stable id, says how it was
//! established, and may carry a candidate patch.
//!
//! ## Proof bases
//!
//! - `proven`: derived from the policy and the evaluator's semantics, lane by
//!   lane, and -- for every reachability claim -- confirmed by asking the
//!   canonical evaluator ([`crate::policy_eval`]) which element decides a
//!   witness request the claimed element itself matches, in the element's
//!   ordinary lane. An existential claim -- an overlap, a lane effect, a grant
//!   a tool entry refuses -- is proven only when the evaluator answers the
//!   witness the analyzer built that way. The brute-force tests check every
//!   proven claim, in every lane it names, over small policy universes.
//! - `heuristic`: a statement whose risk depends on the deployment or on
//!   intent rather than on the policy alone (how many issuers it trusts, or
//!   whether a port is unusual, for example).
//! - `inconclusive`: a structural relation the evaluator did not confirm on
//!   its witness. It is reported, never dropped, and carries no patch.
//!
//! `bounded_replay`, the basis of a finding informed by retained traffic, is
//! reserved: this analyzer reads no traffic, so nothing it reports is about
//! what was or was not observed, and nothing is ever called unreachable
//! because it was not seen.
//!
//! ## False-positive bias
//!
//! Every inclusion the analyzer relies on is a proof ([`coverage`]): when it
//! cannot prove that one element covers another it says nothing, so it misses
//! findings rather than inventing them. An element covered only by the union
//! of several earlier ones, a pattern inclusion that needs more than one
//! alignment, two spellings of one origin, a route a configured MCP alias
//! selects by exact prefix, and partial overlaps between routes or between
//! rate overrides are not reported, and a partial rule overlap the evaluator
//! does not confirm is `inconclusive`. A clean report is therefore not a
//! statement that the policy is free of these problems;
//! `docs/policy-analysis.md` lists every blind spot.
//!
//! ## Advisory patches
//!
//! A patch is a list of `policy-simulation.v1` edits over the analyzed
//! document, with the access effect the analyzer proved for it. Nothing in
//! the gateway applies one: adopting a patch means simulating it, testing it,
//! saving the edited document as a draft and publishing that draft under the
//! ordinary preconditions and authorization.
//!
//! ## No side effects
//!
//! [`checks::analyze`] is pure: it compiles the policy for analysis, asks the
//! evaluator synthetic questions, and returns values. It performs no I/O,
//! emits no event or metric, and touches no rate bucket, tool permit,
//! resolver or upstream; the resources it judges against are read by the
//! endpoint and handed over, and an egress question carries its own witness
//! resolution facts. Its work is bounded by a comparison budget, a
//! deadline and a findings cap; exhausting any of them makes the result
//! incomplete, never clean.

pub(crate) mod checks;
pub(crate) mod coverage;
pub(crate) mod report;
pub(crate) mod request;
#[cfg(test)]
mod tests;

use serde_json::{json, Map, Value};

/// The only request schema this module implements.
pub(crate) const ANALYSIS_SCHEMA_VERSION: &str = "policy-analysis.v1";
/// The schema of the result document.
pub(crate) const RESULT_SCHEMA_VERSION: &str = "policy-analysis-results.v1";
/// The media type the request digest is framed with.
pub(crate) const ANALYSIS_MEDIA_TYPE: &str = "application/vnd.greengateway.policy-analysis+json";
/// The version of the analyzer's checks and finding semantics. A change to
/// what any finding means, or to how one is established, bumps it.
pub(crate) const ANALYZER_VERSION: &str = "gg-policy-analyzer-v1";
/// Frame kind of a finding fingerprint. Outside ADR-0004's reserved
/// `source`/`semantic` namespace: the identity is this analyzer's own.
const FINDING_FINGERPRINT_KIND: &str = "gg.policy-analysis.finding.v1";
/// Most element comparisons one analysis may make. Pairwise checks stop
/// when it is spent and the result is incomplete.
pub(crate) const MAX_COMPARISONS: usize = 2_000_000;
/// Most findings one analysis reports. Analysis stops at the cap and the
/// result is incomplete.
pub(crate) const MAX_FINDINGS: usize = 1_000;

/// A stable finding code. The string is the contract; the rationale and
/// remediation texts may be reworded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FindingCode {
    DefaultAllow,
    GlobalShadowEnforcement,
    BroadUnconstrainedAllow,
    BroadUnconstrainedShadow,
    WildcardGrantWithoutIssuer,
    RuleUnreachable,
    RuleShadowed,
    RouteUnreachable,
    RouteShadowed,
    RouteBypassed,
    RateOverrideUnreachable,
    RateOverrideShadowed,
    RulePartiallyShadowed,
    McpAliasRuleOverridden,
    McpAliasRoutePrecedence,
    SelectedUpstreamAllowIgnored,
    ToolRuleNeverDecides,
    ToolRuleGrantNarrowed,
    IssuerlessRoleGrant,
    WildcardPermission,
    BroadPathGrant,
    AllMethodsGrant,
    RateOverrideLooserThanGlobal,
    EgressBroadWildcardHost,
    EgressNonPublicCidr,
    EgressUnusualPort,
    EgressChangeRequiresRestart,
    RoleNotDefined,
    RoutePermissionUngranted,
    ToolNotRegistered,
    ConnectionEndpointEgressDenied,
    NameCaseCollision,
    PolicyWriteUnreachable,
}

impl FindingCode {
    /// Every code, in the fixed order SARIF rule indexes follow. A new code
    /// is appended, so an existing code's rule index never changes.
    pub(crate) const ALL: [Self; 33] = [
        Self::DefaultAllow,
        Self::GlobalShadowEnforcement,
        Self::BroadUnconstrainedAllow,
        Self::BroadUnconstrainedShadow,
        Self::WildcardGrantWithoutIssuer,
        Self::RuleUnreachable,
        Self::RuleShadowed,
        Self::RouteUnreachable,
        Self::RouteShadowed,
        Self::RouteBypassed,
        Self::RateOverrideUnreachable,
        Self::RateOverrideShadowed,
        Self::RulePartiallyShadowed,
        Self::McpAliasRuleOverridden,
        Self::McpAliasRoutePrecedence,
        Self::SelectedUpstreamAllowIgnored,
        Self::ToolRuleNeverDecides,
        Self::ToolRuleGrantNarrowed,
        Self::IssuerlessRoleGrant,
        Self::WildcardPermission,
        Self::BroadPathGrant,
        Self::AllMethodsGrant,
        Self::RateOverrideLooserThanGlobal,
        Self::EgressBroadWildcardHost,
        Self::EgressNonPublicCidr,
        Self::EgressUnusualPort,
        Self::EgressChangeRequiresRestart,
        Self::RoleNotDefined,
        Self::RoutePermissionUngranted,
        Self::ToolNotRegistered,
        Self::ConnectionEndpointEgressDenied,
        Self::NameCaseCollision,
        Self::PolicyWriteUnreachable,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DefaultAllow => "default_allow",
            Self::GlobalShadowEnforcement => "global_shadow_enforcement",
            Self::BroadUnconstrainedAllow => "broad_unconstrained_allow",
            Self::BroadUnconstrainedShadow => "broad_unconstrained_shadow",
            Self::WildcardGrantWithoutIssuer => "wildcard_grant_without_issuer",
            Self::RuleUnreachable => "rule_unreachable",
            Self::RuleShadowed => "rule_shadowed",
            Self::RouteUnreachable => "route_unreachable",
            Self::RouteShadowed => "route_shadowed",
            Self::RouteBypassed => "route_bypassed",
            Self::RateOverrideUnreachable => "rate_override_unreachable",
            Self::RateOverrideShadowed => "rate_override_shadowed",
            Self::RulePartiallyShadowed => "rule_partially_shadowed",
            Self::McpAliasRuleOverridden => "mcp_alias_rule_overridden",
            Self::McpAliasRoutePrecedence => "mcp_alias_route_precedence",
            Self::SelectedUpstreamAllowIgnored => "selected_upstream_allow_ignored",
            Self::ToolRuleNeverDecides => "tool_rule_never_decides",
            Self::ToolRuleGrantNarrowed => "tool_rule_grant_narrowed",
            Self::IssuerlessRoleGrant => "issuerless_role_grant",
            Self::WildcardPermission => "wildcard_permission",
            Self::BroadPathGrant => "broad_path_grant",
            Self::AllMethodsGrant => "all_methods_grant",
            Self::RateOverrideLooserThanGlobal => "rate_override_looser_than_global",
            Self::EgressBroadWildcardHost => "egress_broad_wildcard_host",
            Self::EgressNonPublicCidr => "egress_non_public_cidr",
            Self::EgressUnusualPort => "egress_unusual_port",
            Self::EgressChangeRequiresRestart => "egress_change_requires_restart",
            Self::RoleNotDefined => "role_not_defined",
            Self::RoutePermissionUngranted => "route_permission_ungranted",
            Self::ToolNotRegistered => "tool_not_registered",
            Self::ConnectionEndpointEgressDenied => "connection_endpoint_egress_denied",
            Self::NameCaseCollision => "name_case_collision",
            Self::PolicyWriteUnreachable => "policy_write_unreachable",
        }
    }

    /// Why the finding matters. Value-free: it names no path, permission,
    /// role or caller.
    pub(crate) fn rationale(self) -> &'static str {
        match self {
            Self::DefaultAllow => {
                "default_action is allow: a request no direct rule or route decides is allowed"
            }
            Self::GlobalShadowEnforcement => {
                "enforcement_mode is shadow: a route or default denial without its own mode is observed and forwarded, not blocked"
            }
            Self::BroadUnconstrainedAllow => {
                "an enabled allow rule matches every path for every caller, unauthenticated ones included, so no later rule, route or default decides an ordinary request it matches"
            }
            Self::BroadUnconstrainedShadow => {
                "an enabled shadow rule matches every path for every caller, unauthenticated ones included; it forwards what it decides, so no later rule, route or default decides an ordinary request it matches"
            }
            Self::WildcardGrantWithoutIssuer => {
                "a role grants every permission and names no issuer, so a credential from any issuer the gateway trusts that carries the role holds every permission"
            }
            Self::RuleUnreachable => {
                "an earlier enabled rule at least as restrictive matches every request this rule matches, so this rule never decides a request in any evaluation lane"
            }
            Self::RuleShadowed => {
                "an earlier, less restrictive enabled rule matches every request this rule matches, so this rule never decides an ordinary request; it may decide only in the lanes listed in may_decide_in"
            }
            Self::RouteUnreachable => {
                "an earlier route with the same permission and enforcement mode, or a direct deny rule that matches every caller, decides every request this route matches, so this route never decides a request"
            }
            Self::RouteShadowed => {
                "an earlier route matches every request this route matches and requires a different permission or enforcement mode, so this route's own requirement never applies"
            }
            Self::RouteBypassed => {
                "a direct allow or shadow rule that matches every caller decides every ordinary request this route matches, so the route's permission is never checked for them"
            }
            Self::RateOverrideUnreachable => {
                "an earlier rate-limit override with the same limits selects every request this override matches, so this override is never selected"
            }
            Self::RateOverrideShadowed => {
                "an earlier rate-limit override with different limits selects every request this override matches, so this override's limits never apply"
            }
            Self::RulePartiallyShadowed => {
                "an earlier, less restrictive enabled rule decides some of the requests this rule matches, so this rule does not decide them where rules decide by first match"
            }
            Self::McpAliasRuleOverridden => {
                "for a request that reaches the MCP endpoint by a configured alias path, a rule later in source order with a more restrictive action decides instead of this rule, although this rule is the first rule that matches the request"
            }
            Self::McpAliasRoutePrecedence => {
                "a request that reaches the MCP endpoint by a configured alias path selects this route by its exact prefix before the route that decides the canonical MCP path, and this route admits a caller that route refuses"
            }
            Self::SelectedUpstreamAllowIgnored => {
                "a direct allow or shadow rule never authorizes a selected host-qualified virtual upstream: a request this rule forwards when it is addressed to a host-bound route's host is blocked when that host's virtual upstream is selected"
            }
            Self::ToolRuleNeverDecides => {
                "the tool's own policy entry refuses every caller this tool-name rule matches before any tool-name rule is read, so this rule never decides an invocation"
            }
            Self::ToolRuleGrantNarrowed => {
                "the tool's own policy entry refuses a caller this allow or shadow tool-name rule names before any tool-name rule is read, so the rule grants less than it names"
            }
            Self::IssuerlessRoleGrant => {
                "a grant names a role without the issuers that role is bound to: a direct rule or a tool entry matches the role a caller claims from any issuer, while a route permission the role grants applies only for the role's issuers"
            }
            Self::WildcardPermission => {
                "a role grants every permission, administrative permissions included"
            }
            Self::BroadPathGrant => {
                "an enabled allow or shadow rule matches every path for the callers it names, so no later rule, route or default decides an ordinary request of theirs"
            }
            Self::AllMethodsGrant => {
                "an enabled allow or shadow rule matches every method, unsafe ones included, for every caller, unauthenticated ones included"
            }
            Self::RateOverrideLooserThanGlobal => {
                "a rate-limit override allows more requests per second or a larger burst than the global lane its methods are charged in; the global lane limits each client address first, so the higher limit applies only across several addresses"
            }
            Self::EgressBroadWildcardHost => {
                "an egress host pattern admits every name under a single label, such as a top-level domain"
            }
            Self::EgressNonPublicCidr => {
                "an egress CIDR admits loopback, link-local or private addresses the gateway otherwise refuses to connect to"
            }
            Self::EgressUnusualPort => {
                "the egress port list admits a port other than the usual web ports"
            }
            Self::EgressChangeRequiresRestart => {
                "the egress section differs from the active policy's, and the policy API cannot apply an egress change: it needs an edit of the policy file and a restart"
            }
            Self::RoleNotDefined => "an element names a role no roles entry defines",
            Self::RoutePermissionUngranted => {
                "no role grants the permission a route requires, so the route admits no caller unless its mode is shadow"
            }
            Self::ToolNotRegistered => {
                "the policy names a tool this gateway's tool registry does not hold"
            }
            Self::ConnectionEndpointEgressDenied => {
                "the static egress controls refuse the endpoint of an enabled Connection"
            }
            Self::NameCaseCollision => {
                "two role or two tool names differ only in case; names compare exactly, so they are two names"
            }
            Self::PolicyWriteUnreachable => {
                "the active policy lets some principal hold admin:policy:write and this policy lets none, so after publication nobody could change the policy through the policy API"
            }
        }
    }

    /// What to do about it, in general terms.
    pub(crate) fn remediation(self) -> &'static str {
        match self {
            Self::DefaultAllow => {
                "set default_action to deny and grant access through routes and rules"
            }
            Self::GlobalShadowEnforcement => {
                "set enforcement_mode to enforce once the observed would-deny events are reviewed; keep shadow on individual routes being rolled out"
            }
            Self::BroadUnconstrainedAllow | Self::BroadUnconstrainedShadow => {
                "constrain the rule's principal, narrow its path, or remove it"
            }
            Self::WildcardGrantWithoutIssuer => {
                "bind the role to the issuers that may grant it, or replace the wildcard with the permissions the role needs"
            }
            Self::RuleUnreachable | Self::RateOverrideUnreachable => {
                "remove the element, or move it before the element that covers it if it was meant to apply first"
            }
            Self::RuleShadowed => {
                "move the rule before the less restrictive rule that covers it, or remove it if the earlier rule is the intended decision"
            }
            Self::RouteUnreachable => "remove the route",
            Self::RouteShadowed => {
                "move the more specific route before the route that covers it, or remove it if the earlier route's requirement is intended"
            }
            Self::RouteBypassed => {
                "constrain the rule's principal or remove it so the route's permission applies"
            }
            Self::RateOverrideShadowed => {
                "move the override before the override that covers it, or remove it if the earlier limits are intended"
            }
            Self::RulePartiallyShadowed => {
                "move the rule before the less restrictive rule, or narrow that rule so it no longer matches what this rule is meant to decide"
            }
            Self::McpAliasRuleOverridden => {
                "review the later rule: it decides every request reaching the MCP endpoint by an alias that it matches, whatever its position; narrow it if it was not meant to"
            }
            Self::McpAliasRoutePrecedence => {
                "require the same permission at the alias path as at the canonical MCP path, or remove the alias route"
            }
            Self::SelectedUpstreamAllowIgnored => {
                "grant the access through the host-bound route's permission, which decides a selected virtual upstream"
            }
            Self::ToolRuleNeverDecides => {
                "remove the rule, or enable the tool's entry and align the rule's principal with the issuers and authentication methods the entry admits"
            }
            Self::ToolRuleGrantNarrowed => {
                "admit the caller in the tool's entry too, or narrow the rule to callers the entry admits"
            }
            Self::IssuerlessRoleGrant => {
                "constrain the grant to the role's issuers, or grant the access through a route permission"
            }
            Self::WildcardPermission => {
                "replace the wildcard with the permissions the role needs"
            }
            Self::BroadPathGrant => "narrow the rule's path to what the callers it names need",
            Self::AllMethodsGrant => {
                "list the methods the rule is meant to allow, or constrain its principal"
            }
            Self::RateOverrideLooserThanGlobal => {
                "lower the override's limits to at most the global lane's, or raise the global lane if more is intended"
            }
            Self::EgressBroadWildcardHost => {
                "replace the pattern with the names, or a wildcard under a domain, the gateway needs to reach"
            }
            Self::EgressNonPublicCidr => {
                "narrow the CIDR to the internal addresses upstreams use; admit loopback or link-local addresses only for an upstream that lives there"
            }
            Self::EgressUnusualPort => "list only the ports upstreams listen on",
            Self::EgressChangeRequiresRestart => {
                "edit the policy file and restart the gateway to change egress, or keep the active egress section in this document"
            }
            Self::RoleNotDefined => "define the role, or correct the name",
            Self::RoutePermissionUngranted => {
                "grant the permission through a role, or correct the permission"
            }
            Self::ToolNotRegistered => "register the tool, or correct the name",
            Self::ConnectionEndpointEgressDenied => {
                "admit the endpoint in the egress controls, or correct the Connection"
            }
            Self::NameCaseCollision => "use one spelling",
            Self::PolicyWriteUnreachable => {
                "keep a role that grants admin:policy:write to a principal that can hold it"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProofBasis {
    Proven,
    Heuristic,
    Inconclusive,
}

impl ProofBasis {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Heuristic => "heuristic",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// What a candidate patch can do to access, judged on the effective action
/// (forward or block) and, for a rate override, the configured limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccessEffect {
    /// No request's decision changes.
    Equivalent,
    /// No request forwarded after the patch was blocked before it, and no
    /// request is admitted under a looser rate limit; some may be blocked or
    /// limited that were not.
    Narrowing,
    /// Some request may be forwarded, or admitted under a looser limit, that
    /// was not before.
    Expanding,
    /// The analyzer could not tell.
    Unknown,
}

impl AccessEffect {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::Narrowing => "narrowing",
            Self::Expanding => "expanding",
            Self::Unknown => "unknown",
        }
    }
}

/// An evaluation lane: one way the evaluator reads the same policy elements.
/// Reachability differs between them, so a reachability finding says in
/// which lanes it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lane {
    /// One path identity, no selected virtual upstream: first match.
    Http,
    /// An MCP endpoint reached by an alias: both identities, most
    /// restrictive action first, and routes by exact prefix first.
    McpAlias,
    /// A selected host-qualified virtual upstream: direct denies only, then
    /// host-bound routes.
    SelectedUpstream,
    /// A rendered local tool HTTP operation: first match, unknown dispatch.
    RenderedToolHttp,
    /// An enum-source refresh request: direct denies only.
    SourceRequest,
    /// MCP tool-name rules: first match per tool name.
    Tool,
    /// Rate-limit override selection: first match.
    Rate,
}

impl Lane {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::McpAlias => "mcp_alias",
            Self::SelectedUpstream => "selected_upstream",
            Self::RenderedToolHttp => "rendered_tool_http",
            Self::SourceRequest => "source_request",
            Self::Tool => "tool",
            Self::Rate => "rate",
        }
    }
}

/// The policy section an element lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Section {
    DefaultAction,
    EnforcementMode,
    Roles,
    Rules,
    Routes,
    RateLimits,
    Tools,
    Egress,
    IdentityMappings,
}

impl Section {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DefaultAction => "default_action",
            Self::EnforcementMode => "enforcement_mode",
            Self::Roles => "roles",
            Self::Rules => "rules",
            Self::Routes => "routes",
            Self::RateLimits => "rate_limits",
            Self::Tools => "tools",
            Self::Egress => "egress",
            Self::IdentityMappings => "identity_mappings",
        }
    }
}

/// A policy element a finding names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ElementRef {
    pub(crate) section: Section,
    /// RFC 6901 pointer into the analyzed document.
    pub(crate) pointer: String,
    /// Position in an ordered section.
    pub(crate) position: Option<usize>,
    /// The element's stable id, when it has one.
    pub(crate) id: Option<String>,
    /// A role's or a tool's name.
    pub(crate) name: Option<String>,
    /// For a finding about one member of the element -- one role a rule's
    /// principal names, say -- that member's pointer relative to the
    /// element. Part of the identity, and not rendered: `pointer` already
    /// names it.
    pub(crate) member: Option<String>,
}

impl ElementRef {
    /// The element's identity for a fingerprint: its stable id or name when
    /// it has one, so a fingerprint survives a reorder, else its position;
    /// and the member, when the finding is about one.
    fn identity(&self) -> Value {
        let key = match (&self.id, &self.name, self.position) {
            (Some(id), _, _) => json!({ "id": id }),
            (None, Some(name), _) => json!({ "name": name }),
            (None, None, Some(position)) => json!({ "position": position }),
            (None, None, None) => json!({}),
        };
        let mut identity = json!({ "section": self.section.as_str(), "key": key });
        if let (Some(member), Some(identity)) = (&self.member, identity.as_object_mut()) {
            identity.insert("member".to_owned(), json!(member));
        }
        identity
    }

    pub(crate) fn to_json(&self) -> Value {
        let mut view = Map::new();
        view.insert("section".to_owned(), json!(self.section.as_str()));
        view.insert("pointer".to_owned(), json!(self.pointer));
        if let Some(position) = self.position {
            view.insert("position".to_owned(), json!(position));
        }
        if let Some(id) = &self.id {
            view.insert("id".to_owned(), json!(id));
        }
        if let Some(name) = &self.name {
            view.insert("name".to_owned(), json!(name));
        }
        Value::Object(view)
    }
}

/// A candidate patch: `policy-simulation.v1` edits over the analyzed
/// document. Never applied by the gateway.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CandidatePatch {
    pub(crate) access_effect: AccessEffect,
    pub(crate) edits: Vec<Value>,
}

/// One finding.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Finding {
    pub(crate) code: FindingCode,
    pub(crate) severity: Severity,
    pub(crate) proof_basis: ProofBasis,
    pub(crate) element: ElementRef,
    /// The element that establishes the finding, such as the earlier rule
    /// that covers this one.
    pub(crate) related: Option<ElementRef>,
    /// Lanes in which the element provably never decides a request.
    pub(crate) never_decides_in: Vec<Lane>,
    /// Lanes in which the analyzer did not prove that the element never
    /// decides: it may still decide there.
    pub(crate) may_decide_in: Vec<Lane>,
    /// Value-free facts specific to the finding.
    pub(crate) details: Map<String, Value>,
    pub(crate) patch: Option<CandidatePatch>,
    /// Stable codes for what the analyzer could not establish.
    pub(crate) limitations: Vec<&'static str>,
}

impl Finding {
    /// The finding's stable fingerprint: its code and the identities of the
    /// elements it names, framed and hashed. It does not change when an
    /// unrelated element changes, or when a named element with a stable id
    /// moves.
    pub(crate) fn fingerprint(&self) -> Result<String, AnalysisError> {
        let identity = json!({
            "code": self.code.as_str(),
            "element": self.element.identity(),
            "related": self.related.as_ref().map(ElementRef::identity),
        });
        let bytes = crate::canonical_json::canonical_json_bytes(&identity)
            .map_err(|_| AnalysisError::Internal("fingerprint_unavailable"))?;
        Ok(format!(
            "sha256:{}",
            hex::encode(crate::policy_eval::framed_digest(
                FINDING_FINGERPRINT_KIND,
                ANALYSIS_MEDIA_TYPE,
                RESULT_SCHEMA_VERSION,
                &bytes,
            ))
        ))
    }
}

/// Why an analysis did not cover the whole policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AnalysisLimitation {
    ComparisonBudgetExhausted,
    DeadlineExceeded,
    FindingsTruncated,
    /// A resource a check needs could not be read -- part of the
    /// cross-resource view, or the global rate lanes for a policy with rate
    /// overrides -- so the checks that need it did not run.
    ResourcesUnavailable,
}

impl AnalysisLimitation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ComparisonBudgetExhausted => "comparison_budget_exhausted",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::FindingsTruncated => "findings_truncated",
            Self::ResourcesUnavailable => "resources_unavailable",
        }
    }
}

/// A finished analysis.
#[derive(Debug)]
pub(crate) struct AnalysisOutcome {
    /// Sorted: severity, then section, position and code.
    pub(crate) findings: Vec<Finding>,
    /// Every check ran over every element. An incomplete analysis says
    /// nothing about the elements it did not reach.
    pub(crate) complete: bool,
    pub(crate) limitations: Vec<AnalysisLimitation>,
    /// Element comparisons made, against [`MAX_COMPARISONS`].
    pub(crate) comparisons: usize,
}

/// An analysis that failed. No partial result accompanies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AnalysisError {
    /// The evaluator refused a question the analyzer built for reasons other
    /// than its facts, or an internal invariant failed.
    Internal(&'static str),
}
