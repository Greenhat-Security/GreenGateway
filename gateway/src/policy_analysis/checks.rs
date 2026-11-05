//! The checks, and the witness confirmations that tie every reachability
//! claim to the canonical evaluator.
//!
//! A reachability claim is built from [`super::coverage`]'s inclusion proofs
//! and the evaluator's documented precedence in each lane. Before it is
//! reported as `proven`, the analyzer builds a witness request the claimed
//! element itself matches -- asking the evaluator about the element alone --
//! and asks the evaluator which element of the analyzed policy decides that
//! witness in the element's ordinary lane (for a route, the policy's route
//! lane). Only an answer naming an earlier element confirms
//! the claim; any other answer reports the finding `inconclusive`, without a
//! patch. An evaluator error that is not a refusal of the witness's facts
//! fails the analysis.
//!
//! The overlap, lane-effect and grant checks make existential claims -- some
//! request a rule matches is decided by an earlier, less restrictive one; an
//! alias request is decided by a later, more restrictive one; a caller a
//! grant names is refused, or admitted although its role is not active for
//! it -- and each is shown the same way: by a witness built from the
//! elements' predicates and answered by the evaluator. The egress checks ask
//! the static egress lane, with witness resolution facts, never a resolver.
//! The cross-resource and lockout checks are the publication's own
//! ([`validate_resources`]), run over the resources the endpoint read once.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use http::Method;
use ipnet::IpNet;
use serde_json::{json, Map, Value};
use url::Url;

use super::{
    coverage::{
        dispatch_covers, hosts_cover, matches_every_path, pattern_covers, pattern_intersection,
        prefix_covers, prefix_pattern, principal_covers, segments, Segments,
    },
    AccessEffect, AnalysisError, AnalysisLimitation, AnalysisOutcome, CandidatePatch, ElementRef,
    Finding, FindingCode, Lane, ProofBasis, Section, Severity, MAX_COMPARISONS, MAX_FINDINGS,
};
use crate::{
    auth::{protected_resource::MCP_RESOURCE_PATH, AuthMethod, Principal},
    middleware::rate_limit::GlobalRateLanes,
    policy_eval::{
        analysis::DirectRuleOutcome,
        egress::{
            CompiledEgressPolicy, EgressControls, EgressDestination, EgressEvaluationContext,
            EgressOutcome, ResolutionFact, EGRESS_CONTEXT_VERSION,
        },
        tools::{ToolOperation, ToolReason},
        CompiledPolicy, DispatchFacts, EvaluationError, PolicyEffect, PrincipalFact,
        PrincipalIdentity, RuleReference,
    },
    policy_replay::auth_method_from_code,
    policy_testing::{
        runner::{http_context, rate_context, tool_context},
        suite::{HttpRequest, SyntheticPrincipal, SyntheticTarget},
    },
    rbac::{
        engine::grants_permission,
        matcher::{
            matches_every_method, method_matches, methods_cover, path_pattern_matches,
            PatternSegment,
        },
        policy_document::{is_valid_element_id, pointer_token, IssueCode},
        policy_resources::{validate_resources, PolicyResourceView},
        DefaultAction, EgressPolicy, EnforcementMode, Policy, PrincipalMatcher, RateLimitRule,
        RouteRule, Rule, RuleAction, RuleDispatchKind, RuleDispatchMatcher,
    },
};

/// How often, in comparisons, the deadline is read.
const DEADLINE_CHECK_INTERVAL: usize = 1024;
/// The subject of a witness principal whose matcher names no principal id.
const WITNESS_SUBJECT: &str = "analysis-witness";
/// The upstream origin of a witness for a route-bound rule, which matches on
/// the route id alone. `.invalid` never resolves; nothing resolves it anyway.
const WITNESS_ORIGIN: &str = "https://analysis-witness.invalid";
/// The value a witness path puts where a pattern accepts any one segment.
const WITNESS_SEGMENT: &str = "w";
/// The deep path a broad rule's second witness probes.
const WITNESS_DEEP_PATH: &str = "/w/w";
/// The issuer of a witness caller that claims a role from an issuer the
/// role is not bound to. `.invalid` is never an issuer anyone trusts.
const WITNESS_ISSUER: &str = "https://analysis-witness.invalid";
/// The route id of a witness's selected virtual upstream.
const WITNESS_ROUTE_ID: &str = "analysis-witness";
/// The host of an egress witness destination. Nothing resolves it: the
/// witness supplies its own resolution facts.
const WITNESS_EGRESS_HOST: &str = "analysis-witness.invalid";
/// The port of an egress witness destination: `https`'s default.
const WITNESS_EGRESS_PORT: u16 = 443;
/// Ports an egress port list may name without a finding: the web ports
/// upstreams ordinarily listen on.
const USUAL_EGRESS_PORTS: [u16; 4] = [80, 443, 8080, 8443];
/// Address ranges an egress CIDR can admit that the non-global registry
/// otherwise refuses, by the category a finding names. The categories are
/// listed in the order a finding lists them.
const NON_PUBLIC_RANGES: [(&str, &str); 9] = [
    ("loopback", "127.0.0.0/8"),
    ("loopback", "::1/128"),
    ("link_local", "169.254.0.0/16"),
    ("link_local", "fe80::/10"),
    ("private", "10.0.0.0/8"),
    ("private", "172.16.0.0/12"),
    ("private", "192.168.0.0/16"),
    ("private", "100.64.0.0/10"),
    ("private", "fc00::/7"),
];
/// The lanes in which an earlier, less restrictive rule pre-empts a later
/// one by source order.
const PRE_EMPTED_IN: [&str; 2] = ["http", "rendered_tool_http"];

/// Every lane a direct HTTP rule decides in.
const HTTP_RULE_LANES: [Lane; 5] = [
    Lane::Http,
    Lane::McpAlias,
    Lane::SelectedUpstream,
    Lane::RenderedToolHttp,
    Lane::SourceRequest,
];
/// The lanes that decide direct HTTP rules by first match in source order.
const FIRST_MATCH_HTTP_LANES: [Lane; 2] = [Lane::Http, Lane::RenderedToolHttp];
/// Every lane a route decides in.
const ROUTE_LANES: [Lane; 3] = [Lane::Http, Lane::McpAlias, Lane::SelectedUpstream];

/// What the analysis reads besides the policy.
pub(crate) struct AnalysisResources<'a> {
    /// The request paths that reach an MCP endpoint by an alias rather than
    /// its canonical policy identity (the gateway's MCP route paths other
    /// than `/mcp`). An alias request selects a route whose prefix equals its
    /// path before any other, so a route at such a prefix is never claimed
    /// unreachable by a broader earlier route.
    pub(crate) mcp_alias_paths: &'a [String],
    /// The active policy the analyzed one would replace -- the analyzed
    /// policy itself when it is the active one -- for the checks that judge
    /// a change: lockout and egress.
    pub(crate) active: &'a Policy,
    /// The configured limits of the global rate lanes, or `None` when the
    /// rate stage is not attached.
    pub(crate) global_rate_lanes: Option<GlobalRateLanes>,
    /// What the cross-resource checks a publication runs read: the tool
    /// registry, the Connections, the static egress lane and the
    /// configuration identity, as they were read once for this analysis.
    pub(crate) resource_view: &'a PolicyResourceView,
}

/// Analyze `policy`: every check, within the comparison budget, the
/// findings cap and `deadline`.
pub(crate) fn analyze(
    policy: &Policy,
    resources: &AnalysisResources<'_>,
    deadline: Instant,
) -> Result<AnalysisOutcome, AnalysisError> {
    let mut run = Run {
        policy,
        compiled: CompiledPolicy::for_analysis(policy.clone()),
        routes_only: None,
        alias_paths: resources.mcp_alias_paths,
        active: resources.active,
        global_rate_lanes: resources.global_rate_lanes,
        resource_view: resources.resource_view,
        deadline,
        comparisons: 0,
        stopped: None,
        resources_unavailable: false,
        covered_rules: BTreeSet::new(),
        findings: Vec::new(),
    };
    // The linear checks first, so a budget spent on pairwise comparisons
    // never costs them.
    run.risky_defaults();
    run.wildcard_grants();
    run.broad_rules()?;
    run.issuerless_role_grants()?;
    run.tool_policy_conflicts()?;
    run.rate_lane_lints()?;
    run.egress_lints()?;
    run.cross_resources()?;
    run.direct_rules()?;
    run.partial_overlaps()?;
    run.tool_rules()?;
    run.mcp_alias_lane()?;
    run.selected_upstreams()?;
    run.routes()?;
    run.rate_overrides()?;
    Ok(run.finish())
}

struct Run<'a> {
    policy: &'a Policy,
    compiled: CompiledPolicy,
    /// The analyzed policy without its direct rules, compiled on first use:
    /// the route lane alone, for route witnesses.
    routes_only: Option<CompiledPolicy>,
    alias_paths: &'a [String],
    active: &'a Policy,
    global_rate_lanes: Option<GlobalRateLanes>,
    resource_view: &'a PolicyResourceView,
    deadline: Instant,
    comparisons: usize,
    stopped: Option<AnalysisLimitation>,
    /// A check did not run because a resource it needs was not read.
    resources_unavailable: bool,
    /// Rules already reported as never deciding where they would otherwise
    /// be compared: covered by an earlier rule, or refused every caller by
    /// their tool's entry. Their partial overlaps and lane effects are not
    /// reported on top.
    covered_rules: BTreeSet<usize>,
    findings: Vec<Finding>,
}

impl Run<'_> {
    /// Spend one comparison. `false` once the budget, the deadline or the
    /// findings cap has stopped the analysis; nothing further is compared.
    fn spend(&mut self) -> bool {
        if self.stopped.is_some() {
            return false;
        }
        if self.comparisons >= MAX_COMPARISONS {
            self.stopped = Some(AnalysisLimitation::ComparisonBudgetExhausted);
            return false;
        }
        if self.comparisons.is_multiple_of(DEADLINE_CHECK_INTERVAL)
            && Instant::now() >= self.deadline
        {
            self.stopped = Some(AnalysisLimitation::DeadlineExceeded);
            return false;
        }
        self.comparisons += 1;
        true
    }

    fn push(&mut self, finding: Finding) {
        if self.findings.len() >= MAX_FINDINGS {
            self.stopped
                .get_or_insert(AnalysisLimitation::FindingsTruncated);
            return;
        }
        self.findings.push(finding);
    }

    fn finish(mut self) -> AnalysisOutcome {
        self.findings.sort_by(|left, right| {
            sort_key(left)
                .cmp(&sort_key(right))
                .then_with(|| left.code.cmp(&right.code))
                .then_with(|| left.element.pointer.cmp(&right.element.pointer))
        });
        let mut limitations: Vec<AnalysisLimitation> = self.stopped.into_iter().collect();
        if self.resources_unavailable {
            limitations.push(AnalysisLimitation::ResourcesUnavailable);
        }
        AnalysisOutcome {
            findings: self.findings,
            complete: limitations.is_empty(),
            limitations,
            comparisons: self.comparisons,
        }
    }

    /// The first element that decides every ordinary request, so the default
    /// never does: a route for `/` with every method and no host binding, or
    /// an enabled direct rule matching every caller, method and path.
    fn default_masked_by(&self) -> Option<ElementRef> {
        if let Some((index, route)) = self.policy.routes.iter().enumerate().find(|(_, route)| {
            route.path_prefix == "/"
                && matches_every_method(&route.methods)
                && route.hosts.is_empty()
        }) {
            return Some(route_ref(index, route));
        }
        self.policy
            .rules
            .iter()
            .enumerate()
            .find(|(_, rule)| {
                is_http_rule(rule)
                    && unconditional(rule)
                    && rule.principal.is_unconstrained()
                    && rule.dispatch.is_none()
                    && matches_every_method(&rule.methods)
                    && matches_every_path(&segments(&rule.path))
            })
            .map(|(index, rule)| rule_ref(index, rule))
    }

    fn risky_defaults(&mut self) {
        let masked_by = self.default_masked_by();
        if self.policy.default_action == DefaultAction::Allow {
            let mut finding = finding(
                FindingCode::DefaultAllow,
                if masked_by.is_some() {
                    Severity::Low
                } else {
                    Severity::High
                },
                ProofBasis::Proven,
                scalar_ref(Section::DefaultAction),
            );
            finding
                .details
                .insert("masked".to_owned(), json!(masked_by.is_some()));
            finding.patch = Some(CandidatePatch {
                // A default that never decides changes nothing when it
                // changes; one that does can only turn allows into denials.
                access_effect: if masked_by.is_some() {
                    AccessEffect::Equivalent
                } else {
                    AccessEffect::Narrowing
                },
                edits: vec![set_edit("default_action", "deny")],
            });
            finding.related = masked_by.clone();
            self.push(finding);
        }
        if self.policy.enforcement_mode == EnforcementMode::Shadow {
            let inheriting = self
                .policy
                .routes
                .iter()
                .filter(|route| route.enforcement_mode.is_none())
                .count();
            // The mode softens only denials: the default's when it denies and
            // can decide, and those of routes without a mode of their own.
            let default_softened =
                masked_by.is_none() && self.policy.default_action == DefaultAction::Deny;
            let inert = inheriting == 0 && !default_softened;
            let mut finding = finding(
                FindingCode::GlobalShadowEnforcement,
                if inert { Severity::Low } else { Severity::High },
                ProofBasis::Proven,
                scalar_ref(Section::EnforcementMode),
            );
            finding
                .details
                .insert("inheriting_routes".to_owned(), json!(inheriting));
            finding
                .details
                .insert("default_softened".to_owned(), json!(default_softened));
            finding.patch = Some(CandidatePatch {
                access_effect: if inert {
                    AccessEffect::Equivalent
                } else {
                    AccessEffect::Narrowing
                },
                edits: vec![set_edit("enforcement_mode", "enforce")],
            });
            self.push(finding);
        }
    }

    /// Roles granting `*`: medium without an issuer, which any trusted issuer
    /// can then activate, and low when bound to issuers.
    fn wildcard_grants(&mut self) {
        let mut names: Vec<&String> = self.policy.roles.keys().collect();
        names.sort();
        for name in names {
            let role = &self.policy.roles[name];
            let Some(index) = role
                .permissions
                .iter()
                .position(|permission| permission == "*")
            else {
                continue;
            };
            let (code, severity) = if role.issuers.is_empty() {
                (FindingCode::WildcardGrantWithoutIssuer, Severity::Medium)
            } else {
                (FindingCode::WildcardPermission, Severity::Low)
            };
            self.push(finding(
                code,
                severity,
                // Whether any issuer but the intended one could grant the
                // role, or whether every permission is more than the role
                // needs, depends on the deployment and on intent.
                ProofBasis::Heuristic,
                ElementRef {
                    section: Section::Roles,
                    pointer: format!("/roles/{}/permissions/{index}", pointer_token(name)),
                    position: None,
                    id: None,
                    name: Some(name.clone()),
                    member: None,
                },
            ));
        }
    }

    /// Allows and shadows broader than any one grant should be: every path
    /// for every caller, every path for the callers a rule names, and every
    /// method for every caller.
    fn broad_rules(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        for (index, rule) in policy.rules.iter().enumerate() {
            if rule.action == RuleAction::Deny
                || !is_http_rule(rule)
                || !unconditional(rule)
                || rule.dispatch.is_some()
            {
                continue;
            }
            let every_path = matches_every_path(&segments(&rule.path));
            if !every_path || !rule.principal.is_unconstrained() {
                self.narrower_broad_rule(index, rule, every_path)?;
                continue;
            }
            let code = if rule.action == RuleAction::Allow {
                FindingCode::BroadUnconstrainedAllow
            } else {
                FindingCode::BroadUnconstrainedShadow
            };
            let confirmed = confirm_broad(policy, rule)?;
            let mut finding = finding(
                code,
                Severity::High,
                ProofBasis::Proven,
                rule_ref(index, rule),
            );
            finding.details.insert(
                "all_methods".to_owned(),
                json!(matches_every_method(&rule.methods)),
            );
            // Removing an allow or a shadow lets later rules, routes and the
            // default decide what it decided; it forwarded all of it.
            finding.patch = delete_edit(&finding.element).map(|edit| CandidatePatch {
                access_effect: AccessEffect::Narrowing,
                edits: vec![edit],
            });
            self.push(unconfirmed_unless(confirmed, finding));
        }
        Ok(())
    }

    fn direct_rules(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let rules = policy.rules.as_slice();
        let patterns: Vec<Segments<'_>> = rules.iter().map(|rule| segments(&rule.path)).collect();
        for (position, rule) in rules.iter().enumerate() {
            if !is_http_rule(rule) {
                continue;
            }
            let mut at_least_as_restrictive = None;
            let mut less_restrictive = None;
            for (earlier_position, earlier) in rules[..position].iter().enumerate() {
                if !is_http_rule(earlier) {
                    continue;
                }
                if !self.spend() {
                    return Ok(());
                }
                if !http_rule_covers(
                    earlier,
                    &patterns[earlier_position],
                    rule,
                    &patterns[position],
                ) {
                    continue;
                }
                if restrictiveness(&earlier.action) >= restrictiveness(&rule.action) {
                    at_least_as_restrictive = Some(earlier_position);
                    break;
                }
                less_restrictive.get_or_insert(earlier_position);
            }
            if at_least_as_restrictive.is_some() || less_restrictive.is_some() {
                self.covered_rules.insert(position);
            }
            if let Some(earlier_position) = at_least_as_restrictive {
                let earlier = &rules[earlier_position];
                let duplicate = earlier.action == rule.action
                    && self.spend()
                    && http_rule_covers(
                        rule,
                        &patterns[position],
                        earlier,
                        &patterns[earlier_position],
                    );
                let confirmed = self.confirm_rule(position, rule)?;
                let finding = unreachable_rule(
                    position,
                    rule,
                    earlier_position,
                    earlier,
                    duplicate,
                    &HTTP_RULE_LANES,
                );
                self.push(unconfirmed_unless(confirmed, finding));
            } else if let Some(earlier_position) = less_restrictive {
                let confirmed = self.confirm_rule(position, rule)?;
                // A deny still decides where denies are read first or alone;
                // a shadow only where the most restrictive action wins.
                let may_decide_in: &[Lane] = match rule.action {
                    RuleAction::Deny => {
                        &[Lane::McpAlias, Lane::SelectedUpstream, Lane::SourceRequest]
                    }
                    _ => &[Lane::McpAlias],
                };
                let finding = shadowed_rule(
                    position,
                    rule,
                    earlier_position,
                    &rules[earlier_position],
                    &FIRST_MATCH_HTTP_LANES,
                    may_decide_in,
                );
                self.push(unconfirmed_unless(confirmed, finding));
            }
        }
        Ok(())
    }

    /// Tool-name rules decide by first match among the rules naming the same
    /// tool, in one lane.
    fn tool_rules(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let rules = policy.rules.as_slice();
        for (position, rule) in rules.iter().enumerate() {
            let Some(tool_name) = rule.tool_name.as_deref() else {
                continue;
            };
            // A rule its tool's entry refuses every caller of is reported
            // for that, and is not also compared with earlier rules.
            if !rule.enabled || self.covered_rules.contains(&position) {
                continue;
            }
            let mut covering = None;
            for (earlier_position, earlier) in rules[..position].iter().enumerate() {
                if !earlier.enabled || earlier.tool_name.as_deref() != Some(tool_name) {
                    continue;
                }
                if !self.spend() {
                    return Ok(());
                }
                if unconditional(earlier) && principal_covers(&earlier.principal, &rule.principal) {
                    covering = Some(earlier_position);
                    break;
                }
            }
            let Some(earlier_position) = covering else {
                continue;
            };
            let earlier = &rules[earlier_position];
            let confirmed = self.confirm_tool_rule(position, rule, tool_name)?;
            let finding = if restrictiveness(&earlier.action) >= restrictiveness(&rule.action) {
                let duplicate = earlier.action == rule.action
                    && unconditional(rule)
                    && principal_covers(&rule.principal, &earlier.principal);
                unreachable_rule(
                    position,
                    rule,
                    earlier_position,
                    earlier,
                    duplicate,
                    &[Lane::Tool],
                )
            } else {
                shadowed_rule(
                    position,
                    rule,
                    earlier_position,
                    earlier,
                    &[Lane::Tool],
                    &[],
                )
            };
            self.push(unconfirmed_unless(confirmed, finding));
        }
        Ok(())
    }

    fn routes(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let rules = policy.rules.as_slice();
        let rule_patterns: Vec<Segments<'_>> =
            rules.iter().map(|rule| segments(&rule.path)).collect();
        let routes = policy.routes.as_slice();
        for (position, route) in routes.iter().enumerate() {
            // Every direct rule runs before every route.
            let route_pattern = prefix_pattern(&route.path_prefix);
            let route_segments = route_pattern.as_deref().map(segments).unwrap_or(None);
            let mut deciding_rule = None;
            if route_segments.is_some() {
                for (rule_position, rule) in rules.iter().enumerate() {
                    if !is_http_rule(rule)
                        || !unconditional(rule)
                        || !rule.principal.is_unconstrained()
                        || rule.dispatch.is_some()
                    {
                        continue;
                    }
                    if !self.spend() {
                        return Ok(());
                    }
                    if methods_cover(&rule.methods, &route.methods)
                        && pattern_covers(&rule_patterns[rule_position], &route_segments)
                    {
                        deciding_rule = Some(rule_position);
                        break;
                    }
                }
            }
            if let Some(rule_position) = deciding_rule {
                let rule = &rules[rule_position];
                let confirmed = self.confirm_route_decided_by_rule(route)?;
                let finding = if rule.action == RuleAction::Deny {
                    let mut finding = finding(
                        FindingCode::RouteUnreachable,
                        Severity::Low,
                        ProofBasis::Proven,
                        route_ref(position, route),
                    );
                    finding.related = Some(rule_ref(rule_position, rule));
                    finding.never_decides_in = ROUTE_LANES.to_vec();
                    finding
                        .details
                        .insert("decided_by".to_owned(), json!("rule"));
                    finding.patch = delete_edit(&finding.element).map(|edit| CandidatePatch {
                        access_effect: AccessEffect::Equivalent,
                        edits: vec![edit],
                    });
                    finding
                } else {
                    let mut finding = finding(
                        FindingCode::RouteBypassed,
                        Severity::High,
                        ProofBasis::Proven,
                        route_ref(position, route),
                    );
                    let related = rule_ref(rule_position, rule);
                    finding.never_decides_in = vec![Lane::Http, Lane::McpAlias];
                    // A selected virtual upstream reads only direct denies,
                    // so a host-bound route still decides it.
                    if !route.hosts.is_empty() {
                        finding.may_decide_in = vec![Lane::SelectedUpstream];
                    }
                    finding
                        .details
                        .insert("rule_action".to_owned(), json!(action_str(&rule.action)));
                    finding.patch = delete_edit(&related).map(|edit| CandidatePatch {
                        access_effect: AccessEffect::Narrowing,
                        edits: vec![edit],
                    });
                    finding.related = Some(related);
                    finding
                };
                self.push(unconfirmed_unless(confirmed, finding));
                continue;
            }

            let mut covering = None;
            for (earlier_position, earlier) in routes[..position].iter().enumerate() {
                if !self.spend() {
                    return Ok(());
                }
                if route_covers(earlier, route) && self.alias_cannot_select(earlier, route) {
                    covering = Some(earlier_position);
                    break;
                }
            }
            let Some(earlier_position) = covering else {
                continue;
            };
            let earlier = &routes[earlier_position];
            let confirmed = self.confirm_route_decided_earlier(position, route)?;
            let permission_differs = earlier.permission != route.permission;
            let mode_differs = self.route_mode(earlier) != self.route_mode(route);
            let mut finding = if permission_differs || mode_differs {
                let mut finding = finding(
                    FindingCode::RouteShadowed,
                    Severity::Medium,
                    ProofBasis::Proven,
                    route_ref(position, route),
                );
                finding
                    .details
                    .insert("permission_differs".to_owned(), json!(permission_differs));
                finding
                    .details
                    .insert("mode_differs".to_owned(), json!(mode_differs));
                finding.patch = Some(CandidatePatch {
                    access_effect: self.route_move_effect(earlier, route),
                    edits: vec![move_edit(&finding.element, position, earlier_position)],
                });
                finding
            } else {
                let mut finding = finding(
                    FindingCode::RouteUnreachable,
                    Severity::Low,
                    ProofBasis::Proven,
                    route_ref(position, route),
                );
                finding
                    .details
                    .insert("decided_by".to_owned(), json!("route"));
                finding.patch = delete_edit(&finding.element).map(|edit| CandidatePatch {
                    access_effect: AccessEffect::Equivalent,
                    edits: vec![edit],
                });
                finding
            };
            finding.related = Some(route_ref(earlier_position, earlier));
            finding.never_decides_in = ROUTE_LANES.to_vec();
            self.push(unconfirmed_unless(confirmed, finding));
        }
        Ok(())
    }

    /// An MCP alias request selects the first route whose prefix equals its
    /// path before matching any prefix, so a broader earlier route does not
    /// stop a route at an alias path from deciding. An identical prefix does.
    fn alias_cannot_select(&self, earlier: &RouteRule, route: &RouteRule) -> bool {
        earlier.path_prefix == route.path_prefix || !self.alias_paths.contains(&route.path_prefix)
    }

    fn route_mode(&self, route: &RouteRule) -> EnforcementMode {
        route
            .enforcement_mode
            .unwrap_or(self.policy.enforcement_mode)
    }

    /// The access effect of moving `route` before `earlier`, which covers
    /// it: the requests `route` matches stop needing `earlier`'s permission
    /// under its mode and need `route`'s under its own. Every other request
    /// keeps its deciding route.
    fn route_move_effect(&self, earlier: &RouteRule, route: &RouteRule) -> AccessEffect {
        let narrows = self.route_requirement_implies(route, earlier);
        let widens = self.route_requirement_implies(earlier, route);
        match (narrows, widens) {
            (true, true) => AccessEffect::Equivalent,
            (true, false) => AccessEffect::Narrowing,
            (false, true) => AccessEffect::Expanding,
            (false, false) => AccessEffect::Unknown,
        }
    }

    /// Whether every request `stricter` forwards, `looser` forwards too: a
    /// shadow route forwards everything, and an enforcing one exactly the
    /// callers holding its permission. Holding a permission is decided by the
    /// roles that grant it, so one permission implies another when every role
    /// granting the first also grants the second.
    fn route_requirement_implies(&self, stricter: &RouteRule, looser: &RouteRule) -> bool {
        match (self.route_mode(stricter), self.route_mode(looser)) {
            (_, EnforcementMode::Shadow) => true,
            (EnforcementMode::Shadow, EnforcementMode::Enforce) => false,
            (EnforcementMode::Enforce, EnforcementMode::Enforce) => {
                self.policy.roles.values().all(|role| {
                    !grants_permission(&role.permissions, &stricter.permission)
                        || grants_permission(&role.permissions, &looser.permission)
                })
            }
        }
    }

    fn rate_overrides(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let limits = policy.rate_limits.as_slice();
        let patterns: Vec<Segments<'_>> = limits
            .iter()
            .map(|limit| limit.path.as_deref().map(segments).unwrap_or(None))
            .collect();
        for (position, limit) in limits.iter().enumerate() {
            let mut covering = None;
            for (earlier_position, earlier) in limits[..position].iter().enumerate() {
                if !self.spend() {
                    return Ok(());
                }
                if rate_covers(
                    earlier,
                    &patterns[earlier_position],
                    limit,
                    &patterns[position],
                ) {
                    covering = Some(earlier_position);
                    break;
                }
            }
            let Some(earlier_position) = covering else {
                continue;
            };
            let earlier = &limits[earlier_position];
            let confirmed = self.confirm_rate(position, limit)?;
            let same = earlier.requests_per_second == limit.requests_per_second
                && earlier.burst == limit.burst;
            let element = rate_ref(position, limit);
            let mut finding = if same {
                let mut finding = finding(
                    FindingCode::RateOverrideUnreachable,
                    Severity::Low,
                    ProofBasis::Proven,
                    element,
                );
                finding.patch = delete_edit(&finding.element).map(|edit| CandidatePatch {
                    access_effect: AccessEffect::Equivalent,
                    edits: vec![edit],
                });
                finding
            } else {
                let stricter = limit.requests_per_second <= earlier.requests_per_second
                    && limit.burst <= earlier.burst;
                let looser = limit.requests_per_second >= earlier.requests_per_second
                    && limit.burst >= earlier.burst;
                let mut finding = finding(
                    FindingCode::RateOverrideShadowed,
                    // A stricter limit that never applies is protection the
                    // author meant to have; a looser one is only capacity.
                    if stricter {
                        Severity::Medium
                    } else {
                        Severity::Low
                    },
                    ProofBasis::Proven,
                    element,
                );
                finding.details.insert(
                    "limits".to_owned(),
                    json!(match (stricter, looser) {
                        (true, _) => "stricter",
                        (_, true) => "looser",
                        _ => "mixed",
                    }),
                );
                finding.patch = Some(CandidatePatch {
                    access_effect: match (stricter, looser) {
                        (true, _) => AccessEffect::Narrowing,
                        (_, true) => AccessEffect::Expanding,
                        _ => AccessEffect::Unknown,
                    },
                    edits: vec![move_edit(&finding.element, position, earlier_position)],
                });
                finding
            };
            finding.related = Some(rate_ref(earlier_position, earlier));
            finding.never_decides_in = vec![Lane::Rate];
            self.push(unconfirmed_unless(confirmed, finding));
        }
        Ok(())
    }

    /// An allow or shadow narrower than [`Self::broad_rules`]' first case:
    /// every path for the callers it names, or every method for every
    /// caller on less than every path.
    fn narrower_broad_rule(
        &mut self,
        index: usize,
        rule: &Rule,
        every_path: bool,
    ) -> Result<(), AnalysisError> {
        let every_method = matches_every_method(&rule.methods);
        let (code, confirmed) = if every_path {
            (
                FindingCode::BroadPathGrant,
                confirm_broad(self.policy, rule)?,
            )
        } else if every_method && rule.principal.is_unconstrained() {
            (
                FindingCode::AllMethodsGrant,
                confirm_all_methods(self.policy, rule)?,
            )
        } else {
            return Ok(());
        };
        let mut finding = finding(
            code,
            Severity::Medium,
            ProofBasis::Proven,
            rule_ref(index, rule),
        );
        finding
            .details
            .insert("action".to_owned(), json!(action_str(&rule.action)));
        if code == FindingCode::BroadPathGrant {
            finding
                .details
                .insert("all_methods".to_owned(), json!(every_method));
        }
        self.push(unconfirmed_unless(confirmed, finding));
        Ok(())
    }

    /// A grant by a role name that does not carry the issuers the role is
    /// bound to. A route permission a role grants is active only for the
    /// role's issuers and authentication methods, but a direct rule and a
    /// tool entry match the role names a caller claims, so an enabled allow
    /// or shadow rule, or a tool entry, that names an issuer-bound role and
    /// no issuer of its own admits that role claimed from any issuer.
    ///
    /// Claimed-role mode only: in mapped-role mode a caller holds the roles
    /// its issuer's mappings grant, never the ones it claims.
    fn issuerless_role_grants(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        if policy.identity_mappings.is_some() {
            return Ok(());
        }
        let bound = |role: &String| {
            policy
                .roles
                .get(role)
                .is_some_and(|entry| !entry.issuers.is_empty())
        };
        for (position, rule) in policy.rules.iter().enumerate() {
            if !rule.enabled
                || rule.action == RuleAction::Deny
                || !rule.principal.issuers.is_empty()
            {
                continue;
            }
            let Some((index, role)) = rule
                .principal
                .roles
                .iter()
                .enumerate()
                .find(|(_, role)| bound(role))
            else {
                continue;
            };
            let principal = foreign_issuer_caller(
                role,
                rule.principal.auth_methods.first(),
                rule.principal.principal_ids.first(),
            );
            let confirmed = match principal {
                Some(principal) => {
                    self.rule_alone_admits(rule, &principal)?
                        && !self.holds_active_role(&principal, role)
                }
                None => false,
            };
            let mut element = rule_ref(position, rule);
            element.member = Some(format!("/principal/roles/{index}"));
            element.pointer = format!("/rules/{position}/principal/roles/{index}");
            let mut finding = finding(
                FindingCode::IssuerlessRoleGrant,
                if rule.action == RuleAction::Allow {
                    Severity::High
                } else {
                    Severity::Medium
                },
                ProofBasis::Proven,
                element,
            );
            finding
                .details
                .insert("action".to_owned(), json!(action_str(&rule.action)));
            finding.details.insert(
                "lane".to_owned(),
                json!(if rule.tool_name.is_some() {
                    Lane::Tool.as_str()
                } else {
                    Lane::Http.as_str()
                }),
            );
            self.push(unconfirmed_unless(confirmed, finding));
        }
        let mut names: Vec<&String> = policy.tools.keys().collect();
        names.sort();
        for name in names {
            let entry = &policy.tools[name];
            if !entry.enabled || !entry.issuers.is_empty() {
                continue;
            }
            let Some((index, role)) = entry
                .allowed_roles
                .iter()
                .enumerate()
                .find(|(_, role)| bound(role))
            else {
                continue;
            };
            let confirmed = match foreign_issuer_caller(role, entry.auth_methods.first(), None) {
                Some(principal) => {
                    self.tool_admits(name, &principal)? && !self.holds_active_role(&principal, role)
                }
                None => false,
            };
            let token = pointer_token(name);
            let mut finding = finding(
                FindingCode::IssuerlessRoleGrant,
                Severity::Medium,
                ProofBasis::Proven,
                ElementRef {
                    section: Section::Tools,
                    pointer: format!("/tools/{token}/allowed_roles/{index}"),
                    position: None,
                    id: None,
                    name: Some(name.clone()),
                    member: Some(format!("/allowed_roles/{index}")),
                },
            );
            finding
                .details
                .insert("lane".to_owned(), json!(Lane::Tool.as_str()));
            self.push(unconfirmed_unless(confirmed, finding));
        }
        Ok(())
    }

    /// Whether `rule`, compiled alone, matches a request from `principal`:
    /// its own witness request for an HTTP rule, its tool name for a
    /// tool-name rule.
    fn rule_alone_admits(
        &self,
        rule: &Rule,
        principal: &SyntheticPrincipal,
    ) -> Result<bool, AnalysisError> {
        let alone = rule_alone(self.policy, rule);
        let answer = match rule.tool_name.as_deref() {
            Some(tool_name) => alone.match_tool_rules(tool_name, &principal_fact_of(principal)),
            None => {
                let Some((request, _)) = http_rule_witness(rule) else {
                    return Ok(false);
                };
                alone.match_direct_rules(&http_context(alone.snapshot(), &request, principal))
            }
        };
        Ok(answered(answer)? == Some(DirectRuleOutcome::Matched { index: 0 }))
    }

    /// Whether the analyzed policy holds `role` active for `principal`: the
    /// role is claimed and admits the principal's issuer and authentication
    /// method, as a route permission check reads it.
    fn holds_active_role(&self, principal: &SyntheticPrincipal, role: &str) -> bool {
        principal.principal().is_some_and(|principal| {
            self.compiled
                .engine()
                .principal_has_active_role(principal, role)
        })
    }

    /// Whether the tool lane's admission -- the tool's entry, before any
    /// tool-name rule -- admits `principal` for an invocation of `tool_name`.
    fn tool_admits(
        &self,
        tool_name: &str,
        principal: &SyntheticPrincipal,
    ) -> Result<bool, AnalysisError> {
        Ok(match self.tool_invocation(tool_name, principal)? {
            Some(reason) => !refused_by_admission(reason),
            None => false,
        })
    }

    /// The tool lane's reason for an invocation of `tool_name` by
    /// `principal`, over the analyzed policy, or `None` when the evaluator
    /// refused the witness's facts.
    fn tool_invocation(
        &self,
        tool_name: &str,
        principal: &SyntheticPrincipal,
    ) -> Result<Option<ToolReason>, AnalysisError> {
        let context = tool_context(
            self.compiled.snapshot(),
            ToolOperation::Invocation,
            tool_name,
            principal,
            None,
        );
        Ok(answered(self.compiled.evaluate_tool(&context))?
            .filter(|evaluation| evaluation.is_complete())
            .map(|evaluation| evaluation.reason()))
    }

    /// Tool-name rules against the tool policy entry the tool lane admits
    /// an invocation by before any tool-name rule is read: a rule for a tool
    /// without an enabled entry, or whose principal and the entry's share no
    /// issuer or no authentication method, never decides; an allow or shadow
    /// that names a caller the entry refuses grants less than it names.
    fn tool_policy_conflicts(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        for (position, rule) in policy.rules.iter().enumerate() {
            let Some(tool_name) = rule.tool_name.as_deref() else {
                continue;
            };
            if !rule.enabled {
                continue;
            }
            let reason = match policy.tools.get(tool_name) {
                None => Some("tool_absent"),
                Some(entry) if !entry.enabled => Some("tool_disabled"),
                Some(entry) if disjoint(&entry.issuers, &rule.principal.issuers) => {
                    Some("issuers_disjoint")
                }
                Some(entry) if disjoint(&entry.auth_methods, &rule.principal.auth_methods) => {
                    Some("auth_methods_disjoint")
                }
                Some(_) => None,
            };
            if let Some(reason) = reason {
                let refused = self.confirm_tool_refusal(rule, tool_name)?;
                self.covered_rules.insert(position);
                let mut finding = finding(
                    FindingCode::ToolRuleNeverDecides,
                    Severity::Low,
                    ProofBasis::Proven,
                    rule_ref(position, rule),
                );
                finding.never_decides_in = vec![Lane::Tool];
                finding.details.insert("reason".to_owned(), json!(reason));
                finding
                    .details
                    .insert("action".to_owned(), json!(action_str(&rule.action)));
                // A rule that decides nothing changes nothing when it goes:
                // a tool-name rule matches no HTTP request in any lane.
                finding.patch = delete_edit(&finding.element).map(|edit| CandidatePatch {
                    access_effect: AccessEffect::Equivalent,
                    edits: vec![edit],
                });
                self.push(unconfirmed_unless(refused, finding));
            } else if rule.action != RuleAction::Deny
                && !rule.principal.is_unconstrained()
                && self.confirm_tool_refusal(rule, tool_name)?
            {
                // Reported only when the evaluator refuses the very caller
                // the rule names: nothing structural is claimed beyond it.
                let mut finding = finding(
                    FindingCode::ToolRuleGrantNarrowed,
                    Severity::Low,
                    ProofBasis::Proven,
                    rule_ref(position, rule),
                );
                finding
                    .details
                    .insert("action".to_owned(), json!(action_str(&rule.action)));
                self.push(finding);
            }
        }
        Ok(())
    }

    /// The witness caller `rule` names matches the rule alone, and the tool
    /// lane over the analyzed policy refuses it at admission, before any
    /// tool-name rule.
    fn confirm_tool_refusal(&self, rule: &Rule, tool_name: &str) -> Result<bool, AnalysisError> {
        let Some(principal) = witness_principal(&rule.principal) else {
            return Ok(false);
        };
        if !self.rule_alone_admits(rule, &principal)? {
            return Ok(false);
        }
        Ok(self
            .tool_invocation(tool_name, &principal)?
            .is_some_and(refused_by_admission))
    }

    /// Rate overrides looser than the global lane their methods are charged
    /// in. Both stages limit an authenticated request: the global lane per
    /// client address, before authentication, then the override.
    fn rate_lane_lints(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        if policy.rate_limits.is_empty() {
            return Ok(());
        }
        let Some(lanes) = self.global_rate_lanes else {
            self.resources_unavailable = true;
            return Ok(());
        };
        for (position, limit) in policy.rate_limits.iter().enumerate() {
            let mut looser_lanes = Vec::new();
            let mut witness = None;
            let (mut rate_higher, mut burst_higher) = (false, false);
            for (lane_name, method) in charged_lanes(&limit.methods) {
                let (_, lane) = lanes.for_method(&method);
                let rate = limit.requests_per_second > lane.requests_per_second;
                let burst = limit.burst > lane.burst;
                if rate || burst {
                    looser_lanes.push(lane_name);
                    witness.get_or_insert(method);
                    rate_higher |= rate;
                    burst_higher |= burst;
                }
            }
            let Some(method) = witness else {
                continue;
            };
            let confirmed = self.confirm_rate_alone(limit, &method)?;
            let mut finding = finding(
                FindingCode::RateOverrideLooserThanGlobal,
                Severity::Low,
                ProofBasis::Proven,
                rate_ref(position, limit),
            );
            finding
                .details
                .insert("lanes".to_owned(), json!(looser_lanes));
            finding
                .details
                .insert("requests_per_second_higher".to_owned(), json!(rate_higher));
            finding
                .details
                .insert("burst_higher".to_owned(), json!(burst_higher));
            self.push(unconfirmed_unless(confirmed, finding));
        }
        Ok(())
    }

    /// The override alone is selected for a witness request with `method`.
    fn confirm_rate_alone(
        &self,
        limit: &RateLimitRule,
        method: &Method,
    ) -> Result<bool, AnalysisError> {
        let (Some(path), Some(identity)) = (
            match limit.path.as_deref() {
                Some(pattern) => segments(pattern).as_deref().map(witness_path),
                None => Some("/".to_owned()),
            },
            witness_identity(&limit.principal),
        ) else {
            return Ok(false);
        };
        let principal = SyntheticPrincipal::Authenticated(identity);
        let alone = CompiledPolicy::for_analysis(Policy {
            rate_limits: vec![limit.clone()],
            ..empty_policy(self.policy)
        });
        let answer =
            alone.select_rate_lane(&rate_context(alone.snapshot(), method, &path, &principal));
        Ok(answered(answer)?.and_then(|selection| selection.matched()) == Some(0))
    }

    /// The policy's `egress` section: host patterns over a single label,
    /// CIDRs that admit loopback, link-local or private addresses, and
    /// ports other than the usual web ports. The section adds to the
    /// environment's egress controls, so each is judged by what it admits.
    fn egress_lints(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let egress = &policy.egress;
        for (index, pattern) in egress.hosts.iter().enumerate() {
            let Some(suffix) = pattern.strip_prefix("*.") else {
                continue;
            };
            // A suffix with a dot is a domain; one label is a top-level
            // domain or a bare internal name. Whether a longer suffix is a
            // public one is not knowable here, so it is not reported.
            if suffix.contains('.') {
                continue;
            }
            let witness = format!("{WITNESS_SEGMENT}.{suffix}");
            if !egress_pattern_admits(pattern, &witness)? {
                continue;
            }
            self.push(finding(
                FindingCode::EgressBroadWildcardHost,
                Severity::Medium,
                // Whether every name under the label is reachable, or
                // registrable by anyone, depends on DNS, not on the policy.
                ProofBasis::Heuristic,
                egress_ref("hosts", index),
            ));
        }
        for (index, cidr) in egress.cidrs.iter().enumerate() {
            // Validation refused a CIDR that does not parse.
            let Ok(cidr) = cidr.parse::<IpNet>() else {
                continue;
            };
            self.non_public_cidr(index, cidr)?;
        }
        for (index, port) in egress.ports.iter().enumerate() {
            if USUAL_EGRESS_PORTS.contains(port) {
                continue;
            }
            self.push(finding(
                FindingCode::EgressUnusualPort,
                Severity::Low,
                // Which ports are unusual depends on the upstreams.
                ProofBasis::Heuristic,
                egress_ref("ports", index),
            ));
        }
        Ok(())
    }

    /// The non-public ranges `cidr` overlaps, each confirmed by the static
    /// egress lane on one address: refused without the CIDR, admitted with
    /// it.
    fn non_public_cidr(&mut self, index: usize, cidr: IpNet) -> Result<(), AnalysisError> {
        let mut categories: Vec<&'static str> = Vec::new();
        let mut covers_whole_range = false;
        let mut confirmed = true;
        for (category, range) in NON_PUBLIC_RANGES {
            let Ok(range) = range.parse::<IpNet>() else {
                return Err(AnalysisError::Internal("non_public_range_invalid"));
            };
            let whole = cidr.contains(&range);
            if !whole && !range.contains(&cidr) {
                continue;
            }
            covers_whole_range |= whole && category == "private";
            if !categories.contains(&category) {
                categories.push(category);
            }
            let witness = if whole {
                range.hosts().next()
            } else {
                cidr.hosts().next()
            };
            confirmed &= match witness {
                Some(address) => egress_admits(&[cidr], address)? && !egress_admits(&[], address)?,
                None => false,
            };
        }
        if categories.is_empty() {
            return Ok(());
        }
        let exposes_host = categories.contains(&"loopback") || categories.contains(&"link_local");
        let mut finding = finding(
            FindingCode::EgressNonPublicCidr,
            if exposes_host {
                Severity::High
            } else if covers_whole_range {
                Severity::Medium
            } else {
                Severity::Low
            },
            ProofBasis::Proven,
            egress_ref("cidrs", index),
        );
        finding
            .details
            .insert("categories".to_owned(), json!(categories));
        finding
            .details
            .insert("covers_whole_range".to_owned(), json!(covers_whole_range));
        self.push(unconfirmed_unless(confirmed, finding));
        Ok(())
    }

    /// The cross-resource, lockout and egress-change checks a publication
    /// runs ([`validate_resources`]), as findings: the same checks over the
    /// same resources, the analyzed policy judged as the replacement of the
    /// active one. No publisher is named, so an analysis does not depend on
    /// who asks; a publication still checks its publisher. The risks those
    /// checks report are this analyzer's own findings already, and a tool
    /// rule the tool lane never reaches is [`Self::tool_policy_conflicts`]'.
    fn cross_resources(&mut self) -> Result<(), AnalysisError> {
        let validation = validate_resources(self.policy, self.active, self.resource_view, None);
        if !validation.snapshot().is_complete() {
            self.resources_unavailable = true;
        }
        for resource in validation.findings() {
            let diagnostic = &resource.diagnostic;
            let Some((code, severity, basis)) = resource_finding_code(diagnostic.code) else {
                continue;
            };
            let element = resource_element(
                self.policy,
                &diagnostic.pointer,
                diagnostic.element_id.clone(),
            )?;
            self.push(finding(code, severity, basis, element));
        }
        Ok(())
    }

    /// First-match conflicts short of full coverage: an earlier, less
    /// restrictive rule that decides some of the requests a later rule
    /// matches. A rule an earlier one fully covers is reported by
    /// [`Self::direct_rules`] and not again here.
    ///
    /// The overlap is shown by a witness request both rules match, built
    /// from their predicates; it is `proven` when the evaluator confirms that
    /// the later rule alone matches the witness and that an earlier, less
    /// restrictive rule decides it over the analyzed policy, and
    /// `inconclusive` otherwise.
    fn partial_overlaps(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let rules = policy.rules.as_slice();
        let patterns: Vec<Segments<'_>> = rules.iter().map(|rule| segments(&rule.path)).collect();
        for (position, rule) in rules.iter().enumerate() {
            if !is_http_rule(rule)
                || !unconditional(rule)
                || rule.action == RuleAction::Allow
                || self.covered_rules.contains(&position)
            {
                continue;
            }
            // The first earlier rule whose witness the evaluator confirms,
            // else the first one a witness could be built for.
            let mut overlap: Option<(usize, bool)> = None;
            for (earlier_position, earlier) in rules[..position].iter().enumerate() {
                if !is_http_rule(earlier)
                    || !unconditional(earlier)
                    || restrictiveness(&earlier.action) >= restrictiveness(&rule.action)
                {
                    continue;
                }
                if !self.spend() {
                    return Ok(());
                }
                let Some(witness) = overlap_witness(
                    earlier,
                    &patterns[earlier_position],
                    rule,
                    &patterns[position],
                ) else {
                    continue;
                };
                if let Some(decided_by) = self.confirm_partial(position, rule, &witness)? {
                    overlap = Some((decided_by, true));
                    break;
                }
                overlap.get_or_insert((earlier_position, false));
            }
            if let Some((related_position, confirmed)) = overlap {
                let related = &rules[related_position];
                let mut finding = finding(
                    FindingCode::RulePartiallyShadowed,
                    // A deny that does not block part of what it names is
                    // the exposure; a shadow only loses part of its telemetry.
                    if rule.action == RuleAction::Deny {
                        Severity::Medium
                    } else {
                        Severity::Low
                    },
                    ProofBasis::Proven,
                    rule_ref(position, rule),
                );
                finding.related = Some(rule_ref(related_position, related));
                finding
                    .details
                    .insert("action".to_owned(), json!(action_str(&rule.action)));
                finding.details.insert(
                    "preempting_action".to_owned(),
                    json!(action_str(&related.action)),
                );
                finding
                    .details
                    .insert("pre_empted_in".to_owned(), json!(PRE_EMPTED_IN));
                self.push(unconfirmed_unless(confirmed, finding));
            }
        }
        Ok(())
    }

    /// The earlier rule that decides `witness` over the analyzed policy,
    /// when `rule` alone matches it and that rule is earlier and less
    /// restrictive.
    fn confirm_partial(
        &self,
        position: usize,
        rule: &Rule,
        (request, principal): &(HttpRequest, SyntheticPrincipal),
    ) -> Result<Option<usize>, AnalysisError> {
        let alone = rule_alone(self.policy, rule);
        let own = alone.match_direct_rules(&http_context(alone.snapshot(), request, principal));
        let whole = self.compiled.match_direct_rules(&http_context(
            self.compiled.snapshot(),
            request,
            principal,
        ));
        Ok(match (answered(own)?, answered(whole)?) {
            (
                Some(DirectRuleOutcome::Matched { index: 0 }),
                Some(DirectRuleOutcome::Matched { index }),
            ) if index < position
                && self.policy.rules.get(index).is_some_and(|decider| {
                    restrictiveness(&decider.action) < restrictiveness(&rule.action)
                }) =>
            {
                Some(index)
            }
            _ => None,
        })
    }

    /// The MCP alias lane's own precedence, beyond reachability: direct
    /// rules decide an alias request by the most restrictive action anywhere
    /// in the rulebase, and routes by an exact prefix on the alias path
    /// first. Only the configured alias paths are read.
    fn mcp_alias_lane(&mut self) -> Result<(), AnalysisError> {
        let alias_paths = self.alias_paths;
        let mut aliases: Vec<&str> = alias_paths
            .iter()
            .map(String::as_str)
            .filter(|path| *path != MCP_RESOURCE_PATH)
            .collect();
        aliases.sort_unstable();
        aliases.dedup();
        if aliases.is_empty() {
            return Ok(());
        }
        self.alias_rule_overrides(&aliases)?;
        self.alias_route_precedence(&aliases)
    }

    /// An allow or shadow rule that is the first rule matching an alias
    /// request, which a later, more restrictive rule decides instead.
    fn alias_rule_overrides(&mut self, aliases: &[&str]) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let rules = policy.rules.as_slice();
        for (position, rule) in rules.iter().enumerate() {
            if !is_http_rule(rule)
                || !unconditional(rule)
                || rule.action == RuleAction::Deny
                || !reaches_alias_lane(rule)
                || self.covered_rules.contains(&position)
            {
                continue;
            }
            // The first later rule the evaluator confirms deciding an alias
            // request instead. Nothing is reported without that answer: a
            // witness an even earlier rule decides shows no surprise.
            let mut overridden = None;
            'aliases: for alias in aliases {
                if !matches_alias_identity(rule, alias) {
                    continue;
                }
                for later in rules.iter().skip(position + 1) {
                    if !is_http_rule(later)
                        || !unconditional(later)
                        || restrictiveness(&later.action) <= restrictiveness(&rule.action)
                        || !reaches_alias_lane(later)
                    {
                        continue;
                    }
                    if !self.spend() {
                        return Ok(());
                    }
                    if !matches_alias_identity(later, alias) {
                        continue;
                    }
                    let (Some(method), Some(principal)) = (
                        common_method(&rule.methods, &later.methods),
                        common_principal(&rule.principal, &later.principal),
                    ) else {
                        continue;
                    };
                    let request = HttpRequest {
                        method,
                        path: (*alias).to_owned(),
                        host: None,
                        target: SyntheticTarget::McpAlias {
                            canonical_path: MCP_RESOURCE_PATH.to_owned(),
                        },
                    };
                    if let Some(decided_by) =
                        self.confirm_alias_override(position, rule, &request, &principal)?
                    {
                        overridden = Some(decided_by);
                        break 'aliases;
                    }
                }
            }
            let Some(related_position) = overridden else {
                continue;
            };
            let related = &rules[related_position];
            let mut finding = finding(
                FindingCode::McpAliasRuleOverridden,
                // The alias is decided more restrictively than the first
                // matching rule says: never an exposure.
                Severity::Low,
                ProofBasis::Proven,
                rule_ref(position, rule),
            );
            finding.related = Some(rule_ref(related_position, related));
            finding
                .details
                .insert("action".to_owned(), json!(action_str(&rule.action)));
            finding.details.insert(
                "deciding_action".to_owned(),
                json!(action_str(&related.action)),
            );
            finding
                .details
                .insert("lane".to_owned(), json!(Lane::McpAlias.as_str()));
            self.push(finding);
        }
        Ok(())
    }

    /// The later, more restrictive rule that decides the alias `request`,
    /// when `rule` alone matches it and is also the first rule in source
    /// order that matches either of its identities.
    fn confirm_alias_override(
        &self,
        position: usize,
        rule: &Rule,
        request: &HttpRequest,
        principal: &SyntheticPrincipal,
    ) -> Result<Option<usize>, AnalysisError> {
        let alone = rule_alone(self.policy, rule);
        let own = alone.evaluate(&http_context(alone.snapshot(), request, principal));
        if answered(own)?.and_then(|evaluation| evaluation.matched())
            != Some(RuleReference::Direct(0))
        {
            return Ok(None);
        }
        // The first rule in source order matching either identity, read as
        // an ordinary request to each.
        let mut first = None;
        for path in [request.path.as_str(), MCP_RESOURCE_PATH] {
            let ordinary = HttpRequest {
                method: request.method.clone(),
                path: path.to_owned(),
                host: None,
                target: SyntheticTarget::Contextless,
            };
            let answer = self.compiled.match_direct_rules(&http_context(
                self.compiled.snapshot(),
                &ordinary,
                principal,
            ));
            if let Some(DirectRuleOutcome::Matched { index }) = answered(answer)? {
                first = Some(first.map_or(index, |first: usize| first.min(index)));
            }
        }
        if first != Some(position) {
            return Ok(None);
        }
        let whole =
            self.compiled
                .evaluate(&http_context(self.compiled.snapshot(), request, principal));
        Ok(
            match answered(whole)?.and_then(|evaluation| evaluation.matched()) {
                Some(RuleReference::Direct(index))
                    if index > position
                        && self.policy.rules.get(index).is_some_and(|decider| {
                            restrictiveness(&decider.action) > restrictiveness(&rule.action)
                        }) =>
                {
                    Some(index)
                }
                _ => None,
            },
        )
    }

    /// A route an alias request selects by its exact prefix, whose
    /// requirement admits a caller the route deciding the canonical MCP path
    /// refuses. Judged in the route lane, as route coverage is; unbound
    /// routes only, because an alias request names no virtual host.
    fn alias_route_precedence(&mut self, aliases: &[&str]) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let routes = policy.routes.as_slice();
        for alias in aliases {
            if !self.spend() {
                return Ok(());
            }
            let Some((position, route)) = routes
                .iter()
                .enumerate()
                .find(|(_, route)| route.path_prefix == *alias && route.hosts.is_empty())
            else {
                continue;
            };
            let Some(method) = witness_method(&route.methods) else {
                continue;
            };
            let Some((canonical_position, canonical)) =
                routes.iter().enumerate().find(|(_, candidate)| {
                    candidate.hosts.is_empty()
                        && method_matches(&candidate.methods, method.as_str())
                        && prefix_covers(&candidate.path_prefix, MCP_RESOURCE_PATH)
                })
            else {
                continue;
            };
            // Every caller the alias route admits, the canonical one admits
            // too: the alias is no weaker.
            if self.route_requirement_implies(route, canonical) {
                continue;
            }
            let Some(confirmed) =
                self.confirm_alias_route(position, canonical_position, alias, &method)?
            else {
                return Ok(());
            };
            let mut finding = finding(
                FindingCode::McpAliasRoutePrecedence,
                Severity::Medium,
                ProofBasis::Proven,
                route_ref(position, route),
            );
            finding.related = Some(route_ref(canonical_position, canonical));
            finding.details.insert(
                "permission_differs".to_owned(),
                json!(route.permission != canonical.permission),
            );
            finding.details.insert(
                "mode_differs".to_owned(),
                json!(self.route_mode(route) != self.route_mode(canonical)),
            );
            self.push(unconfirmed_unless(confirmed, finding));
        }
        Ok(())
    }

    /// A witness caller -- anonymous, or one holding a single role -- whom
    /// the route lane forwards at `alias` by the route at `position` and
    /// blocks at the canonical MCP path by the route at
    /// `canonical_position`. `None` when the comparison budget ran out
    /// before an answer.
    fn confirm_alias_route(
        &mut self,
        position: usize,
        canonical_position: usize,
        alias: &str,
        method: &Method,
    ) -> Result<Option<bool>, AnalysisError> {
        let policy = self.policy;
        let mut names: Vec<&String> = policy.roles.keys().collect();
        names.sort();
        let callers = std::iter::once(Some(SyntheticPrincipal::Anonymous)).chain(
            names
                .into_iter()
                .map(|name| role_holder(name, &policy.roles[name])),
        );
        for caller in callers {
            if !self.spend() {
                return Ok(None);
            }
            let Some(caller) = caller else {
                continue;
            };
            let routes_only = self.routes_only.get_or_insert_with(|| {
                CompiledPolicy::for_analysis(Policy {
                    rules: Vec::new(),
                    ..policy.clone()
                })
            });
            let alias_request = HttpRequest {
                method: method.clone(),
                path: alias.to_owned(),
                host: None,
                target: SyntheticTarget::McpAlias {
                    canonical_path: MCP_RESOURCE_PATH.to_owned(),
                },
            };
            let canonical_request = HttpRequest {
                method: method.clone(),
                path: MCP_RESOURCE_PATH.to_owned(),
                host: None,
                target: SyntheticTarget::Contextless,
            };
            let alias_answer = answered(routes_only.evaluate(&http_context(
                routes_only.snapshot(),
                &alias_request,
                &caller,
            )))?;
            let canonical_answer = answered(routes_only.evaluate(&http_context(
                routes_only.snapshot(),
                &canonical_request,
                &caller,
            )))?;
            let admitted_at_alias = alias_answer.is_some_and(|evaluation| {
                evaluation.matched() == Some(RuleReference::Route(position))
                    && evaluation.effect() != PolicyEffect::Block
            });
            let refused_at_canonical = canonical_answer.is_some_and(|evaluation| {
                evaluation.matched() == Some(RuleReference::Route(canonical_position))
                    && evaluation.effect() == PolicyEffect::Block
            });
            if admitted_at_alias && refused_at_canonical {
                return Ok(Some(true));
            }
        }
        Ok(Some(false))
    }

    /// Host qualification's exception: when a host-qualified virtual
    /// upstream is selected, direct rules decide by their denies alone and a
    /// host-bound route must authorize the request. An unbound allow or
    /// shadow that forwards a request addressed to a host-bound route's host
    /// does not forward it once that host's upstream is selected.
    fn selected_upstreams(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        let host_routes: Vec<(usize, &RouteRule, String)> = policy
            .routes
            .iter()
            .enumerate()
            .filter(|(_, route)| !route.hosts.is_empty())
            .filter_map(|(index, route)| {
                prefix_pattern(&route.path_prefix).map(|pattern| (index, route, pattern))
            })
            .collect();
        if host_routes.is_empty() {
            return Ok(());
        }
        for (position, rule) in policy.rules.iter().enumerate() {
            if !is_http_rule(rule)
                || !unconditional(rule)
                || rule.action == RuleAction::Deny
                || rule.dispatch.is_some()
                || self.covered_rules.contains(&position)
            {
                continue;
            }
            let rule_pattern = segments(&rule.path);
            for (route_position, route, route_pattern) in &host_routes {
                if !self.spend() {
                    return Ok(());
                }
                let (Some(method), Some(principal), Some(host)) = (
                    common_method(&rule.methods, &route.methods),
                    witness_principal(&rule.principal),
                    route.hosts.first(),
                ) else {
                    continue;
                };
                let Some(path) =
                    pattern_intersection(&rule_pattern, &segments(route_pattern), WITNESS_SEGMENT)
                        .map(|segments| joined_path(&segments))
                else {
                    continue;
                };
                // Reported only when the evaluator shows the difference: an
                // allow whose callers the host-bound route admits anyway
                // loses nothing when the upstream is selected.
                if !self.confirm_selected_upstream(position, &method, &path, host, &principal)? {
                    continue;
                }
                let mut finding = finding(
                    FindingCode::SelectedUpstreamAllowIgnored,
                    // The selected upstream is decided more strictly than the
                    // rule says: never an exposure.
                    Severity::Low,
                    ProofBasis::Proven,
                    rule_ref(position, rule),
                );
                finding.related = Some(route_ref(*route_position, route));
                finding
                    .details
                    .insert("action".to_owned(), json!(action_str(&rule.action)));
                finding
                    .details
                    .insert("lane".to_owned(), json!(Lane::SelectedUpstream.as_str()));
                self.push(finding);
                break;
            }
        }
        Ok(())
    }

    /// The rule at `position` decides and forwards the witness addressed to
    /// `host`, and the same witness is blocked once `host`'s virtual
    /// upstream is selected.
    fn confirm_selected_upstream(
        &self,
        position: usize,
        method: &Method,
        path: &str,
        host: &str,
        principal: &SyntheticPrincipal,
    ) -> Result<bool, AnalysisError> {
        let addressed = HttpRequest {
            method: method.clone(),
            path: path.to_owned(),
            host: Some(host.to_owned()),
            target: SyntheticTarget::Contextless,
        };
        let selected = HttpRequest {
            method: method.clone(),
            path: path.to_owned(),
            host: Some(host.to_owned()),
            target: SyntheticTarget::ProxyDispatch(DispatchFacts {
                route_id: Some(WITNESS_ROUTE_ID.to_owned()),
                route_host: Some(host.to_owned()),
                route_path_prefix: None,
                upstream_origin: WITNESS_ORIGIN.to_owned(),
            }),
        };
        let snapshot = self.compiled.snapshot();
        let forwarded = answered(
            self.compiled
                .evaluate(&http_context(snapshot, &addressed, principal)),
        )?
        .is_some_and(|evaluation| {
            evaluation.matched() == Some(RuleReference::Direct(position))
                && evaluation.effect() != PolicyEffect::Block
        });
        if !forwarded {
            return Ok(false);
        }
        Ok(answered(
            self.compiled
                .evaluate(&http_context(snapshot, &selected, principal)),
        )?
        .is_some_and(|evaluation| evaluation.effect() == PolicyEffect::Block))
    }

    /// The witness for `rule` matches the rule alone, and over the whole
    /// policy an earlier rule decides it in the first-match lane.
    fn confirm_rule(&self, position: usize, rule: &Rule) -> Result<bool, AnalysisError> {
        let Some((request, principal)) = http_rule_witness(rule) else {
            return Ok(false);
        };
        let alone = rule_alone(self.policy, rule);
        let own = alone.match_direct_rules(&http_context(alone.snapshot(), &request, &principal));
        let whole = self.compiled.match_direct_rules(&http_context(
            self.compiled.snapshot(),
            &request,
            &principal,
        ));
        Ok(match (answered(own)?, answered(whole)?) {
            (
                Some(DirectRuleOutcome::Matched { index: 0 }),
                Some(DirectRuleOutcome::Matched { index }),
            ) => index < position,
            _ => false,
        })
    }

    fn confirm_tool_rule(
        &self,
        position: usize,
        rule: &Rule,
        tool_name: &str,
    ) -> Result<bool, AnalysisError> {
        let Some(principal) = witness_principal(&rule.principal) else {
            return Ok(false);
        };
        let principal = principal_fact(principal);
        let alone = rule_alone(self.policy, rule);
        let own = alone.match_tool_rules(tool_name, &principal);
        let whole = self.compiled.match_tool_rules(tool_name, &principal);
        Ok(match (answered(own)?, answered(whole)?) {
            (
                Some(DirectRuleOutcome::Matched { index: 0 }),
                Some(DirectRuleOutcome::Matched { index }),
            ) => index < position,
            _ => false,
        })
    }

    /// The witness for `route` selects the route alone, and the route lane of
    /// the analyzed policy -- the policy without its direct rules -- selects
    /// an earlier route for it.
    fn confirm_route_decided_earlier(
        &mut self,
        position: usize,
        route: &RouteRule,
    ) -> Result<bool, AnalysisError> {
        let Some(request) = route_witness(route) else {
            return Ok(false);
        };
        if !route_alone_selects(self.policy, route, &request)? {
            return Ok(false);
        }
        let policy = self.policy;
        let routes_only = self.routes_only.get_or_insert_with(|| {
            CompiledPolicy::for_analysis(Policy {
                rules: Vec::new(),
                ..policy.clone()
            })
        });
        let answer = routes_only.evaluate(&http_context(
            routes_only.snapshot(),
            &request,
            &SyntheticPrincipal::Anonymous,
        ));
        Ok(matches!(
            answered(answer)?.and_then(|evaluation| evaluation.matched()),
            Some(RuleReference::Route(index)) if index < position
        ))
    }

    /// The witness for `route` selects the route alone, and over the whole
    /// policy a direct rule decides it.
    fn confirm_route_decided_by_rule(&self, route: &RouteRule) -> Result<bool, AnalysisError> {
        let Some(request) = route_witness(route) else {
            return Ok(false);
        };
        if !route_alone_selects(self.policy, route, &request)? {
            return Ok(false);
        }
        let answer = self.compiled.evaluate(&http_context(
            self.compiled.snapshot(),
            &request,
            &SyntheticPrincipal::Anonymous,
        ));
        Ok(matches!(
            answered(answer)?.and_then(|evaluation| evaluation.matched()),
            Some(RuleReference::Direct(_))
        ))
    }

    /// The witness for `limit` selects the override alone, and over the whole
    /// policy an earlier override is selected for it.
    fn confirm_rate(&self, position: usize, limit: &RateLimitRule) -> Result<bool, AnalysisError> {
        let (Some(method), Some(path), Some(identity)) = (
            witness_method(&limit.methods),
            match limit.path.as_deref() {
                Some(pattern) => segments(pattern).as_deref().map(witness_path),
                None => Some("/".to_owned()),
            },
            witness_identity(&limit.principal),
        ) else {
            return Ok(false);
        };
        // The rate lane never selects for an anonymous caller.
        let principal = SyntheticPrincipal::Authenticated(identity);
        let alone = CompiledPolicy::for_analysis(Policy {
            rate_limits: vec![limit.clone()],
            ..empty_policy(self.policy)
        });
        let own =
            alone.select_rate_lane(&rate_context(alone.snapshot(), &method, &path, &principal));
        let whole = self.compiled.select_rate_lane(&rate_context(
            self.compiled.snapshot(),
            &method,
            &path,
            &principal,
        ));
        Ok(
            match (
                answered(own)?.and_then(|selection| selection.matched()),
                answered(whole)?.and_then(|selection| selection.matched()),
            ) {
                (Some(0), Some(index)) => index < position,
                _ => false,
            },
        )
    }
}

/// A broad rule's witnesses: the root and a deep path, for an anonymous
/// caller, each matched by the rule alone.
fn confirm_broad(policy: &Policy, rule: &Rule) -> Result<bool, AnalysisError> {
    let (Some(method), Some(principal)) = (
        witness_method(&rule.methods),
        witness_principal(&rule.principal),
    ) else {
        return Ok(false);
    };
    let alone = rule_alone(policy, rule);
    for path in ["/", WITNESS_DEEP_PATH] {
        let request = HttpRequest {
            method: method.clone(),
            path: path.to_owned(),
            host: None,
            target: SyntheticTarget::Contextless,
        };
        let answer =
            alone.match_direct_rules(&http_context(alone.snapshot(), &request, &principal));
        if answered(answer)? != Some(DirectRuleOutcome::Matched { index: 0 }) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// An every-method rule's witnesses: an anonymous request with a safe and
/// an unsafe method to its witness path, each matched by the rule alone.
fn confirm_all_methods(policy: &Policy, rule: &Rule) -> Result<bool, AnalysisError> {
    let Some(path) = segments(&rule.path).as_deref().map(witness_path) else {
        return Ok(false);
    };
    let alone = rule_alone(policy, rule);
    for method in [Method::GET, Method::DELETE] {
        let request = HttpRequest {
            method,
            path: path.clone(),
            host: None,
            target: SyntheticTarget::Contextless,
        };
        let answer = alone.match_direct_rules(&http_context(
            alone.snapshot(),
            &request,
            &SyntheticPrincipal::Anonymous,
        ));
        if answered(answer)? != Some(DirectRuleOutcome::Matched { index: 0 }) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A request both HTTP rules match, from a caller both accept, or `None`
/// when their methods, callers, dispatch bindings or paths share nothing
/// the analyzer can build.
fn overlap_witness(
    left: &Rule,
    left_path: &Segments<'_>,
    right: &Rule,
    right_path: &Segments<'_>,
) -> Option<(HttpRequest, SyntheticPrincipal)> {
    let target = if dispatch_covers(left.dispatch.as_ref(), right.dispatch.as_ref()) {
        witness_target(right.dispatch.as_ref())?
    } else if dispatch_covers(right.dispatch.as_ref(), left.dispatch.as_ref()) {
        witness_target(left.dispatch.as_ref())?
    } else {
        return None;
    };
    let path = pattern_intersection(left_path, right_path, WITNESS_SEGMENT)?;
    let request = HttpRequest {
        method: common_method(&left.methods, &right.methods)?,
        path: joined_path(&path),
        host: None,
        target,
    };
    Some((
        request,
        common_principal(&left.principal, &right.principal)?,
    ))
}

/// An absolute path from its segments.
fn joined_path(segments: &[&str]) -> String {
    if segments.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// A method both lists match, as the matcher reads them.
fn common_method(left: &[String], right: &[String]) -> Option<Method> {
    match (matches_every_method(left), matches_every_method(right)) {
        (true, true) => Some(Method::GET),
        (true, false) => witness_method(right),
        (false, true) => witness_method(left),
        (false, false) => left
            .iter()
            .map(|method| method.trim().to_ascii_uppercase())
            .find(|method| method_matches(right, method))
            .and_then(|method| Method::from_bytes(method.as_bytes()).ok()),
    }
}

/// A caller both principal matchers accept: anonymous when neither
/// constrains the caller; otherwise one carrying, for each field either
/// constrains, a value both admit -- and one role from each side, since a
/// role constraint is satisfied by holding any role it names. `None` when
/// two constrained fields share no value.
fn common_principal(
    left: &PrincipalMatcher,
    right: &PrincipalMatcher,
) -> Option<SyntheticPrincipal> {
    if left.is_unconstrained() && right.is_unconstrained() {
        return Some(SyntheticPrincipal::Anonymous);
    }
    // `None` for no common value; `Some(None)` when neither side constrains.
    let shared = |left: &[String], right: &[String]| -> Option<Option<String>> {
        match (left.first(), right.first()) {
            (None, None) => Some(None),
            (Some(value), None) | (None, Some(value)) => Some(Some(value.clone())),
            (Some(_), Some(_)) => left
                .iter()
                .find(|&value| right.contains(value))
                .map(|value| Some(value.clone())),
        }
    };
    let issuer = shared(&left.issuers, &right.issuers)?;
    let auth_method = match shared(&left.auth_methods, &right.auth_methods)? {
        None => AuthMethod::Bearer,
        Some(code) => auth_method_from_code(&code)?,
    };
    let user_id = shared(&left.principal_ids, &right.principal_ids)?
        .unwrap_or_else(|| WITNESS_SUBJECT.to_owned());
    let mut roles: Vec<String> = Vec::new();
    for role in [left.roles.first(), right.roles.first()]
        .into_iter()
        .flatten()
    {
        if !roles.contains(role) {
            roles.push(role.clone());
        }
    }
    Some(SyntheticPrincipal::Authenticated(Principal {
        user_id,
        issuer,
        email: None,
        org_id: None,
        roles,
        session_id: String::new(),
        auth_method,
    }))
}

/// A caller claiming `role` from an issuer no role is bound to, with the
/// authentication method and id the grant names, if any.
fn foreign_issuer_caller(
    role: &str,
    auth_method: Option<&String>,
    principal_id: Option<&String>,
) -> Option<SyntheticPrincipal> {
    let auth_method = match auth_method {
        None => AuthMethod::Bearer,
        Some(code) => auth_method_from_code(code)?,
    };
    Some(SyntheticPrincipal::Authenticated(Principal {
        user_id: principal_id
            .cloned()
            .unwrap_or_else(|| WITNESS_SUBJECT.to_owned()),
        issuer: Some(WITNESS_ISSUER.to_owned()),
        email: None,
        org_id: None,
        roles: vec![role.to_owned()],
        session_id: String::new(),
        auth_method,
    }))
}

/// A caller holding `name` alone, from the first issuer and authentication
/// method the role admits, so the role is active for it.
fn role_holder(name: &str, role: &crate::rbac::policy::RoleEntry) -> Option<SyntheticPrincipal> {
    let auth_method = match role.auth_methods.first() {
        None => AuthMethod::Bearer,
        Some(code) => auth_method_from_code(code)?,
    };
    Some(SyntheticPrincipal::Authenticated(Principal {
        user_id: WITNESS_SUBJECT.to_owned(),
        issuer: role.issuers.first().cloned(),
        email: None,
        org_id: None,
        roles: vec![name.to_owned()],
        session_id: String::new(),
        auth_method,
    }))
}

/// Two constrained value lists with nothing in common. A principal carries
/// one issuer and one authentication method, so two such constraints with
/// no shared value admit no caller together.
fn disjoint(left: &[String], right: &[String]) -> bool {
    !left.is_empty() && !right.is_empty() && !left.iter().any(|value| right.contains(value))
}

/// A tool lane reason that refuses an invocation before any tool-name rule
/// is read.
fn refused_by_admission(reason: ToolReason) -> bool {
    matches!(
        reason,
        ToolReason::UnknownTool | ToolReason::Disabled | ToolReason::RoleNotAllowed
    )
}

/// Whether a rule can match a request in the MCP alias lane, which judges
/// dispatch bindings as a contextless request does.
fn reaches_alias_lane(rule: &Rule) -> bool {
    rule.dispatch
        .as_ref()
        .is_none_or(|dispatch| dispatch.kind == RuleDispatchKind::Contextless)
}

/// Whether a rule's path pattern matches either identity of an alias
/// request: the alias path, or the canonical MCP path. A filter only: the
/// evaluator decides the witness.
fn matches_alias_identity(rule: &Rule, alias: &str) -> bool {
    path_pattern_matches(&rule.path, alias) || path_pattern_matches(&rule.path, MCP_RESOURCE_PATH)
}

/// The global lanes a method list is charged in, each with a method that
/// is: `GET` for the read lane, and the first other listed method, or
/// `POST`, for the write lane.
fn charged_lanes(methods: &[String]) -> Vec<(&'static str, Method)> {
    if matches_every_method(methods) {
        return vec![("read", Method::GET), ("write", Method::POST)];
    }
    let mut read = None;
    let mut write = None;
    for method in methods {
        let Ok(method) = Method::from_bytes(method.trim().to_ascii_uppercase().as_bytes()) else {
            continue;
        };
        if matches!(method, Method::GET | Method::HEAD) {
            read.get_or_insert(method);
        } else {
            write.get_or_insert(method);
        }
    }
    read.map(|method| ("read", method))
        .into_iter()
        .chain(write.map(|method| ("write", method)))
        .collect()
}

/// The static egress lane with `controls`, asked about the witness
/// destination resolved to `address`.
fn egress_outcome(
    controls: EgressControls,
    address: IpAddr,
) -> Result<EgressOutcome, AnalysisError> {
    let lane = CompiledEgressPolicy::new(controls);
    let url = Url::parse(&format!("https://{WITNESS_EGRESS_HOST}/"))
        .map_err(|_| AnalysisError::Internal("egress_witness_invalid"))?;
    let destination = EgressDestination::from_url(&url);
    let answers = [SocketAddr::new(address, WITNESS_EGRESS_PORT)];
    lane.evaluate(&EgressEvaluationContext {
        version: EGRESS_CONTEXT_VERSION,
        snapshot: lane.snapshot(),
        destination: &destination,
        resolution: ResolutionFact::Resolved(&answers),
    })
    .map(|evaluation| evaluation.outcome())
    .map_err(|_| AnalysisError::Internal("evaluator_refused_analysis"))
}

/// Controls admitting the witness host on every port, refusing non-global
/// addresses outside `cidrs`, as `EGRESS_DENY_PRIVATE_IPS=true` does.
fn witness_egress_controls(cidrs: &[IpNet]) -> EgressControls {
    EgressControls {
        allowed_hosts: HashSet::from([WITNESS_EGRESS_HOST.to_owned()]),
        allowed_host_globs: Vec::new(),
        allowed_ports: HashSet::new(),
        deny_private_ips: true,
        nat64_prefixes: Vec::new(),
        private_ip_allow_cidrs: cidrs.to_vec(),
    }
}

/// Whether the static egress lane, refusing non-global addresses outside
/// `cidrs`, connects to `address`.
fn egress_admits(cidrs: &[IpNet], address: IpAddr) -> Result<bool, AnalysisError> {
    Ok(matches!(
        egress_outcome(witness_egress_controls(cidrs), address)?,
        EgressOutcome::Allow { .. }
    ))
}

/// Whether the static egress lane with `pattern` as its only host entry
/// admits `host` before resolution.
fn egress_pattern_admits(pattern: &str, host: &str) -> Result<bool, AnalysisError> {
    let lane = CompiledEgressPolicy::new(EgressControls {
        allowed_hosts: HashSet::new(),
        allowed_host_globs: vec![pattern.to_owned()],
        allowed_ports: HashSet::new(),
        deny_private_ips: true,
        nat64_prefixes: Vec::new(),
        private_ip_allow_cidrs: Vec::new(),
    });
    let Ok(url) = Url::parse(&format!("https://{host}/")) else {
        return Ok(false);
    };
    let destination = EgressDestination::from_url(&url);
    let evaluation = lane
        .evaluate(&EgressEvaluationContext {
            version: EGRESS_CONTEXT_VERSION,
            snapshot: lane.snapshot(),
            destination: &destination,
            resolution: ResolutionFact::Missing,
        })
        .map_err(|_| AnalysisError::Internal("evaluator_refused_analysis"))?;
    // Admitted by every static check, and waiting only for addresses.
    Ok(matches!(
        evaluation.outcome(),
        EgressOutcome::Indeterminate(_)
    ))
}

/// One member of the `egress` section: `/egress/<list>/<index>`.
fn egress_ref(list: &str, index: usize) -> ElementRef {
    ElementRef {
        section: Section::Egress,
        pointer: format!("/egress/{list}/{index}"),
        position: None,
        id: None,
        name: None,
        member: Some(format!("/{list}/{index}")),
    }
}

/// The finding a cross-resource check's issue code reports, with its
/// severity and proof basis, or `None` for an issue this analyzer reports
/// through a check of its own (or, for `resource_unavailable`, as a
/// limitation).
fn resource_finding_code(code: &str) -> Option<(FindingCode, Severity, ProofBasis)> {
    [
        (
            IssueCode::PolicyWriteUnreachable,
            FindingCode::PolicyWriteUnreachable,
            Severity::High,
            // Likely, not certain: a standalone policy file can still be
            // edited, and a principal may write through another path.
            ProofBasis::Heuristic,
        ),
        (
            IssueCode::EgressChangeRequiresRestart,
            FindingCode::EgressChangeRequiresRestart,
            Severity::Medium,
            ProofBasis::Proven,
        ),
        (
            IssueCode::RoleNotDefined,
            FindingCode::RoleNotDefined,
            Severity::Low,
            // A rule matches a claimed role whether or not it is defined.
            ProofBasis::Heuristic,
        ),
        (
            IssueCode::RoutePermissionUngranted,
            FindingCode::RoutePermissionUngranted,
            Severity::Low,
            // A route no caller passes may be a deliberate lock.
            ProofBasis::Heuristic,
        ),
        (
            IssueCode::ToolNotRegistered,
            FindingCode::ToolNotRegistered,
            Severity::Low,
            ProofBasis::Heuristic,
        ),
        (
            IssueCode::ConnectionEndpointEgressDenied,
            FindingCode::ConnectionEndpointEgressDenied,
            Severity::Medium,
            // Judged without resolution facts, as publication judges it.
            ProofBasis::Heuristic,
        ),
        (
            IssueCode::NameCaseCollision,
            FindingCode::NameCaseCollision,
            Severity::Low,
            ProofBasis::Heuristic,
        ),
    ]
    .into_iter()
    .find(|(issue, ..)| issue.as_str() == code)
    .map(|(_, finding, severity, basis)| (finding, severity, basis))
}

/// The element a cross-resource diagnostic's pointer names in `policy`:
/// a rule, route or rate override by position, a role or tool by name, or
/// a section, with the rest of the pointer as the member. A pointer this
/// analyzer cannot place fails the analysis rather than being dropped.
fn resource_element(
    policy: &Policy,
    pointer: &str,
    diagnostic_id: Option<String>,
) -> Result<ElementRef, AnalysisError> {
    let unplaced = AnalysisError::Internal("resource_finding_unplaced");
    let mut tokens = pointer.split('/').skip(1);
    let section = match tokens.next() {
        Some("rules") => Section::Rules,
        Some("routes") => Section::Routes,
        Some("rate_limits") => Section::RateLimits,
        Some("roles") => Section::Roles,
        Some("tools") => Section::Tools,
        Some("egress") => Section::Egress,
        Some("identity_mappings") => Section::IdentityMappings,
        _ => return Err(unplaced),
    };
    let (prefix_len, position, name) = match (section, tokens.next()) {
        (Section::Rules | Section::Routes | Section::RateLimits, Some(index)) => {
            let position: usize = index.parse().map_err(|_| unplaced)?;
            let len = section.as_str().len() + index.len() + 2;
            (len, Some(position), None)
        }
        (Section::Roles | Section::Tools, Some(token)) => {
            let len = section.as_str().len() + token.len() + 2;
            (len, None, Some(token.replace("~1", "/").replace("~0", "~")))
        }
        _ => (section.as_str().len() + 1, None, None),
    };
    let Some(member) = pointer.get(prefix_len.min(pointer.len())..) else {
        return Err(unplaced);
    };
    let member = (!member.is_empty()).then_some(member);
    // The element's own id, as every other finding names it; the
    // diagnostic's when the element is not one with an id.
    let id = match (section, position) {
        (Section::Rules, Some(position)) => policy
            .rules
            .get(position)
            .and_then(|rule| element_id(rule.id.as_deref())),
        (Section::Routes, Some(position)) => policy
            .routes
            .get(position)
            .and_then(|route| element_id(route.id.as_deref())),
        (Section::RateLimits, Some(position)) => policy
            .rate_limits
            .get(position)
            .and_then(|limit| element_id(limit.id.as_deref())),
        _ => None,
    }
    .or(diagnostic_id);
    Ok(ElementRef {
        section,
        pointer: pointer.to_owned(),
        position,
        id,
        name,
        member: member.map(str::to_owned),
    })
}

fn route_alone_selects(
    policy: &Policy,
    route: &RouteRule,
    request: &HttpRequest,
) -> Result<bool, AnalysisError> {
    let alone = CompiledPolicy::for_analysis(Policy {
        routes: vec![route.clone()],
        ..empty_policy(policy)
    });
    let answer = alone.evaluate(&http_context(
        alone.snapshot(),
        request,
        &SyntheticPrincipal::Anonymous,
    ));
    Ok(matches!(
        answered(answer)?.and_then(|evaluation| evaluation.matched()),
        Some(RuleReference::Route(0))
    ))
}

/// `rule` compiled alone, under the analyzed policy's roles and identity
/// mappings, so it reads a witness's caller as the analyzed policy does.
fn rule_alone(policy: &Policy, rule: &Rule) -> CompiledPolicy {
    CompiledPolicy::for_analysis(Policy {
        rules: vec![rule.clone()],
        ..empty_policy(policy)
    })
}

/// A policy at the analyzed one's schema version, with its roles and identity
/// mappings and no other element, for compiling one element alone. The
/// mappings decide which internal roles a caller holds, so an element alone
/// must be read under the same ones.
fn empty_policy(policy: &Policy) -> Policy {
    Policy {
        schema_version: policy.schema_version.clone(),
        id: None,
        default_action: DefaultAction::Deny,
        enforcement_mode: EnforcementMode::Enforce,
        roles: policy.roles.clone(),
        identity_mappings: policy.identity_mappings.clone(),
        routes: Vec::new(),
        rules: Vec::new(),
        egress: EgressPolicy::default(),
        rate_limits: Vec::new(),
        tools: HashMap::new(),
    }
}

/// An evaluator answer, `None` when the evaluator refused the witness's
/// facts -- an unconfirmed claim, not a failure -- and an error for any
/// other refusal, which means the analyzer asked a malformed question.
fn answered<T>(answer: Result<T, EvaluationError>) -> Result<Option<T>, AnalysisError> {
    match answer {
        Ok(answer) => Ok(Some(answer)),
        Err(error) if error.rejects_supplied_facts() => Ok(None),
        Err(_) => Err(AnalysisError::Internal("evaluator_refused_analysis")),
    }
}

/// `finding` as reported: unchanged when its witness confirmed it, and
/// otherwise inconclusive, without a patch, saying why.
fn unconfirmed_unless(confirmed: bool, mut finding: Finding) -> Finding {
    if !confirmed {
        finding.proof_basis = ProofBasis::Inconclusive;
        finding.patch = None;
        finding.limitations.push("witness_unconfirmed");
    }
    finding
}

fn unreachable_rule(
    position: usize,
    rule: &Rule,
    earlier_position: usize,
    earlier: &Rule,
    duplicate: bool,
    lanes: &[Lane],
) -> Finding {
    let mut finding = finding(
        FindingCode::RuleUnreachable,
        // A later allow or shadow under an earlier deny is an exception that
        // never applies: narrower than written, and worth a look.
        if earlier.action == rule.action {
            Severity::Low
        } else {
            Severity::Medium
        },
        ProofBasis::Proven,
        rule_ref(position, rule),
    );
    finding.related = Some(rule_ref(earlier_position, earlier));
    finding.never_decides_in = lanes.to_vec();
    finding.details.insert(
        "relation".to_owned(),
        json!(if duplicate { "duplicate" } else { "covered" }),
    );
    finding
        .details
        .insert("action".to_owned(), json!(action_str(&rule.action)));
    finding.details.insert(
        "covering_action".to_owned(),
        json!(action_str(&earlier.action)),
    );
    finding.patch = delete_edit(&finding.element).map(|edit| CandidatePatch {
        access_effect: AccessEffect::Equivalent,
        edits: vec![edit],
    });
    finding
}

fn shadowed_rule(
    position: usize,
    rule: &Rule,
    earlier_position: usize,
    earlier: &Rule,
    never_decides_in: &[Lane],
    may_decide_in: &[Lane],
) -> Finding {
    let mut finding = finding(
        FindingCode::RuleShadowed,
        // A deny that does not block is the exposure; a shadow that does
        // not observe only loses telemetry.
        if rule.action == RuleAction::Deny {
            Severity::High
        } else {
            Severity::Low
        },
        ProofBasis::Proven,
        rule_ref(position, rule),
    );
    finding.related = Some(rule_ref(earlier_position, earlier));
    finding.never_decides_in = never_decides_in.to_vec();
    finding.may_decide_in = may_decide_in.to_vec();
    finding
        .details
        .insert("action".to_owned(), json!(action_str(&rule.action)));
    finding.details.insert(
        "covering_action".to_owned(),
        json!(action_str(&earlier.action)),
    );
    // Moved before the earliest less restrictive rule covering it, the rule
    // decides whatever no rule before that one matches, with a more
    // restrictive action than the one that decided it; everything else
    // keeps its deciding rule.
    finding.patch = Some(CandidatePatch {
        access_effect: AccessEffect::Narrowing,
        edits: vec![move_edit(&finding.element, position, earlier_position)],
    });
    finding
}

fn finding(
    code: FindingCode,
    severity: Severity,
    proof_basis: ProofBasis,
    element: ElementRef,
) -> Finding {
    Finding {
        code,
        severity,
        proof_basis,
        element,
        related: None,
        never_decides_in: Vec::new(),
        may_decide_in: Vec::new(),
        details: Map::new(),
        patch: None,
        limitations: Vec::new(),
    }
}

fn sort_key(finding: &Finding) -> (Severity, Section, Option<usize>, Option<&str>) {
    (
        finding.severity,
        finding.element.section,
        finding.element.position,
        finding.element.name.as_deref(),
    )
}

/// An enabled rule that matches HTTP requests rather than tool names.
fn is_http_rule(rule: &Rule) -> bool {
    rule.enabled && rule.tool_name.is_none()
}

/// A rule without typed conditions. A conditioned rule matches only the
/// requests its conditions accept, which no predicate comparison here can
/// bound, so it never covers another element and is never broad. As the
/// covered side it needs no such care: its conditions only narrow it.
fn unconditional(rule: &Rule) -> bool {
    rule.conditions.is_none()
}

fn restrictiveness(action: &RuleAction) -> u8 {
    match action {
        RuleAction::Allow => 0,
        RuleAction::Shadow => 1,
        RuleAction::Deny => 2,
    }
}

fn action_str(action: &RuleAction) -> &'static str {
    match action {
        RuleAction::Allow => "allow",
        RuleAction::Shadow => "shadow",
        RuleAction::Deny => "deny",
    }
}

/// Whether `covering` matches every HTTP request `covered` matches: no
/// conditions, then method, principal, dispatch binding and path, cheapest
/// first.
fn http_rule_covers(
    covering: &Rule,
    covering_path: &Segments<'_>,
    covered: &Rule,
    covered_path: &Segments<'_>,
) -> bool {
    unconditional(covering)
        && methods_cover(&covering.methods, &covered.methods)
        && principal_covers(&covering.principal, &covered.principal)
        && dispatch_covers(covering.dispatch.as_ref(), covered.dispatch.as_ref())
        && pattern_covers(covering_path, covered_path)
}

fn route_covers(covering: &RouteRule, covered: &RouteRule) -> bool {
    methods_cover(&covering.methods, &covered.methods)
        && hosts_cover(&covering.hosts, &covered.hosts)
        && prefix_covers(&covering.path_prefix, &covered.path_prefix)
}

fn rate_covers(
    covering: &RateLimitRule,
    covering_path: &Segments<'_>,
    covered: &RateLimitRule,
    covered_path: &Segments<'_>,
) -> bool {
    principal_covers(&covering.principal, &covered.principal)
        && methods_cover(&covering.methods, &covered.methods)
        && match (&covering.path, &covered.path) {
            (None, _) => true,
            (Some(_), None) => matches_every_path(covering_path),
            (Some(_), Some(_)) => pattern_covers(covering_path, covered_path),
        }
}

fn element_id(id: Option<&str>) -> Option<String> {
    id.filter(|id| is_valid_element_id(id)).map(str::to_owned)
}

fn rule_ref(position: usize, rule: &Rule) -> ElementRef {
    ElementRef {
        section: Section::Rules,
        pointer: format!("/rules/{position}"),
        position: Some(position),
        id: element_id(rule.id.as_deref()),
        name: None,
        member: None,
    }
}

fn route_ref(position: usize, route: &RouteRule) -> ElementRef {
    ElementRef {
        section: Section::Routes,
        pointer: format!("/routes/{position}"),
        position: Some(position),
        id: element_id(route.id.as_deref()),
        name: None,
        member: None,
    }
}

fn rate_ref(position: usize, limit: &RateLimitRule) -> ElementRef {
    ElementRef {
        section: Section::RateLimits,
        pointer: format!("/rate_limits/{position}"),
        position: Some(position),
        id: element_id(limit.id.as_deref()),
        name: None,
        member: None,
    }
}

fn scalar_ref(section: Section) -> ElementRef {
    ElementRef {
        section,
        pointer: format!("/{}", section.as_str()),
        position: None,
        id: None,
        name: None,
        member: None,
    }
}

/// `delete` the element at its position, naming its id when it has one.
fn delete_edit(element: &ElementRef) -> Option<Value> {
    let position = element.position?;
    let mut edit = json!({
        "op": "delete",
        "section": element.section.as_str(),
        "position": position,
    });
    if let (Some(id), Some(edit)) = (&element.id, edit.as_object_mut()) {
        edit.insert("expect_id".to_owned(), json!(id));
    }
    Some(edit)
}

/// `move` the element from `from` to `to`, naming its id when it has one.
fn move_edit(element: &ElementRef, from: usize, to: usize) -> Value {
    let mut edit = json!({
        "op": "move",
        "section": element.section.as_str(),
        "from": from,
        "to": to,
    });
    if let (Some(id), Some(edit)) = (&element.id, edit.as_object_mut()) {
        edit.insert("expect_id".to_owned(), json!(id));
    }
    edit
}

fn set_edit(field: &str, value: &str) -> Value {
    json!({ "op": "set", "field": field, "value": value })
}

/// A method the list matches.
fn witness_method(methods: &[String]) -> Option<Method> {
    if matches_every_method(methods) {
        return Some(Method::GET);
    }
    methods
        .iter()
        .find_map(|method| Method::from_bytes(method.trim().as_bytes()).ok())
}

/// A path the pattern matches: each literal as written, one non-empty
/// segment for each single wildcard or capture, nothing for a deep wildcard.
fn witness_path(pattern: &[PatternSegment<'_>]) -> String {
    let mut path = String::new();
    for segment in pattern {
        match segment {
            PatternSegment::Literal(literal) => {
                path.push('/');
                path.push_str(literal);
            }
            PatternSegment::One => {
                path.push('/');
                path.push_str(WITNESS_SEGMENT);
            }
            PatternSegment::Any | PatternSegment::Never => {}
        }
    }
    if path.is_empty() {
        path.push('/');
    }
    path
}

/// A caller the matcher accepts: anonymous when it accepts every caller,
/// otherwise one carrying the first value of each constrained field.
fn witness_principal(matcher: &PrincipalMatcher) -> Option<SyntheticPrincipal> {
    if matcher.is_unconstrained() {
        return Some(SyntheticPrincipal::Anonymous);
    }
    witness_identity(matcher).map(SyntheticPrincipal::Authenticated)
}

/// An authenticated caller the matcher accepts, or `None` when it names an
/// authentication method no caller can have.
fn witness_identity(matcher: &PrincipalMatcher) -> Option<Principal> {
    let auth_method = match matcher.auth_methods.first() {
        None => AuthMethod::Bearer,
        Some(name) => auth_method_from_code(name)?,
    };
    Some(Principal {
        user_id: matcher
            .principal_ids
            .first()
            .cloned()
            .unwrap_or_else(|| WITNESS_SUBJECT.to_owned()),
        issuer: matcher.issuers.first().cloned(),
        email: None,
        org_id: None,
        roles: matcher.roles.first().cloned().into_iter().collect(),
        session_id: String::new(),
        auth_method,
    })
}

fn principal_fact(principal: SyntheticPrincipal) -> PrincipalFact {
    principal_fact_of(&principal)
}

fn principal_fact_of(principal: &SyntheticPrincipal) -> PrincipalFact {
    match principal {
        SyntheticPrincipal::Anonymous => PrincipalFact::Anonymous,
        SyntheticPrincipal::Authenticated(principal) => {
            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
        }
    }
}

/// The dispatch a rule binding matches: none for an unbound or contextless
/// rule, the normalized legacy origin, or the bound route id without a host,
/// so no virtual upstream is selected.
fn witness_target(dispatch: Option<&RuleDispatchMatcher>) -> Option<SyntheticTarget> {
    let Some(dispatch) = dispatch else {
        return Some(SyntheticTarget::Contextless);
    };
    match dispatch.kind {
        RuleDispatchKind::Contextless => Some(SyntheticTarget::Contextless),
        RuleDispatchKind::Legacy => {
            let origin = Url::parse(dispatch.upstream_origin.as_deref()?).ok()?;
            Some(SyntheticTarget::ProxyDispatch(DispatchFacts {
                route_id: None,
                route_host: None,
                route_path_prefix: None,
                upstream_origin: origin.origin().ascii_serialization(),
            }))
        }
        RuleDispatchKind::Route => Some(SyntheticTarget::ProxyDispatch(DispatchFacts {
            route_id: Some(dispatch.route_id.clone()?),
            route_host: None,
            route_path_prefix: None,
            upstream_origin: WITNESS_ORIGIN.to_owned(),
        })),
    }
}

/// A request the rule alone matches, from the caller its matcher accepts.
fn http_rule_witness(rule: &Rule) -> Option<(HttpRequest, SyntheticPrincipal)> {
    let request = HttpRequest {
        method: witness_method(&rule.methods)?,
        path: witness_path(segments(&rule.path).as_deref()?),
        host: None,
        target: witness_target(rule.dispatch.as_ref())?,
    };
    Some((request, witness_principal(&rule.principal)?))
}

/// A request the route alone selects: its prefix (with a segment appended
/// when the prefix ends in `/`), from its first bound host, if any.
fn route_witness(route: &RouteRule) -> Option<HttpRequest> {
    let path = if route.path_prefix.ends_with('/') {
        format!("{}{WITNESS_SEGMENT}", route.path_prefix)
    } else {
        route.path_prefix.clone()
    };
    Some(HttpRequest {
        method: witness_method(&route.methods)?,
        path,
        host: route.hosts.first().cloned(),
        target: SyntheticTarget::Contextless,
    })
}
