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

use std::{collections::HashMap, time::Instant};

use http::Method;
use serde_json::{json, Map, Value};
use url::Url;

use super::{
    coverage::{
        dispatch_covers, hosts_cover, matches_every_path, pattern_covers, prefix_covers,
        prefix_pattern, principal_covers, segments, Segments,
    },
    AccessEffect, AnalysisError, AnalysisLimitation, AnalysisOutcome, CandidatePatch, ElementRef,
    Finding, FindingCode, Lane, ProofBasis, Section, Severity, MAX_COMPARISONS, MAX_FINDINGS,
};
use crate::{
    auth::{AuthMethod, Principal},
    policy_eval::{
        analysis::DirectRuleOutcome, CompiledPolicy, DispatchFacts, EvaluationError, PrincipalFact,
        PrincipalIdentity, RuleReference,
    },
    policy_replay::auth_method_from_code,
    policy_testing::{
        runner::{http_context, rate_context},
        suite::{HttpRequest, SyntheticPrincipal, SyntheticTarget},
    },
    rbac::{
        engine::grants_permission,
        matcher::{matches_every_method, methods_cover, PatternSegment},
        policy_document::{is_valid_element_id, pointer_token},
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
        deadline,
        comparisons: 0,
        stopped: None,
        findings: Vec::new(),
    };
    // The linear checks first, so a budget spent on pairwise comparisons
    // never costs them.
    run.risky_defaults();
    run.wildcard_grants();
    run.broad_rules()?;
    run.direct_rules()?;
    run.tool_rules()?;
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
    deadline: Instant,
    comparisons: usize,
    stopped: Option<AnalysisLimitation>,
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
        if self.comparisons % DEADLINE_CHECK_INTERVAL == 0 && Instant::now() >= self.deadline {
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
        });
        AnalysisOutcome {
            findings: self.findings,
            complete: self.stopped.is_none(),
            limitations: self.stopped.into_iter().collect(),
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

    fn wildcard_grants(&mut self) {
        let mut names: Vec<&String> = self.policy.roles.keys().collect();
        names.sort();
        for name in names {
            let role = &self.policy.roles[name];
            if !role.issuers.is_empty() {
                continue;
            }
            let Some(index) = role
                .permissions
                .iter()
                .position(|permission| permission == "*")
            else {
                continue;
            };
            self.push(finding(
                FindingCode::WildcardGrantWithoutIssuer,
                Severity::Medium,
                // Whether any issuer but the intended one could grant the
                // role depends on the providers this deployment trusts.
                ProofBasis::Heuristic,
                ElementRef {
                    section: Section::Roles,
                    pointer: format!("/roles/{}/permissions/{index}", pointer_token(name)),
                    position: None,
                    id: None,
                    name: Some(name.clone()),
                },
            ));
        }
    }

    fn broad_rules(&mut self) -> Result<(), AnalysisError> {
        let policy = self.policy;
        for (index, rule) in policy.rules.iter().enumerate() {
            let code = match rule.action {
                RuleAction::Allow => FindingCode::BroadUnconstrainedAllow,
                RuleAction::Shadow => FindingCode::BroadUnconstrainedShadow,
                RuleAction::Deny => continue,
            };
            if !is_http_rule(rule)
                || !rule.principal.is_unconstrained()
                || rule.dispatch.is_some()
                || !matches_every_path(&segments(&rule.path))
            {
                continue;
            }
            let confirmed = confirm_broad(rule)?;
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
            if !rule.enabled {
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
                if principal_covers(&earlier.principal, &rule.principal) {
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
        earlier.path_prefix == route.path_prefix
            || !self
                .alias_paths
                .iter()
                .any(|alias| *alias == route.path_prefix)
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

    /// The witness for `rule` matches the rule alone, and over the whole
    /// policy an earlier rule decides it in the first-match lane.
    fn confirm_rule(&self, position: usize, rule: &Rule) -> Result<bool, AnalysisError> {
        let Some((request, principal)) = http_rule_witness(rule) else {
            return Ok(false);
        };
        let alone = CompiledPolicy::for_candidate_rule(rule.clone());
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
        let alone = CompiledPolicy::for_candidate_rule(rule.clone());
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
fn confirm_broad(rule: &Rule) -> Result<bool, AnalysisError> {
    let (Some(method), Some(principal)) = (
        witness_method(&rule.methods),
        witness_principal(&rule.principal),
    ) else {
        return Ok(false);
    };
    let alone = CompiledPolicy::for_candidate_rule(rule.clone());
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

/// A policy at the analyzed one's schema version with nothing in it, for
/// compiling one element alone.
fn empty_policy(policy: &Policy) -> Policy {
    Policy {
        schema_version: policy.schema_version.clone(),
        id: None,
        default_action: DefaultAction::Deny,
        enforcement_mode: EnforcementMode::Enforce,
        roles: HashMap::new(),
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

/// Whether `covering` matches every HTTP request `covered` matches: method,
/// principal, dispatch binding and path, cheapest first.
fn http_rule_covers(
    covering: &Rule,
    covering_path: &Segments<'_>,
    covered: &Rule,
    covered_path: &Segments<'_>,
) -> bool {
    methods_cover(&covering.methods, &covered.methods)
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
    }
}

fn route_ref(position: usize, route: &RouteRule) -> ElementRef {
    ElementRef {
        section: Section::Routes,
        pointer: format!("/routes/{position}"),
        position: Some(position),
        id: element_id(route.id.as_deref()),
        name: None,
    }
}

fn rate_ref(position: usize, limit: &RateLimitRule) -> ElementRef {
    ElementRef {
        section: Section::RateLimits,
        pointer: format!("/rate_limits/{position}"),
        position: Some(position),
        id: element_id(limit.id.as_deref()),
        name: None,
    }
}

fn scalar_ref(section: Section) -> ElementRef {
    ElementRef {
        section,
        pointer: format!("/{}", section.as_str()),
        position: None,
        id: None,
        name: None,
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
    match principal {
        SyntheticPrincipal::Anonymous => PrincipalFact::Anonymous,
        SyntheticPrincipal::Authenticated(principal) => {
            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal))
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
