//! The stage traces of the HTTP, tool and rate lanes (issue #243, slices 10
//! and 12).
//!
//! [`CompiledPolicy::evaluate`](super::CompiledPolicy::evaluate) decides a
//! request in a fixed order: the facts it needs, the host routes are matched
//! against, the direct rules, the deny-only narrowing a selected virtual
//! upstream imposes, the routes and their permission, and the policy default.
//! An admin explanation of a decision has to say which of those ran and what
//! each one found, and the only honest source of that is the evaluator itself:
//! a second walk over the policy that re-derived the stages would be exactly
//! the approximate second implementation ADR-0004 forbids, and would drift the
//! first time the order changed.
//!
//! So the evaluator reports its own stages to a [`StageSink`] as it runs them.
//! The live adapters pass [`NoStages`], whose `record` does nothing and
//! allocates nothing, and get the same decision code the simulator runs; only
//! an admin analysis passes a collecting sink. A stage carries enums,
//! positions and the enforcement mode that applied -- never an authored path,
//! permission, identifier or any value from the evaluated context.
//!
//! The tool lane ([`ToolStage`]) and the rate lane ([`RateStage`]) report
//! through the same sink, each in its own stage vocabulary, from
//! `evaluate_tool_with_facts` and `select_rate_lane_with_facts` themselves.
//!
//! A stage the evaluator did not reach is not recorded. Whether that means
//! "decided earlier" or "unknown because a fact was missing" follows from the
//! evaluation's own outcome, which the consumer always holds beside the trace.

use crate::rbac::{EnforcementMode, RuleAction};

use super::{tools::ToolLimitation, Limitation};

/// Most stages one evaluation records: each stage below is recorded at most
/// once, so a collecting sink never needs more room than this.
pub(crate) const MAX_HTTP_STAGES: usize = 7;
/// Most stages one tool-lane evaluation records: each [`ToolStage`] at most
/// once.
pub(crate) const MAX_TOOL_STAGES: usize = 4;
/// Most stages one rate-lane selection records: each [`RateStage`] at most
/// once.
pub(crate) const MAX_RATE_STAGES: usize = 3;

/// One stage of the HTTP lane, as [`CompiledPolicy::evaluate`] ran it.
///
/// [`CompiledPolicy::evaluate`]: super::CompiledPolicy::evaluate
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HttpStage {
    /// Whether method, path, principal and routing classification were all
    /// supplied, or the first one that was not. A missing fact ends the
    /// evaluation as indeterminate.
    Facts(Option<Limitation>),
    /// The host routes were matched against.
    RequestHost(HostUse),
    /// The first enabled direct rule that matched, under the single-identity
    /// or alias precedence order the target calls for.
    DirectRules(Option<DirectMatch>),
    /// The deny-only narrowing of direct rules for a selected virtual
    /// upstream, and the deny that decided under it.
    UpstreamBinding(UpstreamBinding),
    /// The first route the method, path and host admitted, or none.
    Routes(Option<RouteMatch>),
    /// A selected virtual upstream that no host-bound route authorized was
    /// refused; the default was not consulted.
    HostPolicyRequired,
    /// The policy default decided.
    Default(DefaultMatch),
}

/// Which host routes were matched against, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostUse {
    /// The selected virtual upstream's bound host.
    SelectedUpstream,
    /// The request's own `Host`.
    Request,
    /// The request carried no `Host`.
    Absent,
    /// The host was not captured and no route is host-qualified, so it could
    /// not change the answer.
    NotRequired,
    /// The host was not captured and a host-qualified route could turn on it.
    Missing,
}

/// The direct rule that matched first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectMatch {
    /// Position in the pinned source order, disabled and tool rules included.
    pub(crate) rule: usize,
    pub(crate) action: DirectAction,
}

/// A direct rule's action, in the trace's own vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectAction {
    Allow,
    Deny,
    Shadow,
}

impl From<&RuleAction> for DirectAction {
    fn from(action: &RuleAction) -> Self {
        match action {
            RuleAction::Allow => Self::Allow,
            RuleAction::Deny => Self::Deny,
            RuleAction::Shadow => Self::Shadow,
        }
    }
}

/// Whether a selected virtual upstream narrowed direct rules to denies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UpstreamBinding {
    /// No virtual upstream was selected; direct rules decided as written.
    NotSelected,
    /// A virtual upstream was selected: only a direct deny could decide, and
    /// this is the one that did, if any.
    DenyOnly(Option<usize>),
}

/// The route that matched and the permission check it imposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RouteMatch {
    /// Position in the pinned source order.
    pub(crate) route: usize,
    pub(crate) permission: PermissionCheck,
    /// The enforcement mode a denial under this route takes.
    pub(crate) mode: EnforcementMode,
    /// Whether that mode is the policy's, inherited, rather than the route's
    /// own override.
    pub(crate) mode_inherited: bool,
}

/// The outcome of a route's permission check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermissionCheck {
    Granted,
    /// An authenticated principal whose roles do not grant it.
    Missing,
    /// No principal to grant it.
    NoPrincipal,
}

/// The default that decided and the enforcement mode it applied under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DefaultMatch {
    pub(crate) allow: bool,
    pub(crate) mode: EnforcementMode,
}

/// One stage of the tool lane, as
/// [`CompiledPolicy::evaluate_tool_with_facts`] ran it.
///
/// A tool operation runs `Facts`, `Entry`, `Identity` and `Rules` in that
/// order; a rendered tool request runs `Facts` and `Rules` only, because it
/// is decided by the direct HTTP rules alone.
///
/// [`CompiledPolicy::evaluate_tool_with_facts`]: super::CompiledPolicy::evaluate_tool_with_facts
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolStage {
    /// Whether every fact the operation reads was supplied -- the tool name,
    /// the principal and, in mapped-role mode, its internal roles, and for a
    /// rendered request its method and path -- or the first one that was not.
    /// A missing fact ends the evaluation as indeterminate.
    Facts(Option<ToolLimitation>),
    /// The named tool's policy entry.
    Entry(ToolEntry),
    /// Whether the principal meets the entry's identity constraints: its
    /// allowed roles, issuers and authentication methods.
    Identity(IdentityCheck),
    /// The direct rules the operation consults: the tool-name rules, or for a
    /// rendered request the HTTP rules under unknown dispatch.
    Rules(ToolRules),
}

/// The named tool's policy entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolEntry {
    /// The policy has no entry for the tool.
    Absent,
    /// The entry exists and is disabled.
    Disabled,
    /// The entry exists and is enabled.
    Enabled,
}

/// The outcome of a tool entry's identity constraints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityCheck {
    /// The principal meets every constraint, or the entry states none.
    Admitted,
    /// The principal does not meet them, or there is none to meet them.
    Refused,
}

/// What the tool lane's direct rules found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToolRules {
    /// No rule matched.
    NoMatch,
    /// The first rule that matched, under the lane's own precedence.
    Matched(DirectMatch),
    /// A rule's conditions read a fact that was not captured, before any
    /// rule certainly matched. The evaluation ends as indeterminate.
    Undetermined,
}

/// One stage of the rate lane, as
/// [`CompiledPolicy::select_rate_lane_with_facts`] ran it.
///
/// [`CompiledPolicy::select_rate_lane_with_facts`]: super::CompiledPolicy::select_rate_lane_with_facts
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RateStage {
    /// Whether method, path, principal and, in mapped-role mode, its internal
    /// roles were all supplied, or the first one that was not. A missing fact
    /// ends the selection as indeterminate.
    Facts(Option<Limitation>),
    /// Whether the live bypass for an anonymous caller applied: `true` means
    /// no override is consulted at all, as live rate limiting consults none
    /// for a request without a principal.
    AnonymousBypass(bool),
    /// The first override that matched, by position in the pinned source
    /// order, or none.
    Overrides(Option<usize>),
}

/// Receives the stages of one evaluation, in the order they ran. A lane
/// reports its own stage type; the default is the HTTP lane's.
pub(crate) trait StageSink<S = HttpStage> {
    fn record(&mut self, stage: S);
}

/// The sink the live adapters use: it keeps nothing and allocates nothing.
pub(crate) struct NoStages;

impl<S> StageSink<S> for NoStages {
    #[inline]
    fn record(&mut self, _stage: S) {}
}

/// Collects every stage. The evaluator records at most [`MAX_HTTP_STAGES`],
/// [`MAX_TOOL_STAGES`] or [`MAX_RATE_STAGES`] stages per evaluation.
impl<S> StageSink<S> for Vec<S> {
    fn record(&mut self, stage: S) {
        self.push(stage);
    }
}

#[cfg(test)]
mod tests {
    use http::Method;
    use serde_json::json;

    use super::*;
    use crate::{
        auth::{AuthMethod, Principal},
        policy_eval::{
            tools::{ToolEvaluationContext, ToolOperation, TOOL_CONTEXT_VERSION},
            CompiledPolicy, DispatchFacts, HostFact, HttpTarget, PolicyAuthority,
            PolicyEvaluationContext, PrincipalFact, PrincipalIdentity, CONTEXT_VERSION,
        },
        rbac::Policy,
    };

    fn compiled() -> CompiledPolicy {
        let policy = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": { "reader": { "permissions": ["orders:read"] } },
            "rules": [
                { "id": "public", "path": "/public/**", "action": "allow" },
                { "id": "watched", "path": "/orders/watched", "action": "shadow" },
                { "id": "blocked", "path": "/orders/blocked", "action": "deny" }
            ],
            "routes": [
                { "hosts": ["api.example.test"], "path_prefix": "/orders", "permission": "orders:read" },
                { "path_prefix": "/orders", "permission": "orders:read", "enforcement_mode": "shadow" },
                { "path_prefix": "/reports", "permission": "reports:read" }
            ]
        }))
        .expect("policy validates");
        CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
            .expect("policy compiles")
    }

    fn reader() -> PrincipalFact {
        PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&Principal {
            user_id: "stage-subject".to_owned(),
            issuer: None,
            email: None,
            org_id: None,
            roles: vec!["reader".to_owned()],
            session_id: String::new(),
            auth_method: AuthMethod::Bearer,
        }))
    }

    fn context(compiled: &CompiledPolicy, path: &str) -> PolicyEvaluationContext {
        PolicyEvaluationContext {
            version: CONTEXT_VERSION,
            snapshot: compiled.snapshot(),
            method: Some(Method::GET),
            path: Some(path.to_owned()),
            principal: reader(),
            target: HttpTarget::Contextless,
            request_host: HostFact::Absent,
            dispatch: None,
        }
    }

    fn selected_upstream(context: &mut PolicyEvaluationContext) {
        context.target = HttpTarget::ProxyDispatch;
        context.request_host = HostFact::Present("api.example.test".to_owned());
        context.dispatch = Some(DispatchFacts {
            route_id: None,
            route_host: Some("api.example.test".to_owned()),
            route_path_prefix: Some("/".to_owned()),
            upstream_origin: "https://upstream.example.test".to_owned(),
        });
    }

    fn direct(rule: usize, action: DirectAction) -> HttpStage {
        HttpStage::DirectRules(Some(DirectMatch { rule, action }))
    }

    fn route(
        route: usize,
        permission: PermissionCheck,
        mode: EnforcementMode,
        mode_inherited: bool,
    ) -> HttpStage {
        HttpStage::Routes(Some(RouteMatch {
            route,
            permission,
            mode,
            mode_inherited,
        }))
    }

    #[test]
    fn the_stage_trace_describes_exactly_the_decision_evaluate_makes() {
        let compiled = compiled();
        let mut upstream_deny = context(&compiled, "/orders/blocked");
        selected_upstream(&mut upstream_deny);
        let mut upstream_unrouted = context(&compiled, "/reports/7");
        selected_upstream(&mut upstream_unrouted);
        let mut upstream_shadow = context(&compiled, "/orders/watched");
        selected_upstream(&mut upstream_shadow);
        let mut anonymous = context(&compiled, "/reports/7");
        anonymous.principal = PrincipalFact::Anonymous;
        let mut missing_method = context(&compiled, "/orders/1");
        missing_method.method = None;
        let mut missing_host = context(&compiled, "/orders/1");
        missing_host.request_host = HostFact::Missing;

        let facts = HttpStage::Facts(None);
        let absent = HttpStage::RequestHost(HostUse::Absent);
        let selected = HttpStage::RequestHost(HostUse::SelectedUpstream);
        let not_selected = HttpStage::UpstreamBinding(UpstreamBinding::NotSelected);
        let no_deny = HttpStage::UpstreamBinding(UpstreamBinding::DenyOnly(None));
        let cases: Vec<(&str, PolicyEvaluationContext, Vec<HttpStage>)> = vec![
            (
                "direct allow decides",
                context(&compiled, "/public/a"),
                vec![facts, absent, direct(0, DirectAction::Allow), not_selected],
            ),
            (
                "direct shadow decides as an observed deny",
                context(&compiled, "/orders/watched"),
                vec![facts, absent, direct(1, DirectAction::Shadow), not_selected],
            ),
            (
                "the unbound route grants under its own shadow override",
                context(&compiled, "/orders/1"),
                vec![
                    facts,
                    absent,
                    HttpStage::DirectRules(None),
                    not_selected,
                    route(1, PermissionCheck::Granted, EnforcementMode::Shadow, false),
                ],
            ),
            (
                "a missing permission is reported with the inherited mode",
                context(&compiled, "/reports/7"),
                vec![
                    facts,
                    absent,
                    HttpStage::DirectRules(None),
                    not_selected,
                    route(2, PermissionCheck::Missing, EnforcementMode::Enforce, true),
                ],
            ),
            (
                "an anonymous caller has no principal to grant",
                anonymous,
                vec![
                    facts,
                    absent,
                    HttpStage::DirectRules(None),
                    not_selected,
                    route(
                        2,
                        PermissionCheck::NoPrincipal,
                        EnforcementMode::Enforce,
                        true,
                    ),
                ],
            ),
            (
                "the default decides an unrouted request",
                context(&compiled, "/elsewhere"),
                vec![
                    facts,
                    absent,
                    HttpStage::DirectRules(None),
                    not_selected,
                    HttpStage::Routes(None),
                    HttpStage::Default(DefaultMatch {
                        allow: false,
                        mode: EnforcementMode::Enforce,
                    }),
                ],
            ),
            (
                "a selected upstream narrows direct rules to the deny",
                upstream_deny,
                vec![
                    facts,
                    selected,
                    direct(2, DirectAction::Deny),
                    HttpStage::UpstreamBinding(UpstreamBinding::DenyOnly(Some(2))),
                ],
            ),
            (
                "a first matching shadow is only observed, and the host route decides",
                upstream_shadow,
                vec![
                    facts,
                    selected,
                    direct(1, DirectAction::Shadow),
                    no_deny,
                    route(0, PermissionCheck::Granted, EnforcementMode::Enforce, true),
                ],
            ),
            (
                "a selected upstream no host route authorizes never reaches the default",
                upstream_unrouted,
                vec![
                    facts,
                    selected,
                    HttpStage::DirectRules(None),
                    no_deny,
                    HttpStage::Routes(None),
                    HttpStage::HostPolicyRequired,
                ],
            ),
            (
                "a missing fact stops at the facts stage",
                missing_method,
                vec![HttpStage::Facts(Some(Limitation::MissingMethod))],
            ),
            (
                "an uncaptured host stops where a host route could turn on it",
                missing_host,
                vec![facts, HttpStage::RequestHost(HostUse::Missing)],
            ),
        ];
        for (name, context, expected) in cases {
            let mut stages = Vec::new();
            let traced = compiled
                .evaluate_with_stages(&context, &mut stages)
                .expect("evaluates");
            assert_eq!(
                compiled.evaluate(&context).expect("evaluates"),
                traced,
                "{name}: the traced decision must be the live decision"
            );
            assert_eq!(stages, expected, "{name}");
            assert!(stages.len() <= MAX_HTTP_STAGES, "{name}");
        }
    }

    #[test]
    fn an_uncaptured_host_is_not_required_without_a_host_qualified_route() {
        let policy = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "default_action": "allow"
        }))
        .expect("policy validates");
        let compiled = CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
            .expect("policy compiles");
        let mut input = context(&compiled, "/anything");
        input.request_host = HostFact::Missing;
        let mut stages = Vec::new();
        compiled
            .evaluate_with_stages(&input, &mut stages)
            .expect("evaluates");
        assert_eq!(stages[1], HttpStage::RequestHost(HostUse::NotRequired));
        assert_eq!(
            stages.last(),
            Some(&HttpStage::Default(DefaultMatch {
                allow: true,
                mode: EnforcementMode::Enforce,
            }))
        );
    }

    #[test]
    fn a_refused_context_records_no_stage() {
        let compiled = compiled();
        let mut input = context(&compiled, "/orders/1");
        input.path = Some("relative".to_owned());
        let mut stages = Vec::new();
        assert!(compiled.evaluate_with_stages(&input, &mut stages).is_err());
        assert!(stages.is_empty());
    }

    fn lanes_policy() -> CompiledPolicy {
        let policy = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "rules": [
                {
                    "id": "deny-export-for-interns",
                    "tool_name": "export",
                    "principal": { "roles": ["intern"] },
                    "action": "deny"
                },
                { "id": "render-block", "methods": ["POST"], "path": "/render/blocked", "action": "deny" }
            ],
            "tools": {
                "export": { "allowed_roles": ["reader", "intern"] },
                "off": { "enabled": false }
            },
            "rate_limits": [
                {
                    "principal": { "roles": ["reader"] },
                    "path": "/orders/**",
                    "requests_per_second": 5,
                    "burst": 10
                },
                { "path": "/orders/**", "requests_per_second": 1, "burst": 1 }
            ]
        }))
        .expect("policy validates");
        CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
            .expect("policy compiles")
    }

    fn with_roles(roles: &[&str]) -> PrincipalFact {
        PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&Principal {
            user_id: "lane-subject".to_owned(),
            issuer: None,
            email: None,
            org_id: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: String::new(),
            auth_method: AuthMethod::Bearer,
        }))
    }

    fn tool(
        compiled: &CompiledPolicy,
        operation: ToolOperation,
        name: Option<&str>,
        principal: PrincipalFact,
        rendered: Option<(Method, &str)>,
    ) -> ToolEvaluationContext {
        ToolEvaluationContext {
            version: TOOL_CONTEXT_VERSION,
            snapshot: compiled.snapshot(),
            operation,
            tool_name: name.map(str::to_owned),
            principal,
            method: rendered.as_ref().map(|(method, _)| method.clone()),
            path: rendered.map(|(_, path)| path.to_owned()),
        }
    }

    #[test]
    fn the_tool_stage_trace_describes_exactly_the_decision_evaluate_tool_makes() {
        let compiled = lanes_policy();
        let invocation = ToolOperation::Invocation;
        let facts = ToolStage::Facts(None);
        let enabled = ToolStage::Entry(ToolEntry::Enabled);
        let admitted = ToolStage::Identity(IdentityCheck::Admitted);
        let cases: Vec<(&str, ToolEvaluationContext, Vec<ToolStage>)> = vec![
            (
                "an admitted caller with no rule is allowed",
                tool(
                    &compiled,
                    invocation,
                    Some("export"),
                    with_roles(&["reader"]),
                    None,
                ),
                vec![
                    facts,
                    enabled,
                    admitted,
                    ToolStage::Rules(ToolRules::NoMatch),
                ],
            ),
            (
                "a tool-name deny decides after the entry and identity checks",
                tool(
                    &compiled,
                    invocation,
                    Some("export"),
                    with_roles(&["intern"]),
                    None,
                ),
                vec![
                    facts,
                    enabled,
                    admitted,
                    ToolStage::Rules(ToolRules::Matched(DirectMatch {
                        rule: 0,
                        action: DirectAction::Deny,
                    })),
                ],
            ),
            (
                "an unknown tool stops at its entry",
                tool(
                    &compiled,
                    invocation,
                    Some("missing"),
                    with_roles(&["reader"]),
                    None,
                ),
                vec![facts, ToolStage::Entry(ToolEntry::Absent)],
            ),
            (
                "a disabled tool stops at its entry",
                tool(
                    &compiled,
                    invocation,
                    Some("off"),
                    with_roles(&["reader"]),
                    None,
                ),
                vec![facts, ToolStage::Entry(ToolEntry::Disabled)],
            ),
            (
                "a caller without an allowed role stops at the identity check",
                tool(
                    &compiled,
                    invocation,
                    Some("export"),
                    with_roles(&["outsider"]),
                    None,
                ),
                vec![facts, enabled, ToolStage::Identity(IdentityCheck::Refused)],
            ),
            (
                "an uncaptured tool name stops at the facts",
                tool(&compiled, invocation, None, with_roles(&["reader"]), None),
                vec![ToolStage::Facts(Some(ToolLimitation::ToolName))],
            ),
            (
                "an uncaptured principal stops at the facts",
                tool(
                    &compiled,
                    invocation,
                    Some("export"),
                    PrincipalFact::Missing,
                    None,
                ),
                vec![ToolStage::Facts(Some(ToolLimitation::Principal))],
            ),
            (
                "a rendered request is decided by the HTTP rules alone",
                tool(
                    &compiled,
                    ToolOperation::RenderedHttp,
                    Some("export"),
                    with_roles(&["reader"]),
                    Some((Method::POST, "/render/blocked")),
                ),
                vec![
                    facts,
                    ToolStage::Rules(ToolRules::Matched(DirectMatch {
                        rule: 1,
                        action: DirectAction::Deny,
                    })),
                ],
            ),
        ];
        for (name, context, expected) in cases {
            let mut stages = Vec::new();
            let traced = compiled
                .evaluate_tool_with_stages(&context, &mut stages)
                .expect("evaluates");
            assert_eq!(
                compiled.evaluate_tool(&context).expect("evaluates"),
                traced,
                "{name}: the traced decision must be the live decision"
            );
            assert_eq!(stages, expected, "{name}");
            assert!(stages.len() <= MAX_TOOL_STAGES, "{name}");
        }
        // A rendered request without its method: the context is refused as
        // inconsistent unless the operation is rendered, so build one that
        // carries a path only.
        let mut rendered = tool(
            &compiled,
            ToolOperation::RenderedHttp,
            Some("export"),
            with_roles(&["reader"]),
            Some((Method::POST, "/render/blocked")),
        );
        rendered.method = None;
        let mut stages = Vec::new();
        compiled
            .evaluate_tool_with_stages(&rendered, &mut stages)
            .expect("evaluates");
        assert_eq!(stages, [ToolStage::Facts(Some(ToolLimitation::Method))]);
    }

    fn rate(
        compiled: &CompiledPolicy,
        method: Option<Method>,
        path: &str,
        principal: PrincipalFact,
    ) -> PolicyEvaluationContext {
        PolicyEvaluationContext {
            version: CONTEXT_VERSION,
            snapshot: compiled.snapshot(),
            method,
            path: Some(path.to_owned()),
            principal,
            target: HttpTarget::Missing,
            request_host: HostFact::Missing,
            dispatch: None,
        }
    }

    #[test]
    fn the_rate_stage_trace_describes_exactly_the_selection_select_rate_lane_makes() {
        let compiled = lanes_policy();
        let get = Some(Method::GET);
        let facts = RateStage::Facts(None);
        let authenticated = RateStage::AnonymousBypass(false);
        let cases: Vec<(&str, PolicyEvaluationContext, Vec<RateStage>)> = vec![
            (
                "the first matching override governs",
                rate(&compiled, get.clone(), "/orders/1", with_roles(&["reader"])),
                vec![facts, authenticated, RateStage::Overrides(Some(0))],
            ),
            (
                "an override the principal does not meet is passed over",
                rate(&compiled, get.clone(), "/orders/1", with_roles(&["other"])),
                vec![facts, authenticated, RateStage::Overrides(Some(1))],
            ),
            (
                "no override matches",
                rate(
                    &compiled,
                    get.clone(),
                    "/elsewhere",
                    with_roles(&["reader"]),
                ),
                vec![facts, authenticated, RateStage::Overrides(None)],
            ),
            (
                "an anonymous caller takes the live bypass",
                rate(
                    &compiled,
                    get.clone(),
                    "/orders/1",
                    PrincipalFact::Anonymous,
                ),
                vec![facts, RateStage::AnonymousBypass(true)],
            ),
            (
                "an uncaptured method stops at the facts",
                rate(&compiled, None, "/orders/1", with_roles(&["reader"])),
                vec![RateStage::Facts(Some(Limitation::MissingMethod))],
            ),
            (
                "an uncaptured principal stops at the facts",
                rate(&compiled, get, "/orders/1", PrincipalFact::Missing),
                vec![RateStage::Facts(Some(Limitation::MissingPrincipalFact))],
            ),
        ];
        for (name, context, expected) in cases {
            let mut stages = Vec::new();
            let traced = compiled
                .select_rate_lane_with_stages(&context, &mut stages)
                .expect("selects");
            assert_eq!(
                compiled.select_rate_lane(&context).expect("selects"),
                traced,
                "{name}: the traced selection must be the live selection"
            );
            assert_eq!(stages, expected, "{name}");
            assert!(stages.len() <= MAX_RATE_STAGES, "{name}");
        }
    }
}
