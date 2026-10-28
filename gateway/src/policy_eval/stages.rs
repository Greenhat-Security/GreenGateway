//! The HTTP lane's stage trace (issue #243, slice 10).
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
//! A stage the evaluator did not reach is not recorded. Whether that means
//! "decided earlier" or "unknown because a fact was missing" follows from the
//! evaluation's own outcome, which the consumer always holds beside the trace.

use crate::rbac::{EnforcementMode, RuleAction};

use super::Limitation;

/// Most stages one evaluation records: each stage below is recorded at most
/// once, so a collecting sink never needs more room than this.
pub(crate) const MAX_HTTP_STAGES: usize = 7;

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

/// Receives the stages of one evaluation, in the order they ran.
pub(crate) trait StageSink {
    fn record(&mut self, stage: HttpStage);
}

/// The sink the live adapters use: it keeps nothing and allocates nothing.
pub(crate) struct NoStages;

impl StageSink for NoStages {
    #[inline]
    fn record(&mut self, _stage: HttpStage) {}
}

/// Collects every stage. The evaluator records at most [`MAX_HTTP_STAGES`].
impl StageSink for Vec<HttpStage> {
    fn record(&mut self, stage: HttpStage) {
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
}
