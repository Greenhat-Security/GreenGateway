//! Differential tests for suggestion coverage, which now asks the shared
//! evaluator whether the policy already covers a candidate (#422 PR 4),
//! compared with the frozen pre-cutover check in `suggestions_legacy_tests.rs`.
//!
//! Off a host-routed dispatch the two must agree exactly. On one, the frozen
//! check granted coverage whenever some role the candidate holds grants the
//! host-bound route's permission; the evaluator also requires that the
//! candidate can activate that role, and that no direct deny decides the
//! request first, as live evaluation does. The property allows a difference
//! only in that direction and only for one of those two reasons.

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, RngSeed};
use serde_json::json;

use super::legacy::{
    legacy_policy_has_covering_action, legacy_representative_path_from_endpoint_template,
    legacy_representative_principal_for_matcher,
};
use super::*;
use crate::rbac::{PolicyEngine, RuleDispatchContext, RuleMatcher};

const ISSUER: &str = "https://issuer.example";
const OTHER_ISSUER: &str = "https://other-issuer.example";
const HOST: &str = "api.example.test";

fn differential_config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(422_005),
        max_shrink_iters: 1_024,
        ..ProptestConfig::default()
    }
}

fn subset(values: &'static [&'static str]) -> impl Strategy<Value = Vec<String>> {
    proptest::sample::subsequence(values, 0..=values.len())
        .prop_map(|values| values.into_iter().map(str::to_owned).collect())
}

fn rule_strategy() -> impl Strategy<Value = Value> {
    (
        proptest::bool::weighted(0.85),
        prop::sample::select(vec![
            json!([]),
            json!(["GET"]),
            json!(["POST"]),
            json!(["*"]),
        ]),
        prop::sample::select(vec![
            Some("/api/**"),
            Some("/api/items/{id}"),
            Some("/api/items/*"),
            Some("/**"),
            Some("/other"),
            None,
        ]),
        (
            subset(&["reader", "admin"]),
            subset(&[ISSUER, OTHER_ISSUER]),
            subset(&["bearer_token", "session_cookie", "service_token"]),
            subset(&["user-1"]),
        ),
        prop::sample::select(vec![
            serde_json::Value::Null,
            json!({"kind": "contextless"}),
            json!({"kind": "legacy", "upstream_origin": "https://upstream.example"}),
            json!({"kind": "route", "route_id": "payments"}),
        ]),
        prop::sample::select(vec!["allow", "deny", "shadow"]),
    )
        .prop_map(
            |(
                enabled,
                methods,
                path,
                (roles, issuers, auth_methods, principal_ids),
                dispatch,
                action,
            )| {
                let principal = json!({
                    "roles": roles,
                    "issuers": issuers,
                    "auth_methods": auth_methods,
                    "principal_ids": principal_ids,
                });
                let mut rule = match path {
                    Some(path) => json!({
                        "enabled": enabled,
                        "methods": methods,
                        "path": path,
                        "principal": principal,
                        "action": action,
                    }),
                    None => json!({
                        "enabled": enabled,
                        "tool_name": "reports.export",
                        "principal": principal,
                        "action": action,
                    }),
                };
                if path.is_some() && !dispatch.is_null() {
                    rule["dispatch"] = dispatch;
                }
                rule
            },
        )
}

fn policy_strategy() -> impl Strategy<Value = Option<Policy>> {
    (
        proptest::collection::vec(rule_strategy(), 0..5),
        proptest::collection::vec(
            (
                prop::sample::select(vec![json!([]), json!(["GET"]), json!(["POST"])]),
                prop::sample::select(vec![json!([HOST]), json!(["API.example.test"]), json!([])]),
                prop::sample::select(vec!["/", "/api", "/api/items", "/other"]),
                prop::sample::select(vec!["read", "write"]),
            ),
            0..3,
        ),
        proptest::collection::btree_map(
            prop::sample::select(vec!["reader", "admin", "writer"]),
            (
                subset(&["read", "write", "*"]),
                subset(&[ISSUER, OTHER_ISSUER]),
                subset(&["bearer_token", "session_cookie", "service_token"]),
            ),
            0..3,
        ),
    )
        .prop_map(|(rules, routes, roles)| {
            Policy::validate_json_value(json!({
                "schema_version": "0.1.0",
                "rules": rules,
                "routes": routes
                    .into_iter()
                    .map(|(methods, hosts, path_prefix, permission)| json!({
                        "methods": methods,
                        "hosts": hosts,
                        "path_prefix": path_prefix,
                        "permission": permission,
                    }))
                    .collect::<Vec<_>>(),
                "roles": roles
                    .into_iter()
                    .map(|(name, (permissions, issuers, auth_methods))| (name.to_owned(), json!({
                        "permissions": permissions,
                        "issuers": issuers,
                        "auth_methods": auth_methods,
                    })))
                    .collect::<serde_json::Map<_, _>>(),
            }))
            .ok()
        })
}

fn matcher_strategy() -> impl Strategy<Value = PrincipalMatcher> {
    prop_oneof![
        // A baseline candidate: one role, its issuer, its authentication mode.
        (
            prop::sample::select(vec!["reader", "admin", "writer"]),
            prop::sample::select(vec![Some(ISSUER), Some(OTHER_ISSUER), None]),
            prop::sample::select(vec!["bearer_token", "session_cookie", "service_token"]),
        )
            .prop_map(|(role, issuer, auth_method)| PrincipalMatcher {
                roles: vec![role.to_owned()],
                issuers: issuer.into_iter().map(str::to_owned).collect(),
                auth_methods: vec![auth_method.to_owned()],
                principal_ids: Vec::new(),
            }),
        // A signal's principal, or none.
        (
            prop::sample::select(vec![Some(ISSUER), None]),
            prop::sample::select(vec!["bearer_token", "service_token"]),
        )
            .prop_map(|(issuer, auth_method)| PrincipalMatcher {
                roles: Vec::new(),
                issuers: issuer.into_iter().map(str::to_owned).collect(),
                auth_methods: vec![auth_method.to_owned()],
                principal_ids: vec!["user-1".to_owned()],
            }),
        Just(PrincipalMatcher::default()),
    ]
}

fn covering_strategy() -> impl Strategy<Value = Vec<RuleAction>> {
    prop::sample::select(vec![
        vec![RuleAction::Allow, RuleAction::Shadow],
        vec![RuleAction::Deny, RuleAction::Shadow],
    ])
}

type GeneratedDispatch = (
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
    Option<&'static str>,
);

fn dispatch_strategy() -> impl Strategy<Value = GeneratedDispatch> {
    prop::sample::select(vec![
        // (route id, route host, route path prefix, upstream origin)
        (None, None, None, None),
        (None, None, None, Some("https://upstream.example")),
        (Some("payments"), None, None, Some("pool:payments")),
        (Some("payments"), Some(HOST), None, Some("pool:payments")),
        (
            None,
            Some("api.EXAMPLE.test"),
            Some("/api"),
            Some("https://upstream.example"),
        ),
        (None, None, Some("/api"), Some("https://upstream.example")),
    ])
}

fn coverage_dispatch(dispatch: GeneratedDispatch) -> CoverageDispatch<'static> {
    let (route_id, route_host, route_path_prefix, upstream_origin) = dispatch;
    CoverageDispatch {
        route_id,
        route_host,
        route_path_prefix,
        upstream_origin,
    }
}

fn legacy_dispatch_context(dispatch: GeneratedDispatch) -> RuleDispatchContext<'static> {
    let (route_id, route_host, route_path_prefix, upstream_origin) = dispatch;
    RuleDispatchContext::classified_with_route_id(
        route_id,
        route_host,
        route_path_prefix,
        upstream_origin,
    )
}

proptest! {
    #![proptest_config(differential_config())]

    #[test]
    fn generated_candidates_are_covered_alike_by_the_frozen_check_and_the_evaluator(
        policy in policy_strategy(),
        method in prop::sample::select(vec!["GET", "POST", "MCP"]),
        path_pattern in prop::sample::select(vec![
            "/api/items/{id}",
            "/api/items/{name}",
            "/api",
            "/other",
            "/mcp/tools/reports.export",
        ]),
        matcher in matcher_strategy(),
        covering in covering_strategy(),
        dispatch in dispatch_strategy(),
    ) {
        prop_assume!(policy.is_some());
        let policy = policy.expect("checked above");
        let compiled = CompiledPolicy::for_analysis(policy.clone());
        let live = policy_coverage(
            &compiled,
            method,
            path_pattern,
            &matcher,
            &covering,
            coverage_dispatch(dispatch),
        );
        let legacy = legacy_policy_has_covering_action(
            &policy,
            method,
            path_pattern,
            &matcher,
            &covering,
            dispatch.1,
            legacy_dispatch_context(dispatch),
        );
        prop_assert_ne!(live, PolicyCoverage::Unevaluated);
        let covered = live == PolicyCoverage::Covered;
        if dispatch.1.is_none() || covered {
            prop_assert_eq!(covered, legacy);
        } else if legacy {
            // The frozen check granted coverage the evaluator does not: the
            // candidate's representative caller either activates no role that
            // grants the route's permission, or meets a direct deny first.
            let principal = legacy_representative_principal_for_matcher(&matcher);
            let path = legacy_representative_path_from_endpoint_template(path_pattern);
            let denied_first = principal.as_ref().is_some_and(|principal| {
                RuleMatcher::new(&policy.rules)
                    .evaluate_denies_with_dispatch(
                        method,
                        &path,
                        Some(principal),
                        legacy_dispatch_context(dispatch),
                    )
                    .is_some()
            });
            let route = policy.routes.iter().find(|route| {
                crate::rbac::matcher::method_matches(&route.methods, method)
                    && crate::path_match::path_prefix_matches(&path, &route.path_prefix)
                    && route.hosts.iter().any(|host| dispatch.1.is_some_and(|bound| host.eq_ignore_ascii_case(bound)))
            });
            let activated_grant = route.zip(principal.as_ref()).is_some_and(|(route, principal)| {
                PolicyEngine::new(policy.clone()).principal_has_permission(principal, &route.permission)
            });
            prop_assert!(denied_first || !activated_grant);
        }
    }
}

fn policy(value: serde_json::Value) -> Policy {
    Policy::validate_json_value(value).expect("policy should validate")
}

fn baseline_matcher(role: &str, issuer: &str, auth_method: &str) -> PrincipalMatcher {
    PrincipalMatcher {
        roles: vec![role.to_owned()],
        issuers: vec![issuer.to_owned()],
        auth_methods: vec![auth_method.to_owned()],
        principal_ids: Vec::new(),
    }
}

const HOST_ROUTED: GeneratedDispatch = (Some("payments"), Some(HOST), None, Some("pool:payments"));

#[test]
fn a_host_routed_candidate_is_covered_only_by_a_role_it_can_activate() {
    let policy = policy(json!({
        "schema_version": "0.1.0",
        "roles": {"payer": {"permissions": ["pay"], "issuers": [ISSUER]}},
        "routes": [{"hosts": [HOST], "path_prefix": "/pay", "permission": "pay"}]
    }));
    let compiled = CompiledPolicy::for_analysis(policy.clone());
    let covering = [RuleAction::Allow, RuleAction::Shadow];
    for (issuer, legacy, live) in [
        (ISSUER, true, PolicyCoverage::Covered),
        // The role is restricted to another issuer, so this caller cannot
        // activate it and the route refuses them; the frozen check did not
        // look.
        (OTHER_ISSUER, true, PolicyCoverage::NotCovered),
    ] {
        let matcher = baseline_matcher("payer", issuer, "bearer_token");
        assert_eq!(
            legacy_policy_has_covering_action(
                &policy,
                "POST",
                "/pay/{id}",
                &matcher,
                &covering,
                HOST_ROUTED.1,
                legacy_dispatch_context(HOST_ROUTED),
            ),
            legacy,
            "{issuer}"
        );
        assert_eq!(
            policy_coverage(
                &compiled,
                "POST",
                "/pay/{id}",
                &matcher,
                &covering,
                coverage_dispatch(HOST_ROUTED),
            ),
            live,
            "{issuer}"
        );
    }
}

#[test]
fn a_host_routed_candidate_a_direct_deny_decides_is_not_covered_by_an_allow() {
    let policy = policy(json!({
        "schema_version": "0.1.0",
        "roles": {"payer": {"permissions": ["pay"]}},
        "routes": [{"hosts": [HOST], "path_prefix": "/pay", "permission": "pay"}],
        "rules": [{"path": "/pay/**", "principal": {"roles": ["payer"]}, "action": "deny"}]
    }));
    let compiled = CompiledPolicy::for_analysis(policy.clone());
    let matcher = baseline_matcher("payer", ISSUER, "bearer_token");
    let covering = [RuleAction::Allow, RuleAction::Shadow];
    assert!(legacy_policy_has_covering_action(
        &policy,
        "POST",
        "/pay/{id}",
        &matcher,
        &covering,
        HOST_ROUTED.1,
        legacy_dispatch_context(HOST_ROUTED),
    ));
    assert_eq!(
        policy_coverage(
            &compiled,
            "POST",
            "/pay/{id}",
            &matcher,
            &covering,
            coverage_dispatch(HOST_ROUTED),
        ),
        PolicyCoverage::NotCovered
    );
}

#[test]
fn a_signal_candidate_is_judged_as_traffic_dispatched_the_way_it_would_be_bound() {
    // A route binding is judged as the pooled route's traffic: its id and its
    // logical origin. The frozen check judged it as contextless traffic.
    let binding = RuleDispatchMatcher::route("payments".to_owned());
    assert_eq!(
        coverage_dispatch_for_binding(&binding),
        (
            Some("payments".to_owned()),
            Some("pool:payments".to_owned())
        )
    );
    assert_eq!(
        coverage_dispatch_for_binding(&RuleDispatchMatcher::legacy(
            "https://upstream.example".to_owned()
        )),
        (None, Some("https://upstream.example".to_owned()))
    );
    assert_eq!(
        coverage_dispatch_for_binding(&RuleDispatchMatcher::contextless()),
        (None, None)
    );

    let covering = [RuleAction::Deny, RuleAction::Shadow];
    let (route_id, upstream_origin) = coverage_dispatch_for_binding(&binding);
    let dispatch = CoverageDispatch {
        route_id: route_id.as_deref(),
        upstream_origin: upstream_origin.as_deref(),
        ..CoverageDispatch::default()
    };
    for (rule_dispatch, legacy, live) in [
        (
            json!({"kind": "route", "route_id": "payments"}),
            false,
            PolicyCoverage::Covered,
        ),
        (
            json!({"kind": "contextless"}),
            true,
            PolicyCoverage::NotCovered,
        ),
    ] {
        let policy = policy(json!({
            "schema_version": "0.1.0",
            "rules": [{"path": "/pay/**", "dispatch": rule_dispatch, "action": "shadow"}]
        }));
        let compiled = CompiledPolicy::for_analysis(policy.clone());
        let matcher = PrincipalMatcher::default();
        assert_eq!(
            legacy_policy_has_covering_action(
                &policy,
                "POST",
                "/pay/{id}",
                &matcher,
                &covering,
                None,
                RuleDispatchContext::classified(None, None, binding.upstream_origin.as_deref()),
            ),
            legacy,
            "{rule_dispatch}"
        );
        assert_eq!(
            policy_coverage(
                &compiled,
                "POST",
                "/pay/{id}",
                &matcher,
                &covering,
                dispatch,
            ),
            live,
            "{rule_dispatch}"
        );
    }
}

#[test]
fn a_candidate_the_evaluator_cannot_judge_is_proposed_and_counted() {
    let policy = policy(json!({
        "schema_version": "0.1.0",
        "rules": [{"path": "/files/**", "action": "allow"}]
    }));
    let observed = [ObservedEndpoint {
        method: "GET".to_owned(),
        endpoint_template: "/files/a%20b".to_owned(),
        route_host: None,
        route_path_prefix: None,
        upstream_origin: None,
        routing_context_known_since: Some("2024-01-01T00:00:00Z".to_owned()),
    }];
    let planner = SuggestionPlanner::new(&policy, RuleSuggestionConfig::default(), &[], &observed);
    let matrix = RoleEndpointObservationMatrix {
        observations: vec![RoleEndpointObservation {
            method: "GET".to_owned(),
            endpoint_template: "/files/a%20b".to_owned(),
            issuer: Some(ISSUER.to_owned()),
            auth_method: "bearer_token".to_owned(),
            route_host: None,
            route_path_prefix: None,
            upstream_origin: None,
            role: "reader".to_owned(),
            observation_count: 3,
            error_count: 0,
            first_seen: "2024-06-01T12:00:00Z".to_owned(),
            last_seen: "2024-06-01T12:00:00Z".to_owned(),
        }],
        scanned_event_count: 3,
        ..RoleEndpointObservationMatrix::default()
    };
    // The frozen check matched the allow rule against the escaped path and
    // skipped the candidate as covered. No served request reaches the policy
    // stage with that path, so the evaluator refuses it, and nothing says the
    // candidate is covered.
    assert!(legacy_policy_has_covering_action(
        &policy,
        "GET",
        "/files/a%20b",
        &baseline_matcher("reader", ISSUER, "bearer_token"),
        &[RuleAction::Allow, RuleAction::Shadow],
        None,
        RuleDispatchContext::contextless(),
    ));
    let mut run = BaselineSuggestionRun::default();
    let suggestions = planner
        .baseline_suggestions(
            matrix,
            "2024-06-01T00:00:00Z",
            "2024-06-02T00:00:00Z",
            AUDIT_SQLITE_EVIDENCE_SOURCE,
            &mut run,
        )
        .expect("planning should succeed");
    assert_eq!(run.coverage_unevaluated, 1);
    assert_eq!(run.skipped_policy_covered, 0);
    assert_eq!(suggestions.len(), 1);
}
