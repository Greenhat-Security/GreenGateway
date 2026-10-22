//! Differential tests for the admin analysis consumers that moved onto the
//! shared evaluator (#422 PR 4): the historical rule preview and the traffic
//! inventory's endpoint coverage, each compared with its frozen pre-cutover
//! implementation in `analysis_legacy_tests.rs`, never with a second
//! hand-written evaluator.
//!
//! The generated corpus (fixed seed `422_005`) covers the facts both sides
//! read. Where they differ by design the property names the reason and checks
//! it: an observation the evaluator refuses or cannot judge, which the frozen
//! preview counted, or not, without saying so. The named tests pin the rest of
//! the documented differences one by one.

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, RngSeed};

use super::analysis_legacy::{legacy_endpoint_coverage_scope, legacy_preview_matches};
use super::*;

const ISSUER: &str = "https://issuer.example";
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

fn rule_strategy(auth_methods: &'static [&'static str]) -> impl Strategy<Value = Value> {
    (
        proptest::bool::weighted(0.85),
        prop::sample::select(vec![
            json!([]),
            json!(["GET"]),
            json!(["POST"]),
            json!(["*"]),
            json!(["get", "DELETE"]),
        ]),
        prop::sample::select(vec![
            "/api/**",
            "/api/items/{id}",
            "/api/items/*",
            "/api/items/1",
            "/**",
            "/other",
        ]),
        (
            subset(&["reader", "admin"]),
            subset(&[ISSUER]),
            subset(auth_methods),
            subset(&["reader-1"]),
        ),
        prop::sample::select(vec![
            Value::Null,
            json!({"kind": "contextless"}),
            json!({"kind": "legacy", "upstream_origin": "https://upstream.example"}),
            json!({"kind": "route", "route_id": "payments"}),
            json!({"kind": "route", "route_id": "other"}),
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
                let mut rule = json!({
                    "enabled": enabled,
                    "methods": methods,
                    "path": path,
                    "principal": {
                        "roles": roles,
                        "issuers": issuers,
                        "auth_methods": auth_methods,
                        "principal_ids": principal_ids,
                    },
                    "action": action,
                });
                if !dispatch.is_null() {
                    rule["dispatch"] = dispatch;
                }
                rule
            },
        )
}

/// One retained observation, and whether its recorded facts are ones the
/// evaluator refuses by construction.
#[derive(Clone, Debug)]
struct GeneratedObservation {
    method: &'static str,
    path: &'static str,
    actor: Option<audit::Actor>,
    payload: Value,
    malformed: bool,
    routing_known: bool,
    auth_mode_supported: bool,
}

impl GeneratedObservation {
    fn observation(&self) -> audit::query::RequestObservation {
        request_observation(
            self.method,
            self.path,
            self.actor.clone(),
            self.payload.clone(),
        )
    }
}

fn observation_strategy() -> impl Strategy<Value = GeneratedObservation> {
    (
        prop::sample::select(vec![
            ("GET", false),
            ("POST", false),
            ("DELETE", false),
            ("get", false),
            ("BAD METHOD", true),
        ]),
        prop::sample::select(vec![
            ("/api/items/1", false),
            ("/api/items/2", false),
            ("/api/items/1/", false),
            ("/api/other", false),
            ("/other", false),
            ("/", false),
            ("/api/items/%31", true),
            ("/api//items/1", true),
            ("/api/../items/1", true),
        ]),
        prop::option::of((
            prop::sample::select(vec![
                ("bearer_token", true),
                ("session_cookie", true),
                ("service_token", true),
                ("api_key", false),
            ]),
            prop::sample::select(vec!["reader-1", "admin-1"]),
            prop::option::of(subset(&["reader", "admin"])),
            proptest::bool::ANY,
        )),
        prop::sample::select(vec![None, Some(false), Some(true)]),
        prop::sample::select(vec![
            // (route id, route host, route path prefix, upstream origin, inconsistent)
            (None, None, None, None, false),
            (None, None, None, Some("https://upstream.example"), false),
            (Some("payments"), None, None, Some("pool:payments"), false),
            (
                Some("payments"),
                Some(HOST),
                None,
                Some("pool:payments"),
                false,
            ),
            (Some("other"), None, Some("/api"), Some("pool:other"), false),
            (None, None, None, Some(" "), false),
            (None, Some(HOST), None, None, true),
        ]),
    )
        .prop_map(
            |((method, bad_method), (path, bad_path), actor, routing_known, dispatch)| {
                let (route_id, route_host, route_path_prefix, upstream_origin, inconsistent) =
                    dispatch;
                let mut payload = json!({"method": method, "path": path, "status": 200});
                if let Some(known) = routing_known {
                    payload["routing_context_known"] = json!(known);
                }
                for (key, value) in [
                    ("upstream_route_id", route_id),
                    ("upstream_route_host", route_host),
                    ("upstream_route_path_prefix", route_path_prefix),
                    ("upstream_origin", upstream_origin),
                ] {
                    if let Some(value) = value {
                        payload[key] = json!(value);
                    }
                }
                let auth_mode_supported = actor
                    .as_ref()
                    .is_none_or(|((_, supported), _, _, _)| *supported);
                let actor =
                    actor.map(
                        |((auth_mode, _), user_id, roles, with_issuer)| audit::Actor {
                            user_id: user_id.to_owned(),
                            issuer: with_issuer.then(|| ISSUER.to_owned()),
                            email: None,
                            roles,
                            auth_mode: auth_mode.to_owned(),
                        },
                    );
                let routing_known = routing_known == Some(true);
                GeneratedObservation {
                    method,
                    path,
                    actor,
                    payload,
                    malformed: bad_method || bad_path || (routing_known && inconsistent),
                    routing_known,
                    auth_mode_supported,
                }
            },
        )
}

fn request_observation(
    method: &str,
    path: &str,
    actor: Option<audit::Actor>,
    payload: Value,
) -> audit::query::RequestObservation {
    audit::query::RequestObservation {
        id: 1,
        event_id: "generated".to_owned(),
        timestamp: "2024-06-01T12:00:00Z".to_owned(),
        request_id: "generated-request".to_owned(),
        source_ip: "192.0.2.1".to_owned(),
        user_agent: None,
        actor,
        method: method.to_owned(),
        path: path.to_owned(),
        status: Some(200),
        matched_rule_id: None,
        payload_json: payload.to_string(),
    }
}

fn candidate(rule: &Value) -> rbac::Rule {
    serde_json::from_value(rule.clone()).expect("generated rule should parse")
}

proptest! {
    #![proptest_config(differential_config())]

    /// Every observation is judged as the frozen preview judged it, except
    /// where the evaluator refuses or cannot judge the recorded facts, and
    /// then only for the reason the facts give.
    #[test]
    fn generated_rules_and_observations_are_counted_alike_by_the_frozen_and_live_previews(
        rule in rule_strategy(&["bearer_token", "session_cookie", "service_token", "client_certificate"]),
        generated in observation_strategy(),
    ) {
        let rule = candidate(&rule);
        let compiled = policy_eval::CompiledPolicy::for_candidate_rule(rule.clone());
        let observation = generated.observation();
        let live = preview_observation_outcome(&compiled, &observation)
            .expect("the preview never builds a question the evaluator refuses");
        let legacy = legacy_preview_matches(&rule, &observation);
        if generated.malformed {
            prop_assert_eq!(live, PreviewObservationOutcome::Unevaluated(PREVIEW_MALFORMED_OBSERVATION));
        } else {
            match live {
                PreviewObservationOutcome::Matched => prop_assert!(legacy),
                PreviewObservationOutcome::NotMatched => prop_assert!(!legacy),
                PreviewObservationOutcome::Unevaluated("missing_principal_fact") => {
                    prop_assert!(!legacy);
                    prop_assert!(!generated.auth_mode_supported);
                    prop_assert!(rule.enabled && !rule.principal.is_unconstrained());
                }
                PreviewObservationOutcome::Unevaluated("missing_dispatch_fact") => {
                    prop_assert!(!legacy);
                    prop_assert!(!generated.routing_known);
                    prop_assert!(rule.enabled && rule.dispatch.is_some());
                }
                PreviewObservationOutcome::Unevaluated(reason) => {
                    prop_assert!(false, "unexpected unevaluated reason {}", reason);
                }
            }
        }
    }

    /// Endpoint coverage is the frozen answer for every generated policy and
    /// routing context. Roles here never restrict to client certificates; the
    /// one difference that needs one is pinned by name below.
    #[test]
    fn generated_policies_report_the_same_endpoint_coverage_as_the_frozen_inventory(
        rules in proptest::collection::vec(
            rule_strategy(&["bearer_token", "session_cookie", "service_token", "client_certificate"]),
            0..5,
        ),
        routes in proptest::collection::vec(
            (
                prop::sample::select(vec![json!([]), json!(["GET"]), json!(["POST"])]),
                prop::sample::select(vec![json!([]), json!([HOST]), json!(["API.example.test"]), json!(["other.example.test"])]),
                prop::sample::select(vec!["/", "/api", "/api/items", "/other"]),
                prop::sample::select(vec!["read", "write"]),
            ),
            0..3,
        ),
        roles in proptest::collection::btree_map(
            prop::sample::select(vec!["reader", "admin", "writer"]),
            (
                subset(&["read", "write", "*"]),
                subset(&[ISSUER]),
                subset(&["bearer_token", "session_cookie", "service_token"]),
            ),
            0..3,
        ),
        method in prop::sample::select(vec!["GET", "POST", "MCP"]),
        template in prop::sample::select(vec![
            "/api/items/{id}",
            "/api/items/{name}",
            "/api",
            "/api/items/",
            "/other/x",
            "/",
        ]),
        dispatch in prop::sample::select(vec![
            (None, None, None),
            (None, None, Some("https://upstream.example")),
            (None, None, Some("pool:payments")),
            (Some(HOST), None, Some("pool:payments")),
            (Some("other.example.test"), Some("/api"), Some("https://upstream.example")),
            (None, Some("/api"), Some("pool:other")),
        ]),
    ) {
        let policy = rbac::Policy::validate_json_value(json!({
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
        }));
        prop_assume!(policy.is_ok());
        let policy = policy.expect("checked above");
        let (route_host, route_path_prefix, upstream_origin) = dispatch;
        let context = routing_context(route_host, route_path_prefix, upstream_origin);
        let compiled = policy_eval::CompiledPolicy::for_analysis(policy.clone());
        prop_assert_eq!(
            endpoint_coverage_scope(&compiled, method, template, Some(&context)),
            legacy_endpoint_coverage_scope(&policy, method, template, Some(&context))
        );
    }
}

fn routing_context(
    route_host: Option<&str>,
    route_path_prefix: Option<&str>,
    upstream_origin: Option<&str>,
) -> discovery::query::EndpointRoutingContext {
    discovery::query::EndpointRoutingContext {
        route_host: route_host.map(str::to_owned),
        route_path_prefix: route_path_prefix.map(str::to_owned),
        upstream_origin: upstream_origin.map(str::to_owned),
        first_seen: "2024-06-01T12:00:00Z".to_owned(),
        last_seen: "2024-06-01T12:00:00Z".to_owned(),
        call_count: 1,
        distinct_principal_count: 1,
        covered_by_rule: false,
        coverage_scope: discovery::query::EndpointCoverageScope::None,
    }
}

fn analysis_policy(value: Value) -> (rbac::Policy, policy_eval::CompiledPolicy) {
    let policy = rbac::Policy::validate_json_value(value).expect("policy should validate");
    let compiled = policy_eval::CompiledPolicy::for_analysis(policy.clone());
    (policy, compiled)
}

#[test]
fn a_client_certificate_actor_is_judged_with_its_identity_rather_than_as_anonymous() {
    let rule = candidate(&json!({
        "path": "/api/**",
        "principal": {"auth_methods": ["client_certificate"], "principal_ids": ["device-7"]},
        "action": "deny"
    }));
    let compiled = policy_eval::CompiledPolicy::for_candidate_rule(rule.clone());
    let observation = request_observation(
        "GET",
        "/api/items/1",
        Some(audit::Actor {
            user_id: "device-7".to_owned(),
            issuer: None,
            email: None,
            roles: None,
            auth_mode: "client_certificate".to_owned(),
        }),
        json!({"routing_context_known": true}),
    );
    assert!(!legacy_preview_matches(&rule, &observation));
    assert_eq!(
        preview_observation_outcome(&compiled, &observation).unwrap(),
        PreviewObservationOutcome::Matched
    );
}

#[test]
fn observations_the_frozen_preview_counted_without_the_facts_are_now_reported_unevaluated() {
    let actor = |auth_mode: &str| audit::Actor {
        user_id: "reader-1".to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: None,
        roles: Some(vec!["reader".to_owned()]),
        auth_mode: auth_mode.to_owned(),
    };
    let classified = json!({"routing_context_known": true});

    // A path no served request reaches the policy stage with: the frozen
    // preview counted it as a match.
    let broad = candidate(&json!({"path": "/api/**", "action": "deny"}));
    let compiled = policy_eval::CompiledPolicy::for_candidate_rule(broad.clone());
    let refused = request_observation("GET", "/api/%2e%2e/admin", None, classified.clone());
    assert!(legacy_preview_matches(&broad, &refused));
    assert_eq!(
        preview_observation_outcome(&compiled, &refused).unwrap(),
        PreviewObservationOutcome::Unevaluated(PREVIEW_MALFORMED_OBSERVATION)
    );

    // An actor no principal can carry, against a rule that reads the
    // principal: the frozen preview judged it anonymous and said no match.
    let constrained = candidate(&json!({
        "path": "/api/**", "principal": {"roles": ["reader"]}, "action": "deny"
    }));
    let compiled = policy_eval::CompiledPolicy::for_candidate_rule(constrained.clone());
    let unknown_mode = request_observation(
        "GET",
        "/api/items/1",
        Some(actor("api_key")),
        classified.clone(),
    );
    assert!(!legacy_preview_matches(&constrained, &unknown_mode));
    assert_eq!(
        preview_observation_outcome(&compiled, &unknown_mode).unwrap(),
        PreviewObservationOutcome::Unevaluated("missing_principal_fact")
    );

    // An unclassified observation against a dispatch-bound rule: the frozen
    // preview judged it under an unknown dispatch and said no match.
    let bound = candidate(&json!({
        "path": "/api/**", "dispatch": {"kind": "contextless"}, "action": "deny"
    }));
    let compiled = policy_eval::CompiledPolicy::for_candidate_rule(bound.clone());
    let unclassified = request_observation(
        "GET",
        "/api/items/1",
        Some(actor("bearer_token")),
        json!({}),
    );
    assert!(!legacy_preview_matches(&bound, &unclassified));
    assert_eq!(
        preview_observation_outcome(&compiled, &unclassified).unwrap(),
        PreviewObservationOutcome::Unevaluated("missing_dispatch_fact")
    );

    // Neither fact is demanded of a rule that does not read it.
    let unconstrained = candidate(&json!({"path": "/api/**", "action": "deny"}));
    let compiled = policy_eval::CompiledPolicy::for_candidate_rule(unconstrained.clone());
    let neither = request_observation("GET", "/api/items/1", Some(actor("api_key")), json!({}));
    assert!(legacy_preview_matches(&unconstrained, &neither));
    assert_eq!(
        preview_observation_outcome(&compiled, &neither).unwrap(),
        PreviewObservationOutcome::Matched
    );
}

#[test]
fn an_endpoint_with_no_recorded_routing_context_has_unknown_coverage() {
    let (policy, compiled) = analysis_policy(json!({
        "schema_version": "0.1.0",
        "rules": [{"path": "/api/**", "action": "deny"}]
    }));
    // The frozen inventory judged it under an unknown dispatch; the
    // evaluator is missing the dispatch fact and says so.
    assert_eq!(
        legacy_endpoint_coverage_scope(&policy, "GET", "/api/items/{id}", None),
        discovery::query::EndpointCoverageScope::Endpoint
    );
    assert_eq!(
        endpoint_coverage_scope(&compiled, "GET", "/api/items/{id}", None),
        discovery::query::EndpointCoverageScope::Unknown
    );
    let mut endpoint_contexts = Vec::new();
    assert_eq!(
        aggregate_coverage_scope(&compiled, "GET", "/api/items/{id}", &endpoint_contexts),
        discovery::query::EndpointCoverageScope::Unknown
    );
    endpoint_contexts.push(routing_context(None, None, None));
    apply_routing_context_coverage(&mut endpoint_contexts, &compiled, "GET", "/api/items/{id}");
    assert_eq!(
        aggregate_coverage_scope(&compiled, "GET", "/api/items/{id}", &endpoint_contexts),
        discovery::query::EndpointCoverageScope::Endpoint
    );
    assert!(endpoint_contexts[0].covered_by_rule);
}

#[test]
fn a_representative_request_the_evaluator_refuses_has_unknown_coverage() {
    let (policy, compiled) = analysis_policy(json!({
        "schema_version": "0.1.0",
        "rules": [{"path": "/files/**", "action": "deny"}]
    }));
    let contextless = routing_context(None, None, None);
    for (method, template) in [("GET", "/files/a%20b"), ("BAD METHOD", "/files/{id}")] {
        assert_eq!(
            legacy_endpoint_coverage_scope(&policy, method, template, Some(&contextless)),
            discovery::query::EndpointCoverageScope::Endpoint,
            "{method} {template}"
        );
        assert_eq!(
            endpoint_coverage_scope(&compiled, method, template, Some(&contextless)),
            discovery::query::EndpointCoverageScope::Unknown,
            "{method} {template}"
        );
    }
    // Route facts without an origin cannot come from a classified dispatch.
    let inconsistent = routing_context(Some(HOST), None, None);
    assert_eq!(
        endpoint_coverage_scope(&compiled, "GET", "/files/{id}", Some(&inconsistent)),
        discovery::query::EndpointCoverageScope::Unknown
    );
}

#[test]
fn host_routed_coverage_asks_whether_a_role_caller_is_authorized_or_decided() {
    let host_routed = routing_context(Some(HOST), None, Some("pool:payments"));
    // A role grants the host-bound route's permission only to callers who can
    // activate it. The representative caller activates it, so the frozen
    // inventory's "some role grants the permission" is the same answer.
    let (policy, compiled) = analysis_policy(json!({
        "schema_version": "0.1.0",
        "roles": {"payer": {
            "permissions": ["pay"],
            "issuers": [ISSUER],
            "auth_methods": ["service_token"]
        }},
        "routes": [{"hosts": [HOST], "path_prefix": "/pay", "permission": "pay"}]
    }));
    for scope in [
        legacy_endpoint_coverage_scope(&policy, "POST", "/pay/{id}", Some(&host_routed)),
        endpoint_coverage_scope(&compiled, "POST", "/pay/{id}", Some(&host_routed)),
    ] {
        assert_eq!(scope, discovery::query::EndpointCoverageScope::Principal);
    }
    // No role grants it: no coverage, on either side.
    let (policy, compiled) = analysis_policy(json!({
        "schema_version": "0.1.0",
        "roles": {"reader": {"permissions": ["read"]}},
        "routes": [{"hosts": [HOST], "path_prefix": "/pay", "permission": "pay"}]
    }));
    for scope in [
        legacy_endpoint_coverage_scope(&policy, "POST", "/pay/{id}", Some(&host_routed)),
        endpoint_coverage_scope(&compiled, "POST", "/pay/{id}", Some(&host_routed)),
    ] {
        assert_eq!(scope, discovery::query::EndpointCoverageScope::None);
    }

    // A deny only a client-certificate caller can meet, and a role only such a
    // caller activates, on a route no role grants. The frozen inventory's
    // representative caller for the deny was a bearer, so it never met it, and
    // it found no grant. The role's callers are decided by that deny, which is
    // coverage.
    let (policy, compiled) = analysis_policy(json!({
        "schema_version": "0.1.0",
        "roles": {"device": {"permissions": ["read"], "auth_methods": ["client_certificate"]}},
        "routes": [{"hosts": [HOST], "path_prefix": "/pay", "permission": "pay"}],
        "rules": [{"path": "/pay/**", "principal": {"auth_methods": ["client_certificate"]}, "action": "deny"}]
    }));
    assert_eq!(
        legacy_endpoint_coverage_scope(&policy, "POST", "/pay/{id}", Some(&host_routed)),
        discovery::query::EndpointCoverageScope::None
    );
    assert_eq!(
        endpoint_coverage_scope(&compiled, "POST", "/pay/{id}", Some(&host_routed)),
        discovery::query::EndpointCoverageScope::Principal
    );
}

#[test]
fn coverage_is_judged_by_the_live_snapshot_the_rbac_state_installed() {
    let state = middleware::rbac::RbacState::new(
        rbac::Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "rules": [
                {"id": "deny-api", "path": "/api/**", "action": "deny"},
                {"path": "/other/**", "action": "allow"}
            ]
        }))
        .expect("policy should validate"),
        Vec::new(),
        false,
        audit::AuditLog::new(Arc::new(audit::sink::tests::CaptureSink::new())),
    );
    let snapshot = state.live_policy_snapshot();
    assert_eq!(snapshot.rule_ids(), ["deny-api".to_owned(), "1".to_owned()]);
    assert_eq!(
        endpoint_coverage_scope(
            snapshot.compiled(),
            "GET",
            "/api/items/{id}",
            Some(&routing_context(None, None, None))
        ),
        discovery::query::EndpointCoverageScope::Endpoint
    );
}
