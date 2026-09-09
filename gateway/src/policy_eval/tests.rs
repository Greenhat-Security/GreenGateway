use std::{sync::Arc, time::Duration};

use axum::{body::Body, middleware::from_fn_with_state, routing::any, Router};
use http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::*;
use crate::{
    audit::{sink::tests::CaptureSink, AuditLog, AuditSink},
    middleware::{
        decision::{PolicyDecision, PolicyDecisionOutcome},
        rbac::{rbac_middleware, RbacState},
    },
    upstream_route::{ProxyRouteClassificationCompleted, ProxyRouteObservationContext},
};

fn compile(value: Value) -> CompiledPolicy {
    CompiledPolicy::compile(
        &serde_json::to_vec(&value).unwrap(),
        PolicyAuthority::Standalone,
    )
    .unwrap()
}

fn basic_policy() -> Value {
    json!({"schema_version":"0.1.0", "default_action":"deny"})
}

fn principal(roles: &[&str]) -> Principal {
    Principal {
        user_id: "synthetic-user".to_owned(),
        issuer: Some("https://idp.example.test".to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        auth_method: AuthMethod::Bearer,
        email: None,
        org_id: None,
        session_id: "synthetic-session".to_owned(),
    }
}

fn context(compiled: &CompiledPolicy) -> PolicyEvaluationContext {
    PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(Method::GET),
        path: Some("/data/item".to_owned()),
        principal: PrincipalFact::Anonymous,
        target: HttpTarget::Contextless,
        request_host: HostFact::Absent,
        dispatch: None,
    }
}

#[tokio::test]
async fn http_lane_matches_current_middleware_decisions_reasons_order_and_shadow_events() {
    // Exercise the actual authoritative middleware, never a second hand-written
    // expected evaluator. No listener is bound and the terminal handler is local.
    for global in ["enforce", "shadow"] {
        for default in ["allow", "deny"] {
            for route_override in [None, Some("enforce"), Some("shadow")] {
                for direct in [None, Some("allow"), Some("deny"), Some("shadow")] {
                    let mut first_route =
                        json!({"methods":[" get "],"path_prefix":"/data","permission":"read"});
                    if let Some(mode) = route_override {
                        first_route["enforcement_mode"] = json!(mode);
                    }
                    let mut value = json!({
                        "schema_version":"0.1.0", "default_action":default,"enforcement_mode":global,
                        "roles":{
                            "reader":{"permissions":["read"],"issuers":["https://idp.example.test/"],"auth_methods":["bearer_token"]},
                            "admin":{"permissions":["*"]}
                        },
                        "routes":[first_route,{"path_prefix":"/data/item","permission":"never"}],
                        "rules":[
                            {"id":"disabled","enabled":false,"path":"/**","action":"deny"},
                            {"tool_name":"sample","action":"deny"}
                        ]
                    });
                    if let Some(action) = direct {
                        value["rules"].as_array_mut().unwrap().extend([
                            json!({"path":"/direct/{id}","methods":["GET"],"action":action}),
                            json!({"id":"later-deny","path":"/direct/**","action":"deny"}),
                        ]);
                    }
                    let compiled = compile(value.clone());
                    let policy = Policy::validate_json_value(value).unwrap();
                    let capture = CaptureSink::new();
                    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
                    let state = RbacState::new(policy.clone(), Vec::new(), false, audit.clone());
                    let router = Router::new()
                        .fallback(any(|| async { "local" }))
                        .layer(from_fn_with_state(state, rbac_middleware));
                    let mut expected_events = Vec::new();
                    for path in [
                        "/data/item",
                        "/database",
                        "/data/",
                        "/direct/42",
                        "/direct/42/child",
                        "/elsewhere",
                    ] {
                        for method in [Method::GET, Method::POST] {
                            let mut inactive = principal(&["reader"]);
                            inactive.auth_method = AuthMethod::Cookie;
                            for identity in [
                                None,
                                Some(principal(&["reader"])),
                                Some(principal(&["admin"])),
                                Some(inactive),
                            ] {
                                let mut input = context(&compiled);
                                input.method = Some(method.clone());
                                input.path = Some(path.to_owned());
                                input.principal = identity.as_ref().map_or(
                                    PrincipalFact::Anonymous,
                                    |identity| {
                                        PrincipalFact::Authenticated(
                                            PrincipalIdentity::from_principal(identity),
                                        )
                                    },
                                );
                                let result = compiled.evaluate(&input).unwrap();
                                let mut request = Request::builder()
                                    .method(method.clone())
                                    .uri(path)
                                    .body(Body::empty())
                                    .unwrap();
                                request
                                    .extensions_mut()
                                    .insert(ProxyRouteClassificationCompleted);
                                if let Some(identity) = identity {
                                    request.extensions_mut().insert(identity);
                                }
                                let response = router.clone().oneshot(request).await.unwrap();
                                let live = response.extensions().get::<PolicyDecision>().unwrap();
                                let (outcome, status, event) = match result.effect {
                                    PolicyEffect::Allow => (
                                        PolicyDecisionOutcome::Allowed,
                                        StatusCode::OK,
                                        "authz.allowed",
                                    ),
                                    PolicyEffect::Observe => (
                                        PolicyDecisionOutcome::WouldDeny,
                                        StatusCode::OK,
                                        "authz.would_deny",
                                    ),
                                    PolicyEffect::Block => (
                                        PolicyDecisionOutcome::Denied,
                                        StatusCode::FORBIDDEN,
                                        "authz.denied",
                                    ),
                                };
                                assert_eq!(live.outcome, outcome, "{global}/{default}/{route_override:?}/{direct:?} {method} {path}");
                                assert_eq!(response.status(), status);
                                assert_eq!(live.reason, result.reason.as_str());
                                assert_eq!(
                                    result.logical,
                                    if outcome == PolicyDecisionOutcome::Allowed {
                                        LogicalDecision::Allow
                                    } else {
                                        LogicalDecision::Deny
                                    }
                                );
                                match result.matched {
                                    Some(RuleReference::Direct(index)) => {
                                        assert_eq!(
                                            live.matched_rule_id,
                                            Some(
                                                policy.rules[index]
                                                    .id
                                                    .clone()
                                                    .unwrap_or_else(|| index.to_string())
                                            )
                                        );
                                        assert_eq!(live.permission, None);
                                    }
                                    Some(RuleReference::Route(index)) => {
                                        assert_eq!(
                                            live.permission.as_deref(),
                                            Some(policy.routes[index].permission.as_str())
                                        );
                                        assert_eq!(
                                            live.path_prefix.as_deref(),
                                            Some(policy.routes[index].path_prefix.as_str())
                                        );
                                        assert_eq!(live.matched_rule_id, None);
                                    }
                                    None => {
                                        assert_eq!(live.matched_rule_id, None);
                                        assert_eq!(live.permission, None);
                                    }
                                }
                                assert!(result.complete);
                                expected_events.push(event);
                            }
                        }
                    }
                    audit.close_and_drain(Duration::from_secs(5)).await.unwrap();
                    let events = capture.events();
                    assert_eq!(events.len(), expected_events.len());
                    for (event, expected) in events.iter().zip(expected_events) {
                        assert_eq!(event.event_type, expected);
                    }
                }
            }
        }
    }
}

#[test]
fn missing_facts_are_indeterminate_and_never_reusable_or_permitted() {
    let compiled = compile(json!({"schema_version":"0.1.0","default_action":"allow"}));
    let baseline = context(&compiled);
    let mut cases = Vec::new();
    let mut input = baseline.clone();
    input.method = None;
    cases.push((input, Limitation::MissingMethod));
    let mut input = baseline.clone();
    input.path = None;
    cases.push((input, Limitation::MissingPath));
    let mut input = baseline.clone();
    input.principal = PrincipalFact::Missing;
    cases.push((input, Limitation::MissingPrincipalFact));
    let mut input = baseline.clone();
    input.target = HttpTarget::Missing;
    cases.push((input, Limitation::MissingDispatchFact));
    // A classified dispatch is supported now, but only with its facts supplied.
    let mut input = baseline.clone();
    input.target = HttpTarget::ProxyDispatch;
    cases.push((input, Limitation::MissingDispatchFact));
    let mut input = baseline.clone();
    input.target = HttpTarget::McpAlias;
    cases.push((input, Limitation::UnsupportedTarget));
    for (input, limitation) in cases {
        let result = compiled.evaluate(&input).unwrap();
        assert_eq!(result.logical, LogicalDecision::Indeterminate);
        assert_eq!(result.effect, PolicyEffect::Block);
        assert_eq!(result.limitation, Some(limitation));
        assert!(!result.complete);
        assert!(!result.reusable_for(&input));
    }
    assert_eq!(
        compiled.evaluate(&baseline).unwrap().logical,
        LogicalDecision::Allow
    );
}

#[test]
fn an_uncaptured_host_is_unanswerable_only_when_a_route_could_turn_on_it() {
    // A host-qualified route makes the request host decisive, so not having it
    // is a question this kernel cannot answer -- even under `default_action:
    // allow`, where guessing would be the permissive direction.
    let compiled = compile(json!({
        "schema_version":"0.1.0","default_action":"allow",
        "routes":[{"hosts":["api.example.test"],"path_prefix":"/","permission":"read"}]
    }));
    let mut input = context(&compiled);
    input.request_host = HostFact::Missing;
    let result = compiled.evaluate(&input).unwrap();
    assert_eq!(result.limitation, Some(Limitation::MissingHostFact));
    assert_eq!(result.logical, LogicalDecision::Indeterminate);
    assert_eq!(result.effect, PolicyEffect::Block);
    assert!(!result.complete);

    // The same absent fact against a policy no route binds on is not a
    // limitation at all: it cannot change the answer, so it is not demanded.
    let unbound = compile(json!({
        "schema_version":"0.1.0","default_action":"allow",
        "routes":[{"path_prefix":"/","permission":"read"}]
    }));
    let mut input = context(&unbound);
    input.request_host = HostFact::Missing;
    let result = unbound.evaluate(&input).unwrap();
    assert_eq!(result.limitation, None);
    assert!(result.complete);
}

#[test]
fn a_classified_dispatch_without_its_facts_is_indeterminate() {
    let compiled = compile(json!({
        "schema_version":"0.1.0","default_action":"allow",
        "rules":[{"path":"/**","dispatch":{"kind":"contextless"},"action":"allow"}]
    }));
    let mut input = context(&compiled);
    input.target = HttpTarget::ProxyDispatch;
    input.dispatch = None;
    let result = compiled.evaluate(&input).unwrap();
    assert_eq!(result.limitation, Some(Limitation::MissingDispatchFact));
    assert_eq!(result.effect, PolicyEffect::Block);

    // Routing that was never classified stays unanswerable: a dispatch-scoped
    // rule would silently not apply, which is not the same as not matching.
    let mut input = context(&compiled);
    input.target = HttpTarget::Missing;
    let result = compiled.evaluate(&input).unwrap();
    assert_eq!(result.limitation, Some(Limitation::MissingDispatchFact));

    // MCP aliases still need their raw and canonical identities evaluated
    // together, and that lane is not this one.
    let mut input = context(&compiled);
    input.target = HttpTarget::McpAlias;
    let result = compiled.evaluate(&input).unwrap();
    assert_eq!(result.limitation, Some(Limitation::UnsupportedTarget));
}

#[test]
fn malformed_and_oversized_contexts_reject_before_missing_fact_results() {
    let compiled = compile(basic_policy());
    for path in [
        "",
        "relative",
        "https://example.test/data",
        "/data?query",
        "/data#fragment",
        "/data\n",
        "/data%20item",
        "/data//item",
        "/data/../item",
    ] {
        let mut input = context(&compiled);
        input.path = Some(path.to_owned());
        input.principal = PrincipalFact::Missing;
        assert_eq!(
            compiled.evaluate(&input),
            Err(EvaluationError::MalformedPath)
        );
    }
    let mut input = context(&compiled);
    input.path = Some(format!("/{}", "a".repeat(8192)));
    assert_eq!(
        compiled.evaluate(&input),
        Err(EvaluationError::ContextTooLarge)
    );
    let mut input = context(&compiled);
    input.version += 1;
    assert_eq!(
        compiled.evaluate(&input),
        Err(EvaluationError::UnsupportedContextVersion)
    );
    let mut input = context(&compiled);
    let mut identity = principal(&["reader"]);
    identity.user_id.clear();
    input.principal = PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&identity));
    assert_eq!(
        compiled.evaluate(&input),
        Err(EvaluationError::InvalidPrincipal)
    );
}

#[test]
fn results_bind_exact_source_context_semantics_and_available_revision() {
    let source = serde_json::to_vec(&basic_policy()).unwrap();
    let compiled = CompiledPolicy::compile(&source, PolicyAuthority::Standalone).unwrap();
    let input = context(&compiled);
    let result = compiled.evaluate(&input).unwrap();
    assert!(result.reusable_for(&input));
    let mut formatted_source = source.clone();
    formatted_source.push(b'\n');
    let reformatted =
        CompiledPolicy::compile(&formatted_source, PolicyAuthority::Standalone).unwrap();
    assert_ne!(compiled.snapshot(), reformatted.snapshot());
    assert_eq!(
        reformatted.evaluate(&input),
        Err(EvaluationError::SnapshotMismatch)
    );
    assert!(!result.reusable_for(&context(&reformatted)));
    for revision in [0, 1, 2] {
        let revised = CompiledPolicy::compile(
            &source,
            PolicyAuthority::PostgreSql {
                security_revision: revision,
            },
        )
        .unwrap();
        assert!(!result.reusable_for(&context(&revised)));
        assert_eq!(
            revised.evaluate(&input),
            Err(EvaluationError::SnapshotMismatch)
        );
    }
    let mut changed = input.clone();
    changed.method = Some(Method::POST);
    assert!(!result.reusable_for(&changed));
    let mut changed = input.clone();
    changed.path = Some("/elsewhere".to_owned());
    assert!(!result.reusable_for(&changed));
    let mut changed = input.clone();
    changed.principal =
        PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal(&["reader"])));
    assert!(!result.reusable_for(&changed));
    let mut changed = input.clone();
    changed.snapshot.semantics_version = "future";
    assert_eq!(
        compiled.evaluate(&changed),
        Err(EvaluationError::SnapshotMismatch)
    );
    assert!(!result.reusable_for(&changed));
    assert_eq!(
        CompiledPolicy::compile(
            &source,
            PolicyAuthority::PostgreSql {
                security_revision: -1
            }
        )
        .unwrap_err(),
        CompileError::InvalidRevision
    );
}

#[test]
fn pure_evaluation_is_thread_safe_deterministic_bounded_and_redacted_without_a_runtime() {
    let canary = "synthetic-private-value";
    let compiled = compile(json!({
        "schema_version":"0.1.0", "id":canary,
        "rules":[{"id":canary,"path":"/**","action":"shadow"}]
    }));
    let mut identity = principal(&[canary]);
    identity.user_id = canary.to_owned();
    identity.session_id = canary.to_owned();
    identity.email = Some(canary.to_owned());
    identity.org_id = Some(canary.to_owned());
    let projected = PrincipalIdentity::from_principal(&identity);
    assert!(projected.0.session_id.is_empty());
    assert!(projected.0.email.is_none());
    assert!(projected.0.org_id.is_none());
    let mut input = context(&compiled);
    input.path = Some(format!("/{canary}"));
    input.principal = PrincipalFact::Authenticated(projected);
    let expected = compiled.evaluate(&input).unwrap();
    let bytes = expected.canonical_trace_bytes().unwrap();
    assert!(bytes.len() <= MAX_TRACE_BYTES);
    assert!(!String::from_utf8(bytes.clone()).unwrap().contains(canary));
    assert!(!format!("{compiled:?} {input:?} {expected:?}").contains(canary));
    let trace: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(trace["domain"], HTTP_DOMAIN);
    for stage in [
        "authentication",
        "csrf",
        "mutable_capacity",
        "dns",
        "transport",
        "live_revision_freshness",
    ] {
        assert!(trace["not_evaluated"]
            .as_array()
            .unwrap()
            .contains(&json!(stage)));
    }
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..20 {
                    let actual = compiled.evaluate(&input).unwrap();
                    assert_eq!(actual, expected);
                    assert_eq!(actual.canonical_trace_bytes().unwrap(), bytes);
                }
            });
        }
    });
    identity.session_id = "different-unused-session".to_owned();
    input.principal = PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&identity));
    assert!(expected.reusable_for(&input));
}

#[test]
fn strict_offline_compiler_rejects_ambiguous_or_future_sources_with_safe_errors() {
    for source in [
        r#"{"schema_version":"0.1.0","default_action":"allow","default_action":"deny"}"#,
        r#"{"schema_version":"0.1.0","roles":{"reader":{"permissions":[],"permissions":["*"]}}}"#,
        r#"{"schema_version":"0.1.0"} {}"#,
    ] {
        assert_eq!(
            CompiledPolicy::compile(source.as_bytes(), PolicyAuthority::Standalone).unwrap_err(),
            CompileError::InvalidJson
        );
    }
    for version in ["0.1.1", "0.99.0", "1.0.0"] {
        let source = serde_json::to_vec(&json!({"schema_version":version})).unwrap();
        assert_eq!(
            CompiledPolicy::compile(&source, PolicyAuthority::Standalone).unwrap_err(),
            CompileError::UnsupportedSchema
        );
    }
    for extra in [
        json!({"future":"synthetic-private-value"}),
        json!({"rules":[{"path":"/**","action":"allow","future":"synthetic-private-value"}]}),
    ] {
        let mut value = basic_policy();
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let error = CompiledPolicy::compile(
            &serde_json::to_vec(&value).unwrap(),
            PolicyAuthority::Standalone,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CompileError::UnknownField | CompileError::InvalidPolicy
        ));
        assert!(!format!("{error:?}").contains("synthetic-private-value"));
    }
    assert_eq!(
        CompiledPolicy::compile(&vec![b' '; 1_048_577], PolicyAuthority::Standalone).unwrap_err(),
        CompileError::InputTooLarge
    );
}

#[test]
fn offline_compiler_preserves_fractional_and_exponent_numeric_fields() {
    for rate in ["0.5", "1.0", "1e1"] {
        let source = format!(
            r#"{{"schema_version":"0.1.0","rate_limits":[{{"requests_per_second":{rate},"burst":2}}]}}"#
        );
        let compiled =
            CompiledPolicy::compile(source.as_bytes(), PolicyAuthority::Standalone).unwrap();
        let legacy =
            Policy::validate_json_value(serde_json::from_slice(source.as_bytes()).unwrap())
                .unwrap();
        assert_eq!(compiled.engine.policy(), &legacy);
        assert_eq!(
            compiled.evaluate(&context(&compiled)).unwrap().reason,
            Reason::DefaultDeny
        );
    }
    let object_number = br#"{"schema_version":"0.1.0","rate_limits":[{"requests_per_second":{"$serde_json::private::Number":"0.5"},"burst":2}]}"#;
    assert_eq!(
        CompiledPolicy::compile(object_number, PolicyAuthority::Standalone).unwrap_err(),
        CompileError::InvalidPolicy
    );
}

#[test]
fn direct_principal_constraints_use_existing_identity_and_method_semantics() {
    let compiled = compile(json!({"schema_version":"0.1.0", "rules":[{
        "path":"/**", "action":"allow", "principal":{
            "roles":["reader"], "issuers":["https://idp.example.test///"],
            "principal_ids":["synthetic-user"], "auth_methods":["bearer_token"]
        }
    }]}));
    let mut input = context(&compiled);
    let identity = principal(&["reader"]);
    input.principal = PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&identity));
    assert_eq!(
        compiled.evaluate(&input).unwrap().logical,
        LogicalDecision::Allow
    );
    for altered in 0..4 {
        let mut denied = identity.clone();
        match altered {
            0 => denied.roles.clear(),
            1 => denied.issuer = None,
            2 => denied.user_id = "another-user".to_owned(),
            _ => denied.auth_method = AuthMethod::Cookie,
        }
        input.principal = PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&denied));
        assert_eq!(
            compiled.evaluate(&input).unwrap().reason,
            Reason::DefaultDeny
        );
    }
}

#[tokio::test]
async fn routing_lane_matches_current_middleware_for_host_bound_and_dispatch_scoped_requests() {
    // Same discipline as the contextless lane: the authoritative middleware is
    // the oracle. A second hand-written evaluator would only prove the kernel
    // agrees with a copy of itself, and the asymmetry under test -- a direct
    // allow losing its authority once an upstream is selected -- is exactly the
    // kind of rule a copy quietly gets wrong.
    const UPSTREAM: &str = "https://upstream.internal.test";
    for default in ["allow", "deny"] {
        for direct in [None, Some("allow"), Some("deny"), Some("shadow")] {
            let mut value = json!({
                "schema_version":"0.1.0","default_action":default,
                "roles":{"reader":{"permissions":["read"]}},
                "routes":[
                    {"hosts":["api.example.test"],"path_prefix":"/data","permission":"read"},
                    {"path_prefix":"/data","permission":"read"}
                ],
                "rules":[
                    {"id":"scoped","path":"/scoped/**","dispatch":{"kind":"route","route_id":"route-1"},"action":"deny"}
                ]
            });
            if let Some(action) = direct {
                value["rules"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"id":"broad","path":"/data/**","action":action}));
            }
            let compiled = compile(value.clone());
            let policy = Policy::validate_json_value(value).unwrap();
            let capture = CaptureSink::new();
            let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
            let state = RbacState::new(policy.clone(), Vec::new(), false, audit.clone());
            let router = Router::new()
                .fallback(any(|| async { "local" }))
                .layer(from_fn_with_state(state, rbac_middleware));

            let mut expected_events = Vec::new();
            for route_host in [None, Some("api.example.test"), Some("other.example.test")] {
                for request_host in ["api.example.test", "API.EXAMPLE.TEST", "other.example.test"] {
                    for path in ["/data/item", "/scoped/item"] {
                        for identity in [None, Some(principal(&["reader"]))] {
                            let observation = ProxyRouteObservationContext::new_with_route_id(
                                "route-1".to_owned(),
                                route_host.map(str::to_owned),
                                Some("/".to_owned()),
                                UPSTREAM.to_owned(),
                            );
                            // Production derives the authorization context from
                            // the observation context, so a bound route host is
                            // what makes a virtual upstream selected.
                            let authorization = observation.authorization_context();

                            let mut input = context(&compiled);
                            input.path = Some(path.to_owned());
                            input.target = HttpTarget::ProxyDispatch;
                            input.request_host = HostFact::Present(request_host.to_owned());
                            input.dispatch = Some(DispatchFacts {
                                route_id: Some("route-1".to_owned()),
                                route_host: route_host.map(str::to_owned),
                                route_path_prefix: Some("/".to_owned()),
                                upstream_origin: UPSTREAM.to_owned(),
                            });
                            input.principal =
                                identity
                                    .as_ref()
                                    .map_or(PrincipalFact::Anonymous, |identity| {
                                        PrincipalFact::Authenticated(
                                            PrincipalIdentity::from_principal(identity),
                                        )
                                    });
                            let result = compiled.evaluate(&input).unwrap();

                            let mut request = Request::builder()
                                .method(Method::GET)
                                .uri(path)
                                .header("host", request_host)
                                .body(Body::empty())
                                .unwrap();
                            request
                                .extensions_mut()
                                .insert(ProxyRouteClassificationCompleted);
                            request.extensions_mut().insert(observation);
                            if let Some(authorization) = authorization {
                                request.extensions_mut().insert(authorization);
                            }
                            if let Some(identity) = identity {
                                request.extensions_mut().insert(identity);
                            }
                            let response = router.clone().oneshot(request).await.unwrap();
                            let live = response.extensions().get::<PolicyDecision>().unwrap();

                            let label = format!(
                                "{default}/{direct:?} route_host={route_host:?} request_host={request_host} {path}"
                            );
                            let (outcome, status, event) = match result.effect {
                                PolicyEffect::Allow => (
                                    PolicyDecisionOutcome::Allowed,
                                    StatusCode::OK,
                                    "authz.allowed",
                                ),
                                PolicyEffect::Observe => (
                                    PolicyDecisionOutcome::WouldDeny,
                                    StatusCode::OK,
                                    "authz.would_deny",
                                ),
                                PolicyEffect::Block => (
                                    PolicyDecisionOutcome::Denied,
                                    StatusCode::FORBIDDEN,
                                    "authz.denied",
                                ),
                            };
                            assert_eq!(live.outcome, outcome, "{label}");
                            assert_eq!(response.status(), status, "{label}");
                            assert_eq!(live.reason, result.reason.as_str(), "{label}");
                            match result.matched {
                                Some(RuleReference::Direct(index)) => assert_eq!(
                                    live.matched_rule_id,
                                    Some(
                                        policy.rules[index]
                                            .id
                                            .clone()
                                            .unwrap_or_else(|| index.to_string())
                                    ),
                                    "{label}"
                                ),
                                Some(RuleReference::Route(index)) => {
                                    assert_eq!(
                                        live.permission.as_deref(),
                                        Some(policy.routes[index].permission.as_str()),
                                        "{label}"
                                    );
                                    assert_eq!(
                                        live.path_prefix.as_deref(),
                                        Some(policy.routes[index].path_prefix.as_str()),
                                        "{label}"
                                    );
                                }
                                None => {
                                    assert_eq!(live.matched_rule_id, None, "{label}");
                                    assert_eq!(live.permission, None, "{label}");
                                }
                            }
                            assert!(result.complete, "{label}");
                            // A shadow rule the host binding stripped of its
                            // authority still records a would-deny first.
                            if result.observation.is_some() {
                                expected_events.push("authz.would_deny");
                            }
                            expected_events.push(event);
                        }
                    }
                }
            }
            audit.close_and_drain(Duration::from_secs(5)).await.unwrap();
            let events = capture.events();
            let observed: Vec<&str> = events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect();
            assert_eq!(observed, expected_events, "{default}/{direct:?}");
        }
    }
}

#[tokio::test]
async fn a_direct_allow_cannot_authorize_a_selected_upstream_but_a_deny_still_blocks() {
    // The asymmetry stated plainly, so a future simplification that collapses
    // it fails here with an obvious name rather than deep inside a matrix.
    const UPSTREAM: &str = "https://upstream.internal.test";
    for (action, expected) in [
        (json!("allow"), PolicyEffect::Block),
        (json!("deny"), PolicyEffect::Block),
    ] {
        let compiled = compile(json!({
            "schema_version":"0.1.0","default_action":"deny",
            "routes":[{"hosts":["other.example.test"],"path_prefix":"/data","permission":"read"}],
            "rules":[{"id":"broad","path":"/data/**","action":action}]
        }));
        let mut input = context(&compiled);
        input.path = Some("/data/item".to_owned());
        input.target = HttpTarget::ProxyDispatch;
        input.request_host = HostFact::Present("api.example.test".to_owned());
        input.dispatch = Some(DispatchFacts {
            route_id: None,
            route_host: Some("api.example.test".to_owned()),
            route_path_prefix: Some("/".to_owned()),
            upstream_origin: UPSTREAM.to_owned(),
        });
        let result = compiled.evaluate(&input).unwrap();
        assert_eq!(result.effect, expected, "{action}");
        // The allow did not decide, and no host-bound route authorized the
        // selected upstream, so the refusal is the host-binding one rather than
        // the policy default -- which here would have been the same answer, and
        // under `default_action: allow` would not have been.
        if action == json!("allow") {
            assert_eq!(result.matched, None);
            assert_eq!(result.reason, Reason::HostPolicyRequired);
        } else {
            assert_eq!(result.matched, Some(RuleReference::Direct(0)));
        }

        // Without a selected upstream the same allow decides, as it always has.
        let mut unbound = input.clone();
        unbound.target = HttpTarget::Contextless;
        unbound.dispatch = None;
        let result = compiled.evaluate(&unbound).unwrap();
        assert_eq!(result.matched, Some(RuleReference::Direct(0)));
    }
}

#[test]
fn a_permissive_default_does_not_authorize_an_unrouted_virtual_upstream() {
    // The case where the host-binding refusal is not merely the same answer the
    // default would have given. `default_action: allow` means "allow what this
    // gateway serves directly", not "allow any virtual host reachable through
    // it", and shadow enforcement must not forward on that basis either.
    for mode in ["enforce", "shadow"] {
        let compiled = compile(json!({
            "schema_version":"0.1.0","default_action":"allow","enforcement_mode":mode,
            "routes":[{"hosts":["other.example.test"],"path_prefix":"/data","permission":"read"}]
        }));
        let mut input = context(&compiled);
        input.path = Some("/data/item".to_owned());
        input.target = HttpTarget::ProxyDispatch;
        input.request_host = HostFact::Present("api.example.test".to_owned());
        input.dispatch = Some(DispatchFacts {
            route_id: None,
            route_host: Some("api.example.test".to_owned()),
            route_path_prefix: Some("/".to_owned()),
            upstream_origin: "https://upstream.internal.test".to_owned(),
        });
        let result = compiled.evaluate(&input).unwrap();
        assert_eq!(result.logical, LogicalDecision::Deny, "{mode}");
        assert_eq!(result.effect, PolicyEffect::Block, "{mode}");
        assert_eq!(result.reason, Reason::HostPolicyRequired, "{mode}");
        assert!(result.complete, "{mode}");

        // The identical request with no upstream selected takes the default.
        let mut direct = input.clone();
        direct.target = HttpTarget::Contextless;
        direct.dispatch = None;
        let result = compiled.evaluate(&direct).unwrap();
        assert_eq!(result.logical, LogicalDecision::Allow, "{mode}");
        assert_eq!(result.reason, Reason::DefaultAllow, "{mode}");
    }
}

#[test]
fn dispatch_facts_on_a_non_dispatch_target_are_rejected_rather_than_ignored() {
    // Two readings of one context is the bug: the target says there is no
    // dispatch, the facts say a virtual upstream was selected. Ignoring the
    // facts would drop the `route_host` that makes a refusal a refusal.
    let compiled = compile(json!({
        "schema_version":"0.1.0","default_action":"allow",
        "routes":[{"hosts":["other.example.test"],"path_prefix":"/data","permission":"read"}]
    }));
    let facts = DispatchFacts {
        route_id: None,
        route_host: Some("api.example.test".to_owned()),
        route_path_prefix: Some("/".to_owned()),
        upstream_origin: "https://upstream.internal.test".to_owned(),
    };
    for target in [
        HttpTarget::Contextless,
        HttpTarget::Missing,
        HttpTarget::McpAlias,
    ] {
        let mut input = context(&compiled);
        input.target = target;
        input.dispatch = Some(facts.clone());
        assert_eq!(
            compiled.evaluate(&input),
            Err(EvaluationError::InconsistentContext),
            "{target:?}"
        );
    }

    // The same facts under the target that evaluates them are accepted.
    let mut input = context(&compiled);
    input.target = HttpTarget::ProxyDispatch;
    input.dispatch = Some(facts);
    assert!(compiled.evaluate(&input).is_ok());
}

fn dispatch_with_host(route_host: Option<&str>) -> DispatchFacts {
    DispatchFacts {
        route_id: None,
        route_host: route_host.map(str::to_owned),
        route_path_prefix: Some("/".to_owned()),
        upstream_origin: "https://upstream.internal.test".to_owned(),
    }
}

#[test]
fn a_host_that_is_not_a_bare_hostname_is_rejected() {
    // The routing lane compares hosts with port and brackets already stripped.
    // A value still carrying either would silently fail every comparison, which
    // looks like a policy decision rather than the malformed input it is.
    let compiled = compile(basic_policy());
    // Note `2001:db8::1:8443` is absent on purpose: it is a valid IPv6 address,
    // indistinguishable from a host with a port, and the helper never strips a
    // port from an unbracketed value. Refusing it would refuse a real host.
    for host in [
        "",
        "api.example.test:8443",
        "api.example.test/data",
        "[2001:db8::1]",
        "[2001:db8::1]:8443",
    ] {
        let mut input = context(&compiled);
        input.request_host = HostFact::Present(host.to_owned());
        assert_eq!(
            compiled.evaluate(&input),
            Err(EvaluationError::InvalidHost),
            "request host {host}"
        );

        let mut input = context(&compiled);
        input.target = HttpTarget::ProxyDispatch;
        input.dispatch = Some(dispatch_with_host(Some(host)));
        assert_eq!(
            compiled.evaluate(&input),
            Err(EvaluationError::InvalidHost),
            "route host {host}"
        );
    }
}

#[test]
fn an_ipv6_request_host_is_evaluated_rather_than_refused_as_malformed() {
    // `request_host_without_port` turns `[2001:db8::1]:8443` into the bare
    // literal, colons intact. Refusing every colon would leave the kernel unable
    // to answer for an IPv6 request at all -- including one whose policy has no
    // host-qualified route, where the host could not have changed the decision.
    //
    // A policy cannot bind a route to an IPv6 literal: route hosts must be DNS
    // hostnames (`is_valid_hostname_without_port`). So the request host is the
    // only place such a value appears, and the decision it must not break is the
    // ordinary direct-rule, unbound-route or default one.
    let compiled = compile(json!({
        "schema_version":"0.1.0","default_action":"deny",
        "roles":{"reader":{"permissions":["read"]}},
        "routes":[
            {"hosts":["api.example.test"],"path_prefix":"/bound","permission":"read"},
            {"path_prefix":"/data","permission":"read"}
        ],
        "rules":[{"id":"broad","path":"/direct/**","action":"allow"}]
    }));
    for host in [
        "2001:db8::1",
        "::1",
        "2001:DB8::1",
        "fe80::1ff:fe23:4567:890a",
    ] {
        for (path, expected) in [
            ("/direct/item", Some(RuleReference::Direct(0))),
            ("/data/item", Some(RuleReference::Route(1))),
            ("/elsewhere", None),
        ] {
            let mut input = context(&compiled);
            input.path = Some(path.to_owned());
            input.request_host = HostFact::Present(host.to_owned());
            let result = compiled
                .evaluate(&input)
                .unwrap_or_else(|error| panic!("{host} {path} rejected as {error:?}"));
            assert!(result.complete, "{host} {path}");
            assert_eq!(result.matched, expected, "{host} {path}");
        }

        // The host-qualified route simply does not match, which is a decision
        // rather than an error -- the distinction this whole fix is about.
        let mut input = context(&compiled);
        input.path = Some("/bound/item".to_owned());
        input.request_host = HostFact::Present(host.to_owned());
        let result = compiled.evaluate(&input).unwrap();
        assert_eq!(result.matched, None, "{host}");
        assert_eq!(result.reason, Reason::DefaultDeny, "{host}");
    }
}

#[test]
fn a_classified_dispatch_with_no_upstream_identity_is_rejected() {
    // An origin-less dispatch has no identity at all, and a `kind: contextless`
    // rule matches exactly that shape -- so a contextless-only allow would
    // authorize what the caller labeled a proxy dispatch. Production's
    // observation context always carries an origin; so must this.
    let compiled = compile(json!({
        "schema_version":"0.1.0","default_action":"deny",
        "rules":[{"id":"ctx","path":"/**","dispatch":{"kind":"contextless"},"action":"allow"}]
    }));
    let mut input = context(&compiled);
    input.target = HttpTarget::ProxyDispatch;
    input.dispatch = Some(DispatchFacts {
        route_id: None,
        route_host: None,
        route_path_prefix: None,
        upstream_origin: String::new(),
    });
    assert_eq!(
        compiled.evaluate(&input),
        Err(EvaluationError::InconsistentContext)
    );

    // With an origin the same rule correctly does not match, because the
    // dispatch is no longer contextless.
    let mut input = context(&compiled);
    input.target = HttpTarget::ProxyDispatch;
    input.dispatch = Some(dispatch_with_host(None));
    let result = compiled.evaluate(&input).unwrap();
    assert_eq!(result.matched, None);
    assert_eq!(result.reason, Reason::DefaultDeny);
}

#[test]
fn a_route_host_alone_makes_the_host_binding_mandatory() {
    // The host binding is derived from `route_host`, never carried twice, so a
    // caller cannot supply the route host and omit the fact that enforces it.
    let compiled = compile(json!({
        "schema_version":"0.1.0","default_action":"allow",
        "routes":[{"hosts":["other.example.test"],"path_prefix":"/data","permission":"read"}],
        "rules":[{"id":"broad","path":"/data/**","action":"allow"}]
    }));
    let mut input = context(&compiled);
    input.path = Some("/data/item".to_owned());
    input.target = HttpTarget::ProxyDispatch;
    input.request_host = HostFact::Present("api.example.test".to_owned());
    input.dispatch = Some(dispatch_with_host(Some("api.example.test")));
    let result = compiled.evaluate(&input).unwrap();
    assert_eq!(result.reason, Reason::HostPolicyRequired);
    assert_eq!(result.effect, PolicyEffect::Block);

    // No bound route host is no selected upstream, so the broad allow decides.
    let mut input = context(&compiled);
    input.path = Some("/data/item".to_owned());
    input.target = HttpTarget::ProxyDispatch;
    input.request_host = HostFact::Present("api.example.test".to_owned());
    input.dispatch = Some(dispatch_with_host(None));
    let result = compiled.evaluate(&input).unwrap();
    assert_eq!(result.matched, Some(RuleReference::Direct(0)));
    assert_eq!(result.effect, PolicyEffect::Allow);
}
