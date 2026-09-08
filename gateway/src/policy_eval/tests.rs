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
    for target in [HttpTarget::ProxyDispatch, HttpTarget::McpAlias] {
        let mut input = baseline.clone();
        input.target = target;
        cases.push((input, Limitation::UnsupportedTarget));
    }
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
fn routing_contracts_remain_explicitly_unsupported_even_with_permissive_defaults() {
    for extra in [
        json!({"routes":[{"hosts":["api.example.test"],"path_prefix":"/","permission":"read"}]}),
        json!({"rules":[{"path":"/**","dispatch":{"kind":"contextless"},"action":"allow"}]}),
    ] {
        let mut value = json!({"schema_version":"0.1.0","default_action":"allow"});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let compiled = compile(value);
        let result = compiled.evaluate(&context(&compiled)).unwrap();
        assert_eq!(
            result.limitation,
            Some(Limitation::UnsupportedRoutingPolicy)
        );
        assert_eq!(result.effect, PolicyEffect::Block);
    }
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
    assert_eq!(trace["domain"], "http_contextless_v1");
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
