use super::*;
use crate::{
    audit::{sink::tests::CaptureSink, AuditLog, AuditSink},
    auth::{actor_from_principal, AuthMethod},
    middleware::rbac::RbacState,
    policy_eval::{PolicyAuthority, PrincipalIdentity},
    rbac::Policy,
    tools::runtime::{ToolInvocationContext, ToolRuntime, ToolRuntimeConfig, ToolRuntimeError},
};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

fn principal() -> Principal {
    Principal {
        user_id: "synthetic-subject".into(),
        issuer: Some("https://idp.example.test".into()),
        roles: vec!["reader".into()],
        auth_method: AuthMethod::Bearer,
        email: Some("synthetic-email@example.test".into()),
        org_id: Some("synthetic-organization".into()),
        session_id: "synthetic-session".into(),
    }
}

fn input(
    compiled: &CompiledPolicy,
    operation: ToolOperation,
    identity: Option<&Principal>,
) -> ToolEvaluationContext {
    ToolEvaluationContext {
        version: TOOL_CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        operation,
        tool_name: Some("reports.export".into()),
        principal: identity.map_or(PrincipalFact::Anonymous, |p| {
            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(p))
        }),
        method: (operation == ToolOperation::RenderedHttp).then_some(Method::GET),
        path: (operation == ToolOperation::RenderedHttp).then(|| "/reports/42".into()),
    }
}

fn compile(value: Value) -> CompiledPolicy {
    CompiledPolicy::compile(
        &serde_json::to_vec(&value).unwrap(),
        PolicyAuthority::Standalone,
    )
    .unwrap()
}

fn base() -> Value {
    json!({"schema_version":"0.1.0", "default_action":"deny", "tools":{"reports.export":{}}})
}

fn live(policy: &Policy) -> (RbacState, ToolRuntime, AuditLog, CaptureSink) {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let state = RbacState::new(policy.clone(), vec![], false, audit.clone());
    let runtime = ToolRuntime::new_with_rbac_state(
        ToolRuntimeConfig::default().with_policy_tools(policy),
        audit.clone(),
        Some(state.clone()),
    );
    (state, runtime, audit, capture)
}

fn expected_event(
    result: &ToolEvaluation,
    policy: &Policy,
    request_id: &str,
) -> Option<(String, String, String)> {
    let Some(RuleReference::Direct(index)) = result.matched() else {
        return None;
    };
    let event = match result.effect() {
        PolicyEffect::Allow => "authz.allowed",
        PolicyEffect::Block => "authz.denied",
        PolicyEffect::Observe => "authz.would_deny",
    };
    Some((
        request_id.into(),
        event.into(),
        policy.rules[index]
            .id
            .clone()
            .unwrap_or_else(|| index.to_string()),
    ))
}

async fn assert_audit(
    audit: AuditLog,
    capture: CaptureSink,
    expected: Vec<(String, String, String)>,
) {
    audit.close_and_drain(Duration::from_secs(5)).await.unwrap();
    let actual: Vec<_> = capture
        .events()
        .iter()
        .filter(|e| e.event_type.starts_with("authz."))
        .map(|e| {
            (
                e.request_id.clone(),
                e.event_type.clone(),
                e.payload["matched_rule_id"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn policy_backed_invocation_visibility_inventory_and_composite_match_live_consumers() {
    // Compare the unchanged authoritative consumers, including invocation's
    // rule check AFTER policy entry admission. Local work never performs I/O.
    for global in ["enforce", "shadow"] {
        for default in ["deny", "allow"] {
            for action in [None, Some("allow"), Some("deny"), Some("shadow")] {
                for constraint in [
                    json!({}),
                    json!({"allowed_roles":["reader"]}),
                    json!({"issuers":["https://idp.example.test/"]}),
                    json!({"auth_methods":["bearer_token"]}),
                    json!({"allowed_roles":["reader"],"issuers":["https://idp.example.test"],"auth_methods":["bearer_token"]}),
                ] {
                    let mut value = json!({
                        "schema_version":"0.1.0", "default_action":default,"enforcement_mode":global,
                        // Tool roles use exact claims, not activation of this role definition.
                        "roles":{"reader":{"permissions":[],"auth_methods":["service_token"]}},
                        "tools":{"reports.export":constraint,"disabled":{"enabled":false}},
                        "rules":[{"id":"inactive","tool_name":"reports.export","enabled":false,"action":"deny"}, {"path":"/**","action":"deny"}]
                    });
                    if let Some(action) = action {
                        value["rules"].as_array_mut().unwrap().extend([
                            json!({"id":"first-tool","tool_name":"reports.export","action":action}),
                            json!({"id":"later-tool","tool_name":"reports.export","action":"deny"}),
                            json!({"tool_name":"disabled","action":"deny"}),
                        ]);
                    }
                    let policy = Policy::validate_json_value(value).unwrap();
                    let (state, runtime, audit, capture) = live(&policy);
                    let installed = state.installed_compiled_policy();
                    let compiled = installed.compiled();
                    let mut wrong_role = principal();
                    wrong_role.roles = vec!["other".into()];
                    let mut wrong_issuer = principal();
                    wrong_issuer.issuer = Some("https://other.example.test".into());
                    let mut cookie = principal();
                    cookie.auth_method = AuthMethod::Cookie;
                    let mut service = principal();
                    service.auth_method = AuthMethod::ServiceToken;
                    let mut expected = Vec::new();
                    for (i, identity) in [
                        None,
                        Some(principal()),
                        Some(wrong_role),
                        Some(wrong_issuer),
                        Some(cookie),
                        Some(service),
                    ]
                    .iter()
                    .enumerate()
                    {
                        for name in ["reports.export", "reports.unknown", "disabled", "absent"] {
                            let context = ToolInvocationContext {
                                request_id: format!("fixture-{i}-{name}"),
                                actor: identity.as_ref().map(actor_from_principal),
                                ..ToolInvocationContext::default()
                            };
                            let mut question =
                                input(compiled, ToolOperation::Invocation, identity.as_ref());
                            question.tool_name = Some(name.into());
                            let answer = compiled.evaluate_tool(&question).unwrap();
                            let mut work_ran = false;
                            let executed = runtime
                                .execute_with_context(
                                    name,
                                    context.clone(),
                                    CancellationToken::new(),
                                    || {
                                        work_ran = true;
                                        async {}
                                    },
                                )
                                .await;
                            assert_eq!(
                                executed.is_ok(),
                                answer.effect() != PolicyEffect::Block,
                                "{name}, {action:?}, {default}, {global}, {i}"
                            );
                            assert_eq!(work_ran, executed.is_ok());
                            if let Err(error) = executed {
                                let reason = match error {
                                    ToolRuntimeError::UnknownTool { .. } => "unknown_tool",
                                    ToolRuntimeError::Disabled { .. } => "disabled",
                                    ToolRuntimeError::RoleDenied { .. } => "role_not_allowed",
                                    ToolRuntimeError::Rejected { ref reason, .. } => reason,
                                    _ => panic!("unexpected admission failure: {error:?}"),
                                };
                                assert_eq!(answer.reason().as_str(), reason);
                            }
                            expected.extend(expected_event(&answer, &policy, &context.request_id));
                            question.operation = ToolOperation::Visibility;
                            let visible = compiled.evaluate_tool(&question).unwrap();
                            assert_eq!(
                                visible.effect() == PolicyEffect::Allow,
                                runtime.tool_visible_to_context(name, &context)
                            );
                            if let Some(identity) = identity {
                                question.operation = ToolOperation::PolicyEligibility;
                                let eligibility = compiled.evaluate_tool(&question).unwrap();
                                let live = state.tool_policy_eligibility(name, identity);
                                assert_eq!(
                                    eligibility.effect() == PolicyEffect::Allow,
                                    live.eligible
                                );
                                assert_eq!(eligibility.reason().as_str(), live.reason);
                            }
                            question.operation = ToolOperation::CompositeLeaf;
                            question.principal = PrincipalFact::Missing;
                            let leaf = compiled.evaluate_tool(&question).unwrap();
                            assert_eq!(
                                leaf.effect() == PolicyEffect::Allow,
                                runtime.composite_leaf_enabled(name)
                            );
                            assert!(leaf.is_complete());
                            assert_eq!(leaf.matched(), None);
                        }
                    }
                    assert_audit(audit, capture, expected).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn rendered_http_matches_live_direct_rules_unknown_dispatch_and_audit_attribution() {
    for global in ["enforce", "shadow"] {
        for action in ["allow", "deny", "shadow"] {
            let policy = Policy::validate_json_value(json!({
                "schema_version":"0.1.0", "default_action":"deny", "enforcement_mode":global,
                "tools":{"reports.export":{"enabled":false}},
                "routes":[{"path_prefix":"/","permission":"unavailable"}],
                "rules":[
                    {"id":"contextless-must-not-match","path":"/**","dispatch":{"kind":"contextless"},"action":"deny"},
                    {"id":"tool-rule-must-not-match","tool_name":"reports.export","action":"deny"},
                    {"id":"rendered-rule","path":"/reports/{id}","methods":[" get "],"principal":{"roles":["reader"]},"action":action},
                    {"path":"/reports/**","methods":["GET"],"action":"deny"}
                ]
            })).unwrap();
            let (state, runtime, audit, capture) = live(&policy);
            let installed = state.installed_compiled_policy();
            let compiled = installed.compiled();
            let mut expected = Vec::new();
            for identity in [None, Some(principal())] {
                for path in [
                    "/reports/42",
                    "/reports/private%2Frecord",
                    "/reports/42/child",
                    "/elsewhere",
                ] {
                    for method in [Method::GET, Method::POST] {
                        let context = ToolInvocationContext {
                            request_id: format!("{path}-{method}-{}", identity.is_some()),
                            actor: identity.as_ref().map(actor_from_principal),
                            ..ToolInvocationContext::default()
                        };
                        let mut question =
                            input(compiled, ToolOperation::RenderedHttp, identity.as_ref());
                        question.path = Some(path.into());
                        question.method = Some(method.clone());
                        // Neither policy entry existence nor enablement decides this lane.
                        question.tool_name = Some("absent".into());
                        let answer = compiled.evaluate_tool(&question).unwrap();
                        assert_eq!(
                            answer.effect() != PolicyEffect::Block,
                            runtime.authorize_http_operation(
                                "absent",
                                method.as_str(),
                                path,
                                &context
                            )
                        );
                        expected.extend(expected_event(&answer, &policy, &context.request_id));
                        if path == "/elsewhere" || method == Method::POST {
                            assert_eq!(answer.reason(), ToolReason::NoHttpRule);
                        }
                    }
                }
            }
            assert_audit(audit, capture, expected).await;
        }
    }
}

#[test]
fn rendered_http_accepts_valid_segment_escapes_and_rejects_malformed_escapes() {
    let compiled = compile(json!({
        "schema_version":"0.1.0", "default_action":"deny",
        "tools":{"reports.export":{}},
        "rules":[{"path":"/reports/{id}","methods":["GET"],"action":"deny"}]
    }));
    let mut context = input(&compiled, ToolOperation::RenderedHttp, Some(&principal()));
    context.path = Some("/reports/private%2Frecord".into());
    let answer = compiled.evaluate_tool(&context).unwrap();
    assert_eq!(answer.effect(), PolicyEffect::Block);
    assert_eq!(answer.reason(), ToolReason::MatchedRule);

    for path in ["/reports/private%2", "/reports/private%GG"] {
        context.path = Some(path.into());
        assert!(matches!(
            compiled.evaluate_tool(&context),
            Err(EvaluationError::MalformedPath)
        ));
    }
}

#[tokio::test]
async fn runtime_actor_projection_and_inventory_identity_are_distinct_inputs() {
    let mut value = base();
    value["tools"]["reports.export"]["auth_methods"] = json!(["client_certificate"]);
    let policy = Policy::validate_json_value(value).unwrap();
    let (state, runtime, audit, capture) = live(&policy);
    let installed = state.installed_compiled_policy();
    let compiled = installed.compiled();
    let mut identity = principal();
    identity.auth_method = AuthMethod::ClientCertificate;
    let context = ToolInvocationContext {
        actor: Some(actor_from_principal(&identity)),
        ..ToolInvocationContext::default()
    };
    // This pins current behavior, not a recommendation for the later adapter:
    // ToolRuntime's actor projection does not recognize client certificates.
    let invocation = compiled
        .evaluate_tool(&input(compiled, ToolOperation::Invocation, None))
        .unwrap();
    assert_eq!(invocation.reason(), ToolReason::RoleNotAllowed);
    assert!(matches!(
        runtime
            .execute_with_context(
                "reports.export",
                context.clone(),
                CancellationToken::new(),
                || async {}
            )
            .await,
        Err(ToolRuntimeError::RoleDenied { .. })
    ));
    assert!(!runtime.tool_visible_to_context("reports.export", &context));
    let inventory = compiled
        .evaluate_tool(&input(
            compiled,
            ToolOperation::PolicyEligibility,
            Some(&identity),
        ))
        .unwrap();
    assert_eq!(inventory.effect(), PolicyEffect::Allow);
    assert!(
        state
            .tool_policy_eligibility("reports.export", &identity)
            .eligible
    );
    assert_audit(audit, capture, vec![]).await;
}

#[tokio::test]
async fn tool_rules_use_exact_names_and_first_matching_principal() {
    let mut value = base();
    value["rules"] = json!([
        {"id":"literal-star","tool_name":"reports.*","action":"deny"},
        {"id":"reader-only","tool_name":"reports.export","principal":{"roles":["reader"]},"action":"shadow"},
        {"tool_name":"reports.export","action":"allow"},
        {"id":"later-deny","tool_name":"reports.export","action":"deny"}
    ]);
    let policy = Policy::validate_json_value(value).unwrap();
    let (state, runtime, audit, capture) = live(&policy);
    let installed = state.installed_compiled_policy();
    let compiled = installed.compiled();
    let mut expected = Vec::new();
    for identity in [None, Some(principal())] {
        let context = ToolInvocationContext {
            request_id: format!("exact-name-{}", identity.is_some()),
            actor: identity.as_ref().map(actor_from_principal),
            ..ToolInvocationContext::default()
        };
        let answer = compiled
            .evaluate_tool(&input(
                compiled,
                ToolOperation::Invocation,
                identity.as_ref(),
            ))
            .unwrap();
        assert_eq!(
            answer.matched(),
            Some(RuleReference::Direct(if identity.is_some() {
                1
            } else {
                2
            }))
        );
        assert_eq!(
            answer.effect(),
            if identity.is_some() {
                PolicyEffect::Observe
            } else {
                PolicyEffect::Allow
            }
        );
        assert!(runtime
            .execute_with_context(
                "reports.export",
                context.clone(),
                CancellationToken::new(),
                || async {}
            )
            .await
            .is_ok());
        expected.extend(expected_event(&answer, &policy, &context.request_id));
    }
    assert_audit(audit, capture, expected).await;
}

#[test]
fn incomplete_invalid_and_inconsistent_facts_fail_closed() {
    let compiled = compile(base());
    for op in [
        ToolOperation::Invocation,
        ToolOperation::Visibility,
        ToolOperation::PolicyEligibility,
        ToolOperation::CompositeLeaf,
        ToolOperation::RenderedHttp,
    ] {
        let context = input(&compiled, op, Some(&principal()));
        let mut missing = context.clone();
        missing.tool_name = None;
        let answer = compiled.evaluate_tool(&missing).unwrap();
        assert_eq!(answer.limitation(), Some(ToolLimitation::ToolName));
        assert_eq!(answer.logical(), LogicalDecision::Indeterminate);
        assert_eq!(answer.effect(), PolicyEffect::Block);
        assert!(!answer.reusable_for(&missing));
        missing = context.clone();
        missing.principal = PrincipalFact::Missing;
        let answer = compiled.evaluate_tool(&missing).unwrap();
        assert_eq!(answer.is_complete(), op == ToolOperation::CompositeLeaf);
        if op != ToolOperation::CompositeLeaf {
            assert_eq!(answer.limitation(), Some(ToolLimitation::Principal));
        }
        let mut invalid = context.clone();
        invalid.version += 1;
        assert_eq!(
            compiled.evaluate_tool(&invalid),
            Err(EvaluationError::UnsupportedContextVersion)
        );
        invalid = context.clone();
        invalid.tool_name = Some("x".repeat(MAX_TOOL_NAME_BYTES + 1));
        assert_eq!(
            compiled.evaluate_tool(&invalid),
            Err(EvaluationError::ContextTooLarge)
        );
        invalid.tool_name = Some("x".repeat(MAX_TOOL_NAME_BYTES));
        assert!(compiled.evaluate_tool(&invalid).is_ok());
        let mut malformed = principal();
        malformed.user_id.clear();
        invalid = input(&compiled, op, Some(&malformed));
        assert_eq!(
            compiled.evaluate_tool(&invalid),
            Err(EvaluationError::InvalidPrincipal)
        );
        if op == ToolOperation::RenderedHttp {
            missing = context.clone();
            missing.method = None;
            assert_eq!(
                compiled.evaluate_tool(&missing).unwrap().limitation(),
                Some(ToolLimitation::Method)
            );
            missing = context.clone();
            missing.path = None;
            assert_eq!(
                compiled.evaluate_tool(&missing).unwrap().limitation(),
                Some(ToolLimitation::Path)
            );
            for path in [
                "relative",
                "/reports?private=synthetic",
                "/../reports",
                "/reports#fragment",
            ] {
                invalid = context.clone();
                invalid.path = Some(path.into());
                assert_eq!(
                    compiled.evaluate_tool(&invalid),
                    Err(EvaluationError::MalformedPath)
                );
            }
        } else {
            invalid = context.clone();
            invalid.path = Some("/reports".into());
            assert_eq!(
                compiled.evaluate_tool(&invalid),
                Err(EvaluationError::InconsistentContext)
            );
        }
    }
    assert_eq!(
        compiled.evaluate_tool(&input(&compiled, ToolOperation::PolicyEligibility, None)),
        Err(EvaluationError::InconsistentContext)
    );
}

#[test]
fn every_deciding_fact_and_operation_is_bound_and_nonpolicy_identity_is_dropped() {
    let compiled = compile(base());
    let context = input(&compiled, ToolOperation::RenderedHttp, Some(&principal()));
    let answer = compiled.evaluate_tool(&context).unwrap();
    assert!(answer.reusable_for(&context));
    let mut changed = Vec::new();
    let mut c = context.clone();
    c.tool_name = Some("other".into());
    changed.push(c);
    let mut c = context.clone();
    c.method = Some(Method::POST);
    changed.push(c);
    let mut c = context.clone();
    c.path = Some("/other".into());
    changed.push(c);
    let mut c = context.clone();
    c.version += 1;
    changed.push(c);
    let mut c = context.clone();
    c.principal = PrincipalFact::Anonymous;
    changed.push(c);
    let mut c = context.clone();
    c.snapshot.authority = PolicyAuthority::PostgreSql {
        security_revision: 1,
    };
    changed.push(c);
    let mut other_policy = base();
    other_policy["default_action"] = json!("allow");
    let mut c = context.clone();
    c.snapshot = compile(other_policy).snapshot();
    changed.push(c);
    for op in [
        ToolOperation::Invocation,
        ToolOperation::Visibility,
        ToolOperation::PolicyEligibility,
        ToolOperation::CompositeLeaf,
    ] {
        changed.push(input(&compiled, op, Some(&principal())));
    }
    for field in 0..4 {
        let mut p = principal();
        match field {
            0 => p.user_id = "other".into(),
            1 => p.issuer = None,
            2 => p.roles.clear(),
            _ => p.auth_method = AuthMethod::Cookie,
        }
        changed.push(input(&compiled, ToolOperation::RenderedHttp, Some(&p)));
    }
    for other in changed {
        assert!(!answer.reusable_for(&other));
    }
    let mut p = principal();
    p.email = None;
    p.org_id = None;
    p.session_id = "another-session".into();
    assert!(answer.reusable_for(&input(&compiled, ToolOperation::RenderedHttp, Some(&p))));
    let mut mismatch = context;
    mismatch.snapshot.authority = PolicyAuthority::PostgreSql {
        security_revision: 1,
    };
    assert_eq!(
        compiled.evaluate_tool(&mismatch),
        Err(EvaluationError::SnapshotMismatch)
    );
}

#[test]
fn pure_tool_evaluation_is_thread_safe_bounded_redacted_and_deterministic_without_runtime() {
    let mut value = base();
    value["rules"] =
        json!([{"id":"synthetic-rule-id","tool_name":"reports.export","action":"shadow"}]);
    let compiled = compile(value);
    let context = input(&compiled, ToolOperation::Invocation, Some(&principal()));
    let answer = compiled.evaluate_tool(&context).unwrap();
    assert_eq!(answer.logical(), LogicalDecision::Deny);
    assert_eq!(answer.effect(), PolicyEffect::Observe);
    let bytes = answer.canonical_trace_bytes().unwrap();
    assert!(bytes.len() <= MAX_TRACE_BYTES);
    let text = format!(
        "{} {answer:?} {context:?}",
        String::from_utf8(bytes.clone()).unwrap()
    );
    for secret in [
        "synthetic-subject",
        "idp.example.test",
        "reader",
        "synthetic-session",
        "synthetic-email",
        "synthetic-organization",
        "synthetic-rule-id",
        "reports.export",
    ] {
        assert!(!text.contains(secret), "leaked {secret}");
    }
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..50 {
                    assert_eq!(
                        compiled
                            .evaluate_tool(&context)
                            .unwrap()
                            .canonical_trace_bytes()
                            .unwrap(),
                        bytes
                    );
                }
            });
        }
    });
}

#[tokio::test]
async fn evaluating_all_tool_operations_emits_no_audit_events() {
    let mut value = base();
    value["rules"] =
        json!([{"tool_name":"reports.export","action":"shadow"}, {"path":"/**","action":"deny"}]);
    let policy = Policy::validate_json_value(value).unwrap();
    let (state, _runtime, audit, capture) = live(&policy);
    let installed = state.installed_compiled_policy();
    let compiled = installed.compiled();
    for op in [
        ToolOperation::Invocation,
        ToolOperation::Visibility,
        ToolOperation::PolicyEligibility,
        ToolOperation::CompositeLeaf,
        ToolOperation::RenderedHttp,
    ] {
        let mut context = input(compiled, op, Some(&principal()));
        assert!(compiled.evaluate_tool(&context).unwrap().is_complete());
        context.tool_name = None;
        assert!(!compiled.evaluate_tool(&context).unwrap().is_complete());
    }
    audit.close_and_drain(Duration::from_secs(5)).await.unwrap();
    assert!(capture.events().is_empty());
}
