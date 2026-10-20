use super::*;
use crate::{
    audit::{sink::tests::CaptureSink, AuditLog, AuditSink},
    auth::{actor_from_principal, AuthMethod},
    middleware::rbac::{RbacState, ToolPolicyEligibility},
    policy_eval::{PolicyAuthority, PrincipalIdentity},
    rbac::Policy,
    request_bounds::MAX_REQUEST_PATH_BYTES,
    tools::runtime::{
        ToolInvocationContext, ToolInvocationSource, ToolRuntime, ToolRuntimeConfig,
        ToolRuntimeError,
    },
};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};
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
async fn live_adapters_translate_the_kernel_answer_for_invocation_visibility_inventory_and_composite(
) {
    // Since #422 PR 2 the live consumers decide through the kernel, so this is
    // not parity evidence: it checks that each adapter translates the
    // installed kernel's answer faithfully -- invocation errors, whether work
    // ran, rule attribution after policy-entry admission, visibility,
    // inventory reasons and composite enablement. The parity evidence is the
    // frozen-oracle comparison further down. Local work never performs I/O.
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

// Old against new (#422 PR 2). The oracle is the frozen pre-cutover
// implementation -- `tools::runtime::legacy` over `middleware::rbac::legacy`,
// as the tool lane stood at 05c295a -- never a hand-written evaluator. Both
// sides answer every question below on their own runtime, and the audit each
// one emitted is compared record for record.

const POLICY_NAMES: [&str; 3] = ["reports.export", "reports.import", "admin.reset"];
/// Every name a generated policy can carry, and one none does.
const PROBED_NAMES: [&str; 4] = [
    "reports.export",
    "reports.import",
    "admin.reset",
    "reports.unknown",
];
const RENDERED_METHODS: [&str; 3] = ["GET", "POST", "DELETE"];
const RENDERED_PATHS: [&str; 4] = [
    "/reports/42",
    "/reports/42/child",
    "/reports/private%2Frecord",
    "/elsewhere",
];

/// Each identity varies one fact a tool entry or rule can constrain. A client
/// certificate is projected away by the runtime's Actor projection and kept by
/// inventory, on both sides alike.
fn differential_identities() -> Vec<Option<Principal>> {
    let mut writer = principal();
    writer.roles = vec!["writer".into(), "role-7".into()];
    writer.auth_method = AuthMethod::Cookie;
    let mut service = principal();
    service.auth_method = AuthMethod::ServiceToken;
    service.issuer = None;
    let mut certificate = principal();
    certificate.auth_method = AuthMethod::ClientCertificate;
    let mut other_issuer = principal();
    other_issuer.issuer = Some("https://other.example.test".into());
    let mut many_roles = principal();
    many_roles.roles = (0..256).map(|index| format!("role-{index}")).collect();
    vec![
        None,
        Some(principal()),
        Some(writer),
        Some(service),
        Some(certificate),
        Some(other_issuer),
        Some(many_roles),
    ]
}

fn differential_context(
    index: usize,
    name: &str,
    identity: Option<&Principal>,
) -> ToolInvocationContext {
    ToolInvocationContext {
        request_id: format!("differential-{index}-{name}"),
        source_ip: "203.0.113.7".into(),
        actor: identity.map(actor_from_principal),
        // The admin playground audits a rendered request under its tool path.
        source: if index.is_multiple_of(2) {
            ToolInvocationSource::Mcp
        } else {
            ToolInvocationSource::AdminPlayground
        },
        admitted_deadline: None,
    }
}

/// Everything an audit record carries except its own id and time.
fn audit_records(capture: &CaptureSink) -> Vec<Value> {
    capture
        .events()
        .iter()
        .map(|event| {
            json!({
                "event_type": event.event_type,
                "request_id": event.request_id,
                "source_ip": event.source_ip,
                "actor": serde_json::to_value(&event.actor).unwrap(),
                "payload": event.payload,
            })
        })
        .collect()
}

/// Ask the frozen consumers and the live runtime every tool-lane question
/// about `policy`, require the same answers, the same audit, and the same
/// outcome from a served invocation.
async fn assert_old_and_new_agree(policy: &Policy) {
    let (state_old, runtime_old, audit_old, capture_old) = live(policy);
    let (state_new, runtime_new, audit_new, capture_new) = live(policy);
    let (_, runtime_served, _, _) = live(policy);
    for (index, identity) in differential_identities().iter().enumerate() {
        for name in PROBED_NAMES {
            let context = differential_context(index, name, identity.as_ref());
            let old = runtime_old.legacy_admit(name, &context);
            let new = runtime_new.admit_for_differential(name, &context);
            assert_eq!(old, new, "admission of {name} for identity {index}");

            let mut work_ran = false;
            let served = runtime_served
                .execute_with_context(name, context.clone(), CancellationToken::new(), || {
                    work_ran = true;
                    async {}
                })
                .await;
            assert_eq!(served.as_ref().err(), old.as_ref().err(), "served {name}");
            assert_eq!(work_ran, old.is_ok(), "work for {name}");

            assert_eq!(
                runtime_old.legacy_tool_visible_to_context(name, &context),
                runtime_new.tool_visible_to_context(name, &context),
                "visibility of {name} for identity {index}"
            );
            assert_eq!(
                runtime_old.legacy_composite_leaf_enabled(name),
                runtime_new.composite_leaf_enabled(name),
                "composite enablement of {name}"
            );
            if let Some(identity) = identity {
                assert_eq!(
                    state_old.legacy_tool_policy_eligibility(name, identity),
                    state_new.tool_policy_eligibility(name, identity),
                    "eligibility of {name} for identity {index}"
                );
            }
            for method in RENDERED_METHODS {
                for path in RENDERED_PATHS {
                    assert_eq!(
                        runtime_old.legacy_authorize_http_operation(name, method, path, &context),
                        runtime_new.authorize_http_operation(name, method, path, &context),
                        "rendered {method} {path} for identity {index}"
                    );
                }
            }
        }
    }
    audit_old
        .close_and_drain(Duration::from_secs(5))
        .await
        .unwrap();
    audit_new
        .close_and_drain(Duration::from_secs(5))
        .await
        .unwrap();
    let old = audit_records(&capture_old);
    assert!(
        !old.is_empty(),
        "the corpus must exercise audited decisions"
    );
    assert_eq!(old, audit_records(&capture_new));
}

fn auth_method_set(code: u8) -> Option<Value> {
    match code {
        1 => Some(json!(["bearer_token"])),
        2 => Some(json!(["session_cookie"])),
        3 => Some(json!(["service_token"])),
        4 => Some(json!(["client_certificate"])),
        5 => Some(json!(["bearer_token", "session_cookie"])),
        _ => None,
    }
}

type GeneratedEntry = (usize, bool, u8, u8, u8, u64, u32);
type GeneratedRule = (u8, usize, u8, bool, u8, bool, u8);

/// A valid policy from generated codes: tool entries over three names with
/// role, issuer and auth-method constraints, and rules of every kind the tool
/// lane reads or must ignore -- tool-name rules (including for a name no entry
/// carries), path rules with and without method sets, and dispatch-scoped path
/// rules that unknown dispatch must never match.
fn generated_policy(
    shadow: bool,
    default_allow: bool,
    entries: &[GeneratedEntry],
    rules: &[GeneratedRule],
) -> Policy {
    let mut tools = serde_json::Map::new();
    for &(name, enabled, roles, issuers, auth_methods, timeout_ms, max_concurrent) in entries {
        let mut entry =
            json!({"enabled":enabled,"timeout_ms":timeout_ms,"max_concurrent":max_concurrent});
        let roles: Vec<_> = ["reader", "writer", "role-7"]
            .iter()
            .enumerate()
            .filter(|(bit, _)| roles & (1 << bit) != 0)
            .map(|(_, role)| *role)
            .collect();
        if !roles.is_empty() {
            entry["allowed_roles"] = json!(roles);
        }
        match issuers {
            1 => entry["issuers"] = json!(["https://idp.example.test/"]),
            2 => entry["issuers"] = json!(["https://other.example.test"]),
            _ => {}
        }
        if let Some(methods) = auth_method_set(auth_methods) {
            entry["auth_methods"] = methods;
        }
        tools.insert(POLICY_NAMES[name].to_owned(), entry);
    }
    let rules: Vec<Value> = rules
        .iter()
        .enumerate()
        .map(
            |(index, &(kind, target, action, enabled, principal, id, methods))| {
                let action = ["deny", "shadow", "allow"][usize::from(action)];
                let mut rule = json!({"action":action,"enabled":enabled});
                if id {
                    rule["id"] = json!(format!("generated-{index}"));
                }
                if kind == 0 {
                    rule["tool_name"] = json!(PROBED_NAMES[target]);
                } else {
                    let path = ["/reports/{id}", "/reports/**", "/**", "/elsewhere"][target];
                    rule["path"] = json!(path);
                    match methods {
                        1 => rule["methods"] = json!(["GET"]),
                        2 => rule["methods"] = json!(["post", " get "]),
                        3 => rule["methods"] = json!(["*"]),
                        _ => {}
                    }
                    match kind {
                        2 => rule["dispatch"] = json!({"kind":"contextless"}),
                        3 => {
                            rule["dispatch"] = json!({"kind":"legacy","upstream_origin":"https://upstream.example.test"})
                        }
                        _ => {}
                    }
                }
                match principal {
                    1 => rule["principal"] = json!({"roles":["reader"]}),
                    2 => rule["principal"] = json!({"issuers":["https://idp.example.test"]}),
                    3 => rule["principal"] = json!({"auth_methods":["session_cookie"]}),
                    4 => rule["principal"] = json!({"principal_ids":["synthetic-subject"]}),
                    _ => {}
                }
                rule
            },
        )
        .collect();
    Policy::validate_json_value(json!({
        "schema_version":"0.1.0",
        "default_action":if default_allow { "allow" } else { "deny" },
        "enforcement_mode":if shadow { "shadow" } else { "enforce" },
        "roles":{"reader":{"permissions":[]}},
        // Routes and the default never decide a tool-lane question.
        "routes":[{"path_prefix":"/","permission":"unavailable"}],
        "tools":tools,
        "rules":rules
    }))
    .expect("generated policies are valid")
}

fn differential_config() -> Config {
    Config {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(422_002),
        max_shrink_iters: 1_024,
        ..Config::default()
    }
}

proptest! {
    #![proptest_config(differential_config())]

    #[test]
    fn generated_policies_are_decided_alike_by_the_frozen_consumers_and_the_live_runtime(
        shadow in any::<bool>(),
        default_allow in any::<bool>(),
        entries in proptest::collection::vec(
            (0..POLICY_NAMES.len(), any::<bool>(), 0u8..8, 0u8..3, 0u8..6, 1u64..60_000, 1u32..8),
            0..5,
        ),
        rules in proptest::collection::vec(
            (0u8..4, 0usize..4, 0u8..3, any::<bool>(), 0u8..5, any::<bool>(), 0u8..4),
            0..8,
        ),
    ) {
        let policy = generated_policy(shadow, default_allow, &entries, &rules);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(assert_old_and_new_agree(&policy));
    }
}

#[tokio::test]
async fn the_frozen_consumers_and_the_live_runtime_agree_across_the_named_matrix() {
    // The named cases the generated corpus reaches only by chance: a rule
    // before and after the deciding one, disabled rules in between (so source
    // ordinals and ids must be attributed exactly), every first-tool action
    // under both modes and defaults, and each identity constraint alone.
    for global in [false, true] {
        for default_allow in [false, true] {
            for action in [None, Some(0u8), Some(1), Some(2)] {
                for (roles, issuers, auth_methods) in [
                    (0, 0, 0),
                    (1, 0, 0),
                    (0, 1, 0),
                    (0, 0, 1),
                    (1, 1, 1),
                    (0, 0, 4),
                ] {
                    let entries = [
                        (0, true, roles, issuers, auth_methods, 250, 2),
                        (1, false, 0, 0, 0, 250, 1),
                    ];
                    let mut rules =
                        vec![(0, 0, 0, false, 0, true, 0), (1, 2, 0, true, 0, false, 1)];
                    if let Some(action) = action {
                        rules.extend([
                            (0, 0, action, true, 1, true, 0),
                            (0, 0, 2, true, 0, false, 0),
                            (0, 0, 0, true, 0, true, 0),
                            (0, 1, 0, true, 0, true, 0),
                            (1, 0, action, true, 1, true, 2),
                        ]);
                    }
                    let policy = generated_policy(global, default_allow, &entries, &rules);
                    assert_old_and_new_agree(&policy).await;
                }
            }
        }
    }
}

#[tokio::test]
async fn the_tool_lane_bounds_are_exactly_the_bounds_policy_validation_and_the_adapter_enforce() {
    // A tool name at the bound is a name a policy can carry and the evaluator
    // answers; one byte past it no policy can carry, and the adapter refuses it
    // before the evaluator is asked. The evaluator's own arm is the same byte.
    let at_bound = "t".repeat(MAX_TOOL_NAME_BYTES);
    let past_bound = "t".repeat(MAX_TOOL_NAME_BYTES + 1);
    let mut value = base();
    value["tools"][at_bound.as_str()] = json!({});
    value["rules"] = json!([{"id":"at-bound","tool_name":at_bound,"action":"allow"}]);
    let policy = Policy::validate_json_value(value.clone()).unwrap();
    let mut past_bound_entry = serde_json::Map::new();
    past_bound_entry.insert(past_bound.clone(), json!({}));
    for (field, invalid) in [
        ("tools", Value::Object(past_bound_entry)),
        ("rules", json!([{"tool_name":past_bound,"action":"deny"}])),
    ] {
        let mut value = value.clone();
        value[field] = invalid;
        let error = Policy::validate_json_value(value).unwrap_err().to_string();
        assert!(error.contains("must not exceed 4096 bytes"), "{error}");
        assert!(
            !error.contains(&past_bound),
            "the refusal must not echo the name"
        );
    }

    let (state, runtime, audit, capture) = live(&policy);
    let installed = state.installed_compiled_policy();
    let compiled = installed.compiled();
    let mut question = input(compiled, ToolOperation::Invocation, None);
    question.tool_name = Some(at_bound.clone());
    assert_eq!(
        compiled.evaluate_tool(&question).unwrap().reason(),
        ToolReason::MatchedRule
    );
    question.tool_name = Some(past_bound.clone());
    assert_eq!(
        compiled.evaluate_tool(&question),
        Err(EvaluationError::ContextTooLarge)
    );
    let context = ToolInvocationContext::default();
    assert!(runtime.admit_for_differential(&at_bound, &context).is_ok());
    assert_eq!(
        runtime.admit_for_differential(&past_bound, &context),
        Err(ToolRuntimeError::Rejected {
            tool_name: past_bound.clone(),
            reason: "tool_name_out_of_bounds".into(),
        })
    );

    // A rendered path at the evaluator's bound is evaluated; one byte past it
    // is refused. Tool rendering applies this same predicate first.
    let at_bound_path = format!("/{}", "p".repeat(MAX_REQUEST_PATH_BYTES - 1));
    assert_eq!(validate_rendered_http_path(&at_bound_path), Ok(()));
    let past_bound_path = format!("{at_bound_path}p");
    assert_eq!(
        validate_rendered_http_path(&past_bound_path),
        Err(EvaluationError::ContextTooLarge)
    );
    assert!(runtime.authorize_http_operation("reports.export", "GET", &at_bound_path, &context));
    audit.close_and_drain(Duration::from_secs(5)).await.unwrap();
    let records = audit_records(&capture);
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0]["event_type"], "authz.allowed");
    assert_eq!(records[1]["payload"]["reason"], "tool_name_out_of_bounds");
}

#[tokio::test]
async fn refusals_block_with_stable_reasons_where_the_frozen_consumers_answered() {
    // Every disagreement between old and new, each resolved toward a block.
    // No policy carries an over-long name, so the only served call that can
    // carry one is to a TOOLS_FILE tool, whose names only the file size caps;
    // old and new both block it. The rest are unreachable from a served call:
    // an authenticated principal has passed the evaluator's own shape check,
    // and rendering refuses a path or method the evaluator would. They are
    // pinned so the fail-closed mapping is a tested statement.
    let mut value = base();
    value["rules"] = json!([
        {"id":"tool-allow","tool_name":"reports.export","action":"allow"},
        {"id":"rendered-allow","path":"/**","action":"allow"}
    ]);
    let policy = Policy::validate_json_value(value).unwrap();
    let (state_old, runtime_old, audit_old, capture_old) = live(&policy);
    let (state_new, runtime_new, audit_new, capture_new) = live(&policy);
    let over_long = "t".repeat(MAX_TOOL_NAME_BYTES + 1);
    let mut empty_subject = principal();
    empty_subject.user_id.clear();
    let identified = ToolInvocationContext {
        request_id: "refusal".into(),
        actor: Some(actor_from_principal(&empty_subject)),
        ..ToolInvocationContext::default()
    };
    let anonymous = ToolInvocationContext {
        request_id: "refusal".into(),
        ..ToolInvocationContext::default()
    };

    // An over-long name: the frozen consumers looked it up and found nothing.
    assert!(matches!(
        runtime_old.legacy_admit(&over_long, &anonymous),
        Err(ToolRuntimeError::UnknownTool { .. })
    ));
    assert!(matches!(
        runtime_new.admit_for_differential(&over_long, &anonymous),
        Err(ToolRuntimeError::Rejected { ref reason, .. }) if reason == "tool_name_out_of_bounds"
    ));
    assert!(!runtime_old.legacy_tool_visible_to_context(&over_long, &anonymous));
    assert!(!runtime_new.tool_visible_to_context(&over_long, &anonymous));
    assert!(!runtime_old.legacy_composite_leaf_enabled(&over_long));
    assert!(!runtime_new.composite_leaf_enabled(&over_long));
    assert_eq!(
        state_old
            .legacy_tool_policy_eligibility(&over_long, &principal())
            .reason,
        "not_in_policy"
    );
    assert_eq!(
        state_new.tool_policy_eligibility(&over_long, &principal()),
        ToolPolicyEligibility {
            eligible: false,
            reason: "tool_name_out_of_bounds",
        }
    );
    // The rendered rule never read the name, so here the block is new.
    assert!(runtime_old.legacy_authorize_http_operation(&over_long, "GET", "/reports", &anonymous));
    assert!(!runtime_new.authorize_http_operation(&over_long, "GET", "/reports", &anonymous));

    // A principal the evaluator refuses for shape.
    assert!(runtime_old
        .legacy_admit("reports.export", &identified)
        .is_ok());
    assert!(matches!(
        runtime_new.admit_for_differential("reports.export", &identified),
        Err(ToolRuntimeError::Rejected { ref reason, .. }) if reason == "policy_evaluation_error"
    ));
    assert!(runtime_old.legacy_tool_visible_to_context("reports.export", &identified));
    assert!(!runtime_new.tool_visible_to_context("reports.export", &identified));
    assert!(
        state_old
            .legacy_tool_policy_eligibility("reports.export", &empty_subject)
            .eligible
    );
    assert_eq!(
        state_new.tool_policy_eligibility("reports.export", &empty_subject),
        ToolPolicyEligibility {
            eligible: false,
            reason: "policy_evaluation_error",
        }
    );
    assert!(runtime_old.legacy_authorize_http_operation(
        "reports.export",
        "GET",
        "/reports",
        &identified
    ));
    assert!(!runtime_new.authorize_http_operation(
        "reports.export",
        "GET",
        "/reports",
        &identified
    ));

    // Rendered facts the evaluator refuses: an empty segment, a relative
    // path, a malformed escape, a method that is not a token.
    for (method, path) in [
        ("GET", "/reports//42"),
        ("GET", "relative"),
        ("GET", "/reports/%zz"),
        ("NOT A TOKEN", "/reports/42"),
    ] {
        assert!(runtime_old.legacy_authorize_http_operation(
            "reports.export",
            method,
            path,
            &anonymous
        ));
        assert!(!runtime_new.authorize_http_operation("reports.export", method, path, &anonymous));
    }

    audit_old
        .close_and_drain(Duration::from_secs(5))
        .await
        .unwrap();
    audit_new
        .close_and_drain(Duration::from_secs(5))
        .await
        .unwrap();
    // Old: the rule attributed allow for every rendered request it answered.
    let old = audit_records(&capture_old);
    assert!(old
        .iter()
        .filter(|record| record["event_type"] == "authz.allowed")
        .all(|record| record["payload"]["reason"] == "matched_rule"));
    // New: each refusal audited with its stable reason and no rule.
    let new = audit_records(&capture_new);
    let reasons: Vec<_> = new
        .iter()
        .map(|record| {
            (
                record["event_type"].as_str().unwrap().to_owned(),
                record["payload"]["reason"].as_str().unwrap().to_owned(),
                record["payload"]["matched_rule_id"].clone(),
            )
        })
        .collect();
    let rejected = |reason: &str| {
        (
            crate::audit::event::TOOL_INVOKE_REJECTED.to_owned(),
            reason.to_owned(),
            Value::Null,
        )
    };
    let denied = |reason: &str| ("authz.denied".to_owned(), reason.to_owned(), Value::Null);
    assert_eq!(
        reasons,
        vec![
            rejected("tool_name_out_of_bounds"),
            denied("tool_name_out_of_bounds"),
            rejected("policy_evaluation_error"),
            denied("policy_evaluation_error"),
            denied("policy_evaluation_error"),
            denied("policy_evaluation_error"),
            denied("policy_evaluation_error"),
            denied("policy_evaluation_error"),
        ]
    );
}
