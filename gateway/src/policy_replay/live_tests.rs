//! The legacy adapters are lossless for what the kernel reads, proved against
//! the live paths rather than against a second description of them.
//!
//! Each test drives real traffic through the real stage -- the RBAC and
//! observation middleware for HTTP, the tool runtime for invocations --
//! captures the audit events it writes, adapts them, and replays the result
//! under the same policy. A replayed decision must be the live decision, or
//! say why the record cannot decide: never a different answer. The facts the
//! adapter read must be the facts the request carried, field by field, and
//! the impact comparison must find every recorded verdict in agreement with
//! the policy that recorded it.

use std::{collections::HashMap, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use http::{Method, StatusCode};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use super::{
    evaluate::{evaluate_http, evaluate_tool, HttpReplayLimitation, HttpReplayOutcome},
    impact::{compare_recorded, http_answer, tool_answer, RecordedComparison, ReplayPolicy},
    legacy::{adapt_audit_event, LegacyRecord},
    HostRecord, McpIdentity, PrincipalRecord, RecordedPolicy, RecordedPrincipal, ReplayFacts,
    RoutingRecord,
};
use crate::{
    audit::{sink::tests::CaptureSink, Actor, AuditEvent, AuditLog, AuditSink},
    auth::{AuthMethod, Principal},
    client_ip::ClientIpPolicy,
    middleware::{
        decision::{AuthOutcome, PolicyDecision, PolicyDecisionOutcome},
        observation::{observation_middleware, ObservationState},
        rbac::{rbac_middleware, RbacState},
    },
    policy_eval::{
        CompiledPolicy, DispatchFacts, Limitation, PolicyAuthority, PolicyEffect, RuleReference,
    },
    rbac::Policy,
    tools::runtime::{ToolInvocationContext, ToolInvocationSource, ToolRuntime, ToolRuntimeConfig},
    upstream_route::{ProxyRouteClassificationCompleted, ProxyRouteObservationContext},
};

const ISSUER: &str = "https://issuer.example";
const HOST: &str = "api.example.test";
const ALIAS: &str = "/base/mcp";

fn http_policy(enforcement_mode: &str) -> Policy {
    Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": enforcement_mode,
        "roles": {
            "reader": { "permissions": ["items:read", "base:read"] },
            "admin": { "permissions": ["*"] },
            "issuer-reader": { "permissions": ["mcp:use"], "issuers": [ISSUER] }
        },
        "routes": [
            { "path_prefix": "/api/items", "methods": ["GET"], "permission": "items:read" },
            { "path_prefix": "/api", "hosts": [HOST], "methods": ["GET", "DELETE"], "permission": "items:read" },
            { "path_prefix": "/base", "permission": "base:read" },
            { "path_prefix": "/mcp", "permission": "mcp:use" }
        ],
        "rules": [
            { "id": "deny-secret", "methods": ["*"], "path": "/api/secret/**", "action": "deny" },
            { "id": "payments-posts", "methods": ["POST"], "path": "/api/**",
              "dispatch": { "kind": "route", "route_id": "payments" }, "action": "allow" },
            { "id": "watch-cookies", "methods": ["GET"], "path": "/api/watch/**",
              "principal": { "auth_methods": ["session_cookie"] }, "action": "shadow" },
            { "id": "issuer-admins", "methods": ["DELETE"], "path": "/api/**",
              "principal": { "issuers": [ISSUER], "roles": ["admin"] }, "action": "allow" },
            { "id": "subject-a", "methods": ["GET"], "path": "/api/me",
              "principal": { "principal_ids": ["subject-a"] }, "action": "allow" },
            { "id": "deny-mcp-certificates", "methods": ["*"], "path": "/mcp",
              "principal": { "auth_methods": ["client_certificate"] }, "action": "deny" },
            { "id": "deny-alias-deletes", "methods": ["DELETE"], "path": ALIAS, "action": "deny" },
            { "methods": ["GET"], "path": "/base/indexed", "action": "allow" }
        ]
    }))
    .expect("the live test policy validates")
}

fn principal(subject: &str, auth_method: AuthMethod, roles: &[&str]) -> Principal {
    Principal {
        user_id: subject.to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: Some(format!("{subject}@example.test")),
        org_id: Some("org-1".to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: "session-1".to_owned(),
        auth_method,
    }
}

fn principals() -> Vec<Option<Principal>> {
    let mut issuerless = principal("subject-b", AuthMethod::ServiceToken, &["reader"]);
    issuerless.issuer = None;
    vec![
        None,
        Some(principal(
            "subject-a",
            AuthMethod::Bearer,
            &["reader", "issuer-reader"],
        )),
        Some(principal("subject-c", AuthMethod::Cookie, &["admin"])),
        Some(issuerless),
        Some(principal(
            "subject-d",
            AuthMethod::ClientCertificate,
            &["admin"],
        )),
    ]
}

/// How the request reached RBAC: as the classification layer leaves it.
#[derive(Clone)]
enum Classification {
    Unclassified,
    Local,
    Dispatch(ProxyRouteObservationContext),
}

fn classifications(path: &str, host: Option<&str>) -> Vec<Classification> {
    let mut classifications = vec![Classification::Unclassified, Classification::Local];
    // MCP routes are gateway-owned and never classified onto a proxy route.
    if path.starts_with("/api") {
        classifications.push(Classification::Dispatch(
            ProxyRouteObservationContext::new_with_route_id(
                "payments".to_owned(),
                None,
                Some("/api".to_owned()),
                "https://payments.example.test".to_owned(),
            ),
        ));
        // The classifier selects a host-bound route only for its host.
        if host == Some(HOST) {
            classifications.push(Classification::Dispatch(
                ProxyRouteObservationContext::new_with_route_id(
                    "virtual".to_owned(),
                    Some(HOST.to_owned()),
                    Some("/api".to_owned()),
                    "pool:virtual".to_owned(),
                ),
            ));
        }
    }
    classifications
}

/// What `routing::proxy_dispatch_context_middleware` leaves on the request
/// and the response, for one fixed classification.
async fn classify(
    State(classification): State<Classification>,
    mut request: Request,
    next: Next,
) -> Response {
    let context = match classification {
        Classification::Unclassified => return next.run(request).await,
        Classification::Local => None,
        Classification::Dispatch(context) => Some(context),
    };
    request
        .extensions_mut()
        .insert(ProxyRouteClassificationCompleted);
    if let Some(context) = &context {
        request.extensions_mut().insert(context.clone());
        if let Some(authorization) = context.authorization_context() {
            request.extensions_mut().insert(authorization);
        }
    }
    let mut response = next.run(request).await;
    response
        .extensions_mut()
        .insert(ProxyRouteClassificationCompleted);
    if let Some(context) = context {
        response.extensions_mut().insert(context);
    }
    response
}

/// What authentication leaves: the principal for RBAC, the outcome for the
/// observation.
async fn authenticate(
    State(principal): State<Option<Principal>>,
    mut request: Request,
    next: Next,
) -> Response {
    if let Some(principal) = &principal {
        request.extensions_mut().insert(principal.clone());
    }
    let mut response = next.run(request).await;
    response.extensions_mut().insert(AuthOutcome {
        authenticated: principal.is_some(),
        principal,
        reason: None,
    });
    response
}

fn live_router(
    policy: Policy,
    audit: &AuditLog,
    classification: Classification,
    principal: Option<Principal>,
) -> Router {
    async fn ok() -> impl IntoResponse {
        StatusCode::OK
    }
    Router::new()
        .route("/{*path}", any(ok))
        .layer(from_fn_with_state(
            RbacState::new_with_mcp_route_paths(
                policy,
                Vec::new(),
                ClientIpPolicy::default(),
                audit.clone(),
                vec![
                    crate::auth::protected_resource::MCP_RESOURCE_PATH.to_owned(),
                    ALIAS.to_owned(),
                ],
            ),
            rbac_middleware,
        ))
        .layer(from_fn_with_state(classification, classify))
        .layer(from_fn_with_state(principal, authenticate))
        .layer(from_fn_with_state(
            ObservationState::from_config(&crate::config::Config::test_defaults(), audit.clone()),
            observation_middleware,
        ))
}

async fn wait_for(capture: &CaptureSink, done: impl Fn(&[AuditEvent]) -> bool) -> Vec<AuditEvent> {
    // Generous: the audit writer is a separate thread on a loaded machine.
    for _ in 0..3000 {
        let events = capture.events();
        if done(&events) {
            return events;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the audit writer did not deliver the expected events");
}

struct LiveRequest {
    request_id: String,
    method: Method,
    path: &'static str,
    host: Option<&'static str>,
    classification: Classification,
    principal: Option<Principal>,
    decision: PolicyDecision,
}

fn expected_principal(principal: Option<&Principal>) -> PrincipalRecord {
    principal.map_or(PrincipalRecord::Anonymous, |principal| {
        PrincipalRecord::Authenticated(RecordedPrincipal {
            subject: principal.user_id.clone(),
            issuer: principal.issuer.clone(),
            roles: principal.roles.clone(),
            auth_method: principal.auth_method.clone(),
        })
    })
}

fn expected_routing(classification: &Classification, path: &str) -> RoutingRecord {
    match classification {
        Classification::Unclassified => RoutingRecord::NotRecorded,
        Classification::Local if path == ALIAS => RoutingRecord::Local(McpIdentity::NotRecorded),
        Classification::Local => RoutingRecord::Local(McpIdentity::Canonical),
        Classification::Dispatch(context) => RoutingRecord::ProxyDispatch(DispatchFacts {
            route_id: context.route_id.clone(),
            route_host: context.route_host.clone(),
            route_path_prefix: context.route_path_prefix.clone(),
            upstream_origin: context.upstream_origin.clone(),
        }),
    }
}

fn live_outcome(effect: PolicyEffect) -> PolicyDecisionOutcome {
    match effect {
        PolicyEffect::Allow => PolicyDecisionOutcome::Allowed,
        PolicyEffect::Observe => PolicyDecisionOutcome::WouldDeny,
        PolicyEffect::Block => PolicyDecisionOutcome::Denied,
    }
}

fn recorded_policy(outcome: PolicyDecisionOutcome) -> RecordedPolicy {
    match outcome {
        PolicyDecisionOutcome::Allowed => RecordedPolicy::Allowed,
        PolicyDecisionOutcome::Denied => RecordedPolicy::Denied,
        PolicyDecisionOutcome::WouldDeny => RecordedPolicy::WouldDeny,
    }
}

#[tokio::test]
async fn replayed_http_decisions_are_the_live_middleware_decisions() {
    let mut decided = 0_usize;
    let mut alias_decided = 0_usize;
    let mut alias_indeterminate = 0_usize;
    let mut unclassified = 0_usize;
    let mut indexed = 0_usize;
    let mut outcomes = HashMap::<&'static str, usize>::new();
    for mode in ["enforce", "shadow"] {
        let policy = http_policy(mode);
        let compiled =
            CompiledPolicy::from_validated_policy(policy.clone(), PolicyAuthority::Standalone)
                .expect("the live test policy compiles");
        let replay_policy =
            ReplayPolicy::compile(policy.clone()).expect("the live test policy compiles");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let mut requests = Vec::new();
        for path in [
            "/api/items/1",
            "/api/secret/x",
            "/api/watch/1",
            "/api/me",
            "/base/thing",
            "/base/indexed",
            ALIAS,
            "/mcp",
            "/other",
        ] {
            for host in [None, Some(HOST)] {
                for classification in classifications(path, host) {
                    for principal in principals() {
                        for method in [Method::GET, Method::POST, Method::DELETE] {
                            let request_id = format!("live-{mode}-{}", requests.len());
                            let mut builder = http::Request::builder()
                                .method(method.clone())
                                .uri(path)
                                .header(crate::REQUEST_ID_HEADER, &request_id);
                            if let Some(host) = host {
                                builder = builder.header(http::header::HOST, host);
                            }
                            let response = live_router(
                                policy.clone(),
                                &audit,
                                classification.clone(),
                                principal.clone(),
                            )
                            .oneshot(builder.body(Body::empty()).expect("request builds"))
                            .await
                            .expect("request completes");
                            let decision = response
                                .extensions()
                                .get::<PolicyDecision>()
                                .cloned()
                                .expect("RBAC records its decision");
                            requests.push(LiveRequest {
                                request_id,
                                method: method.clone(),
                                path,
                                host,
                                classification: classification.clone(),
                                principal: principal.clone(),
                                decision,
                            });
                        }
                    }
                }
            }
        }
        let events = wait_for(&capture, |events| {
            events
                .iter()
                .filter(|event| event.event_type == "http.request_observed")
                .count()
                >= requests.len()
        })
        .await;

        for request in &requests {
            let observation = events
                .iter()
                .find(|event| {
                    event.event_type == "http.request_observed"
                        && event.request_id == request.request_id
                })
                .expect("every request is observed");
            let LegacyRecord::Replayable(context) = adapt_audit_event(observation) else {
                panic!("{} is replayable", request.request_id);
            };
            let ReplayFacts::Http(facts) = &context.facts else {
                panic!("an HTTP observation has HTTP facts");
            };
            let label = format!(
                "{mode} {} {} host={:?} principal={:?}",
                request.method,
                request.path,
                request.host,
                request
                    .principal
                    .as_ref()
                    .map(|principal| &principal.user_id)
            );
            // The facts are the request's, field by field.
            assert_eq!(facts.method, request.method, "{label}");
            assert_eq!(facts.path, request.path, "{label}");
            assert!(
                facts.principal == expected_principal(request.principal.as_ref()),
                "{label}"
            );
            assert!(
                facts.request_host
                    == request
                        .host
                        .map_or(HostRecord::Absent, |host| HostRecord::Present(
                            host.to_owned()
                        )),
                "{label}"
            );
            assert!(
                facts.routing == expected_routing(&request.classification, request.path),
                "{label}"
            );
            // The recorded result is the live decision.
            let live = &request.decision;
            assert_eq!(
                context.recorded.policy,
                recorded_policy(live.outcome),
                "{label}"
            );
            assert_eq!(
                context.recorded.reason.as_deref(),
                Some(live.reason),
                "{label}"
            );
            assert_eq!(
                context.recorded.matched_rule_id, live.matched_rule_id,
                "{label}"
            );
            assert_eq!(context.recorded.permission, live.permission, "{label}");
            assert_eq!(context.recorded.path_prefix, live.path_prefix, "{label}");
            // The impact comparison reads the same record against the same
            // policy and finds what was recorded.
            let comparison = compare_recorded(
                &replay_policy,
                http_answer(&replay_policy, facts).expect("a recorded request is answered"),
                &context.recorded,
                context.source,
            );

            match evaluate_http(&compiled, facts).expect("a recorded request evaluates") {
                HttpReplayOutcome::Decided(replayed) => {
                    decided += 1;
                    assert_eq!(comparison, RecordedComparison::Agrees, "{label}");
                    if request.path == "/base/indexed" && replayed.reason.as_str() == "matched_rule"
                    {
                        indexed += 1;
                    }
                    if request.path == ALIAS {
                        alias_decided += 1;
                    }
                    *outcomes.entry(live.reason).or_default() += 1;
                    assert_eq!(live_outcome(replayed.effect), live.outcome, "{label}");
                    assert_eq!(replayed.reason.as_str(), live.reason, "{label}");
                    match replayed.matched {
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
                        None => assert_eq!(live.matched_rule_id, None, "{label}"),
                    }
                }
                // Live could not answer an unclassified request either, and
                // refused it; replay says the same fact is missing.
                HttpReplayOutcome::Indeterminate(HttpReplayLimitation::Kernel(
                    Limitation::MissingDispatchFact,
                )) => {
                    assert!(
                        matches!(request.classification, Classification::Unclassified),
                        "{label}"
                    );
                    assert_eq!(live.outcome, PolicyDecisionOutcome::Denied, "{label}");
                    assert_eq!(live.reason, "policy_evaluation_incomplete", "{label}");
                    assert_eq!(
                        comparison,
                        RecordedComparison::RecordedNotPolicyVerdict,
                        "{label}"
                    );
                    unclassified += 1;
                }
                // The record does not say the alias was an alias, and the
                // two readings disagree: no answer, rather than the wrong one.
                HttpReplayOutcome::Indeterminate(HttpReplayLimitation::MissingMcpIdentity) => {
                    assert_eq!(request.path, ALIAS, "{label}");
                    assert_eq!(comparison, RecordedComparison::BaseIndeterminate, "{label}");
                    alias_indeterminate += 1;
                }
                other => panic!("{label}: unexpected {other:?}"),
            }
        }
    }
    // The corpus reaches every branch it claims to prove.
    assert!(decided > 400, "{decided}");
    assert!(alias_decided > 0 && alias_indeterminate > 0);
    assert!(unclassified > 0);
    // A rule without an id is recorded by its position, and found by it.
    assert!(indexed > 0);
    for reason in [
        "matched_rule",
        "missing_permission",
        "missing_principal",
        "default_deny",
        "host_policy_required",
    ] {
        assert!(
            outcomes.contains_key(reason),
            "no live {reason} decision in the corpus"
        );
    }
}

fn tool_policy() -> Policy {
    Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "tools": {
            "open": { "timeout_ms": 1000, "max_concurrent": 8 },
            "off": { "enabled": false, "timeout_ms": 1000, "max_concurrent": 8 },
            "readers": { "allowed_roles": ["reader"], "timeout_ms": 1000, "max_concurrent": 8 },
            "issuer-bound": { "issuers": [ISSUER], "timeout_ms": 1000, "max_concurrent": 8 },
            "bearer-only": { "auth_methods": ["bearer_token"], "timeout_ms": 1000, "max_concurrent": 8 },
            "ruled": { "timeout_ms": 1000, "max_concurrent": 8 }
        },
        "rules": [
            { "id": "deny-ruled-admins", "tool_name": "ruled", "principal": { "roles": ["admin"] }, "action": "deny" },
            { "id": "watch-ruled-cookies", "tool_name": "ruled", "principal": { "auth_methods": ["session_cookie"] }, "action": "shadow" },
            { "id": "allow-ruled", "tool_name": "ruled", "action": "allow" }
        ]
    }))
    .expect("the tool test policy validates")
}

fn tool_actor(subject: &str, auth_mode: &str, roles: &[&str]) -> Actor {
    Actor {
        user_id: subject.to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: Some(format!("{subject}@example.test")),
        roles: Some(roles.iter().map(|role| (*role).to_owned()).collect()),
        auth_mode: auth_mode.to_owned(),
    }
}

#[tokio::test]
async fn replayed_tool_admissions_are_the_live_runtime_decisions() {
    let policy = tool_policy();
    let compiled =
        CompiledPolicy::from_validated_policy(policy.clone(), PolicyAuthority::Standalone)
            .expect("the tool test policy compiles");
    let replay_policy =
        ReplayPolicy::compile(policy.clone()).expect("the tool test policy compiles");
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new_with_rbac_state(
        ToolRuntimeConfig::from_policy(&policy).expect("the tool policy configures the runtime"),
        audit.clone(),
        Some(RbacState::new(policy.clone(), Vec::new(), false, audit)),
    );
    let mut issuerless = tool_actor("subject-b", "service_token", &["reader"]);
    issuerless.issuer = None;
    let actors = [
        None,
        Some(tool_actor("subject-a", "bearer_token", &["reader"])),
        Some(tool_actor("subject-c", "session_cookie", &["admin"])),
        Some(tool_actor("subject-e", "session_cookie", &["reader"])),
        Some(issuerless),
        Some(tool_actor("subject-d", "client_certificate", &["reader"])),
    ];
    let mut invocations = Vec::new();
    for tool in [
        "open",
        "off",
        "readers",
        "issuer-bound",
        "bearer-only",
        "ruled",
        "missing",
    ] {
        for actor in &actors {
            let request_id = format!("tool-{}", invocations.len());
            let result = runtime
                .execute_with_context(
                    tool,
                    ToolInvocationContext {
                        request_id: request_id.clone(),
                        source_ip: "203.0.113.9".to_owned(),
                        actor: actor.clone(),
                        caller: None,
                        source: ToolInvocationSource::Mcp,
                        admitted_deadline: None,
                    },
                    CancellationToken::new(),
                    || async {},
                )
                .await;
            invocations.push((request_id, tool, result.is_ok()));
        }
    }
    let events = wait_for(&capture, |events| {
        invocations.iter().all(|(request_id, _, admitted)| {
            let mine = events
                .iter()
                .filter(|event| &event.request_id == request_id);
            if *admitted {
                mine.clone()
                    .any(|event| event.event_type == "tool.invoke_success")
            } else {
                mine.clone()
                    .any(|event| event.event_type == "tool.invoke_rejected")
            }
        })
    })
    .await;

    let mut by_reason = HashMap::<&'static str, usize>::new();
    for (request_id, tool, admitted) in &invocations {
        let label = format!("{request_id} {tool}");
        let mut replayable = Vec::new();
        for event in events
            .iter()
            .filter(|event| &event.request_id == request_id)
        {
            match adapt_audit_event(event) {
                LegacyRecord::Replayable(context) => replayable.push(context),
                LegacyRecord::Duplicate(_) => {}
                other => panic!("{label}: {} classified {}", event.event_type, other.code()),
            }
        }
        // Exactly one record of each invocation is the one to replay.
        assert_eq!(replayable.len(), 1, "{label}");
        let context = &replayable[0];
        let ReplayFacts::Tool(facts) = &context.facts else {
            panic!("{label}: a tool record has tool facts");
        };
        assert_eq!(facts.tool_name, *tool, "{label}");
        assert_eq!(
            compare_recorded(
                &replay_policy,
                tool_answer(&replay_policy, facts).expect("a recorded invocation is answered"),
                &context.recorded,
                context.source,
            ),
            RecordedComparison::Agrees,
            "{label}"
        );
        let replayed = evaluate_tool(&compiled, facts).expect("a recorded invocation evaluates");
        *by_reason.entry(replayed.reason().as_str()).or_default() += 1;
        if *admitted {
            assert!(
                matches!(
                    replayed.effect(),
                    PolicyEffect::Allow | PolicyEffect::Observe
                ),
                "{label}: {:?}",
                replayed.reason()
            );
            assert_eq!(context.recorded.policy, RecordedPolicy::Admitted, "{label}");
        } else {
            assert_eq!(replayed.effect(), PolicyEffect::Block, "{label}");
            assert_eq!(context.recorded.policy, RecordedPolicy::Denied, "{label}");
            assert_eq!(
                context.recorded.reason.as_deref(),
                Some(replayed.reason().as_str()),
                "{label}"
            );
            if let Some(RuleReference::Direct(index)) = replayed.matched() {
                assert_eq!(
                    context.recorded.matched_rule_id.as_deref(),
                    policy.rules[index].id.as_deref(),
                    "{label}"
                );
            }
        }
    }
    for reason in [
        "allowed",
        "matched_rule",
        "disabled",
        "role_not_allowed",
        "unknown_tool",
    ] {
        assert!(
            by_reason.contains_key(reason),
            "no live {reason} invocation"
        );
    }
}

/// A tool-rule decision record's actor is the runtime's projection of the
/// invocation's actor: a client certificate projects to none, so the record
/// names no actor, and replay judges it anonymous exactly as the lane did.
#[test]
fn a_tool_rule_record_carries_the_runtime_projection_of_its_actor() {
    let event = AuditEvent::new(
        "authz.denied",
        "request-1",
        "203.0.113.9",
        None,
        json!({ "tool_name": "ruled", "method": "MCP", "path": "/mcp/tools/ruled",
                "reason": "matched_rule", "matched_rule_id": "deny-ruled-admins" }),
    );
    let LegacyRecord::Replayable(context) = adapt_audit_event(&event) else {
        panic!("a tool-rule denial is replayable");
    };
    let ReplayFacts::Tool(facts) = &context.facts else {
        panic!("tool facts");
    };
    assert!(facts.principal == PrincipalRecord::Anonymous);
}
