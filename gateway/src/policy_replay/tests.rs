//! Replay contexts: the legacy adapters' classification and redaction, the
//! `replay-context.v1` format and its published schema, and what a context
//! answers when the kernel is asked. `live_tests` proves the adapters
//! lossless against the live middleware and tool runtime.

use http::Method;
use serde_json::{json, Value};

use super::{
    evaluate::{
        evaluate_egress, evaluate_http, evaluate_tool, select_rate_lane, HttpReplayLimitation,
        HttpReplayOutcome,
    },
    legacy::{adapt_audit_event, could_be_mcp_route_alias, LegacyRecord},
    EgressFacts, EgressRecord, HostRecord, HttpFacts, McpIdentity, PrincipalRecord, RecordedPolicy,
    RecordedPrincipal, RecordedResult, ReplayContext, ReplayContextError, ReplayFacts,
    ReplaySource, RoutingRecord, ToolFacts, MAX_RECORDED_ELEMENT_BYTES, MAX_REPLAY_CONTEXT_BYTES,
    REPLAY_CONTEXT_SCHEMA_VERSION,
};
use crate::{
    audit::{event, Actor, AuditEvent},
    auth::AuthMethod,
    policy_eval::{
        egress::{CompiledEgressPolicy, EgressControls, EgressDenial, EgressOutcome},
        tools::ToolReason,
        CompiledPolicy, DispatchFacts, Limitation, LogicalDecision, PolicyAuthority, PolicyEffect,
        RateLaneOutcome, Reason,
    },
    rbac::Policy,
};

const ISSUER: &str = "https://issuer.example";
const SUBJECT: &str = "subject-replay-3d1e";

/// Values a record carries that no context may repeat. Each is unusual enough
/// that finding it in a serialized context can only mean it leaked.
const REQUEST_ID_CANARY: &str = "request-id-canary-0b7c";
const SOURCE_IP_CANARY: &str = "198.51.100.77";
const USER_AGENT_CANARY: &str = "user-agent-canary-5e21";
const EMAIL_CANARY: &str = "email-canary@example.test";
const QUERY_CANARY: &str = "query-name-canary-77aa";
const SECRET_CANARY: &str = "secret-canary-c0ffee";
const UPSTREAM_CANARY: &str = "upstream-endpoint-canary-4410";
const AUTH_REASON_CANARY: &str = "auth-reason-canary-91d0";

fn actor(auth_mode: &str, roles: &[&str]) -> Actor {
    Actor {
        user_id: SUBJECT.to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: Some(EMAIL_CANARY.to_owned()),
        roles: (!roles.is_empty()).then(|| roles.iter().map(|role| (*role).to_owned()).collect()),
        auth_mode: auth_mode.to_owned(),
    }
}

fn event(event_type: &str, actor: Option<Actor>, payload: Value) -> AuditEvent {
    AuditEvent::new(
        event_type,
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        actor,
        payload,
    )
    .with_user_agent(USER_AGENT_CANARY)
}

/// An observation of a proxied request, as the observation middleware writes
/// one, with every member the kernel does not read set to a canary.
fn observed_dispatch() -> Value {
    json!({
        "method": "POST",
        "path": "/api/items/42",
        "status": 201,
        "latency_ms": 17,
        "auth_outcome": "authenticated",
        "auth_reason": AUTH_REASON_CANARY,
        "policy_decision": "allowed",
        "routing_context_known": true,
        "request_host": "api.example.test",
        "upstream_origin": "https://payments.example.test",
        "upstream_route_id": "payments",
        "upstream_route_host": "api.example.test",
        "upstream_route_path_prefix": "/api",
        "policy_reason": "matched_rule",
        "permission": "items:write",
        "path_prefix": "/api",
        "upstream_latency_ms": 9,
        "upstream_status": 201,
        "upstream_pool_id": UPSTREAM_CANARY,
        "upstream_endpoint_id": UPSTREAM_CANARY,
        "upstream_attempts": [{ "endpoint_id": UPSTREAM_CANARY, "result": "ok", "duration_ms": 9 }],
        "upstream_retry_exhausted": false,
        "upstream_stream_terminal_pending": false,
        "payload_shape": { "query_params": [{ "name": QUERY_CANARY, "redacted": false, "value_type": "string" }] },
        "request_body_capture_status": "complete",
        "schema_mismatch": false,
        "authorization": SECRET_CANARY,
        "query": SECRET_CANARY,
    })
}

fn replayable(event: &AuditEvent) -> ReplayContext {
    match adapt_audit_event(event) {
        LegacyRecord::Replayable(context) => context,
        other => panic!("expected a replayable record, got {}", other.code()),
    }
}

fn http_facts(context: &ReplayContext) -> &HttpFacts {
    match &context.facts {
        ReplayFacts::Http(facts) => facts,
        ReplayFacts::Tool(_) => panic!("expected HTTP facts"),
    }
}

fn tool_facts(context: &ReplayContext) -> &ToolFacts {
    match &context.facts {
        ReplayFacts::Tool(facts) => facts,
        ReplayFacts::Http(_) => panic!("expected tool facts"),
    }
}

fn recorded_principal(auth_method: AuthMethod, roles: &[&str]) -> RecordedPrincipal {
    RecordedPrincipal {
        subject: SUBJECT.to_owned(),
        issuer: Some(ISSUER.to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        auth_method,
    }
}

fn compiled(policy: Value) -> CompiledPolicy {
    let policy = Policy::validate_json_value(policy).expect("the test policy validates");
    CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
        .expect("a standalone policy compiles")
}

fn http(method: Method, path: &str, principal: PrincipalRecord) -> HttpFacts {
    HttpFacts {
        method,
        path: path.to_owned(),
        principal,
        request_host: HostRecord::Absent,
        routing: RoutingRecord::Local(McpIdentity::Canonical),
        egress: EgressRecord::NotRecorded,
    }
}

fn recorded(policy: RecordedPolicy) -> RecordedResult {
    RecordedResult {
        policy,
        reason: None,
        matched_rule_id: None,
        permission: None,
        path_prefix: None,
        attribution_omitted: false,
    }
}

#[test]
fn an_observation_keeps_every_fact_the_kernel_reads_exactly() {
    let context = replayable(&event(
        "http.request_observed",
        Some(actor("bearer_token", &["writer", "reader"])),
        observed_dispatch(),
    ));

    assert_eq!(context.source, ReplaySource::HttpObservation);
    let facts = http_facts(&context);
    assert_eq!(facts.method, Method::POST);
    assert_eq!(facts.path, "/api/items/42");
    assert!(
        facts.principal
            == PrincipalRecord::Authenticated(recorded_principal(
                AuthMethod::Bearer,
                &["writer", "reader"]
            )),
        "the principal keeps subject, issuer, roles in order and the method"
    );
    assert!(facts.request_host == HostRecord::Present("api.example.test".to_owned()));
    assert!(
        facts.routing
            == RoutingRecord::ProxyDispatch(DispatchFacts {
                route_id: Some("payments".to_owned()),
                route_host: Some("api.example.test".to_owned()),
                route_path_prefix: Some("/api".to_owned()),
                upstream_origin: "https://payments.example.test".to_owned(),
            })
    );
    assert!(facts.egress == EgressRecord::NotRecorded);
    assert!(
        context.recorded
            == RecordedResult {
                policy: RecordedPolicy::Allowed,
                reason: Some("matched_rule".to_owned()),
                matched_rule_id: None,
                permission: Some("items:write".to_owned()),
                path_prefix: Some("/api".to_owned()),
                attribution_omitted: false,
            }
    );
}

#[test]
fn an_observation_redacts_everything_the_kernel_does_not_read() {
    let context = replayable(&event(
        "http.request_observed",
        Some(actor("session_cookie", &["reader"])),
        observed_dispatch(),
    ));
    let serialized = serde_json::to_string(&context.to_json()).expect("serializes");
    for canary in [
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        USER_AGENT_CANARY,
        EMAIL_CANARY,
        QUERY_CANARY,
        SECRET_CANARY,
        UPSTREAM_CANARY,
        AUTH_REASON_CANARY,
        "latency",
        "status",
        "schema_mismatch",
        "payload_shape",
    ] {
        assert!(
            !serialized.contains(canary),
            "a replay context repeated {canary}: {serialized}"
        );
    }
    // What the kernel reads is there, exactly.
    for kept in [
        SUBJECT,
        ISSUER,
        "/api/items/42",
        "api.example.test",
        "payments",
    ] {
        assert!(serialized.contains(kept), "{kept} is a kernel fact");
    }
    // Formatting a context names its source and lane, never a value.
    let formatted = format!("{context:?}");
    for value in [
        SUBJECT,
        ISSUER,
        "/api/items/42",
        "api.example.test",
        EMAIL_CANARY,
    ] {
        assert!(!formatted.contains(value), "{formatted}");
    }
    assert!(formatted.contains("HttpObservation"));
}

#[test]
fn a_tool_record_redacts_everything_the_tool_lane_does_not_read() {
    let context = replayable(&event(
        event::TOOL_INVOKE_REJECTED,
        Some(actor("service_token", &["reader"])),
        json!({
            "tool_name": "lookup",
            "outcome": "rejected",
            "reason": "role_not_allowed",
            "invocation_source": "mcp",
            "arguments": SECRET_CANARY,
        }),
    ));
    let facts = tool_facts(&context);
    assert_eq!(facts.tool_name, "lookup");
    assert!(
        facts.principal
            == PrincipalRecord::Authenticated(recorded_principal(
                AuthMethod::ServiceToken,
                &["reader"]
            ))
    );
    assert_eq!(context.recorded.policy, RecordedPolicy::Denied);
    assert_eq!(context.recorded.reason.as_deref(), Some("role_not_allowed"));
    let serialized = serde_json::to_string(&context.to_json()).expect("serializes");
    for canary in [
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        USER_AGENT_CANARY,
        EMAIL_CANARY,
        SECRET_CANARY,
        "invocation_source",
        "mcp\"",
    ] {
        assert!(!serialized.contains(canary), "{canary}: {serialized}");
    }
}

#[test]
fn facts_a_record_does_not_carry_are_not_recorded_rather_than_defaulted() {
    let observation = |payload: Value| {
        let context = replayable(&event("http.request_observed", None, payload));
        let facts = http_facts(&context);
        (facts.request_host.clone(), facts.routing.clone())
    };
    let base = json!({ "method": "GET", "path": "/api/items/1", "policy_decision": "allowed" });

    // Before routing was recorded, neither routing nor host was.
    let (host, routing) = observation(base.clone());
    assert!(host == HostRecord::NotRecorded && routing == RoutingRecord::NotRecorded);

    // Recorded but unclassified: routing is unknown, and no host is absent.
    let mut unclassified = base.clone();
    unclassified["routing_context_known"] = json!(false);
    let (host, routing) = observation(unclassified);
    assert!(host == HostRecord::Absent && routing == RoutingRecord::NotRecorded);

    // A dispatch recorded before route ids existed cannot judge a
    // route-scoped rule, so its routing is not recorded.
    let mut before_route_ids = base.clone();
    before_route_ids["routing_context_known"] = json!(true);
    before_route_ids["upstream_origin"] = json!("https://payments.example.test");
    let (_, routing) = observation(before_route_ids);
    assert!(routing == RoutingRecord::NotRecorded);

    // Locally classified, and no configuration could alias this path.
    let mut local = base.clone();
    local["routing_context_known"] = json!(true);
    let (_, routing) = observation(local.clone());
    assert!(routing == RoutingRecord::Local(McpIdentity::Canonical));

    // A path that could have been an MCP alias does not state its identity.
    local["path"] = json!("/base/mcp");
    let (_, routing) = observation(local.clone());
    assert!(routing == RoutingRecord::Local(McpIdentity::NotRecorded));
    local["path"] = json!("/mcp");
    let (_, routing) = observation(local);
    assert!(routing == RoutingRecord::Local(McpIdentity::Canonical));
}

#[test]
fn an_actor_is_recorded_only_when_the_envelope_and_method_state_it_fully() {
    let principal = |schema_version: &str, actor: Option<Actor>| {
        let mut event = event(
            "http.request_observed",
            actor,
            json!({ "method": "GET", "path": "/x", "policy_decision": "denied" }),
        );
        event.schema_version = schema_version.to_owned();
        http_facts(&replayable(&event)).principal.clone()
    };
    assert!(principal("0.2.0", None) == PrincipalRecord::Anonymous);
    assert!(principal("0.1.0", None) == PrincipalRecord::Anonymous);
    // 0.1.0 predates the actor's issuer: the issuer may have existed.
    assert!(principal("0.1.0", Some(actor("bearer_token", &[]))) == PrincipalRecord::NotRecorded);
    // A mode no principal carries is not guessed into one.
    assert!(principal("0.2.0", Some(actor("api_key", &[]))) == PrincipalRecord::NotRecorded);
    let mut issuerless = actor("client_certificate", &[]);
    issuerless.issuer = None;
    assert!(
        principal("0.2.0", Some(issuerless))
            == PrincipalRecord::Authenticated(RecordedPrincipal {
                subject: SUBJECT.to_owned(),
                issuer: None,
                roles: Vec::new(),
                auth_method: AuthMethod::ClientCertificate,
            })
    );
}

/// The adapter was written against this envelope. Bumping it changes what a
/// stored event means, so the adapter must be reviewed with the bump.
#[test]
fn the_adapter_was_reviewed_for_the_current_audit_envelope() {
    assert_eq!(event::SCHEMA_VERSION, "0.2.0");
    let mut future = event(
        "http.request_observed",
        None,
        json!({ "method": "GET", "path": "/x", "policy_decision": "allowed" }),
    );
    future.schema_version = "0.3.0".to_owned();
    assert_eq!(
        adapt_audit_event(&future).code(),
        "unsupported_envelope_version"
    );
}

#[test]
fn every_record_is_classified_under_a_stable_code() {
    let observation = |payload: Value| event("http.request_observed", None, payload);
    let ok = json!({ "method": "GET", "path": "/x", "policy_decision": "allowed", "routing_context_known": true });
    let with = |key: &str, value: Value| {
        let mut payload = ok.clone();
        payload[key] = value;
        observation(payload)
    };
    let tool = |event_type: &str, payload: Value| event(event_type, None, payload);
    let rejected = |reason: &str| {
        tool(
            event::TOOL_INVOKE_REJECTED,
            json!({ "tool_name": "lookup", "outcome": "rejected", "reason": reason }),
        )
    };
    let cases = [
        (observation(ok.clone()), "replayable"),
        (
            with("policy_decision", json!("not_evaluated")),
            "not_policy_evaluated",
        ),
        (
            with("tool_name", json!("lookup")),
            "duplicate_tool_observation",
        ),
        (
            with("policy_decision", json!("maybe")),
            "malformed_policy_decision",
        ),
        (with("method", json!("GE T")), "malformed_method"),
        (with("path", json!("relative")), "malformed_path"),
        (with("path", json!("/x?query=1")), "malformed_path"),
        (
            with("request_host", json!("api.example.test:443")),
            "malformed_request_host",
        ),
        (
            with("routing_context_known", json!("yes")),
            "malformed_routing",
        ),
        (
            with("upstream_route_id", json!("payments")),
            "malformed_routing",
        ),
        (
            with(
                "upstream_origin",
                json!("https://upstream.example.test/path"),
            ),
            "malformed_routing",
        ),
        (
            with(
                "upstream_origin",
                json!("https://user:pw@upstream.example.test"),
            ),
            "malformed_routing",
        ),
        (
            with("policy_reason", json!("Not A Code")),
            "malformed_recorded_result",
        ),
        (
            with("matched_rule_id", json!("")),
            "malformed_recorded_result",
        ),
        (
            observation(json!({
                "method": "GET", "path": "/x", "policy_decision": "allowed",
                "routing_context_known": false, "upstream_origin": "https://u.example.test"
            })),
            "malformed_routing",
        ),
        (
            event("http.request_observed", None, json!("not an object")),
            "malformed_payload",
        ),
        (
            event(
                "http.request_observed",
                Some(Actor {
                    user_id: String::new(),
                    ..actor("bearer_token", &[])
                }),
                ok.clone(),
            ),
            "malformed_principal",
        ),
        (
            tool(
                "authz.allowed",
                json!({ "method": "GET", "path": "/x", "reason": "default_allow" }),
            ),
            "duplicate_http_decision",
        ),
        (
            tool(
                "authz.denied",
                json!({ "method": "GET", "path": "/x", "reason": "missing_permission" }),
            ),
            "duplicate_http_decision",
        ),
        (
            tool(
                "authz.revision_check_failed",
                json!({ "method": "GET", "path": "/x" }),
            ),
            "duplicate_http_decision",
        ),
        (
            tool(
                "authz.allowed",
                json!({ "tool_name": "lookup", "method": "MCP", "path": "/mcp/tools/lookup", "reason": "matched_rule", "matched_rule_id": "r" }),
            ),
            "duplicate_tool_rule_decision",
        ),
        (
            tool(
                "authz.would_deny",
                json!({ "tool_name": "lookup", "method": "MCP", "path": "/mcp/tools/lookup", "reason": "matched_rule", "matched_rule_id": "r" }),
            ),
            "duplicate_tool_rule_decision",
        ),
        (
            tool(
                "authz.denied",
                json!({ "tool_name": "lookup", "method": "MCP", "path": "/mcp/tools/lookup", "reason": "matched_rule", "matched_rule_id": "r" }),
            ),
            "replayable",
        ),
        (
            tool(
                "authz.denied",
                json!({ "tool_name": "lookup", "method": "GET", "path": "/v1/lookup/argument-value", "reason": "matched_rule", "matched_rule_id": "r" }),
            ),
            "unsupported_rendered_tool_request",
        ),
        (
            tool(
                event::TOOL_INVOKE_START,
                json!({ "tool_name": "lookup", "outcome": "started" }),
            ),
            "replayable",
        ),
        (
            tool(
                event::TOOL_INVOKE_START,
                json!({ "tool_name": "", "outcome": "started" }),
            ),
            "malformed_tool_name",
        ),
        (
            tool(
                event::TOOL_INVOKE_SUCCESS,
                json!({ "tool_name": "lookup", "outcome": "success" }),
            ),
            "duplicate_tool_outcome",
        ),
        (
            tool(
                event::TOOL_INVOKE_FAILURE,
                json!({ "tool_name": "lookup", "outcome": "failure" }),
            ),
            "duplicate_tool_outcome",
        ),
        (rejected("unknown_tool"), "replayable"),
        (rejected("disabled"), "replayable"),
        (rejected("role_not_allowed"), "replayable"),
        (rejected("policy_evaluation_incomplete"), "replayable"),
        (rejected("tool_name_out_of_bounds"), "replayable"),
        (rejected("queue_full"), "replayable"),
        (rejected("authority_unavailable"), "replayable"),
        (rejected("matched_rule"), "duplicate_tool_rejection"),
        (rejected("precondition_failed"), "duplicate_tool_rejection"),
        (rejected("some_future_reason"), "unsupported_tool_rejection"),
        (
            tool("auth.failure", json!({ "reason": "missing_credential" })),
            "not_request_record",
        ),
        (tool(event::POLICY_CHANGED, json!({})), "not_request_record"),
    ];
    for (event, expected) in cases {
        assert_eq!(
            adapt_audit_event(&event).code(),
            expected,
            "{} {}",
            event.event_type,
            event.payload
        );
    }
}

#[test]
fn tool_records_state_what_policy_decided_at_admission() {
    let admission = |event_type: &str, reason: Option<&str>| {
        let mut payload = json!({ "tool_name": "lookup", "outcome": "rejected" });
        if let Some(reason) = reason {
            payload["reason"] = json!(reason);
        }
        replayable(&event(event_type, None, payload)).recorded
    };
    assert!(admission(event::TOOL_INVOKE_START, None) == recorded(RecordedPolicy::Admitted));
    // Capacity refused it after policy admitted it; that is not a policy result.
    assert!(
        admission(event::TOOL_INVOKE_REJECTED, Some("queue_timeout"))
            == recorded(RecordedPolicy::Admitted)
    );
    let denied = admission(event::TOOL_INVOKE_REJECTED, Some("disabled"));
    assert_eq!(denied.policy, RecordedPolicy::Denied);
    assert_eq!(denied.reason.as_deref(), Some("disabled"));

    let rule = replayable(&event(
        "authz.denied",
        Some(actor("bearer_token", &["admin"])),
        json!({
            "tool_name": "lookup", "method": "MCP", "path": "/mcp/tools/lookup",
            "reason": "matched_rule", "matched_rule_id": "deny-admins", "invocation_source": "mcp"
        }),
    ));
    assert_eq!(rule.source, ReplaySource::ToolRuleDecision);
    assert_eq!(tool_facts(&rule).tool_name, "lookup");
    assert_eq!(rule.recorded.policy, RecordedPolicy::Denied);
    assert_eq!(
        rule.recorded.matched_rule_id.as_deref(),
        Some("deny-admins")
    );
}

#[test]
fn an_overlong_recorded_element_is_omitted_and_flagged_never_cut() {
    let long_id = "r".repeat(MAX_RECORDED_ELEMENT_BYTES + 1);
    let context = replayable(&event(
        "http.request_observed",
        None,
        json!({
            "method": "GET", "path": "/x", "policy_decision": "denied",
            "policy_reason": "matched_rule", "matched_rule_id": long_id,
        }),
    ));
    assert_eq!(context.recorded.matched_rule_id, None);
    assert!(context.recorded.attribution_omitted);
    let serialized = context.to_json();
    assert_eq!(serialized["recorded"]["attribution_omitted"], json!(true));
    assert!(!serde_json::to_string(&serialized)
        .expect("serializes")
        .contains(&long_id));
}

#[test]
fn every_alias_the_gateway_derives_could_be_an_mcp_route_alias() {
    for public_url in [
        "https://gateway.example.test",
        "https://gateway.example.test/",
        "https://gateway.example.test/base",
        "https://gateway.example.test/base/",
        "https://gateway.example.test/a/b%20c",
        "https://gateway.example.test/mcp",
    ] {
        let mut config = crate::config::Config::test_defaults();
        config.gateway_public_url = Some(public_url.to_owned());
        for path in crate::auth::protected_resource::mcp_route_paths(&config) {
            assert_eq!(
                could_be_mcp_route_alias(&path),
                path != crate::auth::protected_resource::MCP_RESOURCE_PATH,
                "{public_url} derives {path}"
            );
        }
    }
    for own_identity in [
        "/mcp",
        "/",
        "/api/items",
        "/mcpx",
        "/xmcp",
        "/mcp/tools/lookup",
    ] {
        assert!(!could_be_mcp_route_alias(own_identity), "{own_identity}");
    }
}

/// One context per state every fact can take, for the format tests.
fn every_state() -> Vec<ReplayContext> {
    let observation = replayable(&event(
        "http.request_observed",
        Some(actor("bearer_token", &["writer"])),
        observed_dispatch(),
    ));
    let with_facts = |mutate: &dyn Fn(&mut HttpFacts)| {
        let mut context = observation.clone();
        if let ReplayFacts::Http(facts) = &mut context.facts {
            mutate(facts);
        }
        context
    };
    let tool = ReplayContext {
        source: ReplaySource::ToolAdmission,
        facts: ReplayFacts::Tool(ToolFacts {
            tool_name: "lookup".to_owned(),
            principal: PrincipalRecord::NotRecorded,
            egress: EgressRecord::NotRecorded,
        }),
        recorded: recorded(RecordedPolicy::Admitted),
    };
    let mut overlong = observation.clone();
    overlong.recorded.matched_rule_id = None;
    overlong.recorded.attribution_omitted = true;
    vec![
        observation.clone(),
        with_facts(&|facts| {
            facts.principal = PrincipalRecord::Anonymous;
            facts.request_host = HostRecord::Absent;
            facts.routing = RoutingRecord::Local(McpIdentity::Canonical);
        }),
        with_facts(&|facts| {
            facts.principal = PrincipalRecord::NotRecorded;
            facts.request_host = HostRecord::NotRecorded;
            facts.routing = RoutingRecord::NotRecorded;
        }),
        with_facts(&|facts| {
            facts.routing = RoutingRecord::Local(McpIdentity::NotRecorded);
        }),
        with_facts(&|facts| {
            facts.routing = RoutingRecord::Local(McpIdentity::Alias {
                canonical_path: "/mcp".to_owned(),
            });
        }),
        with_facts(&|facts| {
            facts.routing = RoutingRecord::ProxyDispatch(DispatchFacts {
                route_id: None,
                route_host: None,
                route_path_prefix: None,
                upstream_origin: "pool:payments".to_owned(),
            });
            facts.principal = PrincipalRecord::Authenticated(RecordedPrincipal {
                issuer: None,
                roles: Vec::new(),
                ..recorded_principal(AuthMethod::ClientCertificate, &[])
            });
        }),
        with_facts(&|facts| {
            facts.egress = EgressRecord::Destination(EgressFacts {
                scheme: "https".to_owned(),
                host: Some("payments.example.test".to_owned()),
                port: Some(443),
                userinfo: false,
                fragment: false,
            });
        }),
        with_facts(&|facts| {
            facts.egress = EgressRecord::Destination(EgressFacts {
                scheme: "http".to_owned(),
                host: None,
                port: None,
                userinfo: true,
                fragment: true,
            });
        }),
        overlong,
        tool,
    ]
}

fn published_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/replay-context.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

#[test]
fn every_context_round_trips_and_matches_the_published_schema() {
    let validator = jsonschema::validator_for(&published_schema()).expect("the schema compiles");
    for context in every_state() {
        let serialized = context.to_json();
        if let Err(error) = validator.validate(&serialized) {
            panic!("the published schema refused {serialized}: {error}");
        }
        let bytes = serde_json::to_vec(&serialized).expect("serializes");
        let parsed = ReplayContext::parse(&bytes).expect("a written context parses");
        assert!(parsed == context, "{serialized}");
        assert_eq!(parsed.to_json(), serialized);
        assert_eq!(
            serialized["schema_version"],
            json!(REPLAY_CONTEXT_SCHEMA_VERSION)
        );
    }
}

/// Every refusal JSON Schema can express is refused by both the published
/// schema and the parser; the ones it cannot (duplicate members, byte length)
/// by the parser.
#[test]
fn the_parser_and_the_published_schema_refuse_the_same_contexts() {
    let validator = jsonschema::validator_for(&published_schema()).expect("the schema compiles");
    let base = every_state()[0].to_json();
    let tool = every_state().last().expect("a tool context").to_json();
    let edit = |value: &Value, edit: &dyn Fn(&mut Value)| {
        let mut value = value.clone();
        edit(&mut value);
        value
    };
    let refused = [
        (
            edit(&base, &|v| v["schema_version"] = json!("replay-context.v2")),
            ReplayContextError::UnsupportedSchemaVersion,
        ),
        (
            edit(&base, &|v| v["extra"] = json!(1)),
            ReplayContextError::UnknownMember,
        ),
        (
            edit(&base, &|v| v["facts"]["headers"] = json!({})),
            ReplayContextError::ForbiddenMember,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["principal"]["token"] = json!(SECRET_CANARY)
            }),
            ReplayContextError::ForbiddenMember,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["principal"]["email"] = json!(EMAIL_CANARY)
            }),
            ReplayContextError::ForbiddenMember,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["routing"]["upstream_status"] = json!(200)
            }),
            ReplayContextError::UnknownMember,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["request_host"] = json!({ "state": "absent", "host": "a.example" })
            }),
            ReplayContextError::UnknownMember,
        ),
        (
            edit(&base, &|v| v["recorded"]["status"] = json!(200)),
            ReplayContextError::UnknownMember,
        ),
        (
            edit(&base, &|v| {
                v["facts"]
                    .as_object_mut()
                    .expect("object")
                    .remove("routing");
            }),
            ReplayContextError::MissingMember,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["principal"]
                    .as_object_mut()
                    .expect("object")
                    .remove("roles");
            }),
            ReplayContextError::MissingMember,
        ),
        (
            edit(&base, &|v| v["source"] = json!("tool_admission")),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&tool, &|v| v["source"] = json!("http_observation")),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&tool, &|v| v["facts"]["operation"] = json!("visibility")),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["principal"]["auth_method"] = json!("api_key")
            }),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["routing"]["state"] = json!("guessed")
            }),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| v["recorded"]["policy"] = json!("safe")),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| {
                v["recorded"]["attribution_omitted"] = json!(false)
            }),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| v["recorded"]["reason"] = json!("Not A Code")),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| v["facts"]["path"] = json!("relative")),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["path"] = json!(format!("/{}", "p".repeat(8192)))
            }),
            ReplayContextError::TooLong,
        ),
        (
            edit(&base, &|v| v["facts"]["principal"]["subject"] = json!("")),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["routing"]["upstream_origin"] = json!("https://user@u.example.test")
            }),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["egress"] = json!({
                    "state": "destination", "scheme": "https", "port": 70000, "userinfo": false,
                    "fragment": false, "resolution": { "state": "not_recorded" }
                })
            }),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| {
                v["facts"]["egress"] = json!({
                    "state": "destination", "scheme": "https", "userinfo": false, "fragment": false,
                    "resolution": { "state": "recorded", "addresses": ["192.0.2.1"] }
                })
            }),
            ReplayContextError::InvalidValue,
        ),
        (
            edit(&base, &|v| v["facts"]["method"] = json!(7)),
            ReplayContextError::InvalidType,
        ),
        (json!([]), ReplayContextError::InvalidType),
    ];
    for (value, expected) in refused {
        // Refusals are stable snake_case codes that never carry a value.
        assert!(expected
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        let bytes = serde_json::to_vec(&value).expect("serializes");
        assert_eq!(
            ReplayContext::parse(&bytes).map(|_| ()),
            Err(expected),
            "the parser accepted or misjudged {value}"
        );
        // The schema cannot state the origin form; the rest it refuses too.
        let schema_states_it =
            value["facts"]["routing"]["upstream_origin"] != json!("https://user@u.example.test");
        if schema_states_it {
            assert!(
                !validator.is_valid(&value),
                "the published schema accepted {value}"
            );
        }
    }

    let duplicate =
        br#"{"schema_version":"replay-context.v1","schema_version":"replay-context.v1"}"#;
    assert_eq!(
        ReplayContext::parse(duplicate).map(|_| ()),
        Err(ReplayContextError::DuplicateMember)
    );
    let oversized = vec![b' '; MAX_REPLAY_CONTEXT_BYTES + 1];
    assert_eq!(
        ReplayContext::parse(&oversized).map(|_| ()),
        Err(ReplayContextError::TooLarge)
    );
    assert_eq!(
        ReplayContext::parse(b"{").map(|_| ()),
        Err(ReplayContextError::InvalidJson)
    );
}

#[test]
fn routing_that_was_not_recorded_is_indeterminate_not_contextless() {
    let policy = compiled(json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "rules": [{ "id": "payments", "methods": ["GET"], "path": "/api/**",
                    "dispatch": { "kind": "route", "route_id": "payments" }, "action": "allow" }]
    }));
    let mut facts = http(Method::GET, "/api/items", PrincipalRecord::Anonymous);
    facts.routing = RoutingRecord::NotRecorded;
    assert_eq!(
        evaluate_http(&policy, &facts).expect("evaluates"),
        HttpReplayOutcome::Indeterminate(HttpReplayLimitation::Kernel(
            Limitation::MissingDispatchFact
        ))
    );
    facts.routing = RoutingRecord::ProxyDispatch(DispatchFacts {
        route_id: Some("payments".to_owned()),
        route_host: None,
        route_path_prefix: Some("/api".to_owned()),
        upstream_origin: "https://payments.example.test".to_owned(),
    });
    let HttpReplayOutcome::Decided(decision) = evaluate_http(&policy, &facts).expect("evaluates")
    else {
        panic!("a recorded dispatch decides");
    };
    assert_eq!(decision.logical, LogicalDecision::Allow);
    assert_eq!(decision.reason, Reason::MatchedRule);
}

#[test]
fn an_unrecorded_host_or_principal_is_indeterminate_only_where_it_matters() {
    let plain = compiled(json!({ "schema_version": "0.1.0", "default_action": "allow" }));
    let host_bound = compiled(json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "roles": { "reader": { "permissions": ["items:read"] } },
        "routes": [{ "path_prefix": "/api", "hosts": ["api.example.test"], "permission": "items:read" }]
    }));
    let mut facts = http(Method::GET, "/api/items", PrincipalRecord::Anonymous);
    facts.request_host = HostRecord::NotRecorded;
    assert!(matches!(
        evaluate_http(&plain, &facts).expect("evaluates"),
        HttpReplayOutcome::Decided(_)
    ));
    assert_eq!(
        evaluate_http(&host_bound, &facts).expect("evaluates"),
        HttpReplayOutcome::Indeterminate(HttpReplayLimitation::Kernel(Limitation::MissingHostFact))
    );
    facts.request_host = HostRecord::Absent;
    facts.principal = PrincipalRecord::NotRecorded;
    assert_eq!(
        evaluate_http(&plain, &facts).expect("evaluates"),
        HttpReplayOutcome::Indeterminate(HttpReplayLimitation::Kernel(
            Limitation::MissingPrincipalFact
        ))
    );
}

#[test]
fn an_unstated_mcp_identity_decides_only_when_both_readings_agree() {
    let mut facts = http(Method::POST, "/base/mcp", PrincipalRecord::Anonymous);
    facts.routing = RoutingRecord::Local(McpIdentity::NotRecorded);

    // Nothing distinguishes the two identities: both readings allow.
    let indifferent = compiled(json!({ "schema_version": "0.1.0", "default_action": "allow" }));
    let HttpReplayOutcome::Decided(decision) =
        evaluate_http(&indifferent, &facts).expect("evaluates")
    else {
        panic!("agreeing readings decide");
    };
    assert_eq!(decision.readings, 2);
    assert_eq!(decision.logical, LogicalDecision::Allow);

    // A rule on the canonical identity decides the alias reading only: the
    // contextless reading allows by default, the alias reading denies.
    let canonical_rule = compiled(json!({
        "schema_version": "0.1.0",
        "default_action": "allow",
        "rules": [{ "id": "deny-mcp", "methods": ["*"], "path": "/mcp", "action": "deny" }]
    }));
    assert_eq!(
        evaluate_http(&canonical_rule, &facts).expect("evaluates"),
        HttpReplayOutcome::Indeterminate(HttpReplayLimitation::MissingMcpIdentity)
    );
    assert_eq!(
        HttpReplayLimitation::MissingMcpIdentity.as_str(),
        "missing_mcp_identity"
    );
    assert_eq!(
        HttpReplayLimitation::Kernel(Limitation::MissingDispatchFact).as_str(),
        "missing_dispatch_fact"
    );
    // Stated, each identity decides alone.
    facts.routing = RoutingRecord::Local(McpIdentity::Alias {
        canonical_path: "/mcp".to_owned(),
    });
    let HttpReplayOutcome::Decided(alias) =
        evaluate_http(&canonical_rule, &facts).expect("evaluates")
    else {
        panic!("a stated alias decides");
    };
    assert_eq!((alias.logical, alias.readings), (LogicalDecision::Deny, 1));
    facts.routing = RoutingRecord::Local(McpIdentity::Canonical);
    let HttpReplayOutcome::Decided(canonical) =
        evaluate_http(&canonical_rule, &facts).expect("evaluates")
    else {
        panic!("a canonical path decides");
    };
    assert_eq!(canonical.logical, LogicalDecision::Allow);
}

#[test]
fn rate_lane_selection_reads_the_recorded_request() {
    let policy = compiled(json!({
        "schema_version": "0.1.0",
        "rate_limits": [{ "methods": ["GET"], "path": "/api/**",
                          "principal": { "roles": ["reader"] },
                          "requests_per_second": 5.0, "burst": 10 }]
    }));
    let reader =
        PrincipalRecord::Authenticated(recorded_principal(AuthMethod::Bearer, &["reader"]));
    let lane = |principal: PrincipalRecord| {
        select_rate_lane(&policy, &http(Method::GET, "/api/items", principal))
            .expect("selects")
            .outcome()
    };
    assert!(matches!(
        lane(reader),
        RateLaneOutcome::Override { index: 0, .. }
    ));
    // The live bypass: an anonymous caller reaches no override.
    assert!(matches!(
        lane(PrincipalRecord::Anonymous),
        RateLaneOutcome::NoOverride
    ));
    assert!(matches!(
        lane(PrincipalRecord::NotRecorded),
        RateLaneOutcome::Indeterminate(Limitation::MissingPrincipalFact)
    ));
}

#[test]
fn a_tool_invocation_replays_through_the_tool_lane_projection() {
    let policy = compiled(json!({
        "schema_version": "0.1.0",
        "tools": { "lookup": { "allowed_roles": ["reader"], "timeout_ms": 1000, "max_concurrent": 1 } }
    }));
    let facts = |principal: PrincipalRecord| ToolFacts {
        tool_name: "lookup".to_owned(),
        principal,
        egress: EgressRecord::NotRecorded,
    };
    let bearer = evaluate_tool(
        &policy,
        &facts(PrincipalRecord::Authenticated(recorded_principal(
            AuthMethod::Bearer,
            &["reader"],
        ))),
    )
    .expect("evaluates");
    assert_eq!(bearer.effect(), PolicyEffect::Allow);
    // The tool runtime does not project a client-certificate actor, so the
    // tool lane judged that caller anonymous, and replay does too.
    let certificate = evaluate_tool(
        &policy,
        &facts(PrincipalRecord::Authenticated(recorded_principal(
            AuthMethod::ClientCertificate,
            &["reader"],
        ))),
    )
    .expect("evaluates");
    assert_eq!(certificate.reason(), ToolReason::RoleNotAllowed);
    let unknown = evaluate_tool(&policy, &facts(PrincipalRecord::NotRecorded)).expect("evaluates");
    assert_eq!(unknown.logical(), LogicalDecision::Indeterminate);
}

#[test]
fn a_recorded_egress_destination_is_never_allowed_without_resolution() {
    let policy = CompiledEgressPolicy::new(EgressControls {
        allowed_hosts: ["payments.example.test".to_owned()].into_iter().collect(),
        allowed_host_globs: Vec::new(),
        allowed_ports: [443].into_iter().collect(),
        deny_private_ips: true,
        private_ip_allow_cidrs: Vec::new(),
        nat64_prefixes: Vec::new(),
    });
    let destination = |host: &str, userinfo: bool| {
        EgressRecord::Destination(EgressFacts {
            scheme: "https".to_owned(),
            host: Some(host.to_owned()),
            port: Some(443),
            userinfo,
            fragment: false,
        })
    };
    let outcome = |record: &EgressRecord| {
        evaluate_egress(&policy, record)
            .expect("a destination is evaluated")
            .expect("evaluates")
            .outcome()
    };
    assert!(matches!(
        outcome(&destination("payments.example.test", false)),
        EgressOutcome::Indeterminate(_)
    ));
    assert!(matches!(
        outcome(&destination("elsewhere.example.test", false)),
        EgressOutcome::Deny(EgressDenial::HostNotAllowed)
    ));
    assert!(matches!(
        outcome(&destination("payments.example.test", true)),
        EgressOutcome::Deny(EgressDenial::Userinfo)
    ));
    assert!(evaluate_egress(&policy, &EgressRecord::NotRecorded).is_none());
}
