use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::Duration,
};

use http::StatusCode;
use rusqlite::{params, Connection};
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::Notify,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

use super::*;
use crate::{
    audit::{
        sink::{tests::CaptureSink, AuditSink, CompositeSink},
        Actor, AuditLog,
    },
    connections::{
        control_plane::ConnectionControlPlane,
        http::ConnectionHttpRuntime,
        model::{
            AdditionalHeader, ConnectionAuthentication, ConnectionEndpoint, ConnectionId,
            ConnectionKind, ConnectionWrite, OAuthClientAuthMethod, TlsProfile,
        },
        secret::{OperatorSecretAliasConfig, OperatorSecretAliasSource, SecretRootConfig},
        store::{StoredEnumSourceValue, StoredOpenApiCatalog, StoredOpenApiCatalogEntry},
    },
    discovery::{
        aggregator::{EndpointAggregatorSink, EndpointAggregatorSinkConfig},
        signals::{DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD, SCHEMA_MISMATCH_SIGNAL_TYPE},
    },
    egress::EgressConfig,
    rbac::{Policy, PrincipalMatcher, Rule, RuleAction},
    tools::{
        definitions::{EnumBinding, HttpToolMapping, ToolVisibility},
        overlay::{
            EnumSourcePlan, EnumSourceSelectionPlan, OverlaySourcePlan, SourceCache, SourceLimits,
            SourceRequestPlan,
        },
        runtime::{
            DefaultToolPolicy, ToolInvocationSource, ToolRuntimeConfig, ToolRuntimeToolConfig,
        },
        selector::Selector,
    },
};

const EXPECTED_STRICT_SCHEMA_INJECTION_MAX_DEPTH: usize = 64;
const OVERSIZED_AUTH_BODY_CANARY: &str = "oversized-oauth-auth-body-canary";
const OAUTH_CHALLENGE_CANARY: &str = "Bearer realm=\"oversized-challenge-canary\"";
const FIRST_OAUTH_ACCESS_TOKEN: &str = "first-oauth-access-token";
const REPLACEMENT_OAUTH_ACCESS_TOKEN: &str = "replacement-oauth-access-token";

#[test]
fn non_global_egress_reason_preserves_machine_contract() {
    let error =
        EgressError::NonGlobalIpBlocked("10.0.0.1".parse().expect("test IP address should parse"));

    assert_eq!(egress_error_reason(&error), "private_ip_blocked");
}

#[test]
fn transform_warning_bound_preserves_the_real_truncation_state() {
    let core_bounded = (0..MAX_TRANSFORM_WARNINGS - 1)
        .map(|index| TransformWarning {
            path: format!("/data/{index}"),
            reason: "decode_failed".to_owned(),
        })
        .chain(std::iter::once(TransformWarning {
            path: "/".to_owned(),
            reason: "warnings_truncated".to_owned(),
        }))
        .collect();

    let (warnings, warnings_truncated) = bounded_transform_warnings(core_bounded);

    assert!(warnings_truncated);
    assert_eq!(warnings.len(), MAX_TRANSFORM_WARNINGS);
    assert_eq!(warnings.last().expect("sentinel").path, "/");
    assert_eq!(
        warnings.last().expect("sentinel").reason,
        "warnings_truncated"
    );
    assert_eq!(
        warnings
            .iter()
            .filter(|warning| warning.reason == "warnings_truncated")
            .count(),
        1
    );
}

#[tokio::test]
async fn valid_args_are_mapped_to_upstream_request_and_audited() {
    let (addr, server) = one_request_server(StatusCode::CREATED, br#"{"ok":true}"#).await;
    let (executor, capture) = executor_for_tools(
        addr,
        [echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );

    let response = http_response(
        executor
            .execute(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("valid tool invocation should succeed"),
    );

    assert_eq!(response.status, StatusCode::CREATED);
    assert_eq!(response.body, br#"{"ok":true}"#);

    let request = server.await.expect("server task should join");
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/echo");
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.body, br#"{"message":"hello"}"#);

    let events = audit_events(&capture, 4).await;
    assert_eq!(events[0].event_type, audit::event::TOOL_INVOKE_START);
    assert_eq!(events[1].event_type, audit::event::TOOL_UPSTREAM_REQUEST);
    assert_eq!(events[2].event_type, HTTP_REQUEST_OBSERVED);
    assert_eq!(events[3].event_type, audit::event::TOOL_INVOKE_SUCCESS);
    for event in &events {
        assert_eq!(event.payload["invocation_source"], json!("internal"));
    }
    assert_eq!(events[1].payload["tool_name"], json!("echo"));
    assert_eq!(events[1].payload["method"], json!("POST"));
    assert_eq!(events[1].payload["path_template"], json!("/v1/echo"));
    assert_eq!(events[1].payload["outcome"], json!("success"));
    assert_eq!(events[1].payload["upstream_status"], json!(201));
    assert!(
        events[1].payload["latency_ms"].as_u64().is_some(),
        "upstream audit event should include latency_ms"
    );
    assert_eq!(events[2].payload["tool_name"], json!("echo"));
    assert_eq!(events[2].payload["method"], json!("MCP"));
    assert_eq!(events[2].payload["path"], json!("/mcp/tools/echo"));
    assert_eq!(
        events[2].payload["endpoint_template"],
        json!("/mcp/tools/echo")
    );
    assert_eq!(events[2].payload["status"], json!(201));
    assert_eq!(events[2].payload["schema_mismatch"], json!(false));
    assert_eq!(events[2].payload["routing_context_known"], json!(true));
    assert!(
        events[2].payload["latency_ms"].as_u64().is_some(),
        "tool observation event should include latency_ms"
    );
    assert_eq!(executor.validator_cache_guard().len(), 1);
}

#[tokio::test]
async fn currency_number_round_trips_to_micros_and_back_in_one_request() {
    let response_body = br#"{"data":{"createCompany":{"annualRecurringRevenue":{"amountMicros":"24000000000","currencyCode":"USD"},"name":"Acme"}}}"#;
    let (addr, server) = one_request_json_server(StatusCode::OK, response_body).await;
    let tool = currency_transform_tool("create_company", "/data/createCompany");
    let (executor, _capture) = executor_for_tools(
        addr,
        [tool],
        runtime_config([("create_company", enabled_tool(1_000, 1))], 2, 1, 100),
    );

    let result = http_execution_result(
        executor
            .execute(
                "create_company",
                json!({
                    "name": "Acme",
                    "amount": 24000,
                    "currency": "USD",
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("exact currency transform should succeed"),
    );

    assert!(result.warnings.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&result.response.body)
            .expect("transformed response should remain JSON"),
        json!({
            "data": {
                "createCompany": {
                    "name": "Acme",
                    "amount": 24000,
                    "currency": "USD",
                }
            }
        })
    );
    let request = server.await.expect("one-request server should join");
    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/v1/companies");
    assert_eq!(
            request.body,
            br#"{"annualRecurringRevenue":{"amountMicros":"24000000000","currencyCode":"USD"},"name":"Acme"}"#
        );
}

#[tokio::test]
async fn transform_rejection_is_structured_and_happens_before_upstream_io() {
    let server = gated_server().await;
    let tool = currency_transform_tool("create_company", "/data/createCompany");
    let (executor, capture) = executor_for_tools(
        server.addr,
        [tool],
        runtime_config([("create_company", enabled_tool(1_000, 1))], 2, 1, 100),
    );
    let inexact: Value =
        serde_json::from_str("24000.1234567").expect("test decimal should parse exactly");

    let error = executor
        .execute(
            "create_company",
            json!({
                "name": "Acme",
                "amount": inexact,
                "currency": "USD",
            }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("inexact decimal must be rejected without rounding");

    match error {
        ToolRuntimeError::WorkFailed {
            reason,
            details: Some(details),
            ..
        } => {
            assert_eq!(reason.as_deref(), Some(TOOL_INVALID_PARAMS_REASON));
            assert_eq!(details["problems"][0]["path"], json!("/amount"));
            assert_eq!(details["problems"][0]["keyword"], json!("codec"));
            assert_eq!(
                details["problems"][0]["reason"],
                json!("value has 7 fraction digits, codec allows 6")
            );
        }
        other => panic!("unexpected transform rejection: {other:?}"),
    }
    assert_no_upstream_requests(&server).await;
    assert!(capture
        .events()
        .iter()
        .all(|event| event.event_type != audit::event::TOOL_UPSTREAM_REQUEST));
    server.stop.cancel();
    server.handle.abort();
}

#[tokio::test]
async fn markdown_body_is_written_to_both_wire_fields_and_read_back_from_one() {
    let markdown = "First paragraph.\n\nSecond paragraph.";
    let response_body = br#"{"data":{"createNote":{"bodyV2":{"markdown":"First paragraph.\n\nSecond paragraph.","blocknote":"[]"},"id":"note-1"}}}"#;
    let (addr, server) = one_request_json_server(StatusCode::OK, response_body).await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [markdown_transform_tool()],
        runtime_config([("create_note", enabled_tool(1_000, 1))], 2, 1, 100),
    );

    let result = http_execution_result(
        executor
            .execute(
                "create_note",
                json!({ "markdown": markdown }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("supported Markdown should transform"),
    );
    assert!(result.warnings.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&result.response.body)
            .expect("normalized response should be JSON"),
        json!({
            "data": {
                "createNote": {
                    "id": "note-1",
                    "markdown": markdown,
                }
            }
        })
    );

    let request = server.await.expect("one-request server should join");
    let wire: Value =
        serde_json::from_slice(&request.body).expect("wire request body should be JSON");
    assert_eq!(wire["bodyV2"]["markdown"], json!(markdown));
    let blocknote = wire["bodyV2"]["blocknote"]
        .as_str()
        .expect("BlockNote document must be carried as a JSON string");
    let blocks: Value =
        serde_json::from_str(blocknote).expect("BlockNote JSON string should parse");
    assert_eq!(
        blocks.as_array().map(Vec::len),
        Some(2),
        "both Markdown paragraphs should become blocks: {blocks}"
    );
}

#[tokio::test]
async fn response_transform_visits_multiple_objects_and_leaves_failed_field_atomic() {
    let tool = paired_decimal_transform_tool();
    let (executor, capture) = executor_for_tools(
        socket_addr(1),
        [tool],
        runtime_config([("list_companies", enabled_tool(1_000, 1))], 2, 1, 100),
    );
    let definition = executor
        .registry
        .get("list_companies")
        .expect("transformed definition should register");
    let context = invocation_context();
    let mut response = EgressResponse {
            status: StatusCode::OK,
            headers: HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            body: br#"{"data":{"companies":[{"financials":{"amountMicros":"1000000","taxMicros":"2000000"},"id":"one"},{"financials":{"amountMicros":"3000000","taxMicros":"007"},"id":"two"}]}}"#.to_vec(),
        };

    let warnings = executor.apply_http_response_transform(&context, &definition, &mut response);
    assert_eq!(warnings.len(), 1, "one malformed field should warn once");
    let body: Value = serde_json::from_slice(&response.body).expect("response should remain JSON");
    assert_eq!(
        body["data"]["companies"][0],
        json!({"amount": 1, "tax": 2, "id": "one"})
    );
    assert_eq!(
        body["data"]["companies"][1],
        json!({
            "financials": {
                "amountMicros": "3000000",
                "taxMicros": "007",
            },
            "id": "two",
        }),
        "a failed decode must retain the entire wire field without partial agent properties"
    );
    let events = audit_events(&capture, 1).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, audit::event::TOOL_TRANSFORM_WARNING);
    assert_eq!(events[0].payload["warning_count"], json!(1));
    assert!(events[0].payload.get("financials").is_none());
}

#[tokio::test]
async fn malformed_json_warns_only_for_transformed_tools_and_preserves_legacy_bytes() {
    const MALFORMED: &[u8] = b"{FAKE_RESPONSE_VALUE_SHOULD_NOT_BE_AUDITED";
    let (executor, capture) = executor_for_tools(
        socket_addr(1),
        [
            currency_transform_tool("create_company", "/data/createCompany"),
            echo_tool(),
        ],
        runtime_config(
            [
                ("create_company", enabled_tool(1_000, 1)),
                ("echo", enabled_tool(1_000, 1)),
            ],
            2,
            1,
            100,
        ),
    );
    let context = invocation_context();
    let mut transformed_response = json_egress_response(MALFORMED);
    let transformed = executor
        .registry
        .get("create_company")
        .expect("transformed definition should register");
    let warnings =
        executor.apply_http_response_transform(&context, &transformed, &mut transformed_response);
    assert_eq!(transformed_response.body, MALFORMED);
    assert_eq!(
        warnings,
        vec![TransformWarning {
            path: "/".to_owned(),
            reason: "response_json_invalid".to_owned(),
        }]
    );

    let legacy = executor
        .registry
        .get("echo")
        .expect("legacy definition should register");
    let mut legacy_response = json_egress_response(MALFORMED);
    assert!(executor
        .apply_http_response_transform(&context, &legacy, &mut legacy_response)
        .is_empty());
    assert_eq!(legacy_response.body, MALFORMED);

    let events = audit_events(&capture, 1).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, audit::event::TOOL_TRANSFORM_WARNING);
    assert!(!events[0]
        .payload
        .to_string()
        .contains("FAKE_RESPONSE_VALUE"));
}

#[tokio::test]
async fn failed_execution_precondition_rejects_before_egress() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let (executor, capture) = executor_for_tools(
        addr,
        [echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );
    let checks = Arc::new(AtomicUsize::new(0));
    let checks_for_precondition = Arc::clone(&checks);

    let error = executor
        .execute_with_precondition(
            "echo",
            json!({ "message": "hello" }),
            invocation_context(),
            CancellationToken::new(),
            ToolExecutionPrecondition::new(move |definition| {
                assert_eq!(definition.name, "echo");
                checks_for_precondition.fetch_add(1, Ordering::SeqCst);
                Err(ToolExecutionPreconditionError::Failed)
            }),
        )
        .await
        .expect_err("failed execution precondition should reject the invocation");

    assert!(matches!(
        error,
        ToolRuntimeError::Rejected { ref reason, .. }
            if reason == TOOL_PRECONDITION_FAILED_REASON
    ));
    assert_eq!(checks.load(Ordering::SeqCst), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "failed precondition must stop execution before egress"
    );

    let events = audit_events(&capture, 3).await;
    assert!(events.iter().any(|event| {
        event.event_type == audit::event::TOOL_INVOKE_REJECTED
            && event.payload["reason"] == json!(TOOL_PRECONDITION_FAILED_REASON)
    }));
    assert!(events.iter().any(|event| {
        event.event_type == HTTP_REQUEST_OBSERVED
            && event.payload["status"] == json!(StatusCode::PRECONDITION_FAILED.as_u16())
            && event.payload["reason"] == json!(TOOL_PRECONDITION_FAILED_REASON)
    }));
}

#[tokio::test]
async fn unavailable_execution_precondition_is_a_safe_work_failure() {
    let (executor, capture) = executor_for_tools(
        socket_addr(1),
        [echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute_with_precondition(
            "echo",
            json!({ "message": "hello" }),
            invocation_context(),
            CancellationToken::new(),
            ToolExecutionPrecondition::new(|_| Err(ToolExecutionPreconditionError::Unavailable)),
        )
        .await
        .expect_err("unavailable execution state should fail closed");

    assert!(matches!(
        error,
        ToolRuntimeError::WorkFailed {
            ref reason,
            ..
        } if reason.as_deref() == Some(TOOL_EXECUTION_STATE_UNAVAILABLE_REASON)
    ));
    let events = audit_events(&capture, 3).await;
    assert!(events.iter().any(|event| {
        event.event_type == HTTP_REQUEST_OBSERVED
            && event.payload["status"] == json!(StatusCode::SERVICE_UNAVAILABLE.as_u16())
            && event.payload["reason"] == json!(TOOL_EXECUTION_STATE_UNAVAILABLE_REASON)
    }));
}

#[tokio::test]
async fn composite_leaf_enforces_served_dynamic_enum_before_upstream_io() {
    let (addr, ca_pem, server) = scripted_tls_server(Vec::new()).await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"composite-key").await;
    let connection_id = ConnectionId::parse(connection.connection_id.clone())
        .expect("test Connection id should parse");
    let record = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .get(&connection_id)
        .cloned()
        .expect("test Connection should exist");
    let source = EnumSourcePlan {
        id: "note_titles".to_owned(),
        source_digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
        request: SourceRequestPlan {
            tool: None,
            path_and_query: "/metadata/note-titles".to_owned(),
            path_template: "/metadata/note-titles".to_owned(),
            query: Default::default(),
            query_params: Vec::new(),
        },
        select: EnumSourceSelectionPlan {
            items: Selector::parse("/items/*").expect("selector should parse"),
            value: "/value".to_owned(),
            label: None,
        },
        cache: SourceCache::default(),
        limits: SourceLimits::default(),
    };
    let mut definitions = composite_note_definitions(&connection.connection_id);
    let first_leaf = definitions
        .iter_mut()
        .find(|definition| definition.name == "create_note")
        .expect("first composite leaf should exist");
    first_leaf.enum_bindings = vec![EnumBinding {
        property: "title".to_owned(),
        source_id: source.id.clone(),
        source_digest: source.source_digest.clone(),
    }];
    let (executor, _capture) = executor_for_composite_definitions(
        definitions,
        &connection,
        [
            "create_note_for_records",
            "create_note",
            "attach_note",
            "delete_attachment",
            "delete_note",
        ],
    );
    let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
    let enum_runtime = EnumSourceRuntime::new(
        connection.control_plane.clone(),
        connection.runtime.clone(),
        audit,
        Vec::new(),
    );
    let plan = OverlaySourcePlan {
        enum_sources: [(source.id.clone(), source.clone())].into_iter().collect(),
        label_sources: Default::default(),
    };
    enum_runtime.install_resolved_plan(
        &connection_id,
        1,
        &plan,
        &[StoredEnumSourceValue {
            connection_id: connection_id.clone(),
            source_id: source.id,
            overlay_revision: 1,
            source_digest: source.source_digest,
            values_revision: 1,
            connection_revision: record.revisions.connection,
            credential_revision: record.revisions.credential,
            credential_generation_digest: connection
                .control_plane
                .credential_generation_digest(&record),
            values: vec![json!("Public note")],
            labels: None,
            resolved_at: "2099-01-01T00:00:00Z".to_owned(),
        }],
    );
    let executor = executor.with_enum_source_runtime(Some(enum_runtime));

    let error = executor
        .execute(
            "create_note_for_records",
            json!({"title":"Private note","targets":[]}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("a composite leaf must enforce its current dynamic enum");
    let ToolRuntimeError::WorkFailed {
        reason,
        details: Some(details),
        ..
    } = error
    else {
        panic!("dynamic enum rejection should remain a structured composite failure");
    };
    assert_eq!(reason.as_deref(), Some("composite_failed"));
    assert_eq!(details["failed_step"], json!("note"));
    assert_eq!(details["failure_reason"], json!(TOOL_INVALID_PARAMS_REASON));
    assert!(
        server
            .await
            .expect("zero-response test server should stop")
            .is_empty(),
        "dynamic enum rejection must happen before composite member I/O"
    );
}

#[tokio::test]
async fn composite_failing_for_each_step_compensates_its_own_iterations_first() {
    let responses = vec![
        (StatusCode::CREATED, json!({"id":"note-1"})),
        (StatusCode::CREATED, json!({"id":"attachment-a"})),
        (StatusCode::BAD_REQUEST, json!({"error":"rejected"})),
        (StatusCode::NO_CONTENT, Value::Null),
        (StatusCode::NO_CONTENT, Value::Null),
    ];
    let (addr, ca_pem, server) = scripted_tls_server(responses).await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"composite-key").await;
    let definitions = composite_note_definitions(&connection.connection_id);
    let (executor, _capture) = executor_for_composite_definitions(
        definitions,
        &connection,
        [
            "create_note_for_records",
            "create_note",
            "attach_note",
            "delete_attachment",
            "delete_note",
        ],
    );

    let error = executor
        .execute(
            "create_note_for_records",
            json!({"title":"hello","targets":["a","b"]}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("the second attachment should fail the composite");
    let ToolRuntimeError::WorkFailed {
        reason,
        details: Some(details),
        ..
    } = error
    else {
        panic!("expected a structured composite work failure");
    };
    assert_eq!(reason.as_deref(), Some("composite_failed"));
    assert_eq!(details["failed_step"], json!("attach"));
    assert_eq!(details["failed_iteration"], json!(1));
    assert_eq!(details["compensation"], json!("complete"));
    assert_eq!(details["orphans"], json!([]));

    let requests = server.await.expect("scripted TLS server should join");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        vec![
            "/v1/notes",
            "/v1/attachments/a",
            "/v1/attachments/b",
            "/v1/attachments/a",
            "/v1/notes/note-1",
        ]
    );
    assert!(requests
        .iter()
        .all(|request| { request.header("x-api-key") == Some("composite-key") }));
}

#[tokio::test]
async fn composite_executes_multiple_requests_and_projects_declared_result() {
    let responses = vec![
        (StatusCode::CREATED, json!({"id":"note-1"})),
        (StatusCode::CREATED, json!({"id":"attachment-a"})),
        (StatusCode::CREATED, json!({"id":"attachment-b"})),
    ];
    let (addr, ca_pem, server) = scripted_tls_server(responses).await;
    let connection = TemporaryStaticAuthRuntime::header_api_key_with_additional(
        addr,
        &ca_pem,
        b"primary-key",
        &[("cf-access-client-secret", "proxy-secret", b"secondary-key")],
    )
    .await;
    let definitions = composite_note_definitions(&connection.connection_id);
    let (executor, capture) = executor_for_composite_definitions(
        definitions,
        &connection,
        [
            "create_note_for_records",
            "create_note",
            "attach_note",
            "delete_attachment",
            "delete_note",
        ],
    );

    let result = executor
        .execute(
            "create_note_for_records",
            json!({"title":"hello","targets":["a","b"]}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect("the composite should succeed");
    let ToolExecutionResult::Composite(result) = result else {
        panic!("expected a composite result");
    };
    assert_eq!(result.body, json!({"note_id":"note-1"}));
    assert_eq!(result.steps_summary.len(), 3);
    assert!(result
        .steps_summary
        .iter()
        .all(|step| step.outcome == CompositeStepOutcome::Succeeded));

    let requests = server.await.expect("scripted TLS server should join");
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|request| {
        request.header("x-api-key") == Some("primary-key")
            && request.header("cf-access-client-secret") == Some("secondary-key")
    }));
    let events = audit_events(&capture, 9).await;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .count(),
        3
    );
    let completed = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
        .expect("composite completion should be audited");
    assert_eq!(completed.payload["outcome"], json!("success"));
    assert_eq!(completed.payload["steps"].as_array().map(Vec::len), Some(3));
}

#[tokio::test]
async fn composite_write_5xx_is_possible_orphan_and_is_not_compensated() {
    let responses = vec![
        (StatusCode::CREATED, json!({"id":"note-1"})),
        (StatusCode::BAD_GATEWAY, json!({"error":"proxy lost reply"})),
        (StatusCode::NO_CONTENT, Value::Null),
    ];
    let (addr, ca_pem, server) = scripted_tls_server(responses).await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"composite-key").await;
    let definitions = composite_note_definitions(&connection.connection_id);
    let (executor, _capture) = executor_for_composite_definitions(
        definitions,
        &connection,
        [
            "create_note_for_records",
            "create_note",
            "attach_note",
            "delete_attachment",
            "delete_note",
        ],
    );

    let error = executor
        .execute(
            "create_note_for_records",
            json!({"title":"hello","targets":["a"]}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("a write-side 502 must fail ambiguously");
    let ToolRuntimeError::WorkFailed {
        reason,
        details: Some(details),
        ..
    } = error
    else {
        panic!("expected a structured composite work failure");
    };
    assert_eq!(
        reason.as_deref(),
        Some("composite_failed_compensation_incomplete")
    );
    assert_eq!(details["compensation"], json!("incomplete"));
    assert_eq!(details["orphans"][0]["step"], json!("attach"));
    assert_eq!(details["orphans"][0]["certainty"], json!("possible"));
    assert_eq!(details["orphans"][0]["upstream_status"], json!(502));

    let requests = server.await.expect("scripted TLS server should join");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        vec!["/v1/notes", "/v1/attachments/a", "/v1/notes/note-1"]
    );
}

#[tokio::test]
async fn composite_step_http_deny_blocks_rendered_path_before_member_io() {
    let responses = vec![
        (StatusCode::CREATED, json!({"id":"note-1"})),
        (StatusCode::NO_CONTENT, Value::Null),
    ];
    let (addr, ca_pem, server) = scripted_tls_server(responses).await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"composite-key").await;
    let definitions = composite_note_definitions(&connection.connection_id);
    let tool_names = [
        "create_note_for_records",
        "create_note",
        "attach_note",
        "delete_attachment",
        "delete_note",
    ];
    let mut config = runtime_config(
        tool_names.map(|name| (name, enabled_tool(5_000, 1))),
        2,
        1,
        100,
    );
    config.rules.push(Rule {
        id: Some("deny-rendered-attachment".to_owned()),
        enabled: true,
        methods: vec!["POST".to_owned()],
        path: "/attachments/blocked".to_owned(),
        tool_name: None,
        dispatch: None,
        principal: PrincipalMatcher::default(),
        action: RuleAction::Deny,
    });
    let (executor, _capture) =
        executor_for_composite_definitions_with_config(definitions, &connection, config);

    let error = executor
        .execute(
            "create_note_for_records",
            json!({"title":"hello","targets":["blocked"]}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("the rendered member path must be denied");
    let ToolRuntimeError::WorkFailed {
        details: Some(details),
        ..
    } = error
    else {
        panic!("expected structured composite failure");
    };
    assert_eq!(details["failure_reason"], json!("http_rule_denied"));
    let requests = server.await.expect("scripted TLS server should join");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        vec!["/v1/notes", "/v1/notes/note-1"]
    );
}

#[tokio::test]
async fn composite_failed_compensation_continues_and_reports_confirmed_orphan() {
    let responses = vec![
        (StatusCode::CREATED, json!({"id":"note-1"})),
        (StatusCode::CREATED, json!({"id":"attachment-a"})),
        (StatusCode::BAD_REQUEST, json!({"error":"rejected"})),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error":"delete failed"}),
        ),
        (StatusCode::NO_CONTENT, Value::Null),
    ];
    let (addr, ca_pem, server) = scripted_tls_server(responses).await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"composite-key").await;
    let definitions = composite_note_definitions(&connection.connection_id);
    let (executor, _capture) = executor_for_composite_definitions(
        definitions,
        &connection,
        [
            "create_note_for_records",
            "create_note",
            "attach_note",
            "delete_attachment",
            "delete_note",
        ],
    );

    let error = executor
        .execute(
            "create_note_for_records",
            json!({"title":"hello","targets":["a","b"]}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("failed compensation must remain visible");
    let ToolRuntimeError::WorkFailed {
        reason,
        details: Some(details),
        ..
    } = error
    else {
        panic!("expected structured composite failure");
    };
    assert_eq!(
        reason.as_deref(),
        Some("composite_failed_compensation_incomplete")
    );
    assert_eq!(details["orphans"][0]["certainty"], json!("confirmed"));
    assert_eq!(
        details["orphans"][0]["reason"],
        json!("compensation_status:500")
    );
    let requests = server.await.expect("scripted TLS server should join");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        vec![
            "/v1/notes",
            "/v1/attachments/a",
            "/v1/attachments/b",
            "/v1/attachments/a",
            "/v1/notes/note-1",
        ]
    );
}

#[tokio::test]
async fn composite_reserves_compensation_budget_inside_policy_timeout() {
    let responses = vec![
        (StatusCode::CREATED, json!({"id":"note-1"}), Duration::ZERO),
        (
            StatusCode::CREATED,
            json!({"id":"attachment-a"}),
            Duration::from_millis(400),
        ),
        (StatusCode::NO_CONTENT, Value::Null, Duration::ZERO),
    ];
    let (addr, ca_pem, server, _requests_seen) = scripted_tls_server_with_delays(responses).await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"composite-key").await;
    let mut definitions = composite_note_definitions(&connection.connection_id);
    definitions
        .iter_mut()
        .find_map(|definition| definition.composite.as_mut())
        .expect("composite definition should exist")
        .limits
        .compensation_timeout_ms = 250;
    let tool_names = [
        "create_note_for_records",
        "create_note",
        "attach_note",
        "delete_attachment",
        "delete_note",
    ];
    let config = runtime_config(
        tool_names.map(|name| (name, enabled_tool(600, 1))),
        2,
        1,
        100,
    );
    let (executor, _capture) =
        executor_for_composite_definitions_with_config(definitions, &connection, config);
    let started = Instant::now();
    let error = executor
        .execute(
            "create_note_for_records",
            json!({"title":"hello","targets":["a"]}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("the delayed forward step should exhaust only the forward budget");
    assert!(started.elapsed() < Duration::from_millis(600));
    let ToolRuntimeError::WorkFailed {
        details: Some(details),
        ..
    } = error
    else {
        panic!("expected a structured composite failure");
    };
    assert_eq!(details["compensation"], json!("incomplete"));
    let requests = server.await.expect("scripted TLS server should join");
    assert_eq!(
        requests
            .iter()
            .map(|request| request.target.as_str())
            .collect::<Vec<_>>(),
        vec!["/v1/notes", "/v1/attachments/a", "/v1/notes/note-1"]
    );
}

#[tokio::test]
async fn composite_cancel_sends_no_compensation_tail_after_runtime_returns() {
    let responses = vec![
        (StatusCode::CREATED, json!({"id":"note-1"}), Duration::ZERO),
        (
            StatusCode::CREATED,
            json!({"id":"attachment-a"}),
            Duration::from_millis(1_000),
        ),
    ];
    let (addr, ca_pem, server, requests_seen) = scripted_tls_server_with_delays(responses).await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"composite-key").await;
    let definitions = composite_note_definitions(&connection.connection_id);
    let (executor, capture) = executor_for_composite_definitions(
        definitions,
        &connection,
        [
            "create_note_for_records",
            "create_note",
            "attach_note",
            "delete_attachment",
            "delete_note",
        ],
    );
    let cancel = CancellationToken::new();
    let running = tokio::spawn({
        let executor = executor.clone();
        let cancel = cancel.clone();
        async move {
            executor
                .execute(
                    "create_note_for_records",
                    json!({"title":"hello","targets":["a"]}),
                    invocation_context(),
                    cancel,
                )
                .await
        }
    });
    wait_until(Duration::from_secs(2), || {
        requests_seen.load(Ordering::Acquire) >= 2
    })
    .await;
    cancel.cancel();
    let error = running
        .await
        .expect("cancelled composite task should join")
        .expect_err("the runtime should report cancellation");
    assert!(matches!(error, ToolRuntimeError::Cancelled { .. }));

    wait_until(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
    })
    .await;
    let events = capture.events();
    let completed = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
        .expect("Drop must audit the abandoned composite");
    assert_eq!(completed.payload["outcome"], json!("abandoned"));
    assert_eq!(
        completed.payload["pending_compensation"][0]["step"],
        json!("note")
    );
    let requests = server.await.expect("delayed TLS server should join");
    assert_eq!(
        requests.len(),
        2,
        "no compensation request may escape as a tail"
    );
}

#[tokio::test]
async fn composite_lease_loss_sends_no_compensation_tail_after_runtime_returns() {
    let responses = vec![
        (StatusCode::CREATED, json!({"id":"note-1"}), Duration::ZERO),
        (
            StatusCode::CREATED,
            json!({"id":"attachment-a"}),
            Duration::from_millis(1_000),
        ),
    ];
    let (addr, ca_pem, server, requests_seen) = scripted_tls_server_with_delays(responses).await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"composite-key").await;
    let definitions = composite_note_definitions(&connection.connection_id);
    let tool_names = [
        "create_note_for_records",
        "create_note",
        "attach_note",
        "delete_attachment",
        "delete_note",
    ];
    let store = crate::tools::lease::memory::MemoryLeaseStore::new(Duration::from_millis(600));
    let leases: Arc<dyn crate::tools::lease::ExecutionLeaseStore> = Arc::new(store.clone());
    let config = runtime_config(
        tool_names.map(|name| (name, enabled_tool(5_000, 1))),
        2,
        1,
        100,
    );
    let (executor, capture) = executor_for_composite_definitions_with_config_and_leases(
        definitions,
        &connection,
        config,
        Some(leases),
    );
    let running = tokio::spawn({
        let executor = executor.clone();
        async move {
            executor
                .execute(
                    "create_note_for_records",
                    json!({"title":"hello","targets":["a"]}),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
        }
    });
    wait_until(Duration::from_secs(2), || {
        requests_seen.load(Ordering::Acquire) >= 2
    })
    .await;
    store.advance(Duration::from_secs(2));
    let error = tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .expect("the composite invocation should end once its lease is lost")
        .expect("lease-lost composite task should join")
        .expect_err("the runtime should report lease loss");
    assert!(matches!(
        error,
        ToolRuntimeError::LeaseLost { ref tool_name }
            if tool_name == "create_note_for_records"
    ));

    wait_until(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
    })
    .await;
    let events = capture.events();
    let completed = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
        .expect("Drop must audit the lease-lost composite");
    assert_eq!(completed.payload["outcome"], json!("abandoned"));
    assert_eq!(
        completed.payload["pending_compensation"][0]["step"],
        json!("note")
    );
    let requests = server.await.expect("delayed TLS server should join");
    assert_eq!(
        requests.len(),
        2,
        "no compensation request may escape after lease loss returns"
    );
}

#[tokio::test]
async fn composite_iteration_bound_is_invalid_params_before_any_upstream_call() {
    let (addr, ca_pem, server) = scripted_tls_server(Vec::new()).await;
    let connection = TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"unused-key").await;
    let definitions = composite_note_definitions(&connection.connection_id);
    let (executor, _capture) = executor_for_composite_definitions(
        definitions,
        &connection,
        [
            "create_note_for_records",
            "create_note",
            "attach_note",
            "delete_attachment",
            "delete_note",
        ],
    );

    let targets = (0..65)
        .map(|index| format!("target-{index}"))
        .collect::<Vec<_>>();
    let error = executor
        .execute(
            "create_note_for_records",
            json!({"title":"too many","targets":targets}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("an oversized fan-out must fail before I/O");
    assert!(matches!(
        error,
        ToolRuntimeError::WorkFailed {
            reason: Some(reason),
            ..
        } if reason == TOOL_INVALID_PARAMS_REASON
    ));
    assert!(server
        .await
        .expect("zero-response TLS server should join")
        .is_empty());
}

#[tokio::test]
async fn schema_validation_runs_before_execution_precondition() {
    let (executor, _capture) = executor_for_tools(
        socket_addr(1),
        [echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );
    let checks = Arc::new(AtomicUsize::new(0));
    let checks_for_precondition = Arc::clone(&checks);

    let error = executor
        .execute_with_precondition(
            "echo",
            json!({ "unexpected": true }),
            invocation_context(),
            CancellationToken::new(),
            ToolExecutionPrecondition::new(move |_| {
                checks_for_precondition.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        )
        .await
        .expect_err("invalid input must fail before the execution precondition");

    assert!(matches!(
        error,
        ToolRuntimeError::WorkFailed {
            ref reason,
            ..
        } if reason.as_deref() == Some(TOOL_INVALID_PARAMS_REASON)
    ));
    assert_eq!(checks.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn execution_keeps_the_checked_definition_across_registry_reloads() {
    let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );
    let registry = executor.registry.clone();
    let replacement_registry = registry.clone();
    let mut replacement = registry
        .get("echo")
        .expect("echo definition should exist")
        .as_ref()
        .clone();
    replacement.upstream.path_template = "/v2/echo".to_owned();

    let response = http_response(
        executor
            .execute_with_precondition(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
                ToolExecutionPrecondition::new(move |definition| {
                    assert_eq!(definition.upstream.path_template, "/v1/echo");
                    replacement_registry
                        .replace_local_definitions_with_persist(vec![replacement.clone()], || {
                            Ok::<(), ()>(())
                        })
                        .expect("replacement definition should publish");
                    Ok(())
                }),
            )
            .await
            .expect("checked invocation should retain its original definition"),
    );

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        server.await.expect("server task should join").target,
        "/v1/echo",
        "dispatch must use the same definition that passed the precondition"
    );
    assert_eq!(
        registry
            .get("echo")
            .expect("replacement definition should exist")
            .upstream
            .path_template,
        "/v2/echo"
    );
}

#[tokio::test]
async fn mcp_precondition_runs_after_schema_and_before_upstream_lookup() {
    let registry = ToolRegistry::disabled();
    registry
        .merge_definitions(vec![ToolDefinition::mcp_proxy(
            "remote_echo".to_owned(),
            "Remote echo".to_owned(),
            json!({
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": { "type": "string" }
                },
                "additionalProperties": false
            }),
            "missing_server".to_owned(),
            "echo".to_owned(),
        )])
        .expect("MCP proxy definition should publish");
    let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("remote_echo", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = executor_for_registry_with_runtime(registry, runtime, audit, None);
    let checks = Arc::new(AtomicUsize::new(0));
    let checks_for_invalid = Arc::clone(&checks);

    let invalid = executor
        .execute_with_precondition(
            "remote_echo",
            json!({ "unexpected": true }),
            invocation_context(),
            CancellationToken::new(),
            ToolExecutionPrecondition::new(move |_| {
                checks_for_invalid.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        )
        .await
        .expect_err("MCP schema failure should precede the precondition");
    assert!(matches!(
        invalid,
        ToolRuntimeError::WorkFailed {
            ref reason,
            ..
        } if reason.as_deref() == Some(TOOL_INVALID_PARAMS_REASON)
    ));
    assert_eq!(checks.load(Ordering::SeqCst), 0);

    let checks_for_valid = Arc::clone(&checks);
    let rejected = executor
        .execute_with_precondition(
            "remote_echo",
            json!({ "message": "hello" }),
            invocation_context(),
            CancellationToken::new(),
            ToolExecutionPrecondition::new(move |_| {
                checks_for_valid.fetch_add(1, Ordering::SeqCst);
                Err(ToolExecutionPreconditionError::Failed)
            }),
        )
        .await
        .expect_err("MCP precondition should precede missing upstream lookup");
    assert!(matches!(
        rejected,
        ToolRuntimeError::Rejected { ref reason, .. }
            if reason == TOOL_PRECONDITION_FAILED_REASON
    ));
    assert_eq!(checks.load(Ordering::SeqCst), 1);
}

#[test]
fn compiled_validator_cache_stays_bounded_across_schema_revisions() {
    let mut cache = ValidatorCache::new();
    let validator = || {
        Arc::new(
            jsonschema::validator_for(&json!({"type": "object"}))
                .expect("test schema should compile"),
        )
    };
    for revision in 1_u8..=2 {
        insert_bounded_validator(
            &mut cache,
            ValidatorCacheKey {
                tool_name: "managed-tool".to_owned(),
                schema_sha256: [revision; 32],
            },
            validator(),
            2,
        );
    }
    assert_eq!(cache.len(), 2);

    let latest_key = ValidatorCacheKey {
        tool_name: "managed-tool".to_owned(),
        schema_sha256: [3; 32],
    };
    insert_bounded_validator(&mut cache, latest_key.clone(), validator(), 2);
    assert_eq!(cache.len(), 1);
    assert!(cache.contains_key(&latest_key));

    let uncached = validator();
    let returned = insert_bounded_validator(
        &mut cache,
        ValidatorCacheKey {
            tool_name: "uncached".to_owned(),
            schema_sha256: [4; 32],
        },
        Arc::clone(&uncached),
        0,
    );
    assert!(Arc::ptr_eq(&returned, &uncached));
    assert_eq!(cache.len(), 1);
}

#[tokio::test]
async fn dynamic_enum_values_are_served_and_enforced_without_changing_the_stored_definition() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"unused-secret").await;
    let connection_id = ConnectionId::parse(connection.connection_id.clone())
        .expect("test Connection id should parse");
    let record = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .get(&connection_id)
        .cloned()
        .expect("test Connection should exist");
    let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
    let enum_runtime = EnumSourceRuntime::new(
        connection.control_plane.clone(),
        connection.runtime.clone(),
        audit.clone(),
        Vec::new(),
    );
    let source = EnumSourcePlan {
        id: "statuses".to_owned(),
        source_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
        request: SourceRequestPlan {
            tool: None,
            path_and_query: "/metadata/statuses".to_owned(),
            path_template: "/metadata/statuses".to_owned(),
            query: Default::default(),
            query_params: Vec::new(),
        },
        select: EnumSourceSelectionPlan {
            items: Selector::parse("/items/*").expect("selector should parse"),
            value: "/value".to_owned(),
            label: None,
        },
        cache: SourceCache::default(),
        limits: SourceLimits::default(),
    };
    let plan = OverlaySourcePlan {
        enum_sources: [(source.id.clone(), source.clone())].into_iter().collect(),
        label_sources: Default::default(),
    };
    enum_runtime.install_resolved_plan(
        &connection_id,
        1,
        &plan,
        &[StoredEnumSourceValue {
            connection_id: connection_id.clone(),
            source_id: source.id.clone(),
            overlay_revision: 1,
            source_digest: source.source_digest.clone(),
            values_revision: 1,
            connection_revision: record.revisions.connection,
            credential_revision: record.revisions.credential,
            credential_generation_digest: connection
                .control_plane
                .credential_generation_digest(&record),
            values: vec![json!("Active"), json!("Paused")],
            labels: None,
            resolved_at: "2099-01-01T00:00:00Z".to_owned(),
        }],
    );

    let mapping = HttpToolMapping {
        method: "POST".to_owned(),
        path_template: "/statuses".to_owned(),
        query_params: Vec::new(),
        body: None,
    };
    let definition = ToolDefinition {
        name: "set_status".to_owned(),
        title: None,
        description: "Set an exact status".to_owned(),
        input_schema: json!({
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": {"type": "string"}
            },
            "additionalProperties": false
        }),
        target: Some(ToolTarget::Http {
            connection_id: connection.connection_id.clone(),
            mapping: mapping.clone(),
        }),
        source: ToolSource::OpenApi {
            connection_id: connection.connection_id.clone(),
            operation_id: Some("setStatus".to_owned()),
            catalog_revision: Some(1),
        },
        upstream: mapping,
        composite: None,
        visibility: ToolVisibility::Listed,
        transform: None,
        enum_bindings: vec![EnumBinding {
            property: "status".to_owned(),
            source_id: source.id,
            source_digest: source.source_digest,
        }],
        annotations: None,
    };
    let registry = ToolRegistry::disabled();
    registry
        .replace_openapi_connection_catalog(&connection.connection_id, vec![definition], || {
            Ok::<(), ()>(())
        })
        .expect("dynamic OpenAPI tool should install");
    let stored_before = serde_json::to_vec(
        registry
            .get("set_status")
            .expect("stored definition should exist")
            .as_ref(),
    )
    .expect("stored definition should serialize");
    let runtime = ToolRuntime::new(
        runtime_config([("set_status", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = ToolExecutor::new_inner(
        registry.clone(),
        runtime,
        Arc::clone(&connection.egress_client),
        audit,
        ToolExecutorBackends {
            upstream_url: None,
            connection_http: Some(connection.runtime.clone()),
            mcp_catalog_runtime: None,
            openapi_catalog_runtime: None,
            mcp_upstream_servers: HashMap::new(),
            mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                timeout: Duration::from_secs(30),
                response_idle_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(10),
                max_request_body_bytes: 1_048_576,
                max_response_bytes: 5_242_880,
            },
        },
    )
    .expect("executor should build")
    .with_enum_source_runtime(Some(enum_runtime.clone()));

    let stored = registry
        .get("set_status")
        .expect("stored definition should exist");
    let served = executor
        .served_definition(stored.as_ref())
        .expect("served schema should build");
    assert_eq!(
        served
            .definition
            .input_schema
            .pointer("/properties/status/enum"),
        Some(&json!(["Active", "Paused"]))
    );
    assert_eq!(
        serde_json::to_vec(stored.as_ref()).expect("stored definition should serialize"),
        stored_before,
        "serve-time injection must not mutate the registry definition"
    );

    let rejected = executor
        .execute(
            "set_status",
            json!({"status": " active "}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("case and whitespace variants must not be coerced");
    let ToolRuntimeError::WorkFailed {
        reason,
        details,
        message,
        ..
    } = rejected
    else {
        panic!("dynamic enum rejection should be a work failure");
    };
    assert_eq!(reason.as_deref(), Some(TOOL_INVALID_PARAMS_REASON));
    assert!(
        !message.contains(" active "),
        "validation errors must not echo rejected agent values"
    );
    assert!(
        !serde_json::to_string(&details)
            .expect("validation details should serialize")
            .contains(" active "),
        "structured validation details must not echo rejected agent values"
    );
    assert_eq!(
        details
            .as_ref()
            .and_then(|details| details.pointer("/problems/0/allowed")),
        Some(&json!(["Active", "Paused"]))
    );

    enum_runtime.remove_plan(&connection_id);
    let unavailable = executor
        .execute(
            "set_status",
            json!({"status": "Active"}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("missing dynamic values must fail closed");
    assert!(matches!(
        unavailable,
        ToolRuntimeError::WorkFailed { ref reason, .. }
            if reason.as_deref() == Some(TOOL_ENUM_SOURCE_UNAVAILABLE_REASON)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "rejected dynamic enum calls must not reach the upstream"
    );
}

#[test]
fn connection_only_registry_does_not_require_the_legacy_upstream_url() {
    let registry = ToolRegistry::from_json_value(json!({
        "schema_version": "0.1.0",
        "tools": [connection_charge_tool("billing-api")]
    }))
    .expect("connection-bound registry should load");
    let config = Config::test_defaults();
    assert!(config.upstream_url.is_none());
    let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let egress =
        Arc::new(EgressClient::new(EgressConfig::default()).expect("egress client should build"));

    ToolExecutor::from_config(
        &config,
        registry,
        runtime,
        egress,
        ToolConnectionRuntimes::default(),
        audit,
    )
    .expect("a connection-only registry must not require UPSTREAM_URL");
}

#[tokio::test]
async fn connection_bound_manual_tool_injects_primary_and_additional_headers() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let connection = TemporaryStaticAuthRuntime::header_api_key_with_additional(
        addr,
        &ca_pem,
        b"operator-owned-key",
        &[
            (
                "cf-access-client-id",
                "proxy-client-id",
                b"operator-client-id",
            ),
            (
                "cf-access-client-secret",
                "proxy-client-secret",
                b"operator-client-secret",
            ),
        ],
    )
    .await;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(2_000, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = executor_for_connection_tool(
        connection_charge_tool(&connection.connection_id),
        &connection,
        runtime,
        audit,
    );

    let response = http_response(
        executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_123" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("connection-bound tool invocation should succeed"),
    );
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, b"secure");
    let request = server.await.expect("TLS server task should join");
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, "/v1/charges/ch_123");
    assert_eq!(request.header("x-api-key"), Some("operator-owned-key"));
    assert_eq!(
        request.header("cf-access-client-id"),
        Some("operator-client-id")
    );
    assert_eq!(
        request.header("cf-access-client-secret"),
        Some("operator-client-secret")
    );
    assert_eq!(request.header("authorization"), None);
    assert_eq!(request.header("cookie"), None);

    let events = audit_events(&capture, 4).await;
    let upstream = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
        .expect("tool upstream event should exist");
    assert_eq!(
        upstream.payload["connection_id"],
        json!(connection.connection_id)
    );
    assert!(
        !format!("{events:?}").contains("operator-owned-key")
            && !format!("{events:?}").contains("operator-client-id")
            && !format!("{events:?}").contains("operator-client-secret"),
        "audit events must never contain resolved credential material"
    );
}

#[tokio::test]
async fn managed_openapi_tool_without_current_catalog_fails_before_upstream_io() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"must-not-be-read").await;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let mut definition =
        serde_json::from_value::<ToolDefinition>(connection_charge_tool(&connection.connection_id))
            .expect("connection tool definition should deserialize");
    definition.source = ToolSource::OpenApi {
        connection_id: connection.connection_id.clone(),
        operation_id: Some("getCharge".to_owned()),
        catalog_revision: Some(1),
    };
    let registry = ToolRegistry::disabled();
    registry
        .replace_openapi_connection_catalog(&connection.connection_id, vec![definition], || {
            Ok::<(), ()>(())
        })
        .expect("managed OpenAPI definition should publish for the test");
    let executor = ToolExecutor::new_inner(
        registry,
        runtime,
        Arc::clone(&connection.egress_client),
        audit,
        ToolExecutorBackends {
            upstream_url: None,
            connection_http: Some(connection.runtime.clone()),
            mcp_catalog_runtime: None,
            openapi_catalog_runtime: None,
            mcp_upstream_servers: HashMap::new(),
            mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                timeout: Duration::from_secs(30),
                response_idle_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(10),
                max_request_body_bytes: 1_048_576,
                max_response_bytes: 5_242_880,
            },
        },
    )
    .expect("connection-bound executor should build");

    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_stale" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("missing active catalog must fail closed");
    assert!(work_failed_message(error).contains("catalog_stale"));

    let events = audit_events(&capture, 4).await;
    let upstream = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
        .expect("catalog rejection should be audited as an upstream failure");
    assert_eq!(upstream.payload["reason"], json!("catalog_stale"));
    assert_eq!(
        upstream.payload["connection_id"],
        json!(connection.connection_id)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "catalog validation must reject before any upstream socket is opened"
    );
}

#[tokio::test]
async fn held_old_openapi_definition_fails_before_secret_or_upstream_io() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"must-not-be-read").await;
    let record = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .find(|record| record.id.as_str() == connection.connection_id)
        .cloned()
        .expect("test connection should be present");

    let mut held_definition =
        serde_json::from_value::<ToolDefinition>(connection_charge_tool(&connection.connection_id))
            .expect("connection tool definition should deserialize");
    held_definition.source = ToolSource::OpenApi {
        connection_id: connection.connection_id.clone(),
        operation_id: Some("getCharge".to_owned()),
        catalog_revision: Some(1),
    };
    let mut current_definition = held_definition.clone();
    current_definition.description =
        "Current catalog definition with a changed fingerprint.".to_owned();
    current_definition.source = ToolSource::OpenApi {
        connection_id: connection.connection_id.clone(),
        operation_id: Some("getCharge".to_owned()),
        catalog_revision: Some(2),
    };
    let current_catalog = StoredOpenApiCatalog {
        connection_id: record.id.clone(),
        spec_revision: 2,
        catalog_revision: 2,
        observed_etag: record.etag(),
        spec_digest: "current-spec-digest".to_owned(),
        spec: r#"{"openapi":"3.0.0"}"#.to_owned(),
        refreshed_at: "2026-07-28T00:00:00Z".to_owned(),
        entries: vec![StoredOpenApiCatalogEntry {
            tool_name: current_definition.name.clone(),
            operation_id: Some("getCharge".to_owned()),
            selected_scheme_names: vec!["ApiKey".to_owned()],
            definition: serde_json::to_value(&current_definition)
                .expect("current definition should serialize"),
        }],
        overlay_revision: 0,
    };
    let openapi_catalog_runtime =
        OpenApiConnectionCatalogRuntime::from_catalogs_for_test(&[current_catalog])
            .expect("current catalog runtime should build");

    let registry = ToolRegistry::disabled();
    registry
        .replace_openapi_connection_catalog(
            &connection.connection_id,
            vec![held_definition],
            || Ok::<(), ()>(()),
        )
        .expect("held OpenAPI definition should publish for the test");
    fs::remove_file(&connection.secret_path)
        .expect("provider file should disappear before invocation");
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = ToolExecutor::new_inner(
        registry,
        runtime,
        Arc::clone(&connection.egress_client),
        audit,
        ToolExecutorBackends {
            upstream_url: None,
            connection_http: Some(connection.runtime.clone()),
            mcp_catalog_runtime: None,
            openapi_catalog_runtime: Some(openapi_catalog_runtime),
            mcp_upstream_servers: HashMap::new(),
            mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                timeout: Duration::from_secs(30),
                response_idle_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(10),
                max_request_body_bytes: 1_048_576,
                max_response_bytes: 5_242_880,
            },
        },
    )
    .expect("connection-bound executor should build");

    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_old_generation" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("a held definition from an old catalog generation must fail closed");
    assert!(work_failed_message(error).contains("catalog_stale"));

    let events = audit_events(&capture, 4).await;
    let upstream = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
        .expect("old catalog rejection should be audited");
    assert_eq!(upstream.payload["reason"], json!("catalog_stale"));
    assert!(events
        .iter()
        .all(|event| { event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED }));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "catalog generation validation must reject before upstream I/O"
    );
}

#[tokio::test]
async fn connection_tool_auth_rejection_is_sanitized_and_recorded_as_failure() {
    const CHALLENGE_CANARY: &str = "Bearer realm=\"challenge-canary\"";
    const BODY_CANARY: &[u8] = b"upstream-auth-body-canary";
    let (addr, ca_pem, server) = one_request_tls_server_response(
        StatusCode::UNAUTHORIZED,
        BODY_CANARY,
        Some(CHALLENGE_CANARY),
    )
    .await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"operator-owned-key").await;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(2_000, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = executor_for_connection_tool(
        connection_charge_tool(&connection.connection_id),
        &connection,
        runtime,
        audit,
    );

    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_auth_rejected" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("credentialed upstream 401 must fail closed");
    let message = work_failed_message(error);
    assert!(message.contains("auth_failed"));
    assert!(!message.contains(CHALLENGE_CANARY));
    assert!(
        !message.contains(std::str::from_utf8(BODY_CANARY).expect("body canary should be ASCII"))
    );

    let request = server.await.expect("TLS server task should join once");
    assert_eq!(request.method, "GET");
    assert_eq!(request.target, "/v1/charges/ch_auth_rejected");
    let events = audit_events(&capture, 4).await;
    let rendered = serde_json::to_string(&events).expect("events should serialize");
    assert!(!rendered.contains(CHALLENGE_CANARY));
    assert!(
        !rendered.contains(std::str::from_utf8(BODY_CANARY).expect("body canary should be ASCII"))
    );
    let upstream = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
        .expect("tool upstream failure should be audited");
    assert_eq!(upstream.payload["outcome"], json!("failure"));
    assert_eq!(upstream.payload["reason"], json!("auth_failed"));
    assert_eq!(upstream.payload["upstream_status"], Value::Null);
}

#[tokio::test]
async fn oversized_oauth_rejection_invalidates_before_body_buffering() {
    let (addr, ca_pem, server) = oauth_rejection_then_success_tls_server().await;
    let connection = TemporaryStaticAuthRuntime::oauth_client_credentials(addr, &ca_pem).await;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(2_000, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = executor_for_connection_tool(
        connection_charge_tool(&connection.connection_id),
        &connection,
        runtime,
        audit,
    );

    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_oauth_rejected" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("oversized OAuth 401 must fail as an authentication rejection");
    let message = work_failed_message(error);
    assert!(message.contains("auth_failed"));
    assert!(!message.contains("response_too_large"));
    assert!(!message.contains(OAUTH_CHALLENGE_CANARY));
    assert!(!message.contains(OVERSIZED_AUTH_BODY_CANARY));

    let response = http_response(
        executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_after_invalidation" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("the next call should mint a replacement token and succeed"),
    );
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, b"replacement accepted");

    let requests = server.await.expect("OAuth TLS server should join");
    let token_requests = requests
        .iter()
        .filter(|request| request.target == "/oauth/token")
        .count();
    assert_eq!(
        token_requests, 2,
        "the rejected cached token must be invalidated before the next invocation"
    );
    let api_requests = requests
        .iter()
        .filter(|request| request.target.starts_with("/v1/charges/"))
        .collect::<Vec<_>>();
    assert_eq!(api_requests.len(), 2);
    let first_authorization = format!("Bearer {FIRST_OAUTH_ACCESS_TOKEN}");
    let replacement_authorization = format!("Bearer {REPLACEMENT_OAUTH_ACCESS_TOKEN}");
    assert_eq!(
        api_requests[0].header("authorization"),
        Some(first_authorization.as_str())
    );
    assert_eq!(
        api_requests[1].header("authorization"),
        Some(replacement_authorization.as_str())
    );

    let events = audit_events(&capture, 8).await;
    let rendered = serde_json::to_string(&events).expect("events should serialize");
    assert!(!rendered.contains(OAUTH_CHALLENGE_CANARY));
    assert!(!rendered.contains(OVERSIZED_AUTH_BODY_CANARY));
    assert!(events.iter().any(|event| {
        event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
            && event.payload["outcome"] == json!("failure")
            && event.payload["reason"] == json!("auth_failed")
    }));
}

#[tokio::test]
async fn connection_tool_checks_egress_before_reading_the_secret_provider() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let mut connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"unread-secret").await;
    fs::remove_file(&connection.secret_path)
        .expect("provider file should disappear after Connection activation");
    let blocked_config = EgressConfig::default();
    let blocked_client =
        Arc::new(EgressClient::new(blocked_config.clone()).expect("blocked egress should build"));
    connection.runtime = ConnectionHttpRuntime::new(
        connection.control_plane.clone(),
        blocked_config,
        Arc::clone(&blocked_client),
    );
    connection.egress_client = blocked_client;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = executor_for_connection_tool(
        connection_charge_tool(&connection.connection_id),
        &connection,
        runtime,
        audit,
    );

    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_egress_first" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("non-allowlisted Connection destination must fail closed");
    let message = work_failed_message(error);
    assert!(message.contains("host_not_allowed"));
    assert!(!message.contains("127.0.0.1"));
    let events = audit_events(&capture, 3).await;
    assert!(
        events
            .iter()
            .all(|event| { event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED }),
        "the provider must not be touched after an egress denial"
    );
    assert!(
        !format!("{events:?}").contains("unread-secret"),
        "failure telemetry must not contain secret material"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "egress denial must happen before the TLS upstream receives a request"
    );
}

#[tokio::test]
async fn credentialed_connection_trace_fails_before_secret_or_upstream_io() {
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"must-not-be-read").await;
    fs::remove_file(&connection.secret_path)
        .expect("provider file should disappear before invocation");
    let mut tool = connection_charge_tool(&connection.connection_id);
    tool["target"]["mapping"]["method"] = json!("TRACE");
    tool["upstream"]["method"] = json!("TRACE");
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = executor_for_connection_tool(tool, &connection, runtime, audit);

    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "ch_trace" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("credentialed Connection TRACE must fail closed");
    assert!(work_failed_message(error).contains("unsafe_trace_method"));

    let events = audit_events(&capture, 4).await;
    let upstream = events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
        .expect("TRACE rejection should be audited");
    assert_eq!(upstream.payload["reason"], json!("unsafe_trace_method"));
    assert!(events
        .iter()
        .all(|event| { event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED }));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "TRACE rejection must happen before opening an upstream socket"
    );
}

#[tokio::test]
async fn connection_tool_secret_failure_is_safe_and_audited_without_upstream_bytes() {
    const ARGUMENT_CANARY: &str = "admin-playground-argument-canary";
    let (addr, ca_pem, server) = one_request_tls_server().await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"never-log-this").await;
    fs::remove_file(&connection.secret_path)
        .expect("provider file should disappear after Connection activation");
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = executor_for_connection_tool(
        connection_charge_tool(&connection.connection_id),
        &connection,
        runtime,
        audit,
    );
    let mut context = invocation_context();
    context.source = ToolInvocationSource::AdminPlayground;

    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": ARGUMENT_CANARY }),
            context,
            CancellationToken::new(),
        )
        .await
        .expect_err("missing provider material must fail closed");
    let message = work_failed_message(error);
    assert!(message.contains("credential_unavailable"));
    assert!(!message.contains("never-log-this"));
    assert!(!message.contains("api-key"));

    let events = audit_events(&capture, 4).await;
    let failure = events
        .iter()
        .find(|event| event.event_type == audit::event::CONNECTION_SECRET_RESOLUTION_FAILED)
        .expect("secret resolution failure should emit a dedicated audit event");
    assert_eq!(
        failure.payload["connection_id"],
        json!(connection.connection_id)
    );
    assert_eq!(failure.payload["consumer_kind"], json!("manual_tool"));
    assert_eq!(failure.payload["consumer_id"], json!("get_charge"));
    assert_eq!(failure.payload["auth_type"], json!("header_api_key"));
    assert_eq!(failure.payload["reason"], json!("credential_unavailable"));
    assert_eq!(
        failure.payload["invocation_source"],
        json!("admin_playground")
    );
    assert!(failure.payload.get("arguments").is_none());
    let rendered_events = serde_json::to_string(&events).expect("audit events should serialize");
    assert!(!rendered_events.contains("never-log-this"));
    assert!(!rendered_events.contains(ARGUMENT_CANARY));
    assert!(!rendered_events.contains(&format!("https://127.0.0.1:{}", addr.port())));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "credential resolution failure must happen before upstream bytes"
    );
}

#[tokio::test]
async fn connection_change_during_execution_precondition_fails_before_secret_or_upstream_io() {
    const ARGUMENT_CANARY: &str = "connection-race-argument-canary";
    const SECRET_CANARY: &str = "connection-race-secret-canary";

    let (addr, ca_pem, server) = one_request_tls_server().await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, SECRET_CANARY.as_bytes()).await;
    let record = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .find(|record| record.id.as_str() == connection.connection_id)
        .cloned()
        .expect("test Connection should be present");
    let connection_id = record.id.clone();
    let expected_etag = record.etag();
    let mut edited = record.write.clone();
    edited.endpoint.base_path = "/edited".to_owned();

    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = ToolRuntime::new(
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
    );
    let executor = executor_for_connection_tool(
        connection_charge_tool(&connection.connection_id),
        &connection,
        runtime,
        audit,
    );
    let control_plane = connection.control_plane.clone();
    let secret_path = connection.secret_path.clone();
    let mut context = invocation_context();
    context.source = ToolInvocationSource::AdminPlayground;

    let error = executor
        .execute_with_precondition(
            "get_charge",
            json!({ "charge_id": ARGUMENT_CANARY }),
            context,
            CancellationToken::new(),
            // The racing edit is a control-plane write, which is now
            // asynchronous, so the validator is registered as an
            // asynchronous checker and awaited in place.
            ToolExecutionPrecondition::new_async(move |_| {
                let control_plane = control_plane.clone();
                let connection_id = connection_id.clone();
                let expected_etag = expected_etag.clone();
                let edited = edited.clone();
                let secret_path = secret_path.clone();
                Box::pin(async move {
                    let observed = control_plane
                        .runtime_snapshot()
                        .managed()
                        .get(&connection_id)
                        .cloned()
                        .expect("Connection should still exist before the racing edit");
                    assert_eq!(
                        observed.etag(),
                        expected_etag,
                        "the validator must first observe the expected old revision"
                    );
                    control_plane
                        .replace_managed(&connection_id, &expected_etag, edited, "test-admin")
                        .await
                        .expect("racing Connection edit should publish");
                    fs::remove_file(&secret_path)
                        .expect("secret canary should disappear after the validator read");
                    Ok(())
                })
            }),
        )
        .await
        .expect_err("a Connection edit during validation must fail closed");

    assert!(matches!(
        error,
        ToolRuntimeError::Rejected { ref reason, .. }
            if reason == TOOL_PRECONDITION_FAILED_REASON
    ));
    let events = audit_events(&capture, 3).await;
    assert!(events.iter().any(|event| {
        event.event_type == audit::event::TOOL_INVOKE_REJECTED
            && event.payload["reason"] == json!(TOOL_PRECONDITION_FAILED_REASON)
            && event.payload["invocation_source"] == json!("admin_playground")
    }));
    assert!(events.iter().all(|event| {
        event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED
            && event.event_type != audit::event::TOOL_UPSTREAM_REQUEST
    }));
    let rendered_events =
        serde_json::to_string(&events).expect("race audit events should serialize");
    assert!(!rendered_events.contains(ARGUMENT_CANARY));
    assert!(!rendered_events.contains(SECRET_CANARY));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "the edited target must not receive upstream bytes"
    );
}

#[tokio::test]
async fn live_http_deny_published_during_precondition_fails_before_secret_or_upstream_io() {
    const ARGUMENT_CANARY: &str = "policy-race-argument-canary";
    const SECRET_CANARY: &str = "policy-race-secret-canary";

    let (addr, ca_pem, server) = one_request_tls_server().await;
    let connection =
        TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, SECRET_CANARY.as_bytes()).await;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let initial_policy = Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "tools": {
            "get_charge": {
                "timeout_ms": 500,
                "max_concurrent": 1
            }
        }
    }))
    .expect("initial live policy should validate");
    let rbac_state =
        crate::middleware::rbac::RbacState::new(initial_policy, Vec::new(), false, audit.clone());
    let runtime = ToolRuntime::new_with_rbac_state(
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        audit.clone(),
        Some(rbac_state.clone()),
    );
    let executor = executor_for_connection_tool(
        connection_charge_tool(&connection.connection_id),
        &connection,
        runtime,
        audit,
    );
    let policy_path = connection.root.join("live-policy.json");
    let policy_path_for_precondition = policy_path.clone();
    let rbac_state_for_precondition = rbac_state.clone();
    let secret_path = connection.secret_path.clone();
    let precondition = ToolExecutionPrecondition::new_async(move |_| {
        let policy_path = policy_path_for_precondition.clone();
        let rbac_state = rbac_state_for_precondition.clone();
        let secret_path = secret_path.clone();
        Box::pin(async move {
            let deny_policy = json!({
                "schema_version": "0.1.0",
                "tools": {
                    "get_charge": {
                        "timeout_ms": 500,
                        "max_concurrent": 1
                    }
                },
                "rules": [{
                    "id": "deny-charge-after-precondition",
                    "methods": ["GET"],
                    "path": "/charges/{charge_id}",
                    "action": "deny"
                }]
            });
            fs::write(
                &policy_path,
                serde_json::to_vec(&deny_policy).expect("deny policy should serialize"),
            )
            .expect("deny policy should write");
            crate::middleware::rbac::reload_policy_from_file(&rbac_state, &policy_path)
                .await
                .expect("deny policy should publish during the final precondition");
            fs::remove_file(&secret_path)
                .expect("secret canary should disappear after the policy reload");
            Ok(())
        })
    });
    let mut context = invocation_context();
    context.source = ToolInvocationSource::AdminPlayground;

    let error = executor
        .execute_inner(
            "get_charge",
            json!({ "charge_id": ARGUMENT_CANARY }),
            &context,
            &CancellationToken::new(),
            Some(&precondition),
        )
        .await
        .expect_err("the newly published direct HTTP Deny rule must fail closed");

    assert!(matches!(
        error,
        ToolExecutorError::HttpRuleDenied { ref tool_name } if tool_name == "get_charge"
    ));
    let events = audit_events(&capture, 1).await;
    let denied = events
        .iter()
        .find(|event| event.event_type == "authz.denied")
        .expect("the final authorization check should audit the live Deny rule");
    assert_eq!(denied.payload["tool_name"], json!("get_charge"));
    assert_eq!(denied.payload["method"], json!("GET"));
    assert_eq!(denied.payload["path"], json!("/mcp/tools/get_charge"));
    assert_eq!(
        denied.payload["matched_rule_id"],
        json!("deny-charge-after-precondition")
    );
    assert_eq!(
        denied.payload["invocation_source"],
        json!("admin_playground")
    );
    assert!(events.iter().all(|event| {
        event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED
            && event.event_type != audit::event::TOOL_UPSTREAM_REQUEST
    }));
    let rendered_events =
        serde_json::to_string(&events).expect("policy-race audit events should serialize");
    assert!(!rendered_events.contains(ARGUMENT_CANARY));
    assert!(!rendered_events.contains(SECRET_CANARY));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "the newly denied invocation must not send upstream bytes"
    );
}

#[tokio::test]
async fn schema_validation_rejects_args_before_network() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "echo",
            json!({ "unexpected": "value" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("invalid args should fail");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(message.contains("required"));

    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "schema rejection must not reach the upstream listener"
    );
}

#[tokio::test]
async fn schema_validation_rejects_unexpected_args_by_default_before_network() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [echo_tool_without_additional_properties()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "echo",
            json!({
                "message": "hello",
                "unexpected": "value"
            }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("unexpected args should fail without an explicit schema opt-in");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(
        message.contains("unexpected"),
        "validation message should identify the extra argument: {message}"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "strict schema rejection must not reach the upstream listener"
    );
}

#[tokio::test]
async fn schema_validation_skips_strict_injection_for_top_level_one_of_schema() {
    let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [one_of_echo_tool_without_additional_properties()],
        runtime_config([("echo_one_of", enabled_tool(500, 1))], 2, 1, 100),
    );

    let response = http_response(
        executor
            .execute(
                "echo_one_of",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("top-level oneOf schema should validate through its branch"),
    );

    assert_eq!(response.status, StatusCode::OK);
    let request = server.await.expect("server task should join");
    assert_eq!(request.target, "/v1/echo");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.body)
            .expect("request body should be JSON"),
        json!({ "message": "hello" })
    );
}

#[tokio::test]
async fn schema_validation_rejects_unexpected_nested_object_args_by_default_before_network() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [nested_config_tool_without_nested_additional_properties()],
        runtime_config([("configure", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "configure",
            json!({
                "settings": {
                    "name": "primary",
                    "unexpected": "value"
                }
            }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("unexpected nested object args should fail by default");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(
        message.contains("unexpected"),
        "validation message should identify the nested extra argument: {message}"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "nested strict schema rejection must not reach the upstream listener"
    );
}

#[tokio::test]
async fn schema_validation_rejects_unexpected_deeply_nested_object_args_by_default() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [deeply_nested_config_tool_without_additional_properties()],
        runtime_config([("deep_configure", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "deep_configure",
            json!({
                "settings": {
                    "limits": {
                        "rate": 10,
                        "unexpected": true
                    }
                }
            }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("unexpected deeply nested object args should fail by default");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(
        message.contains("unexpected"),
        "validation message should identify the deeply nested extra argument: {message}"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "deeply nested strict schema rejection must not reach the upstream listener"
    );
}

#[test]
fn strict_schema_injection_depth_cap_leaves_deeper_branch_unmodified_without_crashing() {
    let nested_depth = EXPECTED_STRICT_SCHEMA_INJECTION_MAX_DEPTH + 2;
    let tool = tool_definition(
        deep_schema_tool(nested_object_schema(nested_depth)),
        "deep_schema",
    );
    let effective_schema = effective_input_schema(&tool.input_schema);
    let validator = jsonschema::validator_for(&effective_schema)
        .expect("capped strict schema injection should compile without crashing");
    let args = nested_object_args_with_extra_at_depth(nested_depth, nested_depth);
    let problems = validation_problem_messages(&validator, &args);

    assert!(
            problems.is_empty(),
            "extra fields beyond the strict injection depth cap should be left to the original schema: {problems:?}"
        );
}

#[test]
fn strict_schema_injection_applies_at_every_level_below_depth_cap() {
    let nested_depth = EXPECTED_STRICT_SCHEMA_INJECTION_MAX_DEPTH - 1;
    let effective_schema = effective_input_schema(&nested_object_schema(nested_depth));
    let validator = jsonschema::validator_for(&effective_schema)
        .expect("below-cap strict schema should compile");

    for extra_depth in 0..=nested_depth {
        let args = nested_object_args_with_extra_at_depth(nested_depth, extra_depth);
        let problems = validation_problem_messages(&validator, &args);
        assert!(
                !problems.is_empty(),
                "extra field at object depth {extra_depth} should be rejected below the strict injection depth cap"
            );
    }
}

#[tokio::test]
async fn schema_validation_rejects_unexpected_array_item_object_args_before_network() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [array_items_tool_without_item_additional_properties()],
        runtime_config([("bulk_configure", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "bulk_configure",
            json!({
                "items": [
                    {
                        "name": "primary",
                        "unexpected": "value"
                    }
                ]
            }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("unexpected array item object args should fail by default");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(
        message.contains("unexpected"),
        "validation message should identify the array item extra argument: {message}"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "array item strict schema rejection must not reach the upstream listener"
    );
}

#[tokio::test]
async fn schema_validation_rejects_unexpected_prefix_item_object_args_before_network() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [prefix_items_tool_without_item_additional_properties()],
        runtime_config([("tuple_configure", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "tuple_configure",
            json!({
                "items": [
                    {
                        "name": "primary",
                        "unexpected": "value"
                    }
                ]
            }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("unexpected prefix item object args should fail by default");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(
        message.contains("unexpected"),
        "validation message should identify the prefix item extra argument: {message}"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "prefix item strict schema rejection must not reach the upstream listener"
    );
}

#[tokio::test]
async fn schema_validation_rejects_unexpected_nested_array_item_object_args_before_network() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [nested_array_items_tool_without_item_additional_properties()],
        runtime_config([("group_configure", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "group_configure",
            json!({
                "groups": [
                    {
                        "members": [
                            {
                                "name": "alice",
                                "unexpected": "value"
                            }
                        ]
                    }
                ]
            }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("unexpected nested array item object args should fail by default");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(
        message.contains("unexpected"),
        "validation message should identify the nested array item extra argument: {message}"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "nested array item strict schema rejection must not reach the upstream listener"
    );
}

#[tokio::test]
async fn schema_validation_respects_explicit_additional_properties_true() {
    let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [echo_tool_with_additional_properties(true)],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );

    let response = http_response(
        executor
            .execute(
                "echo",
                json!({
                    "message": "hello",
                    "unexpected": "allowed"
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("explicit additionalProperties=true should allow extra args"),
    );

    assert_eq!(response.status, StatusCode::OK);
    let request = server.await.expect("server task should join");
    assert_eq!(request.target, "/v1/echo");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.body)
            .expect("request body should be JSON"),
        json!({
            "message": "hello",
            "unexpected": "allowed"
        })
    );
}

#[tokio::test]
async fn schema_validation_failure_feeds_schema_mismatch_aggregate_and_signal() {
    let db = TempDiscoveryDb::new("tool-schema-mismatch-signal");
    let aggregator = EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
        path: db.path.clone(),
        payload_capture_enabled: false,
        endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
        signal_event_sender: None,
        signal_detector_config: Default::default(),
    })
    .expect("discovery aggregator sink should build");
    let audit = AuditLog::new(Arc::new(aggregator) as Arc<dyn AuditSink>);
    let executor = executor_for_tools_with_audit(
        socket_addr(1),
        [echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 8, 1, 100),
        audit,
    );

    for _ in 0..DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD {
        let error = executor
            .execute(
                "echo",
                json!({ "unexpected": "value" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("schema validation should reject invalid args");
        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
    }

    wait_until(Duration::from_secs(2), || {
        discovery_aggregate_snapshot(&db.path, "MCP", "/mcp/tools/echo").is_some_and(|aggregate| {
            aggregate.call_count
                == i64::try_from(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
                    .expect("default threshold should fit i64")
                && aggregate.schema_mismatch_count
                    == i64::try_from(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
                        .expect("default threshold should fit i64")
        }) && discovery_signal_rows_by_type(&db.path, SCHEMA_MISMATCH_SIGNAL_TYPE).len() == 1
    })
    .await;

    let aggregate = discovery_aggregate_snapshot(&db.path, "MCP", "/mcp/tools/echo")
        .expect("tool schema mismatch aggregate should be present");
    assert_eq!(
        aggregate.call_count,
        i64::try_from(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
            .expect("default threshold should fit i64")
    );
    assert_eq!(aggregate.call_count, aggregate.schema_mismatch_count);

    let rows = discovery_signal_rows_by_type(&db.path, SCHEMA_MISMATCH_SIGNAL_TYPE);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target_kind, "endpoint");
    assert_eq!(rows[0].target_key, "MCP /mcp/tools/echo");
    let evidence: serde_json::Value =
        serde_json::from_str(&rows[0].evidence_json).expect("signal evidence should be JSON");
    assert_eq!(
        evidence["schema_mismatch_count"],
        json!(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
    );
    assert_eq!(
        evidence["threshold"],
        json!(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
    );
}

#[tokio::test]
async fn missing_path_placeholder_arg_is_rejected() {
    let (executor, capture) = executor_for_tools(
        socket_addr(1),
        [widget_tool(false, false)],
        runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "get_widget",
            json!({}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("missing path arg should fail");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(
        message.contains("widget_id"),
        "schema validation error should name the missing path argument: {message}"
    );

    let events = audit_events(&capture, 3).await;
    assert_eq!(events[0].event_type, audit::event::TOOL_INVOKE_START);
    assert_eq!(events[1].event_type, HTTP_REQUEST_OBSERVED);
    assert_eq!(events[2].event_type, audit::event::TOOL_INVOKE_FAILURE);
    assert_eq!(events[1].payload["tool_name"], json!("get_widget"));
    assert_eq!(events[1].payload["method"], json!("MCP"));
    assert_eq!(events[1].payload["path"], json!("/mcp/tools/get_widget"));
    assert_eq!(
        events[1].payload["endpoint_template"],
        json!("/mcp/tools/get_widget")
    );
    assert_eq!(events[1].payload["status"], json!(400));
    assert_eq!(events[1].payload["schema_mismatch"], json!(true));
    assert_eq!(events[1].payload["reason"], json!("input_validation"));
    assert!(
        events[1].payload["latency_ms"].as_u64().is_some(),
        "tool observation event should include latency_ms"
    );
}

#[tokio::test]
async fn missing_upstream_url_reports_configuration_error_observation() {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let executor = executor_for_tools_with_optional_upstream(
        [echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        audit,
        None,
    );

    let error = executor
        .execute(
            "echo",
            json!({ "message": "hello" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("missing upstream URL should fail during request build");

    let message = work_failed_message(error);
    assert!(message.contains("requires UPSTREAM_URL to be set"));

    let events = audit_events(&capture, 3).await;
    assert_eq!(events[0].event_type, audit::event::TOOL_INVOKE_START);
    assert_eq!(events[1].event_type, HTTP_REQUEST_OBSERVED);
    assert_eq!(events[2].event_type, audit::event::TOOL_INVOKE_FAILURE);
    assert_eq!(events[1].payload["tool_name"], json!("echo"));
    assert_eq!(events[1].payload["method"], json!("MCP"));
    assert_eq!(events[1].payload["path"], json!("/mcp/tools/echo"));
    assert_eq!(
        events[1].payload["endpoint_template"],
        json!("/mcp/tools/echo")
    );
    assert_eq!(events[1].payload["status"], json!(520));
    assert_eq!(events[1].payload["schema_mismatch"], json!(false));
    assert_eq!(
        events[1].payload["reason"],
        json!("internal_configuration_error")
    );
    assert!(
        events[1].payload["latency_ms"].as_u64().is_some(),
        "tool observation event should include latency_ms"
    );
}

#[tokio::test]
async fn unknown_tool_emits_raw_name_inventory_observation() {
    let db = TempDiscoveryDb::new("tool-unknown-tool-inventory");
    let aggregator = Arc::new(
        EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
            path: db.path.clone(),
            payload_capture_enabled: false,
            endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            signal_event_sender: None,
            signal_detector_config: Default::default(),
        })
        .expect("discovery aggregator sink should build"),
    ) as Arc<dyn AuditSink>;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(CompositeSink::new(vec![
        Arc::new(capture.clone()) as Arc<dyn AuditSink>,
        aggregator,
    ])) as Arc<dyn AuditSink>);
    let executor = executor_for_tools_with_audit(
        socket_addr(1),
        [echo_tool()],
        runtime_config_without_tools(DefaultToolPolicy::Allow),
        audit,
    );

    let error = executor
        .execute(
            "missing_tool",
            json!({}),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("unknown registry tool should fail inside the executor");

    let message = work_failed_message(error);
    assert!(message.contains("tool 'missing_tool' is not defined"));

    let events = audit_events(&capture, 3).await;
    assert_eq!(events[0].event_type, audit::event::TOOL_INVOKE_START);
    assert_eq!(events[1].event_type, HTTP_REQUEST_OBSERVED);
    assert_eq!(events[2].event_type, audit::event::TOOL_INVOKE_FAILURE);
    assert_eq!(events[1].payload["tool_name"], json!("missing_tool"));
    assert_eq!(events[1].payload["method"], json!("MCP"));
    assert_eq!(events[1].payload["path"], json!("/mcp/tools/missing_tool"));
    // The raw name stays in the event, but it must not become a discovery
    // aggregate key: `endpoint_template` is caller controlled otherwise.
    assert_eq!(
        events[1].payload["endpoint_template"],
        json!(UNKNOWN_TOOL_OBSERVATION_TEMPLATE)
    );
    assert_eq!(events[1].payload["status"], json!(404));
    assert_eq!(events[1].payload["schema_mismatch"], json!(false));
    assert_eq!(events[1].payload["reason"], json!("unknown_tool"));
    assert!(
        events[1].payload["latency_ms"].as_u64().is_some(),
        "tool observation event should include latency_ms"
    );

    wait_until(Duration::from_secs(2), || {
        discovery_aggregate_snapshot(&db.path, "MCP", UNKNOWN_TOOL_OBSERVATION_TEMPLATE)
            .is_some_and(|aggregate| {
                aggregate.call_count == 1 && aggregate.schema_mismatch_count == 0
            })
    })
    .await;

    let aggregate =
        discovery_aggregate_snapshot(&db.path, "MCP", UNKNOWN_TOOL_OBSERVATION_TEMPLATE)
            .expect("unknown tool inventory aggregate should be present");
    assert_eq!(aggregate.call_count, 1);
    assert_eq!(aggregate.schema_mismatch_count, 0);
    assert!(
        discovery_aggregate_snapshot(&db.path, "MCP", "/mcp/tools/missing_tool").is_none(),
        "a caller-supplied tool name must not create its own aggregate"
    );
}

#[tokio::test]
async fn unknown_tool_names_share_one_discovery_endpoint_template() {
    let db = TempDiscoveryDb::new("tool-unknown-tool-cardinality");
    let aggregator = Arc::new(
        EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
            path: db.path.clone(),
            payload_capture_enabled: false,
            endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            signal_event_sender: None,
            signal_detector_config: Default::default(),
        })
        .expect("discovery aggregator sink should build"),
    ) as Arc<dyn AuditSink>;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(CompositeSink::new(vec![
        Arc::new(capture.clone()) as Arc<dyn AuditSink>,
        aggregator,
    ])) as Arc<dyn AuditSink>);
    let executor = executor_for_tools_with_audit(
        socket_addr(1),
        [echo_tool()],
        runtime_config_without_tools(DefaultToolPolicy::Allow),
        audit,
    );

    for index in 0..4 {
        executor.record_unknown_tool_call(
            &invocation_context(),
            &format!("attacker_chosen_name_{index}"),
            Duration::from_millis(1),
        );
    }

    let events = audit_events(&capture, 4).await;
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.event_type, HTTP_REQUEST_OBSERVED);
        assert_eq!(
            event.payload["tool_name"],
            json!(format!("attacker_chosen_name_{index}"))
        );
        assert_eq!(
            event.payload["endpoint_template"],
            json!(UNKNOWN_TOOL_OBSERVATION_TEMPLATE),
            "every unknown name must collapse onto one aggregate key"
        );
    }

    wait_until(Duration::from_secs(2), || {
        discovery_aggregate_snapshot(&db.path, "MCP", UNKNOWN_TOOL_OBSERVATION_TEMPLATE)
            .is_some_and(|aggregate| aggregate.call_count == 4)
    })
    .await;

    for index in 0..4 {
        assert!(
            discovery_aggregate_snapshot(
                &db.path,
                "MCP",
                &format!("/mcp/tools/attacker_chosen_name_{index}")
            )
            .is_none(),
            "no per-name aggregate may be created"
        );
    }
}

#[tokio::test]
async fn known_tool_keeps_its_own_discovery_endpoint_template() {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let executor = executor_for_tools_with_audit(
        socket_addr(1),
        [echo_tool()],
        runtime_config_without_tools(DefaultToolPolicy::Allow),
        audit,
    );

    executor.record_unknown_tool_call(&invocation_context(), "echo", Duration::from_millis(1));

    let events = audit_events(&capture, 1).await;
    assert_eq!(
        events[0].payload["endpoint_template"],
        json!("/mcp/tools/echo"),
        "a registered tool keeps its own aggregate key"
    );
}

#[tokio::test]
async fn disabled_live_policy_tool_feeds_inventory_observation() {
    let (audit, capture, db) = inventory_audit("tool-disabled-policy-inventory");
    let runtime = live_policy_runtime(
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "enabled": false,
                    "timeout_ms": 500,
                    "max_concurrent": 1
                }
            }
        }),
        audit.clone(),
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );
    let executor = executor_for_tools_with_runtime(socket_addr(1), [echo_tool()], runtime, audit);

    let error = executor
        .execute(
            "echo",
            json!({ "message": "hello" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("live policy enabled=false should reject before execution");

    assert!(matches!(error, ToolRuntimeError::Disabled { .. }));
    assert_inventory_observation(&capture, &db.path, "echo", 403, "disabled").await;
}

#[tokio::test]
async fn role_denied_live_policy_tool_feeds_inventory_observation() {
    let (audit, capture, db) = inventory_audit("tool-role-denied-policy-inventory");
    let runtime = live_policy_runtime(
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "allowed_roles": ["operator"],
                    "timeout_ms": 500,
                    "max_concurrent": 1
                }
            }
        }),
        audit.clone(),
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );
    let executor = executor_for_tools_with_runtime(socket_addr(1), [echo_tool()], runtime, audit);

    let error = executor
        .execute(
            "echo",
            json!({ "message": "hello" }),
            invocation_context_with_roles(&["viewer"]),
            CancellationToken::new(),
        )
        .await
        .expect_err("viewer should not satisfy the live policy allowed_roles");

    assert!(matches!(error, ToolRuntimeError::RoleDenied { .. }));
    assert_inventory_observation(&capture, &db.path, "echo", 403, "role_not_allowed").await;
}

#[tokio::test]
async fn direct_http_deny_rule_blocks_rendered_tool_path_before_egress() {
    let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = live_policy_runtime(
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "get_widget": {
                    "timeout_ms": 500,
                    "max_concurrent": 1
                }
            },
            "rules": [
                {
                    "id": "deny-widget-http-path",
                    "methods": ["GET"],
                    "path": "/v1/widgets/{widget_id}",
                    "action": "deny"
                }
            ]
        }),
        audit.clone(),
        runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
    );
    let executor =
        executor_for_tools_with_runtime(addr, [widget_tool(false, true)], runtime, audit);
    let precondition_checks = Arc::new(AtomicUsize::new(0));
    let precondition_checks_for_call = Arc::clone(&precondition_checks);

    let error = executor
        .execute_with_precondition(
            "get_widget",
            json!({ "widget_id": "private/record" }),
            invocation_context(),
            CancellationToken::new(),
            ToolExecutionPrecondition::new(move |_| {
                precondition_checks_for_call.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        )
        .await
        .expect_err("matching direct HTTP Deny rule should reject the tool invocation");

    assert!(matches!(
        error,
        ToolRuntimeError::Rejected { ref reason, .. } if reason == TOOL_MATCHED_RULE_REASON
    ));
    assert_eq!(
        precondition_checks.load(Ordering::SeqCst),
        0,
        "direct HTTP policy must reject before the execution precondition"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "direct HTTP Deny rule must stop the rendered request before egress"
    );

    let events = audit_events(&capture, 4).await;
    let denied = events
        .iter()
        .find(|event| event.event_type == "authz.denied")
        .expect("direct HTTP Deny rule should emit authz.denied");
    assert_eq!(denied.payload["tool_name"], json!("get_widget"));
    assert_eq!(denied.payload["method"], json!("GET"));
    assert_eq!(
        denied.payload["path"],
        json!("/v1/widgets/private%2Frecord")
    );
    assert_eq!(
        denied.payload["matched_rule_id"],
        json!("deny-widget-http-path")
    );
    assert_eq!(denied.payload["invocation_source"], json!("internal"));
    assert!(events.iter().any(|event| {
        event.event_type == audit::event::TOOL_INVOKE_REJECTED
            && event.payload["reason"] == json!(TOOL_MATCHED_RULE_REASON)
    }));
    assert!(events.iter().any(|event| {
        event.event_type == HTTP_REQUEST_OBSERVED
            && event.payload["status"] == json!(StatusCode::FORBIDDEN.as_u16())
            && event.payload["reason"] == json!(TOOL_MATCHED_RULE_REASON)
    }));
}

#[tokio::test]
async fn direct_http_deny_rule_runs_before_connection_lookup() {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = live_policy_runtime(
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "get_charge": {
                    "timeout_ms": 500,
                    "max_concurrent": 1
                }
            },
            "rules": [
                {
                    "id": "deny-charge-http-path",
                    "methods": ["GET"],
                    "path": "/charges/{charge_id}",
                    "action": "deny"
                }
            ]
        }),
        audit.clone(),
        runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
    );
    let registry = ToolRegistry::from_json_value(json!({
        "schema_version": "0.1.0",
        "tools": [connection_charge_tool("missing-connection")]
    }))
    .expect("connection-bound tool should load");
    let executor = executor_for_registry_with_runtime(registry, runtime, audit, None);

    let error = executor
        .execute(
            "get_charge",
            json!({ "charge_id": "private" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("matching deny rule should reject before Connection lookup");
    assert!(matches!(
        error,
        ToolRuntimeError::Rejected { ref reason, .. } if reason == TOOL_MATCHED_RULE_REASON
    ));
    let events = audit_events(&capture, 3).await;
    assert!(events.iter().any(|event| {
        event.event_type == "authz.denied"
            && event.payload["matched_rule_id"] == json!("deny-charge-http-path")
    }));
    assert!(events
        .iter()
        .all(|event| { event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED }));
}

#[tokio::test]
async fn direct_http_shadow_rule_audits_rendered_tool_path_and_allows_egress() {
    let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime = live_policy_runtime(
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "get_widget": {
                    "timeout_ms": 500,
                    "max_concurrent": 1
                }
            },
            "rules": [
                {
                    "id": "shadow-widget-http-path",
                    "methods": ["GET"],
                    "path": "/v1/widgets/{widget_id}",
                    "action": "shadow"
                }
            ]
        }),
        audit.clone(),
        runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
    );
    let executor =
        executor_for_tools_with_runtime(addr, [widget_tool(false, true)], runtime, audit);

    let response = http_response(
        executor
            .execute(
                "get_widget",
                json!({ "widget_id": "public" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("Shadow rule should preserve tool execution"),
    );

    assert_eq!(response.status, StatusCode::OK);
    let request = server.await.expect("server task should join");
    assert_eq!(request.target, "/v1/widgets/public?");

    let events = audit_events(&capture, 5).await;
    let shadow = events
        .iter()
        .find(|event| event.event_type == "authz.would_deny")
        .expect("direct HTTP Shadow rule should emit authz.would_deny");
    assert_eq!(shadow.payload["tool_name"], json!("get_widget"));
    assert_eq!(shadow.payload["method"], json!("GET"));
    assert_eq!(shadow.payload["path"], json!("/v1/widgets/public"));
    assert_eq!(
        shadow.payload["matched_rule_id"],
        json!("shadow-widget-http-path")
    );
}

#[tokio::test]
async fn live_policy_unknown_tool_feeds_inventory_observation() {
    let (audit, capture, db) = inventory_audit("tool-live-policy-unknown-inventory");
    let runtime = live_policy_runtime(
        json!({ "schema_version": "0.1.0" }),
        audit.clone(),
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );
    let executor = executor_for_tools_with_runtime(socket_addr(1), [echo_tool()], runtime, audit);

    let error = executor
        .execute(
            "echo",
            json!({ "message": "hello" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("registered tool absent from live policy tools map should reject");

    assert!(matches!(error, ToolRuntimeError::UnknownTool { .. }));
    assert_inventory_observation(&capture, &db.path, "echo", 404, "unknown_tool").await;
}

#[tokio::test]
async fn queue_full_rejection_feeds_inventory_observation() {
    let server = gated_server().await;
    let (audit, capture, db) = inventory_audit("tool-queue-full-inventory");
    let executor = executor_for_tools_with_audit(
        server.addr,
        [widget_tool(false, true)],
        runtime_config([("get_widget", enabled_tool(1_000, 1))], 1, 1, 100),
        audit,
    );

    let first = tokio::spawn({
        let executor = executor.clone();
        async move {
            executor
                .execute(
                    "get_widget",
                    json!({ "widget_id": "first" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
        }
    });
    wait_until(Duration::from_secs(1), || server.request_count() == 1).await;

    let error = executor
        .execute(
            "get_widget",
            json!({ "widget_id": "second" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("full runtime queue should reject before execution");

    assert!(matches!(
        error,
        ToolRuntimeError::Rejected { ref reason, .. } if reason == "queue_full"
    ));
    assert_inventory_observation(&capture, &db.path, "get_widget", 429, "queue_full").await;

    server.release.release();
    first
        .await
        .expect("first invocation task should join")
        .expect("first invocation should complete after server release");
    server.stop.cancel();
    server.handle.abort();
}

#[tokio::test]
async fn execution_timeout_after_work_started_feeds_inventory_observation() {
    let server = gated_server().await;
    let (audit, capture, db) = inventory_audit("tool-execution-timeout-inventory");
    // The tool timeout must outlast the arrival-wait budget below. If it fires
    // first the executor drops the connection mid-request, `read_http_request`
    // panics on the truncated head, the request is never recorded, and the
    // wait then fails -- so "after work started" is never actually exercised.
    let executor = executor_for_tools_with_audit(
        server.addr,
        [widget_tool(false, true)],
        runtime_config([("get_widget", enabled_tool(2_000, 1))], 2, 1, 100),
        audit,
    );

    let running = tokio::spawn({
        let executor = executor.clone();
        async move {
            executor
                .execute(
                    "get_widget",
                    json!({ "widget_id": "timeout" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
        }
    });
    wait_until(Duration::from_secs(1), || server.request_count() == 1).await;

    let error = running
        .await
        .expect("timed-out invocation task should join")
        .expect_err("runtime timeout should abort slow upstream work");

    assert!(matches!(error, ToolRuntimeError::Timeout { .. }));
    assert_inventory_observation(&capture, &db.path, "get_widget", 504, "timeout").await;

    server.stop.cancel();
    server.handle.abort();
}

#[tokio::test]
async fn mid_execution_cancellation_feeds_inventory_observation() {
    let server = gated_server().await;
    let (audit, capture, db) = inventory_audit("tool-execution-cancelled-inventory");
    let executor = executor_for_tools_with_audit(
        server.addr,
        [widget_tool(false, true)],
        runtime_config([("get_widget", enabled_tool(1_000, 1))], 2, 1, 100),
        audit,
    );
    let cancel = CancellationToken::new();

    let running = tokio::spawn({
        let executor = executor.clone();
        let cancel = cancel.clone();
        async move {
            executor
                .execute(
                    "get_widget",
                    json!({ "widget_id": "cancelled" }),
                    invocation_context(),
                    cancel,
                )
                .await
        }
    });
    wait_until(Duration::from_secs(1), || server.request_count() == 1).await;
    cancel.cancel();

    let error = running
        .await
        .expect("cancelled invocation task should join")
        .expect_err("mid-execution cancellation should abort upstream work");

    assert!(matches!(error, ToolRuntimeError::Cancelled { .. }));
    assert_inventory_observation(&capture, &db.path, "get_widget", 429, "cancelled").await;

    server.stop.cancel();
    server.handle.abort();
}

#[tokio::test]
async fn missing_required_query_arg_is_rejected() {
    let (executor, _capture) = executor_for_tools(
        socket_addr(1),
        [widget_tool(true, false)],
        runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "get_widget",
            json!({ "widget_id": "abc" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("missing required query arg should fail");

    let message = work_failed_message(error);
    assert!(message.contains("arguments failed input schema validation"));
    assert!(
        message.contains("include_details"),
        "schema validation error should name the missing query argument: {message}"
    );
}

#[tokio::test]
async fn dot_dot_path_placeholder_arg_is_rejected_before_network() {
    assert_dot_segment_rejected_before_network(
        widget_tool(false, true),
        "get_widget",
        json!({ "widget_id": ".." }),
        "widget_id",
    )
    .await;
}

#[tokio::test]
async fn single_dot_path_placeholder_arg_is_rejected_before_network() {
    assert_dot_segment_rejected_before_network(
        widget_tool(false, true),
        "get_widget",
        json!({ "widget_id": "." }),
        "widget_id",
    )
    .await;
}

#[tokio::test]
async fn non_dot_segment_path_placeholder_args_with_dots_are_accepted_and_encoded() {
    for (value, expected_target) in [
        ("v1.2.3", "/v1/widgets/v1%2E2%2E3?include_details=true"),
        ("file.txt", "/v1/widgets/file%2Etxt?include_details=true"),
        (".hidden", "/v1/widgets/%2Ehidden?include_details=true"),
    ] {
        let (addr, server) = one_request_server(StatusCode::OK, b"safe").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [widget_tool(false, true)],
            runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
        );

        let response = http_response(
            executor
                .execute(
                    "get_widget",
                    json!({
                        "widget_id": value,
                        "include_details": true
                    }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("non-dot-segment value should make a valid request"),
        );

        assert_eq!(response.status, StatusCode::OK);
        let request = server.await.expect("server task should join");
        assert_eq!(request.target, expected_target);
    }
}

#[tokio::test]
async fn tenant_subtree_dot_segment_placeholder_arg_is_rejected_before_network() {
    for (args, rejected_arg_name) in [
        (
            json!({
                "tenant_id": "..",
                "config_name": "default"
            }),
            "tenant_id",
        ),
        (
            json!({
                "tenant_id": "tenant-a",
                "config_name": "."
            }),
            "config_name",
        ),
    ] {
        assert_dot_segment_rejected_before_network(
            tenant_config_tool(),
            "get_tenant_config",
            args,
            rejected_arg_name,
        )
        .await;
    }
}

#[tokio::test]
async fn path_placeholder_args_are_segment_encoded_to_block_path_injection() {
    let (addr, server) = one_request_server(StatusCode::OK, b"safe").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [widget_tool(false, true)],
        runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
    );

    let malicious = "../../../etc/passwd?host=evil.example.com#frag";
    let response = http_response(
        executor
            .execute(
                "get_widget",
                json!({
                    "widget_id": malicious,
                    "include_details": true
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("encoded malicious value should still make a valid request"),
    );

    assert_eq!(response.status, StatusCode::OK);
    let request = server.await.expect("server task should join");
    assert_eq!(
            request.target,
            "/v1/widgets/%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd%3Fhost=evil%2Eexample%2Ecom%23frag?include_details=true"
        );
    assert!(
        !request.target.contains("../"),
        "raw traversal must not survive substitution: {}",
        request.target
    );
    assert!(
        !request.target.contains("?host=evil.example.com"),
        "argument value must not introduce a query string: {}",
        request.target
    );
    assert!(
        !request.target.contains("#frag"),
        "argument value must not introduce a fragment: {}",
        request.target
    );
}

#[tokio::test]
async fn runtime_timeout_cancels_slow_upstream_call() {
    let (addr, server) = delayed_response_server(Duration::from_secs(5)).await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [widget_tool(false, true)],
        runtime_config([("get_widget", enabled_tool(50, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            "get_widget",
            json!({ "widget_id": "abc" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("runtime timeout should abort slow upstream work");

    assert!(matches!(error, ToolRuntimeError::Timeout { .. }));
    server.abort();
}

#[tokio::test]
async fn runtime_queue_limits_apply_to_executor_invocations() {
    let server = gated_server().await;
    let (executor, _capture) = executor_for_tools(
        server.addr,
        [widget_tool(false, true)],
        runtime_config([("get_widget", enabled_tool(1_000, 1))], 2, 1, 50),
    );

    let first = tokio::spawn({
        let executor = executor.clone();
        async move {
            executor
                .execute(
                    "get_widget",
                    json!({ "widget_id": "first" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
        }
    });
    wait_until(Duration::from_secs(1), || server.request_count() == 1).await;

    let second = executor
        .execute(
            "get_widget",
            json!({ "widget_id": "second" }),
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("second invocation should time out in the runtime queue");

    assert!(matches!(second, ToolRuntimeError::QueueTimeout { .. }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        server.request_count(),
        1,
        "queue-limited invocation must not reach upstream"
    );

    server.release.release();
    first
        .await
        .expect("first invocation task should join")
        .expect("first invocation should complete after server release");
    server.stop.cancel();
    server.handle.abort();
}

#[tokio::test]
async fn default_policy_deny_blocks_registry_tool_absent_from_policy_map() {
    let server = gated_server().await;
    let (executor, _capture) = executor_for_tools(
        server.addr,
        [echo_tool()],
        runtime_config_without_tools(DefaultToolPolicy::Deny),
    );
    let precondition_checks = Arc::new(AtomicUsize::new(0));
    let precondition_checks_for_call = Arc::clone(&precondition_checks);

    let error = executor
        .execute_with_precondition(
            "echo",
            json!({ "message": "hello" }),
            invocation_context(),
            CancellationToken::new(),
            ToolExecutionPrecondition::new(move |_| {
                precondition_checks_for_call.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
        )
        .await
        .expect_err("default deny should reject registry tools absent from policy map");

    assert!(matches!(error, ToolRuntimeError::UnknownTool { .. }));
    assert_eq!(
        precondition_checks.load(Ordering::SeqCst),
        0,
        "normal tool policy must reject before the execution precondition"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        server.request_count(),
        0,
        "default-policy rejection must not reach upstream"
    );

    server.stop.cancel();
    server.handle.abort();
}

#[tokio::test]
async fn default_policy_allow_permits_registry_tool_absent_from_policy_map() {
    let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [echo_tool()],
        runtime_config_without_tools(DefaultToolPolicy::Allow),
    );

    let response = http_response(
        executor
            .execute(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect("default allow should admit a registered tool absent from policy map"),
    );

    assert_eq!(response.status, StatusCode::OK);
    let request = server.await.expect("server task should join");
    assert_eq!(request.target, "/v1/echo");
}

#[tokio::test]
async fn composite_only_tool_looks_unknown_to_non_admin_executor_callers() {
    let (addr, server) = one_request_server(StatusCode::OK, b"must-not-run").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [composite_only_echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );

    for source in [ToolInvocationSource::Internal, ToolInvocationSource::Mcp] {
        let mut context = invocation_context();
        context.source = source;
        let error = executor
            .execute(
                "echo",
                json!({ "message": "must stay private" }),
                context,
                CancellationToken::new(),
            )
            .await
            .expect_err("composite-only tools must look absent outside the admin playground");

        assert!(matches!(
            error,
            ToolRuntimeError::UnknownTool { ref tool_name } if tool_name == "echo"
        ));
    }

    let mut task_context = invocation_context();
    task_context.source = ToolInvocationSource::Mcp;
    let task_error = executor
        .reject_task_tool_call(task_context, "echo")
        .await
        .expect_err("task invocation must not disclose a composite-only tool");
    assert!(matches!(
        task_error,
        ToolRuntimeError::UnknownTool { ref tool_name } if tool_name == "echo"
    ));

    assert!(
        tokio::time::timeout(Duration::from_millis(100), server)
            .await
            .is_err(),
        "visibility rejection must happen before upstream network I/O"
    );
}

#[tokio::test]
async fn admin_playground_can_execute_composite_only_tool() {
    let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
    let (executor, _capture) = executor_for_tools(
        addr,
        [composite_only_echo_tool()],
        runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
    );
    let mut context = invocation_context();
    context.source = ToolInvocationSource::AdminPlayground;

    let response = http_response(
        executor
            .execute(
                "echo",
                json!({ "message": "admin inspection" }),
                context,
                CancellationToken::new(),
            )
            .await
            .expect("the admin playground is allowed to inspect a composite-only tool"),
    );

    assert_eq!(response.status, StatusCode::OK);
    let request = server.await.expect("server task should join");
    assert_eq!(request.target, "/v1/echo");
    assert_eq!(request.body, br#"{"message":"admin inspection"}"#);
}

fn http_response(result: ToolExecutionResult) -> EgressResponse {
    http_execution_result(result).response
}

fn http_execution_result(result: ToolExecutionResult) -> HttpToolExecutionResult {
    match result {
        ToolExecutionResult::Http(result) => result,
        ToolExecutionResult::McpCallToolResult(_) => {
            panic!("expected HTTP tool execution result")
        }
        ToolExecutionResult::Composite(_) => {
            panic!("expected HTTP tool execution result")
        }
    }
}

fn executor_for_tools<const N: usize>(
    addr: SocketAddr,
    tools: [Value; N],
    runtime_config: ToolRuntimeConfig,
) -> (ToolExecutor, CaptureSink) {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let executor = executor_for_tools_with_audit(addr, tools, runtime_config, audit);

    (executor, capture)
}

fn executor_for_tools_with_audit<const N: usize>(
    addr: SocketAddr,
    tools: [Value; N],
    runtime_config: ToolRuntimeConfig,
    audit: AuditLog,
) -> ToolExecutor {
    executor_for_tools_with_optional_upstream(
        tools,
        runtime_config,
        audit,
        Some(format!("http://127.0.0.1:{}/ignored-base", addr.port())),
    )
}

fn executor_for_tools_with_optional_upstream<const N: usize>(
    tools: [Value; N],
    runtime_config: ToolRuntimeConfig,
    audit: AuditLog,
    upstream_url: Option<String>,
) -> ToolExecutor {
    let registry = ToolRegistry::from_json_value(json!({
        "schema_version": "0.1.0",
        "tools": Value::Array(tools.into_iter().collect())
    }))
    .expect("test tools should load");
    let runtime = ToolRuntime::new(runtime_config, audit.clone());
    executor_for_registry_with_runtime(registry, runtime, audit, upstream_url)
}

fn executor_for_tools_with_runtime<const N: usize>(
    addr: SocketAddr,
    tools: [Value; N],
    runtime: ToolRuntime,
    audit: AuditLog,
) -> ToolExecutor {
    let registry = ToolRegistry::from_json_value(json!({
        "schema_version": "0.1.0",
        "tools": Value::Array(tools.into_iter().collect())
    }))
    .expect("test tools should load");
    executor_for_registry_with_runtime(
        registry,
        runtime,
        audit,
        Some(format!("http://127.0.0.1:{}/ignored-base", addr.port())),
    )
}

fn executor_for_registry_with_runtime(
    registry: ToolRegistry,
    runtime: ToolRuntime,
    audit: AuditLog,
    upstream_url: Option<String>,
) -> ToolExecutor {
    let egress_client = Arc::new(
        EgressClient::new(EgressConfig {
            allowed_hosts: ["127.0.0.1".to_owned()].into_iter().collect(),
            deny_private_ips: false,
            ..EgressConfig::default()
        })
        .expect("test egress client should build"),
    );
    ToolExecutor::new_inner(
        registry,
        runtime,
        egress_client,
        audit,
        ToolExecutorBackends {
            upstream_url,
            connection_http: None,
            mcp_catalog_runtime: None,
            openapi_catalog_runtime: None,
            mcp_upstream_servers: HashMap::new(),
            mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                timeout: Duration::from_secs(30),
                response_idle_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(10),
                max_request_body_bytes: 1_048_576,
                max_response_bytes: 5_242_880,
            },
        },
    )
    .expect("tool executor should build")
}

fn executor_for_connection_tool(
    tool: Value,
    connection: &TemporaryStaticAuthRuntime,
    runtime: ToolRuntime,
    audit: AuditLog,
) -> ToolExecutor {
    let registry = ToolRegistry::from_json_value(json!({
        "schema_version": "0.1.0",
        "tools": [tool]
    }))
    .expect("connection-bound tool should load");
    ToolExecutor::new_inner(
        registry,
        runtime,
        Arc::clone(&connection.egress_client),
        audit,
        ToolExecutorBackends {
            upstream_url: None,
            connection_http: Some(connection.runtime.clone()),
            mcp_catalog_runtime: None,
            openapi_catalog_runtime: None,
            mcp_upstream_servers: HashMap::new(),
            mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                timeout: Duration::from_secs(30),
                response_idle_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(10),
                max_request_body_bytes: 1_048_576,
                max_response_bytes: 5_242_880,
            },
        },
    )
    .expect("connection-bound tool executor should build without UPSTREAM_URL")
}

fn executor_for_composite_definitions<const N: usize>(
    definitions: Vec<ToolDefinition>,
    connection: &TemporaryStaticAuthRuntime,
    policy_tools: [&str; N],
) -> (ToolExecutor, CaptureSink) {
    executor_for_composite_definitions_with_config(
        definitions,
        connection,
        runtime_config(
            policy_tools.map(|name| (name, enabled_tool(5_000, 1))),
            2,
            1,
            100,
        ),
    )
}

fn executor_for_composite_definitions_with_config(
    definitions: Vec<ToolDefinition>,
    connection: &TemporaryStaticAuthRuntime,
    runtime_config: ToolRuntimeConfig,
) -> (ToolExecutor, CaptureSink) {
    executor_for_composite_definitions_with_config_and_leases(
        definitions,
        connection,
        runtime_config,
        None,
    )
}

fn executor_for_composite_definitions_with_config_and_leases(
    definitions: Vec<ToolDefinition>,
    connection: &TemporaryStaticAuthRuntime,
    runtime_config: ToolRuntimeConfig,
    leases: Option<Arc<dyn crate::tools::lease::ExecutionLeaseStore>>,
) -> (ToolExecutor, CaptureSink) {
    let record = connection
        .control_plane
        .runtime_snapshot()
        .managed()
        .values()
        .find(|record| record.id.as_str() == connection.connection_id)
        .cloned()
        .expect("composite test connection should be present");
    let entries = definitions
        .iter()
        .map(|definition| StoredOpenApiCatalogEntry {
            tool_name: definition.name.clone(),
            operation_id: match &definition.source {
                ToolSource::OpenApi { operation_id, .. } => operation_id.clone(),
                _ => None,
            },
            selected_scheme_names: if matches!(
                definition.target,
                Some(ToolTarget::Composite { .. })
            ) {
                Vec::new()
            } else {
                vec!["ApiKey".to_owned()]
            },
            definition: serde_json::to_value(definition)
                .expect("composite test definition should serialize"),
        })
        .collect::<Vec<_>>();
    let catalog = StoredOpenApiCatalog {
        connection_id: record.id.clone(),
        spec_revision: 1,
        catalog_revision: 1,
        observed_etag: record.etag(),
        spec_digest: "composite-test-spec".to_owned(),
        spec: r#"{"openapi":"3.0.0"}"#.to_owned(),
        entries,
        refreshed_at: "2026-09-03T00:00:00Z".to_owned(),
        overlay_revision: 1,
    };
    let openapi_catalog_runtime =
        OpenApiConnectionCatalogRuntime::from_catalogs_for_test(&[catalog])
            .expect("composite test catalog runtime should build");
    let registry = ToolRegistry::disabled();
    registry
        .replace_openapi_connection_catalog(&connection.connection_id, definitions, || {
            Ok::<(), ()>(())
        })
        .expect("composite definitions should publish");
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let runtime =
        ToolRuntime::new_with_rbac_state_and_leases(runtime_config, audit.clone(), None, leases);
    let executor = ToolExecutor::new_inner(
        registry,
        runtime,
        Arc::clone(&connection.egress_client),
        audit,
        ToolExecutorBackends {
            upstream_url: None,
            connection_http: Some(connection.runtime.clone()),
            mcp_catalog_runtime: None,
            openapi_catalog_runtime: Some(openapi_catalog_runtime),
            mcp_upstream_servers: HashMap::new(),
            mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                timeout: Duration::from_secs(30),
                response_idle_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(10),
                max_request_body_bytes: 1_048_576,
                max_response_bytes: 5_242_880,
            },
        },
    )
    .expect("composite executor should build");
    (executor, capture)
}

fn composite_note_definitions(connection_id: &str) -> Vec<ToolDefinition> {
    let source = |operation_id: Option<&str>| ToolSource::OpenApi {
        connection_id: connection_id.to_owned(),
        operation_id: operation_id.map(str::to_owned),
        catalog_revision: Some(1),
    };
    let http_tool = |name: &str, method: &str, path: &str, input_schema: Value, visibility| {
        let mapping = crate::tools::definitions::HttpToolMapping {
            method: method.to_owned(),
            path_template: path.to_owned(),
            query_params: Vec::new(),
            body: None,
        };
        ToolDefinition {
            name: name.to_owned(),
            title: None,
            description: format!("Composite test leaf {name}"),
            input_schema,
            target: Some(ToolTarget::Http {
                connection_id: connection_id.to_owned(),
                mapping: mapping.clone(),
            }),
            source: source(Some(name)),
            upstream: mapping,
            composite: None,
            visibility,
            transform: None,
            enum_bindings: Vec::new(),
            annotations: None,
        }
    };
    let object_schema = |properties: Value, required: Value| {
        json!({
            "type":"object",
            "properties":properties,
            "required":required,
            "additionalProperties":false
        })
    };
    let listed = crate::tools::definitions::ToolVisibility::Listed;
    let hidden = crate::tools::definitions::ToolVisibility::CompositeOnly;
    let create_note = http_tool(
        "create_note",
        "POST",
        "/notes",
        object_schema(json!({"title":{"type":"string"}}), json!(["title"])),
        listed,
    );
    let attach_note = http_tool(
        "attach_note",
        "POST",
        "/attachments/{target}",
        object_schema(
            json!({"target":{"type":"string"},"note_id":{"type":"string"}}),
            json!(["target", "note_id"]),
        ),
        listed,
    );
    let delete_attachment = http_tool(
        "delete_attachment",
        "DELETE",
        "/attachments/{target}",
        object_schema(json!({"target":{"type":"string"}}), json!(["target"])),
        hidden,
    );
    let delete_note = http_tool(
        "delete_note",
        "DELETE",
        "/notes/{id}",
        object_schema(json!({"id":{"type":"string"}}), json!(["id"])),
        hidden,
    );
    let composite = ToolDefinition {
        name: "create_note_for_records".to_owned(),
        title: None,
        description: "Composite test workflow".to_owned(),
        input_schema: object_schema(
            json!({
                "title":{"type":"string"},
                "targets":{"type":"array","items":{"type":"string"}}
            }),
            json!(["title", "targets"]),
        ),
        target: Some(ToolTarget::Composite {
            connection_id: connection_id.to_owned(),
        }),
        source: source(None),
        upstream: crate::tools::definitions::HttpToolMapping::composite_sentinel(),
        annotations: None,
        composite: Some(CompositeMapping {
            steps: vec![
                CompositeStep {
                    id: "note".to_owned(),
                    tool: "create_note".to_owned(),
                    arguments: [(
                        "title".to_owned(),
                        CompositeBinding::Input {
                            input: "title".to_owned(),
                            pointer: None,
                        },
                    )]
                    .into_iter()
                    .collect(),
                    for_each: None,
                    success_statuses: None,
                    ambiguous_statuses: None,
                    compensate: Some(CompositeCompensation {
                        tool: "delete_note".to_owned(),
                        arguments: [(
                            "id".to_owned(),
                            CompositeBinding::SelfValue {
                                pointer: "/id".to_owned(),
                            },
                        )]
                        .into_iter()
                        .collect(),
                    }),
                },
                CompositeStep {
                    id: "attach".to_owned(),
                    tool: "attach_note".to_owned(),
                    arguments: [
                        (
                            "target".to_owned(),
                            CompositeBinding::Item {
                                item: "target".to_owned(),
                                pointer: None,
                            },
                        ),
                        (
                            "note_id".to_owned(),
                            CompositeBinding::Step {
                                step: "note".to_owned(),
                                pointer: Some("/id".to_owned()),
                                collect: false,
                            },
                        ),
                    ]
                    .into_iter()
                    .collect(),
                    for_each: Some(crate::tools::composite::CompositeForEach {
                        over: CompositeBinding::Input {
                            input: "targets".to_owned(),
                            pointer: None,
                        },
                        item_name: "target".to_owned(),
                    }),
                    success_statuses: None,
                    ambiguous_statuses: None,
                    compensate: Some(CompositeCompensation {
                        tool: "delete_attachment".to_owned(),
                        arguments: [(
                            "target".to_owned(),
                            CompositeBinding::Item {
                                item: "target".to_owned(),
                                pointer: None,
                            },
                        )]
                        .into_iter()
                        .collect(),
                    }),
                },
            ],
            result: Some(
                [(
                    "note_id".to_owned(),
                    CompositeBinding::Step {
                        step: "note".to_owned(),
                        pointer: Some("/id".to_owned()),
                        collect: false,
                    },
                )]
                .into_iter()
                .collect(),
            ),
            limits: crate::tools::composite::CompositeLimits {
                max_iterations: 64,
                compensation_timeout_ms: 500,
            },
        }),
        visibility: listed,
        transform: None,
        enum_bindings: Vec::new(),
    };
    vec![
        create_note,
        attach_note,
        delete_attachment,
        delete_note,
        composite,
    ]
}

fn live_policy_runtime(
    policy_document: Value,
    audit: AuditLog,
    runtime_config: ToolRuntimeConfig,
) -> ToolRuntime {
    let policy =
        Policy::validate_json_value(policy_document).expect("test live policy should validate");
    let rbac_state =
        crate::middleware::rbac::RbacState::new(policy, Vec::new(), false, audit.clone());
    ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state))
}

fn inventory_audit(test_name: &str) -> (AuditLog, CaptureSink, TempDiscoveryDb) {
    let db = TempDiscoveryDb::new(test_name);
    let aggregator = Arc::new(
        EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
            path: db.path.clone(),
            payload_capture_enabled: false,
            endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            signal_event_sender: None,
            signal_detector_config: Default::default(),
        })
        .expect("discovery aggregator sink should build"),
    ) as Arc<dyn AuditSink>;
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(CompositeSink::new(vec![
        Arc::new(capture.clone()) as Arc<dyn AuditSink>,
        aggregator,
    ])) as Arc<dyn AuditSink>);

    (audit, capture, db)
}

fn runtime_config<const N: usize>(
    tools: [(&str, ToolRuntimeToolConfig); N],
    max_queue: usize,
    max_concurrent_global: usize,
    queue_timeout_ms: u64,
) -> ToolRuntimeConfig {
    ToolRuntimeConfig {
        max_queue,
        queue_timeout: Duration::from_millis(queue_timeout_ms),
        max_concurrent_global,
        default_policy: DefaultToolPolicy::Deny,
        default_timeout: Duration::from_millis(500),
        rules: Vec::new(),
        tools: tools
            .into_iter()
            .map(|(name, config)| (name.to_owned(), config))
            .collect::<HashMap<_, _>>(),
    }
}

fn runtime_config_without_tools(default_policy: DefaultToolPolicy) -> ToolRuntimeConfig {
    ToolRuntimeConfig {
        max_queue: 2,
        queue_timeout: Duration::from_millis(100),
        max_concurrent_global: 1,
        default_policy,
        default_timeout: Duration::from_millis(500),
        rules: Vec::new(),
        tools: HashMap::new(),
    }
}

fn enabled_tool(timeout_ms: u64, max_concurrent: usize) -> ToolRuntimeToolConfig {
    ToolRuntimeToolConfig {
        enabled: true,
        allowed_roles: Vec::new(),
        issuers: Vec::new(),
        auth_methods: Vec::new(),
        timeout: Duration::from_millis(timeout_ms),
        max_concurrent,
    }
}

fn echo_tool() -> Value {
    json!({
        "name": "echo",
        "description": "Echoes a message through a generic upstream endpoint.",
        "input_json_schema": {
            "type": "object",
            "required": ["message"],
            "properties": {
                "message": { "type": "string" }
            },
            "additionalProperties": false
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/echo",
            "body": {
                "mode": "whole_args_json"
            }
        }
    })
}

fn currency_transform_tool(name: &str, response_root: &str) -> Value {
    json!({
        "name": name,
        "description": "Creates a company with agent-facing currency values.",
        "input_json_schema": {
            "type": "object",
            "required": ["name", "amount", "currency"],
            "properties": {
                "name": { "type": "string" },
                "amount": { "type": "number" },
                "currency": { "type": "string" }
            },
            "additionalProperties": false
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/companies",
            "body": { "mode": "body_args_json" }
        },
        "transform": {
            "parameters": [{
                "wire_property": "annualRecurringRevenue",
                "wire_required": true,
                "agent": [
                    { "name": "amount", "schema": { "type": "number" } },
                    { "name": "currency", "schema": { "type": "string" } }
                ],
                "wire": [
                    {
                        "pointer": "/amountMicros",
                        "from": "amount",
                        "codec": [{
                            "kind": "decimal_scale",
                            "scale": 6,
                            "wire_encoding": "integer_string",
                            "max_integer_digits": 24
                        }]
                    },
                    { "pointer": "/currencyCode", "from": "currency" }
                ],
                "response": [
                    {
                        "agent_property": "amount",
                        "from": "/amountMicros",
                        "codec": [{
                            "kind": "decimal_scale",
                            "scale": 6,
                            "wire_encoding": "integer_string",
                            "max_integer_digits": 24
                        }]
                    },
                    { "agent_property": "currency", "from": "/currencyCode" }
                ]
            }],
            "response_root": response_root
        }
    })
}

fn markdown_transform_tool() -> Value {
    json!({
        "name": "create_note",
        "description": "Creates a note from agent-facing Markdown.",
        "input_json_schema": {
            "type": "object",
            "required": ["markdown"],
            "properties": { "markdown": { "type": "string" } },
            "additionalProperties": false
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/notes",
            "body": { "mode": "body_args_json" }
        },
        "transform": {
            "parameters": [{
                "wire_property": "bodyV2",
                "wire_required": true,
                "agent": [{
                    "name": "markdown",
                    "schema": { "type": "string" }
                }],
                "wire": [
                    { "pointer": "/markdown", "from": "markdown" },
                    {
                        "pointer": "/blocknote",
                        "from": "markdown",
                        "codec": [
                            {
                                "kind": "markdown_blocks",
                                "dialect": "blocknote",
                                "max_input_bytes": 65536
                            },
                            { "kind": "json_string" }
                        ]
                    }
                ],
                "response": [{
                    "agent_property": "markdown",
                    "from": "/markdown"
                }]
            }],
            "response_root": "/data/createNote"
        }
    })
}

fn paired_decimal_transform_tool() -> Value {
    let decimal_codec = json!({
        "kind": "decimal_scale",
        "scale": 6,
        "wire_encoding": "integer_string",
        "max_integer_digits": 24
    });
    json!({
        "name": "list_companies",
        "description": "Lists normalized company financials.",
        "input_json_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": false
        },
        "upstream": {
            "method": "GET",
            "path_template": "/v1/companies"
        },
        "transform": {
            "response_fields": [{
                "wire_property": "financials",
                "agent": [
                    { "name": "amount", "schema": { "type": "number" } },
                    { "name": "tax", "schema": { "type": "number" } }
                ],
                "wire": [
                    {
                        "pointer": "/amountMicros",
                        "from": "amount",
                        "codec": [decimal_codec.clone()]
                    },
                    {
                        "pointer": "/taxMicros",
                        "from": "tax",
                        "codec": [decimal_codec.clone()]
                    }
                ],
                "response": [
                    {
                        "agent_property": "amount",
                        "from": "/amountMicros",
                        "codec": [decimal_codec.clone()]
                    },
                    {
                        "agent_property": "tax",
                        "from": "/taxMicros",
                        "codec": [decimal_codec]
                    }
                ]
            }],
            "response_root": "/data/companies/*"
        }
    })
}

fn json_egress_response(body: &[u8]) -> EgressResponse {
    EgressResponse {
        status: StatusCode::OK,
        headers: HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        body: body.to_vec(),
    }
}

fn composite_only_echo_tool() -> Value {
    let mut tool = echo_tool();
    tool["visibility"] = json!("composite_only");
    tool
}

fn connection_charge_tool(connection_id: &str) -> Value {
    let mapping = json!({
        "method": "GET",
        "path_template": "/charges/{charge_id}"
    });
    json!({
        "name": "get_charge",
        "description": "Looks up a charge through an operator-managed Connection.",
        "input_json_schema": {
            "type": "object",
            "required": ["charge_id"],
            "properties": {
                "charge_id": { "type": "string" }
            },
            "additionalProperties": false
        },
        "target": {
            "type": "http",
            "connection_id": connection_id,
            "mapping": mapping
        },
        "source": {
            "type": "manual"
        },
        "upstream": mapping
    })
}

fn echo_tool_without_additional_properties() -> Value {
    let mut tool = echo_tool();
    tool["input_json_schema"]
        .as_object_mut()
        .expect("input schema should be an object")
        .remove("additionalProperties");
    tool
}

fn echo_tool_with_additional_properties(additional_properties: bool) -> Value {
    let mut tool = echo_tool();
    tool["input_json_schema"]["additionalProperties"] = json!(additional_properties);
    tool
}

fn one_of_echo_tool_without_additional_properties() -> Value {
    json!({
        "name": "echo_one_of",
        "description": "Echoes a message through a oneOf input schema.",
        "input_json_schema": {
            "properties": {},
            "oneOf": [
                {
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": { "type": "string" }
                    },
                    "additionalProperties": false
                }
            ]
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/echo",
            "body": {
                "mode": "whole_args_json"
            }
        }
    })
}

fn nested_config_tool_without_nested_additional_properties() -> Value {
    json!({
        "name": "configure",
        "description": "Configures nested settings.",
        "input_json_schema": {
            "type": "object",
            "required": ["settings"],
            "properties": {
                "settings": {
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string" }
                    }
                }
            }
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/configure",
            "body": {
                "mode": "whole_args_json"
            }
        }
    })
}

fn deeply_nested_config_tool_without_additional_properties() -> Value {
    json!({
        "name": "deep_configure",
        "description": "Configures deeply nested settings.",
        "input_json_schema": {
            "type": "object",
            "required": ["settings"],
            "properties": {
                "settings": {
                    "type": "object",
                    "required": ["limits"],
                    "properties": {
                        "limits": {
                            "type": "object",
                            "required": ["rate"],
                            "properties": {
                                "rate": { "type": "integer" }
                            }
                        }
                    }
                }
            }
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/configure",
            "body": {
                "mode": "whole_args_json"
            }
        }
    })
}

fn array_items_tool_without_item_additional_properties() -> Value {
    json!({
        "name": "bulk_configure",
        "description": "Configures a list of named items.",
        "input_json_schema": {
            "type": "object",
            "required": ["items"],
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string" }
                        }
                    }
                }
            }
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/bulk-configure",
            "body": {
                "mode": "whole_args_json"
            }
        }
    })
}

fn prefix_items_tool_without_item_additional_properties() -> Value {
    json!({
        "name": "tuple_configure",
        "description": "Configures a tuple-style list of named items.",
        "input_json_schema": {
            "type": "object",
            "required": ["items"],
            "properties": {
                "items": {
                    "type": "array",
                    "prefixItems": [
                        {
                            "type": "object",
                            "required": ["name"],
                            "properties": {
                                "name": { "type": "string" }
                            }
                        }
                    ]
                }
            }
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/tuple-configure",
            "body": {
                "mode": "whole_args_json"
            }
        }
    })
}

fn nested_array_items_tool_without_item_additional_properties() -> Value {
    json!({
        "name": "group_configure",
        "description": "Configures groups with nested member arrays.",
        "input_json_schema": {
            "type": "object",
            "required": ["groups"],
            "properties": {
                "groups": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["members"],
                        "properties": {
                            "members": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {
                                        "name": { "type": "string" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "upstream": {
            "method": "POST",
            "path_template": "/v1/group-configure",
            "body": {
                "mode": "whole_args_json"
            }
        }
    })
}

fn deep_schema_tool(input_schema: Value) -> Value {
    json!({
        "name": "deep_schema",
        "description": "Exercises strict schema depth handling.",
        "input_json_schema": input_schema,
        "upstream": {
            "method": "POST",
            "path_template": "/v1/deep-schema",
            "body": {
                "mode": "whole_args_json"
            }
        }
    })
}

fn nested_object_schema(nested_depth: usize) -> Value {
    let mut schema = json!({
        "type": "object",
        "required": ["value"],
        "properties": {
            "value": { "type": "string" }
        }
    });

    for depth in (0..nested_depth).rev() {
        let property_name = format!("level_{depth}");
        schema = json!({
            "type": "object",
            "required": [property_name],
            "properties": {
                property_name: schema
            }
        });
    }

    schema
}

fn nested_object_args_with_extra_at_depth(nested_depth: usize, extra_depth: usize) -> Value {
    assert!(extra_depth <= nested_depth);
    nested_object_args_at_depth(0, nested_depth, extra_depth)
}

fn nested_object_args_at_depth(
    current_depth: usize,
    nested_depth: usize,
    extra_depth: usize,
) -> Value {
    let mut object = Map::new();
    if current_depth == nested_depth {
        object.insert("value".to_owned(), json!("ok"));
    } else {
        object.insert(
            format!("level_{current_depth}"),
            nested_object_args_at_depth(current_depth + 1, nested_depth, extra_depth),
        );
    }

    if current_depth == extra_depth {
        object.insert("unexpected".to_owned(), json!("value"));
    }

    Value::Object(object)
}

fn validation_problem_messages(validator: &jsonschema::Validator, args: &Value) -> Vec<String> {
    validator
        .iter_errors(args)
        .map(|error| format!("{}: {error}", error.instance_path()))
        .collect()
}

fn widget_tool(query_required: bool, _widget_required: bool) -> Value {
    let required = if query_required {
        json!(["widget_id", "include_details"])
    } else {
        json!(["widget_id"])
    };

    json!({
        "name": "get_widget",
        "description": "Looks up an illustrative widget by identifier.",
        "input_json_schema": {
            "type": "object",
            "required": required,
            "properties": {
                "widget_id": { "type": "string" },
                "include_details": { "type": "boolean" }
            },
            "additionalProperties": false
        },
        "upstream": {
            "method": "GET",
            "path_template": "/v1/widgets/{widget_id}",
            "query_params": [
                {
                    "arg_name": "include_details",
                    "query_name": "include_details",
                    "required": query_required
                }
            ]
        }
    })
}

fn tenant_config_tool() -> Value {
    json!({
        "name": "get_tenant_config",
        "description": "Reads tenant-scoped configuration.",
        "input_json_schema": {
            "type": "object",
            "required": ["tenant_id", "config_name"],
            "properties": {
                "tenant_id": { "type": "string" },
                "config_name": { "type": "string" }
            },
            "additionalProperties": false
        },
        "upstream": {
            "method": "GET",
            "path_template": "/v1/tenants/{tenant_id}/config/{config_name}"
        }
    })
}

async fn one_request_server(
    status: StatusCode,
    body: &'static [u8],
) -> (SocketAddr, tokio::task::JoinHandle<CapturedRequest>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one request");
        let request = read_http_request(&mut stream).await;
        write_response(&mut stream, status, body).await;
        request
    });

    (addr, handle)
}

async fn one_request_json_server(
    status: StatusCode,
    body: &'static [u8],
) -> (SocketAddr, tokio::task::JoinHandle<CapturedRequest>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one request");
        let request = read_http_request(&mut stream).await;
        let reason = status.canonical_reason().unwrap_or("OK");
        let response = format!(
                "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status.as_u16(),
                body.len()
            );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("test JSON response headers should write");
        stream
            .write_all(body)
            .await
            .expect("test JSON response body should write");
        request
    });

    (addr, handle)
}

async fn one_request_tls_server() -> (SocketAddr, String, tokio::task::JoinHandle<CapturedRequest>)
{
    one_request_tls_server_response(StatusCode::OK, b"secure", None).await
}

async fn scripted_tls_server(
    responses: Vec<(StatusCode, Value)>,
) -> (
    SocketAddr,
    String,
    tokio::task::JoinHandle<Vec<CapturedRequest>>,
) {
    let (addr, ca_pem, handle, _requests_seen) = scripted_tls_server_with_delays(
        responses
            .into_iter()
            .map(|(status, value)| (status, value, Duration::ZERO))
            .collect(),
    )
    .await;
    (addr, ca_pem, handle)
}

async fn scripted_tls_server_with_delays(
    responses: Vec<(StatusCode, Value, Duration)>,
) -> (
    SocketAddr,
    String,
    tokio::task::JoinHandle<Vec<CapturedRequest>>,
    Arc<AtomicUsize>,
) {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GreenGateway Composite Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("composite test CA key should generate");
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("composite test CA certificate should build");
    let mut server_params = rcgen::CertificateParams::default();
    server_params.distinguished_name = rcgen::DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "127.0.0.1");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server_key = rcgen::KeyPair::generate().expect("composite test server key should generate");
    let server_certificate = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("composite test server certificate should build");
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                server_certificate.der().as_ref().to_vec(),
            )],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .expect("composite test TLS config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("composite test TLS listener should bind");
    let addr = listener
        .local_addr()
        .expect("composite test TLS address should be available");
    let requests_seen = Arc::new(AtomicUsize::new(0));
    let server_requests_seen = Arc::clone(&requests_seen);
    let handle = tokio::spawn(async move {
        let mut tasks = Vec::with_capacity(responses.len());
        for (index, (status, value, delay)) in responses.into_iter().enumerate() {
            let (stream, _) = listener
                .accept()
                .await
                .expect("composite test TLS server should accept a request");
            let acceptor = acceptor.clone();
            let requests_seen = Arc::clone(&server_requests_seen);
            tasks.push(tokio::spawn(async move {
                    let mut stream = acceptor
                        .accept(stream)
                        .await
                        .expect("composite test TLS handshake should succeed");
                    let request = read_http_request(&mut stream).await;
                    requests_seen.fetch_add(1, Ordering::Release);
                    tokio::time::sleep(delay).await;
                    let body = if status == StatusCode::NO_CONTENT {
                        Vec::new()
                    } else {
                        serde_json::to_vec(&value).expect("scripted response should serialize")
                    };
                    let reason = status.canonical_reason().unwrap_or("Response");
                    let response = format!(
                        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status.as_u16(),
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    (index, request)
                }));
        }
        let mut requests = Vec::with_capacity(tasks.len());
        for task in tasks {
            requests.push(task.await.expect("composite response task should join"));
        }
        requests.sort_by_key(|(index, _)| *index);
        requests.into_iter().map(|(_, request)| request).collect()
    });
    (addr, ca.pem(), handle, requests_seen)
}

async fn one_request_tls_server_response(
    status: StatusCode,
    body: &'static [u8],
    www_authenticate: Option<&'static str>,
) -> (SocketAddr, String, tokio::task::JoinHandle<CapturedRequest>) {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GreenGateway Tool Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("test CA certificate should build");
    let mut server_params = rcgen::CertificateParams::default();
    server_params.distinguished_name = rcgen::DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "127.0.0.1");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server_key = rcgen::KeyPair::generate().expect("test server key should generate");
    let server_certificate = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("test server certificate should build");
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                server_certificate.der().as_ref().to_vec(),
            )],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .expect("test TLS server config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test TLS listener should bind");
    let addr = listener
        .local_addr()
        .expect("test TLS listener address should be available");
    let handle = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("test TLS server should accept one request");
        let mut stream = acceptor
            .accept(stream)
            .await
            .expect("test TLS handshake should succeed");
        let request = read_http_request(&mut stream).await;
        let reason = status.canonical_reason().unwrap_or("Response");
        let challenge = www_authenticate
            .map(|value| format!("WWW-Authenticate: {value}\r\n"))
            .unwrap_or_default();
        let response = format!(
            "HTTP/1.1 {} {reason}\r\n{challenge}Content-Length: {}\r\nConnection: close\r\n\r\n",
            status.as_u16(),
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("test TLS response headers should write");
        stream
            .write_all(body)
            .await
            .expect("test TLS response body should write");
        request
    });

    (addr, ca.pem(), handle)
}

async fn oauth_rejection_then_success_tls_server() -> (
    SocketAddr,
    String,
    tokio::task::JoinHandle<Vec<CapturedRequest>>,
) {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GreenGateway OAuth Tool Test CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("OAuth test CA key should generate");
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("OAuth test CA certificate should build");
    let mut server_params = rcgen::CertificateParams::default();
    server_params.distinguished_name = rcgen::DistinguishedName::new();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "127.0.0.1");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server_key = rcgen::KeyPair::generate().expect("OAuth test server key should generate");
    let server_certificate = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("OAuth test server certificate should build");
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(
                server_certificate.der().as_ref().to_vec(),
            )],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .expect("OAuth test TLS server config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("OAuth test TLS listener should bind");
    let addr = listener
        .local_addr()
        .expect("OAuth test TLS listener address should be available");
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        let mut token_request_count = 0usize;
        let mut api_request_count = 0usize;

        while api_request_count < 2 {
            let (stream, _) = listener
                .accept()
                .await
                .expect("OAuth test server should accept a request");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("OAuth test TLS handshake should succeed");
            let request = read_http_request(&mut stream).await;

            let (status, content_type, challenge, body) = if request.target == "/oauth/token" {
                token_request_count += 1;
                let access_token = if token_request_count == 1 {
                    FIRST_OAUTH_ACCESS_TOKEN
                } else {
                    REPLACEMENT_OAUTH_ACCESS_TOKEN
                };
                (
                    StatusCode::OK,
                    Some("application/json"),
                    None,
                    serde_json::to_vec(&json!({
                        "access_token": access_token,
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }))
                    .expect("OAuth token response should serialize"),
                )
            } else {
                api_request_count += 1;
                if api_request_count == 1 {
                    let mut body = OVERSIZED_AUTH_BODY_CANARY.as_bytes().to_vec();
                    body.resize(256, b'x');
                    (
                        StatusCode::UNAUTHORIZED,
                        Some("text/plain"),
                        Some(OAUTH_CHALLENGE_CANARY),
                        body,
                    )
                } else {
                    (
                        StatusCode::OK,
                        Some("text/plain"),
                        None,
                        b"replacement accepted".to_vec(),
                    )
                }
            };
            let reason = status.canonical_reason().unwrap_or("Response");
            let content_type = content_type
                .map(|value| format!("Content-Type: {value}\r\n"))
                .unwrap_or_default();
            let challenge = challenge
                .map(|value| format!("WWW-Authenticate: {value}\r\n"))
                .unwrap_or_default();
            let response = format!(
                    "HTTP/1.1 {} {reason}\r\n{content_type}{challenge}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    status.as_u16(),
                    body.len()
                );
            if stream.write_all(response.as_bytes()).await.is_ok() {
                let _ = stream.write_all(&body).await;
            }
            requests.push(request);
        }

        requests
    });

    (addr, ca.pem(), handle)
}

struct TemporaryStaticAuthRuntime {
    root: PathBuf,
    secret_path: PathBuf,
    connection_id: String,
    control_plane: ConnectionControlPlane,
    runtime: ConnectionHttpRuntime,
    egress_client: Arc<EgressClient>,
}

impl TemporaryStaticAuthRuntime {
    async fn header_api_key(addr: SocketAddr, ca_pem: &str, secret: &[u8]) -> Self {
        Self::header_api_key_with_additional(addr, ca_pem, secret, &[]).await
    }

    async fn header_api_key_with_additional(
        addr: SocketAddr,
        ca_pem: &str,
        secret: &[u8],
        additional: &[(&str, &str, &[u8])],
    ) -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-tool-static-auth-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("temporary Connection root should create");
        let secret_path = root.join("api-key");
        fs::write(&secret_path, secret).expect("temporary API key should write");
        let ca_path = root.join("test-ca.pem");
        fs::write(&ca_path, ca_pem).expect("test CA should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("temporary Connection root permissions should set");
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                .expect("temporary API-key permissions should set");
            fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
                .expect("temporary CA permissions should set");
        }

        let mut aliases = vec![OperatorSecretAliasConfig {
            id: "billing-api-key".to_owned(),
            label: "Billing API key".to_owned(),
            source: OperatorSecretAliasSource::File {
                key: "api-key".to_owned(),
            },
        }];
        for (_, alias_id, value) in additional {
            let path = root.join(alias_id);
            fs::write(&path, value).expect("temporary additional secret should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("temporary additional secret permissions should set");
            }
            aliases.push(OperatorSecretAliasConfig {
                id: (*alias_id).to_owned(),
                label: format!("Additional header {alias_id}"),
                source: OperatorSecretAliasSource::File {
                    key: (*alias_id).to_owned(),
                },
            });
        }

        let mut config = Config::test_defaults();
        config.connections_sqlite_path =
            Some(root.join("connections.sqlite").display().to_string());
        config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
        config.connection_secret_aliases = aliases;
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let initial = control_plane.runtime_snapshot();
        let created = control_plane
            .create_managed(
                initial.collection_etag(),
                ConnectionWrite {
                    display_name: "Billing API".to_owned(),
                    description: None,
                    enabled: true,
                    kind: ConnectionKind::HttpApi,
                    endpoint: ConnectionEndpoint {
                        base_url: format!("https://127.0.0.1:{}", addr.port()),
                        base_path: "/v1".to_owned(),
                    },
                    authentication: ConnectionAuthentication::HeaderApiKey {
                        header_name: "x-api-key".to_owned(),
                        secret_id: Some("billing-api-key".to_owned()),
                    },
                    additional_headers: additional
                        .iter()
                        .map(|(header_name, alias_id, _)| AdditionalHeader {
                            header_name: (*header_name).to_owned(),
                            secret_id: Some((*alias_id).to_owned()),
                        })
                        .collect(),
                    tls: TlsProfile::default(),
                    timeouts: None,
                    discovery: None,
                    test_profile: None,
                },
                "test-admin",
            )
            .await
            .expect("test Connection should create");
        let mut egress_config = EgressConfig {
            allowed_hosts: ["127.0.0.1".to_owned()].into_iter().collect(),
            deny_private_ips: false,
            ..EgressConfig::default()
        };
        egress_config
            .apply_tls_ca_bundle_path(ca_path)
            .expect("test CA should configure");
        let egress_client = Arc::new(
            EgressClient::new(egress_config.clone()).expect("test egress client should build"),
        );
        let runtime = ConnectionHttpRuntime::new(
            control_plane.clone(),
            egress_config,
            Arc::clone(&egress_client),
        );

        Self {
            root,
            secret_path,
            connection_id: created.id.to_string(),
            control_plane,
            runtime,
            egress_client,
        }
    }

    async fn oauth_client_credentials(addr: SocketAddr, ca_pem: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-tool-static-auth-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("temporary OAuth Connection root should create");
        let secret_path = root.join("client-secret");
        fs::write(&secret_path, b"oauth-client-secret")
            .expect("temporary OAuth client secret should write");
        let ca_path = root.join("test-ca.pem");
        fs::write(&ca_path, ca_pem).expect("OAuth test CA should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("temporary OAuth Connection root permissions should set");
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                .expect("temporary OAuth client-secret permissions should set");
            fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
                .expect("temporary OAuth CA permissions should set");
        }

        let mut config = Config::test_defaults();
        config.connections_sqlite_path =
            Some(root.join("connections.sqlite").display().to_string());
        config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
        config.connection_secret_aliases = vec![OperatorSecretAliasConfig {
            id: "billing-oauth-client-secret".to_owned(),
            label: "Billing OAuth client secret".to_owned(),
            source: OperatorSecretAliasSource::File {
                key: "client-secret".to_owned(),
            },
        }];
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let initial = control_plane.runtime_snapshot();
        let created = control_plane
            .create_managed(
                initial.collection_etag(),
                ConnectionWrite {
                    display_name: "Billing OAuth API".to_owned(),
                    description: None,
                    enabled: true,
                    kind: ConnectionKind::HttpApi,
                    endpoint: ConnectionEndpoint {
                        base_url: format!("https://127.0.0.1:{}", addr.port()),
                        base_path: "/v1".to_owned(),
                    },
                    authentication: ConnectionAuthentication::OAuth2ClientCredentials {
                        client_id: "billing-client".to_owned(),
                        client_secret_id: Some("billing-oauth-client-secret".to_owned()),
                        token_url: format!("https://127.0.0.1:{}/oauth/token", addr.port()),
                        scopes: Vec::new(),
                        audience: None,
                        resource: None,
                        client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
                    },
                    additional_headers: Vec::new(),
                    tls: TlsProfile::default(),
                    timeouts: None,
                    discovery: None,
                    test_profile: None,
                },
                "test-admin",
            )
            .await
            .expect("OAuth test Connection should create");
        let mut egress_config = EgressConfig {
            allowed_hosts: ["127.0.0.1".to_owned()].into_iter().collect(),
            max_response_bytes: 128,
            deny_private_ips: false,
            ..EgressConfig::default()
        };
        egress_config
            .apply_tls_ca_bundle_path(ca_path)
            .expect("OAuth test CA should configure");
        let egress_client = Arc::new(
            EgressClient::new(egress_config.clone())
                .expect("OAuth test egress client should build"),
        );
        let runtime = ConnectionHttpRuntime::new(
            control_plane.clone(),
            egress_config,
            Arc::clone(&egress_client),
        );

        Self {
            root,
            secret_path,
            connection_id: created.id.to_string(),
            control_plane,
            runtime,
            egress_client,
        }
    }
}

impl Drop for TemporaryStaticAuthRuntime {
    fn drop(&mut self) {
        if self
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("greengateway-tool-static-auth-"))
            && self.root.starts_with(std::env::temp_dir())
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

async fn delayed_response_server(
    delay: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<CapturedRequest>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("test server should accept one request");
        let request = read_http_request(&mut stream).await;
        tokio::time::sleep(delay).await;
        write_response(&mut stream, StatusCode::OK, b"late").await;
        request
    });

    (addr, handle)
}

async fn gated_server() -> GatedServer {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let addr = listener
        .local_addr()
        .expect("listener local address should be available");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let release = ReleaseGate::new();
    let stop = CancellationToken::new();
    let handle = tokio::spawn({
        let requests = Arc::clone(&requests);
        let release = release.clone();
        let stop = stop.clone();
        async move {
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    accepted = listener.accept() => {
                    let (mut stream, _) = accepted.expect("test server accept should succeed");
                    let requests = Arc::clone(&requests);
                    let release = release.clone();
                    tokio::spawn(async move {
                        let request = read_http_request(&mut stream).await;
                        requests_guard(&requests).push(request);
                        release.wait().await;
                        write_response(&mut stream, StatusCode::OK, b"released").await;
                    });
                    }
                }
            }
        }
    });

    GatedServer {
        addr,
        requests,
        release,
        stop,
        handle,
    }
}

async fn read_http_request<S>(stream: &mut S) -> CapturedRequest
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];

    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .expect("test server should read request bytes");
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);

        if let Some(header_end) = header_end(&bytes) {
            let content_length = content_length(&bytes[..header_end]);
            if bytes.len() >= header_end + 4 + content_length {
                break;
            }
        }
    }

    let header_end = header_end(&bytes).expect("request should include complete headers");
    let head = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = head.lines();
    let request_line = lines.next().expect("request should include request line");
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .expect("request line should include method")
        .to_owned();
    let target = request_parts
        .next()
        .expect("request line should include target")
        .to_owned();
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect::<HashMap<_, _>>();
    let body = bytes[header_end + 4..].to_vec();

    CapturedRequest {
        method,
        target,
        headers,
        body,
    }
}

async fn write_response<S>(stream: &mut S, status: StatusCode, body: &[u8])
where
    S: AsyncWrite + Unpin,
{
    let reason = status.canonical_reason().unwrap_or("OK");
    let response = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status.as_u16(),
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("test response headers should write");
    stream
        .write_all(body)
        .await
        .expect("test response body should write");
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(header_bytes: &[u8]) -> usize {
    let head = String::from_utf8_lossy(header_bytes);
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

async fn audit_events(capture: &CaptureSink, expected_count: usize) -> Vec<AuditEvent> {
    wait_until(Duration::from_secs(1), || capture.len() >= expected_count).await;
    capture.events()
}

async fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
    let started = Instant::now();

    while started.elapsed() < timeout {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
        condition(),
        "condition did not become true within {timeout:?}"
    );
}

fn work_failed_message(error: ToolRuntimeError) -> String {
    match error {
        ToolRuntimeError::WorkFailed { message, .. } => message,
        other => panic!("expected work failure, got {other:?}"),
    }
}

fn invocation_context() -> ToolInvocationContext {
    ToolInvocationContext {
        request_id: "request-tool-test".to_owned(),
        source_ip: "203.0.113.10".to_owned(),
        actor: None,
        source: ToolInvocationSource::Internal,
        admitted_deadline: None,
    }
}

fn invocation_context_with_roles(roles: &[&str]) -> ToolInvocationContext {
    ToolInvocationContext {
        request_id: "request-tool-test".to_owned(),
        source_ip: "203.0.113.10".to_owned(),
        actor: Some(Actor {
            user_id: "user-123".to_owned(),
            issuer: None,
            email: None,
            roles: Some(roles.iter().map(|role| (*role).to_owned()).collect()),
            auth_mode: "bearer_token".to_owned(),
        }),
        source: ToolInvocationSource::Internal,
        admitted_deadline: None,
    }
}

fn socket_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[derive(Debug)]
struct DiscoveryAggregateSnapshot {
    call_count: i64,
    schema_mismatch_count: i64,
}

fn discovery_aggregate_snapshot(
    path: &Path,
    method: &str,
    endpoint_template: &str,
) -> Option<DiscoveryAggregateSnapshot> {
    let connection = Connection::open(path).expect("test database should open");
    connection
        .query_row(
            r#"
                SELECT call_count, schema_mismatch_count
                FROM discovery_endpoint_aggregates
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
            params![method, endpoint_template],
            |row| {
                Ok(DiscoveryAggregateSnapshot {
                    call_count: row.get(0)?,
                    schema_mismatch_count: row.get(1)?,
                })
            },
        )
        .ok()
}

#[derive(Debug)]
struct DiscoverySignalRow {
    target_kind: String,
    target_key: String,
    evidence_json: String,
}

fn discovery_signal_rows_by_type(path: &Path, signal_type: &str) -> Vec<DiscoverySignalRow> {
    let connection = Connection::open(path).expect("test database should open");
    let mut statement = connection
        .prepare(
            r#"
                SELECT target_kind, target_key, evidence_json
                FROM discovery_signals
                WHERE signal_type = ?1
                ORDER BY created_at, id
                "#,
        )
        .expect("signal query should prepare");

    statement
        .query_map(params![signal_type], |row| {
            Ok(DiscoverySignalRow {
                target_kind: row.get(0)?,
                target_key: row.get(1)?,
                evidence_json: row.get(2)?,
            })
        })
        .expect("signal query should run")
        .collect::<Result<Vec<_>, _>>()
        .expect("signal rows should read")
}

async fn assert_inventory_observation(
    capture: &CaptureSink,
    db_path: &Path,
    tool_name: &str,
    status: u16,
    reason: &str,
) {
    wait_until(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == HTTP_REQUEST_OBSERVED
                && event.payload["tool_name"] == json!(tool_name)
                && event.payload["status"] == json!(status)
                && event.payload["reason"] == json!(reason)
        })
    })
    .await;

    let events = capture.events();
    let observation = events
        .iter()
        .find(|event| {
            event.event_type == HTTP_REQUEST_OBSERVED
                && event.payload["tool_name"] == json!(tool_name)
        })
        .unwrap_or_else(|| panic!("expected inventory observation in {events:#?}"));
    assert_eq!(observation.payload["method"], json!("MCP"));
    assert_eq!(
        observation.payload["path"],
        json!(format!("/mcp/tools/{tool_name}"))
    );
    assert_eq!(
        observation.payload["endpoint_template"],
        json!(format!("/mcp/tools/{tool_name}"))
    );
    assert_eq!(observation.payload["status"], json!(status));
    assert_eq!(observation.payload["schema_mismatch"], json!(false));
    assert_eq!(observation.payload["routing_context_known"], json!(true));
    assert_eq!(observation.payload["reason"], json!(reason));
    assert!(
        observation.payload["latency_ms"].as_u64().is_some(),
        "tool observation event should include latency_ms"
    );

    wait_until(Duration::from_secs(2), || {
        discovery_aggregate_snapshot(db_path, "MCP", &format!("/mcp/tools/{tool_name}"))
            .is_some_and(|aggregate| {
                aggregate.call_count == 1 && aggregate.schema_mismatch_count == 0
            })
    })
    .await;
    let aggregate =
        discovery_aggregate_snapshot(db_path, "MCP", &format!("/mcp/tools/{tool_name}"))
            .expect("inventory aggregate should be present");
    assert_eq!(aggregate.call_count, 1);
    assert_eq!(aggregate.schema_mismatch_count, 0);
}

struct TempDiscoveryDb {
    path: PathBuf,
}

impl TempDiscoveryDb {
    fn new(test_name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-tool-executor-{test_name}-{}.sqlite",
            uuid::Uuid::new_v4()
        ));

        Self { path }
    }
}

impl Drop for TempDiscoveryDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
            let _ = std::fs::remove_file(path);
        }
    }
}

fn requests_guard(
    requests: &Arc<Mutex<Vec<CapturedRequest>>>,
) -> MutexGuard<'_, Vec<CapturedRequest>> {
    match requests.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

async fn assert_dot_segment_rejected_before_network(
    tool: Value,
    tool_name: &str,
    args: Value,
    rejected_arg_name: &str,
) {
    let definition = tool_definition(tool.clone(), tool_name);
    let error = render_path_template(&definition, &args)
        .expect_err("dot-segment path arg should reject during path rendering");
    assert_path_segment_is_dot_segment(error, tool_name, rejected_arg_name);

    let server = gated_server().await;
    let (executor, _capture) = executor_for_tools(
        server.addr,
        [tool],
        runtime_config([(tool_name, enabled_tool(500, 1))], 2, 1, 100),
    );

    let error = executor
        .execute(
            tool_name,
            args,
            invocation_context(),
            CancellationToken::new(),
        )
        .await
        .expect_err("dot-segment path arg should fail before upstream request");
    let message = work_failed_message(error);
    assert!(
        message.contains(&format!(
            "path argument '{rejected_arg_name}' must not be a dot segment"
        )),
        "unexpected error: {message}"
    );

    assert_no_upstream_requests(&server).await;
    server.stop.cancel();
    server.handle.abort();
}

fn tool_definition(tool: Value, tool_name: &str) -> Arc<ToolDefinition> {
    ToolRegistry::from_json_value(json!({
        "schema_version": "0.1.0",
        "tools": [tool]
    }))
    .expect("test tool should load")
    .get(tool_name)
    .expect("test tool should exist")
}

fn assert_path_segment_is_dot_segment(
    error: ToolExecutorError,
    expected_tool_name: &str,
    expected_arg_name: &str,
) {
    match error {
        ToolExecutorError::PathSegmentIsDotSegment {
            tool_name,
            arg_name,
        } => {
            assert_eq!(tool_name, expected_tool_name);
            assert_eq!(arg_name, expected_arg_name);
        }
        other => panic!("expected PathSegmentIsDotSegment, got {other:?}"),
    }
}

async fn assert_no_upstream_requests(server: &GatedServer) {
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        server.request_count(),
        0,
        "dot-segment rejection must not reach upstream"
    );
}

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

struct GatedServer {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    release: ReleaseGate,
    stop: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl GatedServer {
    fn request_count(&self) -> usize {
        requests_guard(&self.requests).len()
    }
}

#[derive(Clone)]
struct ReleaseGate {
    released: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ReleaseGate {
    fn new() -> Self {
        Self {
            released: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        while !self.released.load(Ordering::SeqCst) {
            self.notify.notified().await;
        }
    }
}
