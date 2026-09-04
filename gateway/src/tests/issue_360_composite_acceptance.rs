use super::*;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::{Path, State},
    routing::{delete, post},
    Json,
};
use http::{HeaderName, HeaderValue};
use rmcp::{
    model::{CallToolRequestParams, JsonObject},
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
    },
    ServiceExt as RmcpServiceExt,
};

const COMPOSITE_TOOL: &str = "create_note_for_records";
const FAILURE_REQUEST_ID: &str = "issue-360-composite-failure";
const SUCCESS_REQUEST_ID: &str = "issue-360-composite-success";

#[derive(Clone, Debug, PartialEq, Eq)]
struct SagaWireRequest {
    method: &'static str,
    path: String,
    body: Vec<u8>,
}

impl SagaWireRequest {
    fn new(method: &'static str, path: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method,
            path: path.into(),
            body: body.into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SagaLedger {
    notes: BTreeMap<String, String>,
    targets: BTreeMap<String, (String, String)>,
}

#[derive(Debug, Default)]
struct SagaUpstreamInner {
    requests: Vec<SagaWireRequest>,
    ledger: SagaLedger,
    next_note: usize,
    next_target: usize,
}

#[derive(Clone, Debug, Default)]
struct SagaUpstreamState {
    inner: Arc<Mutex<SagaUpstreamInner>>,
}

impl SagaUpstreamState {
    fn requests(&self) -> Vec<SagaWireRequest> {
        self.inner
            .lock()
            .expect("saga upstream state should not poison")
            .requests
            .clone()
    }

    fn ledger(&self) -> SagaLedger {
        self.inner
            .lock()
            .expect("saga upstream state should not poison")
            .ledger
            .clone()
    }
}

async fn create_note(State(state): State<SagaUpstreamState>, body: Bytes) -> impl IntoResponse {
    let document: Value = serde_json::from_slice(&body).expect("create-note body should be JSON");
    let title = document["title"]
        .as_str()
        .expect("create-note body should carry title")
        .to_owned();
    let mut inner = state
        .inner
        .lock()
        .expect("saga upstream state should not poison");
    inner
        .requests
        .push(SagaWireRequest::new("POST", "/rest/notes", body.to_vec()));
    inner.next_note += 1;
    let id = format!("note-{}", inner.next_note);
    inner.ledger.notes.insert(id.clone(), title);
    (
        StatusCode::CREATED,
        Json(json!({ "data": { "createNote": { "id": id } } })),
    )
}

async fn create_note_target(
    State(state): State<SagaUpstreamState>,
    body: Bytes,
) -> impl IntoResponse {
    let document: Value =
        serde_json::from_slice(&body).expect("create-note-target body should be JSON");
    let note_id = document["note_id"]
        .as_str()
        .expect("create-note-target body should carry note_id")
        .to_owned();
    let company_id = document["company_id"]
        .as_str()
        .expect("create-note-target body should carry company_id")
        .to_owned();
    let mut inner = state
        .inner
        .lock()
        .expect("saga upstream state should not poison");
    inner
        .requests
        .push(SagaWireRequest::new("POST", "/rest/targets", body.to_vec()));
    if company_id == "company-fail" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "scripted rejection" })),
        );
    }
    assert!(
        inner.ledger.notes.contains_key(&note_id),
        "an attachment may only reference a live note"
    );
    inner.next_target += 1;
    let id = format!("target-{}", inner.next_target);
    inner
        .ledger
        .targets
        .insert(id.clone(), (note_id, company_id));
    (
        StatusCode::CREATED,
        Json(json!({ "data": { "createNoteTarget": { "id": id } } })),
    )
}

async fn delete_note(
    State(state): State<SagaUpstreamState>,
    Path(id): Path<String>,
    body: Bytes,
) -> StatusCode {
    let mut inner = state
        .inner
        .lock()
        .expect("saga upstream state should not poison");
    inner.requests.push(SagaWireRequest::new(
        "DELETE",
        format!("/rest/notes/{id}"),
        body.to_vec(),
    ));
    assert!(
        !inner
            .ledger
            .targets
            .values()
            .any(|(note_id, _)| note_id == &id),
        "the note compensation must run after attachment compensations"
    );
    if inner.ledger.notes.remove(&id).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn delete_note_target(
    State(state): State<SagaUpstreamState>,
    Path(id): Path<String>,
    body: Bytes,
) -> StatusCode {
    let mut inner = state
        .inner
        .lock()
        .expect("saga upstream state should not poison");
    inner.requests.push(SagaWireRequest::new(
        "DELETE",
        format!("/rest/targets/{id}"),
        body.to_vec(),
    ));
    if inner.ledger.targets.remove(&id).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

fn composite_openapi_spec() -> &'static str {
    r#"
openapi: 3.0.3
info:
  title: Composite CRM acceptance
  version: 1.0.0
paths:
  /notes:
    post:
      operationId: createOneNote
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [title]
              properties:
                title: { type: string }
      responses:
        '201':
          description: Created
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: object
                    properties:
                      createNote:
                        type: object
                        properties:
                          id: { type: string }
  /notes/{id}:
    delete:
      operationId: deleteOneNote
      parameters:
        - in: path
          name: id
          required: true
          schema: { type: string }
      responses:
        '204': { description: Deleted }
  /targets:
    post:
      operationId: createOneNoteTarget
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [note_id, company_id]
              properties:
                note_id: { type: string }
                company_id: { type: string }
      responses:
        '201':
          description: Created
          content:
            application/json:
              schema:
                type: object
                properties:
                  data:
                    type: object
                    properties:
                      createNoteTarget:
                        type: object
                        properties:
                          id: { type: string }
  /targets/{id}:
    delete:
      operationId: deleteOneNoteTarget
      parameters:
        - in: path
          name: id
          required: true
          schema: { type: string }
      responses:
        '204': { description: Deleted }
"#
}

fn composite_overlay_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "defaults": { "body_mode": "body_args_json" },
        "tools": {
            "createOneNote": {},
            "createOneNoteTarget": {},
            "deleteOneNote": { "visibility": "composite_only" },
            "deleteOneNoteTarget": { "visibility": "composite_only" }
        },
        "composites": {
            COMPOSITE_TOOL: {
                "description": "Create one note and attach it to three records atomically.",
                "input": {
                    "properties": {
                        "title": { "type": "string", "minLength": 1 },
                        "company_ids": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 3,
                            "items": { "type": "string" }
                        }
                    },
                    "required": ["title", "company_ids"]
                },
                "steps": [
                    {
                        "id": "note",
                        "tool": "createOneNote",
                        "arguments": { "title": { "$input": "title" } },
                        "compensate": {
                            "tool": "deleteOneNote",
                            "arguments": {
                                "id": { "$self": "/data/createNote/id" }
                            }
                        }
                    },
                    {
                        "id": "attach",
                        "tool": "createOneNoteTarget",
                        "for_each": {
                            "over": { "$input": "company_ids" },
                            "as": "company"
                        },
                        "arguments": {
                            "note_id": {
                                "$step": "note",
                                "pointer": "/data/createNote/id"
                            },
                            "company_id": { "$item": "company" }
                        },
                        "compensate": {
                            "tool": "deleteOneNoteTarget",
                            "arguments": {
                                "id": { "$self": "/data/createNoteTarget/id" }
                            }
                        }
                    }
                ],
                "result": {
                    "note_id": {
                        "$step": "note",
                        "pointer": "/data/createNote/id"
                    },
                    "target_ids": {
                        "$step": "attach",
                        "pointer": "/data/createNoteTarget/id",
                        "collect": true
                    }
                },
                "limits": {
                    "max_iterations": 3,
                    "compensation_timeout_ms": 1000
                }
            }
        }
    })
}

fn composite_acceptance_policy(include_composite: bool) -> String {
    let tools = if include_composite {
        json!({
            COMPOSITE_TOOL: {
                "allowed_roles": ["admin"],
                "timeout_ms": 5000,
                "max_concurrent": 1
            },
            "createOneNote": {
                "allowed_roles": ["admin"],
                "timeout_ms": 2000,
                "max_concurrent": 1
            },
            "createOneNoteTarget": {
                "allowed_roles": ["admin"],
                "timeout_ms": 2000,
                "max_concurrent": 1
            },
            "deleteOneNote": {
                "allowed_roles": ["admin"],
                "timeout_ms": 2000,
                "max_concurrent": 1
            },
            "deleteOneNoteTarget": {
                "allowed_roles": ["admin"],
                "timeout_ms": 2000,
                "max_concurrent": 1
            }
        })
    } else {
        json!({})
    };
    json!({
        "schema_version": "0.1.0",
        "id": "issue-360-composite-acceptance",
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": { "permissions": ["*"] }
        },
        "routes": [],
        "tools": tools
    })
    .to_string()
}

struct CompositeAcceptanceHarness {
    router: Router,
    admin_token: String,
    capture: audit::sink::tests::CaptureSink,
    _connection_db: TempDb,
    _token_db: TempDb,
    _policy: TempPolicyFile,
    _tools: TempToolsFile,
}

fn composite_admin_request(
    method: Method,
    uri: &str,
    token: &str,
    body: Option<String>,
    if_match: Option<&str>,
) -> Request<Body> {
    let mut request = connection_admin_request(method, uri, None, body, if_match, false);
    request.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .expect("acceptance service token should be a valid header value"),
    );
    request
}

async fn composite_acceptance_harness(
    upstream_addr: std::net::SocketAddr,
) -> CompositeAcceptanceHarness {
    let connection_db = TempDb::new("issue-360-composite-connections");
    let token_db = TempDb::new("issue-360-composite-tokens");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let admin_token = create_service_token(&token_store, &["admin"]);
    let policy = TempPolicyFile::new(&composite_acceptance_policy(false));
    let tools = TempToolsFile::new(&empty_tools_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);

    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.tools_file = Some(tools.path.to_string_lossy().into_owned());
    config.connections_sqlite_path = Some(connection_db.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 20;
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    config.tool_runtime_default_timeout_ms = 5_000;

    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("composite acceptance app should build");

    let listed = router
        .clone()
        .oneshot(composite_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            &admin_token,
            None,
            None,
        ))
        .await
        .expect("connection list should complete");
    assert_eq!(listed.status(), StatusCode::OK);
    let collection_etag = listed
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned();
    let connection_document = json!({
        "display_name": "Composite acceptance CRM",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": format!("http://{upstream_addr}"),
            "base_path": "/rest"
        },
        "authentication": { "type": "none" },
        "timeouts": {
            "connect_timeout_ms": 1000,
            "request_timeout_ms": 2000,
            "response_idle_timeout_ms": 1000
        },
        "discovery": {
            "type": "managed_openapi",
            "use_connection_authentication": false
        }
    });
    let created = router
        .clone()
        .oneshot(composite_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            &admin_token,
            Some(connection_document.to_string()),
            Some(&collection_etag),
        ))
        .await
        .expect("managed OpenAPI connection should create");
    assert_eq!(created.status(), StatusCode::CREATED);
    let connection_etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created connection should include ETag")
        .to_owned();
    let connection_id = json_body(created).await["id"]
        .as_str()
        .expect("created connection should include id")
        .to_owned();

    let preview_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview");
    let register_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/register");
    let overlay_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/overlay");
    let preview = router
        .clone()
        .oneshot(composite_admin_request(
            Method::POST,
            &preview_uri,
            &admin_token,
            Some(json!({ "spec": composite_openapi_spec() }).to_string()),
            None,
        ))
        .await
        .expect("composite OpenAPI preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = json_body(preview).await;
    let selected_tool_names = preview["tools"]
        .as_array()
        .expect("preview should include tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        selected_tool_names.iter().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "createOneNote".to_owned(),
            "createOneNoteTarget".to_owned(),
            "deleteOneNote".to_owned(),
            "deleteOneNoteTarget".to_owned(),
        ])
    );
    let registered = router
        .clone()
        .oneshot(composite_admin_request(
            Method::POST,
            &register_uri,
            &admin_token,
            Some(
                json!({
                    "spec": composite_openapi_spec(),
                    "spec_digest": preview["spec_digest"],
                    "expected_spec_revision": preview["spec_revision"],
                    "expected_catalog_revision": preview["catalog_revision"],
                    "selected_tool_names": selected_tool_names,
                    "security_confirmations": preview["security_confirmations"],
                })
                .to_string(),
            ),
            Some(&connection_etag),
        ))
        .await
        .expect("composite OpenAPI catalog should register");
    assert_eq!(registered.status(), StatusCode::CREATED);

    let initial_overlay = router
        .clone()
        .oneshot(composite_admin_request(
            Method::GET,
            &overlay_uri,
            &admin_token,
            None,
            None,
        ))
        .await
        .expect("initial overlay should read");
    assert_eq!(initial_overlay.status(), StatusCode::OK);
    let overlay_etag = initial_overlay
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("initial overlay should include ETag")
        .to_owned();
    let stored = router
        .clone()
        .oneshot(composite_admin_request(
            Method::PUT,
            &overlay_uri,
            &admin_token,
            Some(composite_overlay_document().to_string()),
            Some(&overlay_etag),
        ))
        .await
        .expect("composite overlay should publish");
    let stored_status = stored.status();
    let stored = json_body(stored).await;
    assert_eq!(
        stored_status,
        StatusCode::OK,
        "composite overlay should publish: {stored}"
    );
    assert_eq!(stored["composites"][0]["name"], json!(COMPOSITE_TOOL));
    assert_eq!(stored["composites"][0]["steps_max"], json!(4));
    assert_eq!(
        stored["composites"][0]["policy_entry_present"],
        json!(false)
    );

    // Composite names are fail-closed against policy-name adoption. Publish
    // the overlay first, then add its policy entry and restart so the stored
    // ownership proof and runtime admission map advance in that order.
    drop(router);
    policy.write(&composite_acceptance_policy(true));
    let mut restarted_config = test_config(Vec::new());
    restarted_config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    restarted_config.tools_file = Some(tools.path.to_string_lossy().into_owned());
    restarted_config.connections_sqlite_path =
        Some(connection_db.path.to_string_lossy().into_owned());
    restarted_config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    restarted_config.service_token_cache_ttl_ms = 20;
    restarted_config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    restarted_config.egress_deny_private_ips = false;
    restarted_config.tool_runtime_default_timeout_ms = 5_000;
    let restarted_recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        restarted_config,
        restarted_recorder.handle(),
        audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>),
        test_audit_event_sender(),
    )
    .expect("composite acceptance app should restart with the published overlay");

    CompositeAcceptanceHarness {
        router,
        admin_token,
        capture,
        _connection_db: connection_db,
        _token_db: token_db,
        _policy: policy,
        _tools: tools,
    }
}

fn assert_failure_wire(requests: &[SagaWireRequest]) {
    assert_eq!(
        requests,
        [
            SagaWireRequest::new(
                "POST",
                "/rest/notes",
                br#"{"title":"rollback-note"}"#.to_vec()
            ),
            SagaWireRequest::new(
                "POST",
                "/rest/targets",
                br#"{"company_id":"company-a","note_id":"note-1"}"#.to_vec(),
            ),
            SagaWireRequest::new(
                "POST",
                "/rest/targets",
                br#"{"company_id":"company-b","note_id":"note-1"}"#.to_vec(),
            ),
            SagaWireRequest::new(
                "POST",
                "/rest/targets",
                br#"{"company_id":"company-fail","note_id":"note-1"}"#.to_vec(),
            ),
            SagaWireRequest::new("DELETE", "/rest/targets/target-2", Vec::new()),
            SagaWireRequest::new("DELETE", "/rest/targets/target-1", Vec::new()),
            SagaWireRequest::new("DELETE", "/rest/notes/note-1", Vec::new()),
        ],
        "failure must make four forward requests then compensate newest-first"
    );
}

fn assert_success_wire(requests: &[SagaWireRequest]) {
    assert_eq!(
        requests,
        [
            SagaWireRequest::new("POST", "/rest/notes", br#"{"title":"kept-note"}"#.to_vec()),
            SagaWireRequest::new(
                "POST",
                "/rest/targets",
                br#"{"company_id":"company-c","note_id":"note-2"}"#.to_vec(),
            ),
            SagaWireRequest::new(
                "POST",
                "/rest/targets",
                br#"{"company_id":"company-d","note_id":"note-2"}"#.to_vec(),
            ),
            SagaWireRequest::new(
                "POST",
                "/rest/targets",
                br#"{"company_id":"company-e","note_id":"note-2"}"#.to_vec(),
            ),
        ],
        "successful fan-out must make exactly four wire-exact requests"
    );
}

fn events_for_request(
    capture: &audit::sink::tests::CaptureSink,
    request_id: &str,
) -> Vec<audit::AuditEvent> {
    capture
        .events()
        .into_iter()
        .filter(|event| event.request_id == request_id)
        .collect()
}

#[tokio::test]
async fn composite_playground_failure_wire_is_allowlisted() {
    let credential_canary = "FAKE_composite_wire_credential";
    let response = tool_playground_runtime_error_response(
        tools::runtime::ToolRuntimeError::WorkFailed {
            tool_name: COMPOSITE_TOOL.to_owned(),
            message: "composite failed".to_owned(),
            reason: Some("composite_failed_compensation_incomplete".to_owned()),
            details: Some(json!({
                "tool_name": COMPOSITE_TOOL,
                "request_id": FAILURE_REQUEST_ID,
                "reason": "composite_failed_compensation_incomplete",
                "failed_step": "attach",
                "failed_iteration": 2,
                "failure_reason": "upstream_status:500",
                "compensation": "incomplete",
                "orphans": [{
                    "step": "attach",
                    "iteration": 1,
                    "tool": "createOneNoteTarget",
                    "certainty": "confirmed",
                    "reason": "compensation_status:500",
                    "upstream_status": 500,
                    "wire_body": credential_canary
                }],
                "authorization": credential_canary
            })),
        },
        None,
    );
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("playground failure body");
    let body: Value = serde_json::from_slice(&body).expect("playground failure JSON");
    assert_eq!(
        body,
        json!({
            "error": "tool execution failed",
            "tool_name": COMPOSITE_TOOL,
            "request_id": FAILURE_REQUEST_ID,
            "reason": "composite_failed_compensation_incomplete",
            "failed_step": "attach",
            "failed_iteration": 2,
            "failure_reason": "upstream_status:500",
            "compensation": "incomplete",
            "orphans": [{
                "step": "attach",
                "iteration": 1,
                "tool": "createOneNoteTarget",
                "certainty": "confirmed",
                "reason": "compensation_status:500",
                "upstream_status": 500
            }]
        })
    );
    assert!(!body.to_string().contains(credential_canary));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_07_overlay_crm_workflow() {
    let state = SagaUpstreamState::default();
    let upstream_addr = spawn_router(
        Router::new()
            .route("/rest/notes", post(create_note))
            .route("/rest/notes/{id}", delete(delete_note))
            .route("/rest/targets", post(create_note_target))
            .route("/rest/targets/{id}", delete(delete_note_target))
            .with_state(state.clone()),
    )
    .await;
    let harness = composite_acceptance_harness(upstream_addr).await;

    let (failure_status, failure) = mcp_rpc(
        &harness.router,
        Some(&harness.admin_token),
        3604,
        "tools/call",
        Some(json!({
            "name": COMPOSITE_TOOL,
            "arguments": {
                "title": "rollback-note",
                "company_ids": ["company-a", "company-b", "company-fail"]
            }
        })),
        FAILURE_REQUEST_ID,
    )
    .await;
    assert_eq!(failure_status, StatusCode::OK);
    assert_eq!(failure["error"]["code"], json!(-32603));
    assert_eq!(
        failure["error"]["data"],
        json!({
            "tool_name": COMPOSITE_TOOL,
            "request_id": FAILURE_REQUEST_ID,
            "reason": "composite_failed",
            "failed_step": "attach",
            "failed_iteration": 2,
            "failure_reason": "upstream_status:400",
            "compensation": "complete",
            "orphans": []
        })
    );
    let after_failure = state.requests();
    assert_eq!(after_failure.len(), 7);
    assert_failure_wire(&after_failure);
    assert_eq!(
        state.ledger(),
        SagaLedger::default(),
        "complete compensation must leave both state ledgers empty"
    );

    assert_eventually(Duration::from_secs(2), || {
        let events = events_for_request(&harness.capture, FAILURE_REQUEST_ID);
        events
            .iter()
            .any(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
    });
    let failure_events = events_for_request(&harness.capture, FAILURE_REQUEST_ID);
    assert_eq!(
        failure_events
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_INVOKE_START)
            .count(),
        1
    );
    assert_eq!(
        failure_events
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_INVOKE_FAILURE)
            .count(),
        1
    );
    assert_eq!(
        failure_events
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .count(),
        7
    );
    let failure_tree = failure_events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
        .expect("failure should emit one composite tree");
    assert_eq!(failure_tree.payload["outcome"], json!("failed"));
    assert_eq!(
        failure_tree.payload["steps"].as_array().map(Vec::len),
        Some(4)
    );
    assert_eq!(
        failure_tree.payload["compensations"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert!(failure_tree.payload.get("pending_compensation").is_none());

    let (gateway_addr, gateway_server) = spawn_gateway_router(harness.router.clone()).await;
    let custom_headers = HashMap::from([
        (
            HeaderName::from_static(REQUEST_ID_HEADER),
            HeaderValue::from_static(SUCCESS_REQUEST_ID),
        ),
        (
            header::COOKIE,
            HeaderValue::from_static("csrf_token=issue-360-composite"),
        ),
        (
            HeaderName::from_static("x-csrf-token"),
            HeaderValue::from_static("issue-360-composite"),
        ),
    ]);
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(format!("http://{gateway_addr}{MCP_ROUTE}"))
            .auth_header(harness.admin_token.clone())
            .custom_headers(custom_headers),
    );
    let client = ().serve(transport).await.expect("rmcp client should initialize");
    let listed = client
        .list_all_tools()
        .await
        .expect("rmcp client should list composite tools");
    assert!(listed.iter().any(|tool| tool.name == COMPOSITE_TOOL));
    assert!(!listed.iter().any(|tool| tool.name == "deleteOneNote"));
    assert!(!listed.iter().any(|tool| tool.name == "deleteOneNoteTarget"));

    let arguments: JsonObject = serde_json::from_value(json!({
        "title": "kept-note",
        "company_ids": ["company-c", "company-d", "company-e"]
    }))
    .expect("composite arguments should be an object");
    let success = client
        .call_tool(CallToolRequestParams::new(COMPOSITE_TOOL).with_arguments(arguments))
        .await
        .expect("rmcp client should execute the composite");
    assert_eq!(success.is_error, Some(false));
    assert_eq!(
        success.structured_content,
        Some(json!({
            "status": 200,
            "body": {
                "note_id": "note-2",
                "target_ids": ["target-3", "target-4", "target-5"]
            }
        }))
    );

    let all_requests = state.requests();
    assert_eq!(all_requests.len(), 11);
    assert_success_wire(&all_requests[7..]);
    assert_eq!(
        state.ledger(),
        SagaLedger {
            notes: BTreeMap::from([("note-2".to_owned(), "kept-note".to_owned())]),
            targets: BTreeMap::from([
                (
                    "target-3".to_owned(),
                    ("note-2".to_owned(), "company-c".to_owned())
                ),
                (
                    "target-4".to_owned(),
                    ("note-2".to_owned(), "company-d".to_owned())
                ),
                (
                    "target-5".to_owned(),
                    ("note-2".to_owned(), "company-e".to_owned())
                ),
            ]),
        }
    );

    assert_eventually(Duration::from_secs(2), || {
        let events = events_for_request(&harness.capture, SUCCESS_REQUEST_ID);
        events
            .iter()
            .any(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
    });
    let success_events = events_for_request(&harness.capture, SUCCESS_REQUEST_ID);
    assert_eq!(
        success_events
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_INVOKE_START)
            .count(),
        1
    );
    assert_eq!(
        success_events
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_INVOKE_SUCCESS)
            .count(),
        1
    );
    assert_eq!(
        success_events
            .iter()
            .filter(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .count(),
        4
    );
    let success_tree = success_events
        .iter()
        .find(|event| event.event_type == audit::event::TOOL_COMPOSITE_COMPLETED)
        .expect("success should emit one composite tree");
    assert_eq!(success_tree.payload["outcome"], json!("success"));
    assert_eq!(
        success_tree.payload["steps"].as_array().map(Vec::len),
        Some(4)
    );
    assert_eq!(
        success_tree.payload["compensations"],
        json!([]),
        "successful execution must have an empty compensation ledger"
    );

    client
        .cancel()
        .await
        .expect("rmcp client should cancel cleanly");
    gateway_server.abort();
}
