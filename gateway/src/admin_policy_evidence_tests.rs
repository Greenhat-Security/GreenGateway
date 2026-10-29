//! `POST /v1{ADMIN_PREFIX}/policy/evidence` (issue #243, slice 20) through the
//! application in standalone mode: the policy file authority, its SQLite
//! history beside it, and the standalone audit log a replay job reads. The
//! request parser and the package assembler are covered in
//! `policy_evidence::tests`.
use super::*;

const EVIDENCE: &str = POLICY_EVIDENCE_ADMIN_ROUTE;
/// Values the request, the history and the retained records carry that no
/// package or export record may repeat.
const ACTOR_CANARY: &str = "evidence-api-actor-canary-e19b";
const SUBJECT_CANARY: &str = "evidence-api-subject-canary-27fd";
const PATH_CANARY: &str = "evidence-api-path-canary-6a03";

fn roles() -> Value {
    json!({
        "admin": {
            "permissions": [
                ADMIN_POLICY_READ_PERMISSION,
                ADMIN_POLICY_WRITE_PERMISSION,
                ADMIN_POLICY_SIMULATE_PERMISSION,
                ADMIN_POLICY_EVIDENCE_READ_PERMISSION,
                ADMIN_AUDIT_READ_PERMISSION
            ]
        },
        "evidence-reader": {
            "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_EVIDENCE_READ_PERMISSION]
        },
        "evidence-simulator": {
            "permissions": [
                ADMIN_POLICY_READ_PERMISSION,
                ADMIN_POLICY_EVIDENCE_READ_PERMISSION,
                ADMIN_POLICY_SIMULATE_PERMISSION
            ]
        },
        "evidence-only": { "permissions": [ADMIN_POLICY_EVIDENCE_READ_PERMISSION] },
        "policy-reader": { "permissions": [ADMIN_POLICY_READ_PERMISSION] },
        "orders-reader": { "permissions": ["orders:read"] }
    })
}

/// The live policy the application starts with: a 0.x file.
fn initial_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "policy-evidence",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": roles(),
        "rules": [
            { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ]
    })
}

/// History version 1: the same policy as a v1 document, whose routes carry
/// stable ids too.
fn first_document() -> Value {
    let mut document = initial_document();
    document["schema_version"] = json!("1.0.0");
    document["routes"][0]["id"] = json!("orders");
    document
}

/// History version 2: version 1 with a deny rule in front of the route.
fn second_document() -> Value {
    let mut document = first_document();
    document["rules"] = json!([
        { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" },
        { "id": "lockdown", "methods": ["GET"], "path": "/orders/restricted", "action": "deny" }
    ]);
    document
}

fn orders_reader() -> Value {
    json!({ "subject": SUBJECT_CANARY, "roles": ["orders-reader"], "auth_method": "bearer_token" })
}

fn suite() -> Value {
    json!({
        "schema_version": "policy-tests.v1",
        "cases": [
            {
                "id": "public-is-open",
                "kind": "http",
                "request": { "method": "GET", "path": format!("/public/{PATH_CANARY}") },
                "principal": "anonymous",
                "expect": { "logical": "allow", "matched": { "rule": "public" } }
            },
            {
                "id": "restricted-is-closed",
                "kind": "http",
                "request": { "method": "GET", "path": "/orders/restricted" },
                "principal": orders_reader(),
                "expect": { "logical": "deny", "matched": { "rule": "lockdown" } }
            }
        ]
    })
}

fn simulation() -> Value {
    json!({
        "trace": "matched",
        "cases": [
            {
                "id": "restricted-order",
                "kind": "http",
                "request": { "method": "GET", "path": "/orders/restricted" },
                "principal": orders_reader()
            },
            {
                "id": "plain-order",
                "kind": "http",
                "request": { "method": "GET", "path": "/orders/7" },
                "principal": orders_reader()
            }
        ]
    })
}

fn evidence_body(version: i64) -> Value {
    json!({
        "schema_version": "policy-evidence-request.v1",
        "publication": { "version": version }
    })
}

struct Harness {
    router: Router,
    capture: audit::sink::tests::CaptureSink,
    audit_db: TempDb,
    _policy: TempPolicyFile,
}

fn evidence_router(
    audit_log: audit::AuditLog,
    policy: &TempPolicyFile,
    audit_db: &TempDb,
) -> Router {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    // The retained source a replay job reads. The application's own records
    // go to the test's sink, so the log changes only when a test writes it.
    config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
    // The history defaults to a database beside the policy file.
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
    // These tests send more writes than the global write lane's default
    // burst admits; that lane is not what they test.
    config.rate_limit_write_burst = 1_000;
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("app should build");
    let GatewayApp::Unified(router) = app.http else {
        panic!("the evidence test app should be unified");
    };
    router
}

fn policy_file() -> TempPolicyFile {
    TempPolicyFile::new(&serde_json::to_string_pretty(&initial_document()).expect("serializes"))
}

fn harness() -> Harness {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = policy_file();
    let audit_db = TempDb::new("policy-evidence");
    let router = evidence_router(audit_log, &policy, &audit_db);
    Harness {
        router,
        capture,
        audit_db,
        _policy: policy,
    }
}

fn principal(roles: &[&str]) -> Option<auth::Principal> {
    let mut principal = test_principal(roles);
    principal.user_id = ACTOR_CANARY.to_owned();
    principal.email = None;
    Some(principal)
}

fn admin() -> Option<auth::Principal> {
    principal(&["admin"])
}

async fn send(router: &Router, request: Request<Body>) -> Response {
    router
        .clone()
        .oneshot(request)
        .await
        .expect("request should complete")
}

async fn request_evidence(
    router: &Router,
    principal: Option<auth::Principal>,
    body: &Value,
) -> Response {
    send(
        router,
        policy_admin_request(
            Method::POST,
            EVIDENCE,
            principal,
            Some(body.to_string()),
            None,
        ),
    )
    .await
}

async fn live_etag(router: &Router) -> String {
    let response = send(
        router,
        policy_admin_request(Method::GET, POLICY_ADMIN_ROUTE, admin(), None, None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    policy_etag_header(&response)
}

/// Replace the live policy; the new ETag.
async fn put_policy(router: &Router, document: &Value, if_match: &str) -> String {
    let response = send(
        router,
        policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            admin(),
            Some(document.to_string()),
            Some(if_match),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    policy_etag_header(&response)
}

/// Save `document` as a draft on `base` and publish it; the new ETag.
async fn publish_draft(router: &Router, document: &Value, base: &str) -> String {
    let created = send(
        router,
        policy_admin_request(
            Method::POST,
            POLICY_DRAFTS_ADMIN_ROUTE,
            admin(),
            Some(json!({ "policy": document }).to_string()),
            Some(base),
        ),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let draft_etag = policy_etag_header(&created);
    let draft = json_body(created).await;
    let draft_id = draft["draft_id"].as_str().expect("draft id");
    let mut request = policy_admin_request(
        Method::POST,
        &format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}/publish"),
        admin(),
        None,
        Some(base),
    );
    request.headers_mut().insert(
        HeaderName::from_static(POLICY_DRAFT_ETAG_HEADER),
        HeaderValue::from_str(&draft_etag).expect("draft ETag is a header value"),
    );
    let published = send(router, request).await;
    assert_eq!(published.status(), StatusCode::OK);
    policy_etag_header(&published)
}

/// Versions 1 (a replace) and 2 (a draft publication) in the history; their
/// ETags.
async fn two_publications(router: &Router) -> (String, String) {
    let initial = live_etag(router).await;
    let first = put_policy(router, &first_document(), &initial).await;
    let second = publish_draft(router, &second_document(), &first).await;
    (first, second)
}

fn exported_events(capture: &audit::sink::tests::CaptureSink) -> Vec<audit::AuditEvent> {
    capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == audit::event::POLICY_EVIDENCE_EXPORTED)
        .collect()
}

/// Audit delivery is asynchronous: wait, bounded, for `count` export records.
async fn wait_for_exports(
    capture: &audit::sink::tests::CaptureSink,
    count: usize,
) -> Vec<audit::AuditEvent> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let events = exported_events(capture);
            if events.len() >= count {
                return events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the export record should be delivered")
}

fn header(response: &Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("the response should carry {name}"))
        .to_owned()
}

async fn refusal(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    (status, json_body(response).await)
}

#[tokio::test]
async fn evidence_needs_authentication_policy_read_evidence_read_and_each_sections_permission() {
    let harness = harness();
    two_publications(&harness.router).await;
    let plain = evidence_body(2);
    let mut with_suite = evidence_body(2);
    with_suite["suite"] = suite();
    let mut with_cases = evidence_body(2);
    with_cases["simulation"] = simulation();
    let mut with_replay = evidence_body(2);
    with_replay["replay_job_id"] = json!("rpl_0123456789abcdef0123456789abcdef");

    let response = request_evidence(&harness.router, None, &plain).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for (roles, body) in [
        (&["policy-reader"][..], &plain),
        (&["evidence-only"][..], &plain),
        (&["orders-reader"][..], &plain),
        (&["evidence-reader"][..], &with_suite),
        (&["evidence-reader"][..], &with_cases),
        (&["evidence-simulator"][..], &with_replay),
    ] {
        let response = request_evidence(&harness.router, principal(roles), body).await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{roles:?} cannot read {body}"
        );
    }
    // A refusal left no export record, and a reader holding exactly the two
    // permissions gets a package.
    let response = request_evidence(&harness.router, principal(&["evidence-reader"]), &plain).await;
    assert_eq!(response.status(), StatusCode::OK);
    let exports = wait_for_exports(&harness.capture, 1).await;
    assert_eq!(exports.len(), 1, "only the served package was recorded");
}

#[tokio::test]
async fn a_package_reports_a_draft_publication_from_the_history() {
    let harness = harness();
    let (first, second) = two_publications(&harness.router).await;
    let validated = json_body(
        send(
            &harness.router,
            policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                admin(),
                Some(second_document().to_string()),
                None,
            ),
        )
        .await,
    )
    .await;
    let semantic_digest = validated["semantic_digest"]
        .as_str()
        .expect("a v1 document has a semantic digest")
        .to_owned();

    let mut body = evidence_body(2);
    body["publication"]["etag"] = json!(second);
    body["suite"] = suite();
    body["simulation"] = simulation();
    let response = request_evidence(&harness.router, admin(), &body).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header(&response, "content-type"),
        "application/vnd.greengateway.policy-evidence+json"
    );
    assert_eq!(header(&response, "cache-control"), "no-store");
    assert_eq!(
        header(&response, "content-disposition"),
        "attachment; filename=\"policy-evidence.json\""
    );
    assert_eq!(
        header(&response, POLICY_EVIDENCE_COMPLETENESS_HEADER),
        "incomplete"
    );
    let digest = header(&response, POLICY_EVIDENCE_DIGEST_HEADER);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    let text = String::from_utf8(bytes.to_vec()).expect("a package is UTF-8");
    for canary in [ACTOR_CANARY, SUBJECT_CANARY, PATH_CANARY] {
        assert!(!text.contains(canary), "{canary} is not repeated");
    }
    let package: Value = serde_json::from_slice(&bytes).expect("a package is JSON");
    assert_eq!(
        crate::canonical_json::canonical_json_bytes(&package).expect("canonical"),
        bytes.to_vec(),
        "a package is served as its RFC 8785 bytes"
    );
    assert_eq!(package["manifest"][0]["digest"], json!(digest));
    let report = &package["report"];

    let publication = &report["publication"];
    assert_eq!(publication["version"], 2);
    assert_eq!(publication["policy"]["etag"], json!(second));
    assert_eq!(publication["policy"]["schema_version"], "1.0.0");
    assert_eq!(
        publication["policy"]["semantic_digest"],
        json!(semantic_digest),
        "the digest `POST /policy/validate` reports for the same document"
    );
    assert_eq!(publication["predecessor"]["version"], 1);
    assert_eq!(publication["predecessor"]["policy"]["etag"], json!(first));
    assert_eq!(publication["predecessor_check"], "matches_recorded_base");

    let approval = &report["approval"];
    assert_eq!(approval["basis"], "authorized_commit");
    assert_eq!(approval["operation"], "policy_draft_published");
    assert_eq!(approval["actor"], "withheld");
    assert_eq!(approval["draft"]["revision"], 1);
    assert_eq!(approval["draft"]["base_etag"], json!(first));

    assert_eq!(report["validation"]["valid"], true);
    // The cross-resource checks read the same resources validation reads.
    assert_eq!(
        report["validation"]["resource_snapshot"], validated["resource_snapshot"],
        "the snapshot `POST /policy/validate` reports for the same resources"
    );
    assert_eq!(report["validation"]["diagnostics"], json!([]));
    let tests = &report["tests"]["results"];
    assert_eq!(tests["status"], "passed");
    assert_eq!(tests["policy"]["source"], "publication");
    assert_eq!(tests["policy"]["etag"], json!(second));
    let simulation = &report["simulation"];
    assert_eq!(simulation["base"]["version"], 1);
    assert_eq!(simulation["candidate"]["version"], 2);
    let restricted = &simulation["cases"][0];
    assert_eq!(restricted["id"], "restricted-order");
    assert_eq!(restricted["results"][0]["changed"], true);
    assert_eq!(restricted["results"][0]["base"]["logical"], "allow");
    assert_eq!(restricted["results"][0]["candidate"]["logical"], "deny");
    assert_eq!(simulation["cases"][1]["results"][0]["changed"], false);
    assert_eq!(report["replay"], json!({ "included": false }));
    assert_eq!(report["completeness"], "incomplete");
    assert_eq!(report["limitations"], json!(["replay_not_included"]));
    assert_eq!(report["trust"]["signed"], false);

    let exports = wait_for_exports(&harness.capture, 1).await;
    let payload = &exports[0].payload;
    assert_eq!(payload["publication_version"], 2);
    assert_eq!(payload["policy_etag"], json!(second));
    assert_eq!(payload["report_digest"], json!(digest));
    assert_eq!(payload["completeness"], "incomplete");
    assert_eq!(payload["tests_status"], "passed");
    let payload_text = payload.to_string();
    for canary in [ACTOR_CANARY, SUBJECT_CANARY, PATH_CANARY] {
        assert!(!payload_text.contains(canary), "{canary} is not recorded");
    }

    // The same inputs, exported again, are the same report; nothing moved.
    let again = request_evidence(&harness.router, admin(), &body).await;
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(header(&again, POLICY_EVIDENCE_DIGEST_HEADER), digest);
    assert_eq!(live_etag(&harness.router).await, second);
}

#[tokio::test]
async fn a_package_names_every_section_it_lacks() {
    let harness = harness();
    let (first, _) = two_publications(&harness.router).await;
    let response = request_evidence(&harness.router, admin(), &evidence_body(1)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_body(response).await["report"].clone();
    assert_eq!(report["publication"]["policy"]["etag"], json!(first));
    // The policy file's own document was never a history version.
    assert_eq!(report["publication"]["predecessor"], Value::Null);
    assert_eq!(report["approval"]["operation"], "policy_replaced");
    assert_eq!(
        report["limitations"],
        json!([
            "predecessor_not_in_history",
            "replay_not_included",
            "simulation_not_included",
            "tests_not_included"
        ])
    );
}

#[tokio::test]
async fn a_publication_is_read_from_the_history_and_pinned_exactly() {
    let harness = harness();
    let (first, second) = two_publications(&harness.router).await;

    let (status, body) =
        refusal(request_evidence(&harness.router, admin(), &evidence_body(3)).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "policy_evidence_publication_not_found");

    let mut pinned = evidence_body(2);
    pinned["publication"]["etag"] = json!(first);
    let (status, body) = refusal(request_evidence(&harness.router, admin(), &pinned).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "policy_evidence_publication_mismatch");
    assert_eq!(body["policy_etag"], json!(second));

    let mut invalid = evidence_body(2);
    invalid["publication"]["digest"] = json!("sha256:caller-supplied");
    let (status, body) = refusal(request_evidence(&harness.router, admin(), &invalid).await).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["reason"], "policy_evidence_invalid");

    let repeated = r#"{"schema_version":"policy-evidence-request.v1","publication":{"version":1},"publication":{"version":2}}"#;
    let (status, body) = refusal(
        send(
            &harness.router,
            policy_admin_request(
                Method::POST,
                EVIDENCE,
                admin(),
                Some(repeated.to_owned()),
                None,
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "policy_evidence_request_invalid");

    // The writer is one FIFO queue: once the export of a served package is
    // delivered, any record a refusal had left would have been delivered
    // before it.
    let response = request_evidence(&harness.router, admin(), &evidence_body(2)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let exports = wait_for_exports(&harness.capture, 1).await;
    assert_eq!(exports.len(), 1, "no refusal was recorded as an export");
}

#[tokio::test]
async fn a_package_is_released_only_once_its_export_is_recorded() {
    let sink = audit::sink::tests::DurableCaptureSink::new();
    let audit_log = audit::AuditLog::new_required(
        Arc::new(sink.clone()) as Arc<dyn audit::AuditSink>,
        Duration::from_secs(2),
    );
    let policy = policy_file();
    let audit_db = TempDb::new("policy-evidence-required");
    let router = evidence_router(audit_log, &policy, &audit_db);
    two_publications(&router).await;

    sink.set(audit::sink::tests::DurableBehaviour::Refuse);
    let (status, body) = refusal(request_evidence(&router, admin(), &evidence_body(2)).await).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["reason"], "policy_evidence_audit_unavailable");
    assert!(body.get("report").is_none(), "no package was released");

    sink.set(audit::sink::tests::DurableBehaviour::Store);
    let response = request_evidence(&router, admin(), &evidence_body(2)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(sink
        .events()
        .iter()
        .any(|event| event.event_type == audit::event::POLICY_EVIDENCE_EXPORTED));
}

fn retained(path: &str) -> audit::AuditEvent {
    audit::AuditEvent::new(
        "http.request_observed",
        "retained-request",
        "192.0.2.10",
        Some(audit::Actor {
            user_id: SUBJECT_CANARY.to_owned(),
            issuer: None,
            email: None,
            roles: Some(vec!["orders-reader".to_owned()]),
            auth_mode: "bearer_token".to_owned(),
        }),
        json!({
            "method": "GET",
            "path": path,
            "status": 200,
            "policy_decision": "allowed",
            "routing_context_known": true,
        }),
    )
}

/// Start a replay job over the last hour and wait until it finishes.
async fn finished_replay(router: &Router, base_etag: &str, candidate: Value) -> Value {
    let from = (OffsetDateTime::now_utc() - time::Duration::hours(1))
        .format(&Rfc3339)
        .expect("a window bound formats");
    let response = send(
        router,
        policy_admin_request(
            Method::POST,
            POLICY_REPLAYS_ADMIN_ROUTE,
            admin(),
            Some(
                json!({
                    "schema_version": "policy-replay.v1",
                    "base_etag": base_etag,
                    "candidate": candidate,
                    "window": { "from": from }
                })
                .to_string(),
            ),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let job = json_body(response).await;
    let job_id = job["job_id"].as_str().expect("job id").to_owned();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let response = send(
            router,
            policy_admin_request(
                Method::GET,
                &format!("{POLICY_REPLAYS_ADMIN_ROUTE}/{job_id}"),
                admin(),
                None,
                None,
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let job = json_body(response).await;
        if !matches!(job["state"].as_str(), Some("queued" | "running")) {
            return job;
        }
        assert!(Instant::now() < deadline, "the replay job should finish");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn a_replay_job_is_bound_to_the_publication_it_replayed() {
    let harness = harness();
    let router = &harness.router;
    let initial = live_etag(router).await;
    let first = put_policy(router, &first_document(), &initial).await;
    {
        let mut connection =
            rusqlite::Connection::open(&harness.audit_db.path).expect("audit log opens");
        audit::sqlite_sink::write_events(
            &mut connection,
            &[
                retained(&format!("/orders/{PATH_CANARY}")),
                retained("/orders/restricted"),
                retained("/public/a"),
            ],
        )
        .expect("retained events are written");
    }

    // Before publishing, the draft's document replayed against the live
    // policy: the impact of publication 2 against what it replaces.
    let before = finished_replay(
        router,
        &first,
        json!({ "source": "inline", "policy": second_document() }),
    )
    .await;
    let second = publish_draft(router, &second_document(), &first).await;
    assert_eq!(
        before["candidate"]["etag"],
        json!(second),
        "the replayed document is the published one"
    );
    let job_id = before["job_id"].as_str().expect("job id").to_owned();
    let mut body = evidence_body(2);
    body["replay_job_id"] = json!(job_id);
    let response = request_evidence(router, admin(), &body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    let text = String::from_utf8(bytes.to_vec()).expect("a package is UTF-8");
    for canary in [ACTOR_CANARY, SUBJECT_CANARY, PATH_CANARY, job_id.as_str()] {
        assert!(!text.contains(canary), "{canary} is not repeated");
    }
    let report =
        serde_json::from_slice::<Value>(&bytes).expect("a package is JSON")["report"].clone();
    let replay = &report["replay"];
    assert_eq!(replay["included"], true);
    assert_eq!(replay["state"], before["state"]);
    assert_eq!(replay["base"]["etag"], json!(first));
    assert_eq!(replay["candidate"]["etag"], json!(second));
    assert_eq!(replay["predecessor_check"], "matches_predecessor");
    assert_eq!(replay["result_digest"], before["result_digest"]);
    assert_eq!(replay["result"], before["result"]);
    let limitations = report["limitations"].as_array().expect("limitations");
    assert!(!limitations.contains(&json!("replay_not_included")));
    assert!(!limitations.contains(&json!("replay_base_not_predecessor")));
    assert_eq!(
        limitations.contains(&json!("replay_incomplete")),
        before["state"] == "completed_incomplete"
    );

    // After publication, replaying the active policy compares the published
    // document with itself: reported, but not the publication's own impact.
    let after = finished_replay(router, &second, json!({ "source": "active" })).await;
    let mut later = evidence_body(2);
    later["replay_job_id"] = after["job_id"].clone();
    let response = request_evidence(router, admin(), &later).await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_body(response).await["report"].clone();
    assert_eq!(
        report["replay"]["predecessor_check"],
        "differs_from_predecessor"
    );
    assert!(report["limitations"]
        .as_array()
        .expect("limitations")
        .contains(&json!("replay_base_not_predecessor")));

    // A job of another policy is evidence about that policy, not this one.
    let edited = finished_replay(
        router,
        &second,
        json!({ "source": "edits", "edits": [{
            "op": "insert", "section": "rules", "position": 0,
            "value": { "id": "everything", "path": "/**", "action": "deny" }
        }] }),
    )
    .await;
    let mut stale = evidence_body(2);
    stale["replay_job_id"] = edited["job_id"].clone();
    let (status, refused) = refusal(request_evidence(router, admin(), &stale).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refused["reason"], "policy_evidence_replay_binding_stale");

    // Publication 1 is not the document the first job replayed either.
    let mut older = evidence_body(1);
    older["replay_job_id"] = json!(job_id);
    let (status, refused) = refusal(request_evidence(router, admin(), &older).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refused["reason"], "policy_evidence_replay_binding_stale");

    // A job is its owner's alone, exactly as on the replay routes.
    let mut other = test_principal(&["admin"]);
    other.user_id = "another-operator".to_owned();
    let (status, refused) = refusal(request_evidence(router, Some(other), &body).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(refused["reason"], "policy_evidence_replay_job_not_found");
    let mut unknown = evidence_body(2);
    unknown["replay_job_id"] = json!("rpl_ffffffffffffffffffffffffffffffff");
    let (status, _) = refusal(request_evidence(router, admin(), &unknown).await).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
