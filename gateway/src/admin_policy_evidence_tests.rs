//! `POST /v1{ADMIN_PREFIX}/policy/evidence` (issue #243) through the
//! application in standalone mode: the policy file authority, its SQLite
//! history, drafts and analysis suppressions beside it, and the standalone
//! audit log a replay job reads. The request parser, the package assembler
//! and the Markdown renderer are covered in `policy_evidence::tests`.
use super::*;

const EVIDENCE: &str = POLICY_EVIDENCE_ADMIN_ROUTE;
/// Values the request, the history, the drafts, the suppressions and the
/// retained records carry that no package or export record may repeat.
const ACTOR_CANARY: &str = "evidence-api-actor-canary-e19b";
const SUBJECT_CANARY: &str = "evidence-api-subject-canary-27fd";
const PATH_CANARY: &str = "evidence-api-path-canary-6a03";
const REASON_CANARY: &str = "evidence-api-reason-canary-b3c1";

fn roles() -> Value {
    json!({
        "admin": {
            "permissions": [
                ADMIN_POLICY_READ_PERMISSION,
                ADMIN_POLICY_WRITE_PERMISSION,
                ADMIN_POLICY_SIMULATE_PERMISSION,
                ADMIN_POLICY_ANALYZE_PERMISSION,
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
    let mut with_analysis = evidence_body(2);
    with_analysis["analysis"] = json!(true);

    let response = request_evidence(&harness.router, None, &plain).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for (roles, body) in [
        (&["policy-reader"][..], &plain),
        (&["evidence-only"][..], &plain),
        (&["orders-reader"][..], &plain),
        (&["evidence-reader"][..], &with_suite),
        (&["evidence-reader"][..], &with_cases),
        (&["evidence-simulator"][..], &with_replay),
        (&["evidence-simulator"][..], &with_analysis),
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
    assert_eq!(report["analysis"], json!({ "included": false }));
    assert_eq!(report["completeness"], "incomplete");
    assert_eq!(
        report["limitations"],
        json!(["analysis_not_included", "replay_not_included"])
    );
    assert_eq!(report["trust"]["signed"], false);
    assert_eq!(report["candidate_kind"], "publication");

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
            "analysis_not_included",
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
async fn revalidation_does_not_judge_a_publication_as_the_replacement_of_its_predecessor() {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = || audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = policy_file();
    let audit_db = TempDb::new("policy-evidence-file-edit");
    let router = evidence_router(audit_log(), &policy, &audit_db);
    // Version 1, published through the API with the file's egress: none.
    let initial = live_etag(&router).await;
    put_policy(&router, &first_document(), &initial).await;

    // The operator gives POLICY_FILE an egress section and restarts. Neither
    // writes a history version.
    let mut edited = first_document();
    edited["egress"] = json!({ "hosts": ["api.example.test"] });
    fs::write(
        &policy.path,
        serde_json::to_string_pretty(&edited).expect("serializes"),
    )
    .expect("the policy file should be edited");
    drop(router);
    let router = evidence_router(audit_log(), &policy, &audit_db);

    // Version 2 keeps the live egress, so the gateway accepts it; its
    // egress differs from version 1's, which it never replaced.
    let mut second = second_document();
    second["egress"] = edited["egress"].clone();
    let restarted = live_etag(&router).await;
    put_policy(&router, &second, &restarted).await;

    let response = request_evidence(&router, admin(), &evidence_body(2)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_body(response).await["report"].clone();
    assert_eq!(report["publication"]["predecessor"]["version"], 1);
    // Revalidation used to judge version 2 as the replacement of version 1
    // and report `egress_change_requires_restart` for an accepted
    // publication.
    assert_eq!(report["validation"]["valid"], true, "{report}");
    assert_eq!(report["validation"]["diagnostics"], json!([]));
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

/// Version 2 with a copy of its `public` rule after it: a rule the analyzer
/// proves never decides a request.
fn analyzed_document() -> Value {
    let mut document = second_document();
    if let Some(rules) = document["rules"].as_array_mut() {
        rules.push(json!({
            "id": "public-copy",
            "methods": ["GET"],
            "path": "/public/**",
            "action": "allow"
        }));
    }
    document
}

/// `POST .../policy/analyses` of the live policy, as a reviewer runs it.
async fn analyze_active(router: &Router, etag: &str) -> Value {
    let response = send(
        router,
        policy_admin_request(
            Method::POST,
            POLICY_ANALYSES_ADMIN_ROUTE,
            admin(),
            Some(
                json!({
                    "schema_version": "policy-analysis.v1",
                    "base_etag": etag,
                    "candidate": { "source": "active" },
                })
                .to_string(),
            ),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

/// Suppress `finding` of the analysis `report` of the live policy `etag`.
async fn suppress(router: &Router, etag: &str, report: &Value, finding: &Value) -> String {
    let expires_at = (OffsetDateTime::now_utc() + time::Duration::days(7))
        .format(&Rfc3339)
        .expect("formats");
    let response = send(
        router,
        policy_admin_request(
            Method::POST,
            POLICY_ANALYSIS_SUPPRESSIONS_ADMIN_ROUTE,
            admin(),
            Some(
                json!({
                    "fingerprint": finding["fingerprint"],
                    "code": finding["code"],
                    "reason": REASON_CANARY,
                    "expires_at": expires_at,
                    "resource_snapshot_digest": report["resource_snapshot"]["digest"],
                })
                .to_string(),
            ),
            Some(etag),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await["suppression_id"]
        .as_str()
        .expect("suppression id")
        .to_owned()
}

fn finding_with_code<'a>(findings: &'a Value, code: &str) -> &'a Value {
    findings
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["code"] == code)
        .unwrap_or_else(|| panic!("a {code} finding"))
}

async fn package_bytes(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read")
        .to_vec()
}

/// The package without the one member that differs between two exports of
/// the same inputs.
fn without_generation_time(bytes: &[u8]) -> Value {
    let mut package: Value = serde_json::from_slice(bytes).expect("a package is JSON");
    package["generated_at"] = Value::Null;
    package
}

#[tokio::test]
async fn a_package_carries_the_analysis_and_a_markdown_rendering_bound_by_digest() {
    let harness = harness();
    let (_, second) = two_publications(&harness.router).await;
    let third = publish_draft(&harness.router, &analyzed_document(), &second).await;
    // A reviewer's analysis of the publication, now live, and a suppression
    // of its proven finding bound to it.
    let reviewed = analyze_active(&harness.router, &third).await;
    let duplicate = finding_with_code(&reviewed["findings"], "rule_unreachable").clone();
    let suppression_id = suppress(&harness.router, &third, &reviewed, &duplicate).await;

    let mut body = evidence_body(3);
    body["suite"] = suite();
    body["simulation"] = simulation();
    body["analysis"] = json!(true);
    let response = request_evidence(&harness.router, admin(), &body).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header(&response, POLICY_EVIDENCE_CANDIDATE_KIND_HEADER),
        "publication"
    );
    assert_eq!(header(&response, "cache-control"), "no-store");
    let digest = header(&response, POLICY_EVIDENCE_DIGEST_HEADER);
    let bytes = package_bytes(response).await;
    let text = String::from_utf8(bytes.clone()).expect("a package is UTF-8");
    for canary in [ACTOR_CANARY, SUBJECT_CANARY, PATH_CANARY, REASON_CANARY] {
        assert!(!text.contains(canary), "{canary} is not repeated");
    }
    let package: Value = serde_json::from_slice(&bytes).expect("a package is JSON");
    let manifest = package["manifest"].as_array().expect("manifest");
    assert_eq!(
        manifest
            .iter()
            .map(|entry| entry["name"].clone())
            .collect::<Vec<_>>(),
        vec![json!("report"), json!("analysis"), json!("report_markdown")]
    );
    assert_eq!(manifest[0]["digest"], json!(digest));

    // The artifact is the analyzer's own report of the same document: the
    // same findings and fingerprints, its suppression applied, no base.
    let analysis = &package["analysis"];
    assert_eq!(
        manifest[1]["digest"],
        json!(crate::canonical_json::semantic_digest(
            crate::policy_evidence::ANALYSIS_MEDIA_TYPE,
            "policy-analysis-results.v1",
            analysis
        )
        .expect("digest"))
    );
    assert!(analysis.get("base").is_none());
    assert_eq!(analysis["analyzed"]["source"], "revision");
    assert_eq!(analysis["analyzed"]["version"], 3);
    assert_eq!(analysis["analyzed"]["etag"], json!(third));
    assert_eq!(
        analysis["findings"].as_array().map(Vec::len),
        reviewed["findings"].as_array().map(Vec::len)
    );
    let packaged = finding_with_code(&analysis["findings"], "rule_unreachable");
    assert_eq!(packaged["fingerprint"], duplicate["fingerprint"]);
    assert_eq!(packaged["suppression"]["state"], "suppressed");
    assert_eq!(
        packaged["suppression"]["suppression_id"],
        json!(suppression_id)
    );
    assert_eq!(analysis["resource_snapshot"], reviewed["resource_snapshot"]);

    let report = &package["report"];
    assert_eq!(report["analysis"]["artifact"], manifest[1]);
    assert_eq!(report["analysis"]["complete"], true);
    assert_eq!(
        report["analysis"]["suppressions"],
        json!({ "available": true, "records": 1 })
    );
    let summarized = finding_with_code(&report["analysis"]["findings"], "rule_unreachable");
    assert_eq!(summarized["proof_basis"], "proven");
    assert_eq!(summarized["element"]["id"], "public-copy");
    assert_eq!(summarized["suppression"]["state"], "suppressed");
    assert_eq!(report["limitations"], json!(["replay_not_included"]));

    // The Markdown: the report's own rendering, bound by its digest.
    let markdown = package["report_markdown"].as_str().expect("Markdown");
    let report_bytes = crate::canonical_json::canonical_json_bytes(report).expect("canonical");
    assert_eq!(
        crate::policy_evidence::markdown::render(&report_bytes).expect("renders"),
        markdown
    );
    assert_eq!(
        manifest[2]["digest"],
        json!(crate::canonical_json::source_digest(
            crate::policy_evidence::MARKDOWN_MEDIA_TYPE,
            crate::policy_evidence::MARKDOWN_SCHEMA_VERSION,
            markdown.as_bytes()
        ))
    );
    assert!(markdown.contains(crate::policy_evidence::TRUST_STATEMENT));

    let exports = wait_for_exports(&harness.capture, 1).await;
    let payload = &exports[0].payload;
    assert_eq!(payload["candidate_kind"], "publication");
    assert_eq!(payload["publication_version"], 3);
    assert_eq!(payload["analysis_included"], true);
    assert_eq!(payload["analysis_digest"], manifest[1]["digest"]);
    assert_eq!(payload["markdown_digest"], manifest[2]["digest"]);
    let payload_text = payload.to_string();
    for canary in [ACTOR_CANARY, SUBJECT_CANARY, PATH_CANARY, REASON_CANARY] {
        assert!(!payload_text.contains(canary), "{canary} is not recorded");
    }

    // The same inputs again: the same bytes, but for when they were made.
    let again = request_evidence(&harness.router, admin(), &body).await;
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(
        without_generation_time(&package_bytes(again).await),
        without_generation_time(&bytes)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_packages_are_byte_identical_but_for_when_they_were_generated() {
    let harness = harness();
    let (_, second) = two_publications(&harness.router).await;
    publish_draft(&harness.router, &analyzed_document(), &second).await;
    let mut body = evidence_body(3);
    body["suite"] = suite();
    body["simulation"] = simulation();
    body["analysis"] = json!(true);

    // As many callers as the replica assembles at once, each on its own
    // blocking worker.
    let requests = (0..MAX_CONCURRENT_POLICY_EVIDENCE)
        .map(|index| {
            let router = harness.router.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let mut caller = test_principal(&["admin"]);
                caller.user_id = format!("evidence-concurrent-{index}");
                let response = request_evidence(&router, Some(caller), &body).await;
                assert_eq!(response.status(), StatusCode::OK);
                package_bytes(response).await
            })
        })
        .collect::<Vec<_>>();
    let mut packages = Vec::new();
    for request in requests {
        packages.push(without_generation_time(
            &request.await.expect("the request task finishes"),
        ));
    }
    let sequential = request_evidence(&harness.router, admin(), &body).await;
    assert_eq!(sequential.status(), StatusCode::OK);
    let sequential = without_generation_time(&package_bytes(sequential).await);
    for package in &packages {
        assert_eq!(package, &sequential, "byte-identical but for generated_at");
    }
}

/// Save `document` as a draft on `base`: its id and draft ETag.
async fn create_draft(router: &Router, document: &Value, base: &str) -> (String, String) {
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
    (
        draft["draft_id"].as_str().expect("draft id").to_owned(),
        draft_etag,
    )
}

fn draft_body(draft_id: &str, draft_etag: &str) -> Value {
    json!({
        "schema_version": "policy-evidence-request.v1",
        "draft": { "draft_id": draft_id, "draft_etag": draft_etag }
    })
}

#[tokio::test]
async fn a_draft_package_is_read_as_its_owner_at_its_pinned_etag_and_never_as_a_publication() {
    let harness = harness();
    let router = &harness.router;
    let (_, second) = two_publications(router).await;
    let (draft_id, draft_etag) = create_draft(router, &analyzed_document(), &second).await;

    let mut body = draft_body(&draft_id, &draft_etag);
    body["suite"] = suite();
    body["simulation"] = simulation();
    body["analysis"] = json!(true);
    let response = request_evidence(router, admin(), &body).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header(&response, POLICY_EVIDENCE_CANDIDATE_KIND_HEADER),
        "draft"
    );
    assert_eq!(
        header(&response, "content-disposition"),
        "attachment; filename=\"policy-draft-evidence.json\""
    );
    assert_eq!(header(&response, "cache-control"), "no-store");
    let bytes = package_bytes(response).await;
    let text = String::from_utf8(bytes.clone()).expect("a package is UTF-8");
    for canary in [ACTOR_CANARY, SUBJECT_CANARY, PATH_CANARY] {
        assert!(!text.contains(canary), "{canary} is not repeated");
    }
    let package: Value = serde_json::from_slice(&bytes).expect("a package is JSON");
    let report = &package["report"];
    assert_eq!(report["candidate_kind"], "draft");
    assert!(report.get("publication").is_none());
    assert!(report.get("approval").is_none());
    assert_eq!(report["draft"]["draft_id"], json!(draft_id));
    assert_eq!(report["draft"]["revision"], 1);
    assert_eq!(report["draft"]["draft_etag"], json!(draft_etag));
    assert_eq!(report["draft"]["base"]["source"], "active");
    assert_eq!(report["draft"]["base"]["policy"]["etag"], json!(second));
    assert_eq!(
        report["trust"]["statement"],
        crate::policy_evidence::DRAFT_TRUST_STATEMENT
    );
    assert_eq!(report["tests"]["results"]["policy"]["source"], "draft");
    assert_eq!(report["simulation"]["base"], json!({ "etag": second }));
    assert_eq!(report["simulation"]["candidate"]["draft_revision"], 1);
    assert_eq!(package["analysis"]["analyzed"]["source"], "draft");
    assert_eq!(package["analysis"]["analyzed"]["draft_id"], json!(draft_id));
    finding_with_code(&report["analysis"]["findings"], "rule_unreachable");
    let markdown = package["report_markdown"].as_str().expect("Markdown");
    assert!(markdown.contains(crate::policy_evidence::DRAFT_TRUST_STATEMENT));
    assert!(!markdown.contains(crate::policy_evidence::TRUST_STATEMENT));

    let exports = wait_for_exports(&harness.capture, 1).await;
    let payload = &exports[0].payload;
    assert_eq!(payload["candidate_kind"], "draft");
    assert_eq!(payload["draft_id"], json!(draft_id));
    assert_eq!(payload["draft_revision"], 1);
    assert!(payload.get("publication_version").is_none());

    // Packaging read the draft and wrote nothing: the draft and the live
    // policy are where they were.
    let read = send(
        router,
        policy_admin_request(
            Method::GET,
            &format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}"),
            admin(),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&read), draft_etag);
    assert_eq!(live_etag(router).await, second);

    // Owner-scoped: another principal's request finds no such draft.
    let mut other = test_principal(&["admin"]);
    other.user_id = "another-operator".to_owned();
    let (status, refused) =
        refusal(request_evidence(router, Some(other), &draft_body(&draft_id, &draft_etag)).await)
            .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(refused["reason"], "policy_draft_not_found");

    // Pinned: a draft ETag the draft no longer has is stale.
    let stale = format!("\"sha256:{}\"", "0".repeat(64));
    let (status, refused) =
        refusal(request_evidence(router, admin(), &draft_body(&draft_id, &stale)).await).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(refused["reason"], "policy_draft_stale");

    // And bound to what it would replace: once the live policy moves, the
    // draft is not rebased into a package.
    put_policy(router, &first_document(), &second).await;
    let (status, refused) =
        refusal(request_evidence(router, admin(), &draft_body(&draft_id, &draft_etag)).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refused["reason"], "policy_draft_base_stale");

    // A request names one candidate.
    let mut both = draft_body(&draft_id, &draft_etag);
    both["publication"] = json!({ "version": 2 });
    let (status, refused) = refusal(request_evidence(router, admin(), &both).await).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused["reason"], "policy_evidence_invalid");
    // Refusals left no export record behind the one served package.
    assert_eq!(exported_events(&harness.capture).len(), 1);
}
