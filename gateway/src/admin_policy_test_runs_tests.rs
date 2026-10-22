//! `POST /v1{ADMIN_PREFIX}/policy/tests/runs` (issue #243, slice 11) through
//! the admin API in standalone mode. The suite parser, runner and renderings
//! are covered in `policy_testing::tests`.
use super::*;

const RUNS: &str = POLICY_TEST_RUNS_ADMIN_ROUTE;
/// A fixture value the run must never repeat in a response or audit record.
const SUBJECT_CANARY: &str = "run-subject-canary-31f9";

fn runs_policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "policy-test-runs",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION,
                    ADMIN_POLICY_SIMULATE_PERMISSION
                ]
            },
            "tester": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_SIMULATE_PERMISSION]
            },
            "policy-reader": { "permissions": [ADMIN_POLICY_READ_PERMISSION] },
            "simulator-only": { "permissions": [ADMIN_POLICY_SIMULATE_PERMISSION] },
            "orders-reader": { "permissions": ["orders:read"] }
        },
        "rules": [
            { "id": "public-health", "methods": ["GET"], "path": "/health", "action": "allow" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ]
    })
}

fn passing_suite() -> Value {
    json!({
        "schema_version": "policy-tests.v1",
        "cases": [
            {
                "id": "health-is-public",
                "kind": "http",
                "request": { "method": "GET", "path": "/health" },
                "principal": "anonymous",
                "expect": { "logical": "allow", "matched": { "rule": "public-health" } }
            },
            {
                "id": "orders-need-a-reader",
                "kind": "http",
                "request": { "method": "GET", "path": "/orders/7" },
                "principal": {
                    "subject": SUBJECT_CANARY,
                    "roles": ["orders-reader"],
                    "auth_method": "bearer_token"
                },
                "expect": { "logical": "allow", "matched": { "route": 0 } }
            }
        ]
    })
}

fn failing_suite() -> Value {
    let mut suite = passing_suite();
    suite["cases"][1]["expect"]["logical"] = json!("deny");
    suite
}

struct Harness {
    router: Router,
    audit: audit::AuditLog,
    capture: audit::sink::tests::CaptureSink,
    policy: TempPolicyFile,
}

fn harness() -> Harness {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&runs_policy_document()).expect("policy serializes"),
    );
    let router = policy_admin_router(Some(&policy), audit_log.clone());
    Harness {
        router,
        audit: audit_log,
        capture,
        policy,
    }
}

fn tester() -> Option<auth::Principal> {
    Some(test_principal(&["tester"]))
}

async fn run_request(
    harness: &Harness,
    principal: Option<auth::Principal>,
    body: String,
    if_match: Option<&str>,
) -> Response {
    harness
        .router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            RUNS,
            principal,
            Some(body),
            if_match,
        ))
        .await
        .expect("policy test run should complete")
}

fn test_run_events(harness: &Harness) -> Vec<audit::AuditEvent> {
    harness
        .capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == audit::event::POLICY_TESTS_RUN)
        .collect()
}

/// Audit delivery is asynchronous: the handler queues its record for the
/// writer thread, which can reach the capture after the response does. Wait,
/// bounded, for `count` test-run records before reading them.
async fn wait_for_test_run_events(harness: &Harness, count: usize) -> Vec<audit::AuditEvent> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let events = test_run_events(harness);
            if events.len() >= count {
                return events;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "expected {count} policy test-run audit records, saw {}",
            test_run_events(harness).len()
        )
    })
}

/// Close the log and wait, bounded, until the writer has delivered every
/// queued record, so a count or an absence read afterwards covers every
/// request the test made. Only for the end of a test: the log accepts
/// nothing more.
async fn drain_audit(harness: &Harness) {
    harness
        .audit
        .close_and_drain(Duration::from_secs(5))
        .await
        .expect("the audit log drains");
}

#[tokio::test]
async fn a_run_needs_authentication_policy_read_and_simulate() {
    let harness = harness();
    let body = json!({ "suite": passing_suite() }).to_string();
    let response = run_request(&harness, None, body.clone(), None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for roles in [&["policy-reader"][..], &["simulator-only"][..]] {
        let response = run_request(&harness, Some(test_principal(roles)), body.clone(), None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
    }
    drain_audit(&harness).await;
    assert!(test_run_events(&harness).is_empty());
}

#[tokio::test]
async fn a_passing_run_answers_the_report_and_audits_digests_and_counts_only() {
    let harness = harness();
    let before = fs::read_to_string(&harness.policy.path).expect("policy reads");
    let (etag, _) = current_policy(&harness.router).await;
    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": passing_suite() }).to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[POLICY_TESTS_STATUS_HEADER], "passed");
    assert_content_type_starts_with(response.headers(), "application/json");
    let body = body_string(response).await;
    assert!(!body.contains(SUBJECT_CANARY));
    let report: Value = serde_json::from_str(&body).expect("report is JSON");
    assert_eq!(report["status"], json!("passed"));
    assert_eq!(report["policy"]["source"], json!("active"));
    assert_eq!(report["policy"]["etag"], json!(etag));
    assert_eq!(report["summary"]["passed"], json!(2));
    let digest = report["suite"]["digest"]
        .as_str()
        .expect("suite digest")
        .to_owned();
    assert!(digest.starts_with("sha256:"));

    // Nothing was written or activated, and the only new record is the run.
    assert_eq!(
        fs::read_to_string(&harness.policy.path).expect("policy reads"),
        before
    );
    drain_audit(&harness).await;
    let events = harness.capture.events();
    assert!(!events
        .iter()
        .any(|event| event.event_type == audit::event::POLICY_CHANGED));
    let runs = test_run_events(&harness);
    assert_eq!(runs.len(), 1);
    let payload = &runs[0].payload;
    assert_eq!(payload["policy_source"], json!("active"));
    assert_eq!(payload["policy_etag"], json!(etag));
    assert_eq!(payload["suite_digest"], json!(digest));
    assert_eq!(payload["status"], json!("passed"));
    assert_eq!(payload["total"], json!(2));
    assert_eq!(payload["passed"], json!(2));
    let recorded = payload.to_string();
    for absent in [
        SUBJECT_CANARY,
        "health-is-public",
        "/orders/7",
        "public-health",
    ] {
        assert!(
            !recorded.contains(absent),
            "the audit record repeats {absent}"
        );
    }
    assert_eq!(
        runs[0].actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("user-123")
    );
}

#[tokio::test]
async fn a_failing_run_is_still_a_completed_run_with_a_failed_status() {
    let harness = harness();
    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": failing_suite() }).to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[POLICY_TESTS_STATUS_HEADER], "failed");
    let report = json_body(response).await;
    assert_eq!(report["summary"]["failed"], json!(1));
    assert_eq!(report["cases"][1]["mismatches"], json!(["logical"]));
    assert_eq!(
        wait_for_test_run_events(&harness, 1).await[0].payload["status"],
        json!("failed")
    );
}

#[tokio::test]
async fn sarif_and_junit_renderings_are_selected_by_format() {
    let harness = harness();
    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": failing_suite(), "format": "sarif" }).to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_content_type_starts_with(response.headers(), "application/sarif+json");
    let sarif = json_body(response).await;
    assert_eq!(sarif["version"], json!("2.1.0"));
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        json!("policy-test/failed")
    );

    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": failing_suite(), "format": "junit" }).to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_content_type_starts_with(response.headers(), "application/xml");
    assert_eq!(response.headers()[POLICY_TESTS_STATUS_HEADER], "failed");
    let xml = body_string(response).await;
    assert!(xml.contains("tests=\"2\" failures=\"1\" errors=\"0\""));
    assert!(!xml.contains(SUBJECT_CANARY));

    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": passing_suite(), "format": "html" }).to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn if_match_pins_the_active_policy() {
    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    let body = json!({ "suite": passing_suite() }).to_string();
    let response = run_request(&harness, tester(), body.clone(), Some(&etag)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = run_request(&harness, tester(), body, Some("\"sha256:stale\"")).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    drain_audit(&harness).await;
    assert_eq!(test_run_events(&harness).len(), 1);
}

#[tokio::test]
async fn a_candidate_is_judged_without_being_written() {
    let harness = harness();
    let before = fs::read_to_string(&harness.policy.path).expect("policy reads");
    let mut candidate = runs_policy_document();
    candidate["rules"][0]["action"] = json!("deny");
    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": passing_suite(), "policy": candidate }).to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_body(response).await;
    assert_eq!(report["policy"]["source"], json!("inline_candidate"));
    assert_eq!(report["status"], json!("failed"));
    assert_eq!(report["cases"][0]["actual"]["logical"], json!("deny"));
    assert_eq!(
        fs::read_to_string(&harness.policy.path).expect("policy reads"),
        before
    );
    let (_, live) = current_policy(&harness.router).await;
    assert_eq!(live["rules"][0]["action"], json!("allow"));
    assert_eq!(
        wait_for_test_run_events(&harness, 1).await[0].payload["policy_source"],
        json!("inline_candidate")
    );

    // A pin on the live policy means nothing for a candidate.
    let (etag, _) = current_policy(&harness.router).await;
    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": passing_suite(), "policy": runs_policy_document() }).to_string(),
        Some(&etag),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": passing_suite(), "policy": { "schema_version": "9.0.0" } }).to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_candidate_invalid")
    );
}

#[tokio::test]
async fn an_invalid_suite_or_body_is_refused_before_any_run() {
    let harness = harness();
    let mut suite = passing_suite();
    suite["cases"][1]["principal"]["token"] = json!(SUBJECT_CANARY);
    let response = run_request(
        &harness,
        tester(),
        json!({ "suite": suite }).to_string(),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_string(response).await;
    assert!(!body.contains(SUBJECT_CANARY));
    let refusal: Value = serde_json::from_str(&body).expect("refusal is JSON");
    assert_eq!(refusal["reason"], json!("policy_tests_invalid"));
    assert_eq!(refusal["diagnostics"][0]["code"], json!("forbidden_field"));
    assert_eq!(
        refusal["diagnostics"][0]["pointer"],
        json!("/cases/1/principal/token")
    );

    for body in [
        "not json".to_owned(),
        "[]".to_owned(),
        json!({ "cases": [] }).to_string(),
        json!({ "suite": passing_suite(), "extra": true }).to_string(),
        // A repeated member is refused even where the two copies agree.
        format!(
            "{{\"suite\":{},\"suite\":{}}}",
            passing_suite(),
            passing_suite()
        ),
    ] {
        let response = run_request(&harness, tester(), body.clone(), None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
    drain_audit(&harness).await;
    assert!(test_run_events(&harness).is_empty());
}

#[test]
fn concurrent_runs_are_bounded_and_a_slot_is_returned_on_drop() {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let first = PolicyTestRunSlot::try_acquire(&COUNTER, 2).expect("first slot");
    let second = PolicyTestRunSlot::try_acquire(&COUNTER, 2).expect("second slot");
    assert!(PolicyTestRunSlot::try_acquire(&COUNTER, 2).is_none());
    drop(first);
    let third = PolicyTestRunSlot::try_acquire(&COUNTER, 2).expect("a released slot is reusable");
    drop((second, third));
    assert_eq!(COUNTER.load(std::sync::atomic::Ordering::Acquire), 0);
}

#[tokio::test]
async fn the_simulate_permission_is_advertised_as_a_capability() {
    let harness = harness();
    let capabilities = |roles: &'static [&'static str]| {
        let router = harness.router.clone();
        async move {
            let response = router
                .oneshot(policy_admin_request(
                    Method::GET,
                    ADMIN_CAPABILITIES_ROUTE,
                    Some(test_principal(roles)),
                    None,
                    None,
                ))
                .await
                .expect("capabilities request should complete");
            assert_eq!(response.status(), StatusCode::OK);
            json_body(response).await["permissions"].clone()
        }
    };
    assert!(capabilities(&["tester"])
        .await
        .as_array()
        .expect("permissions")
        .contains(&json!(ADMIN_POLICY_SIMULATE_PERMISSION)));
    assert!(!capabilities(&["policy-reader"])
        .await
        .as_array()
        .expect("permissions")
        .contains(&json!(ADMIN_POLICY_SIMULATE_PERMISSION)));

    let routes = AdminRoutes::from_prefix(config::DEFAULT_ADMIN_PREFIX);
    assert_eq!(routes.policy_test_runs_route, POLICY_TEST_RUNS_ADMIN_ROUTE);
    let custom = AdminRoutes::from_prefix("/ops");
    assert_eq!(custom.policy_test_runs_route, "/v1/ops/policy/tests/runs");
}
