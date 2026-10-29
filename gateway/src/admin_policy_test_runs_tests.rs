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

/// A candidate is read from the bytes of its `policy` member by the parser
/// `PUT /policy` reads a body with, so a v1 number spelled as serde_json's
/// private tag -- a number through a `Value`, an object in the bytes -- is
/// refused with the error `PUT` gives it, and nothing runs. A `null`
/// candidate is still a candidate, and is refused as one.
#[tokio::test]
async fn a_candidate_is_read_from_its_bytes_like_a_policy_write() {
    let harness = harness();
    let request =
        |candidate: &str| format!(r#"{{"suite":{},"policy":{candidate}}}"#, passing_suite());
    let tagged = r#"{"schema_version":"1.0.0","rate_limits":[{"id":"l","requests_per_second":{"$serde_json::private::Number":"0.5"},"burst":1}]}"#;
    let response = run_request(&harness, tester(), request(tagged), None).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_candidate_invalid"));
    assert_eq!(
        body["errors"],
        json!(["the value is not one this location accepts"])
    );

    let response = run_request(&harness, tester(), request("null"), None).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_candidate_invalid")
    );
    drain_audit(&harness).await;
    assert!(test_run_events(&harness).is_empty());
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

/// The test-run route alone, over `limiter`, so a test can see and hold the
/// slots the route admits runs into. The application builds the same route
/// with a limiter of its own.
fn limited_router(
    harness: &Harness,
    limiter: Arc<PolicyEvaluationLimiter>,
    max_body_size: usize,
) -> Router {
    let policy =
        rbac::Policy::validate_json_value(runs_policy_document()).expect("policy is valid");
    let rbac_state =
        middleware::rbac::RbacState::new(policy, Vec::new(), false, harness.audit.clone());
    Router::new()
        .route(
            RUNS,
            post(policy_test_runs_endpoint).layer(Extension(limiter)),
        )
        .with_state(PolicyAdminState {
            policy_file: Some(harness.policy.path.clone()),
            rbac_state: Some(rbac_state),
            history_store: None,
            draft_store: None,
            #[cfg(feature = "postgres")]
            control_plane: None,
            #[cfg(feature = "postgres")]
            membership: None,
            event_store: None,
            query_store: None,
            audit: harness.audit.clone(),
            client_ip_policy: client_ip::ClientIpPolicy::default(),
            max_body_size,
        })
}

fn tester_named(user_id: &str) -> auth::Principal {
    let mut principal = test_principal(&["tester"]);
    principal.user_id = user_id.to_owned();
    principal
}

async fn refusal_reason(response: Response) -> Value {
    json_body(response).await["reason"].clone()
}

/// A body that never finishes arriving, and a signal for when the handler
/// first asks for it: the moment a run that admitted before reading its body
/// would already hold a slot.
fn stalled_body() -> (Body, tokio::sync::oneshot::Receiver<()>) {
    let (polled, polled_signal) = tokio::sync::oneshot::channel();
    let chunks = stream::once(async move {
        let _ = polled.send(());
        std::future::pending::<Result<Bytes, Infallible>>().await
    });
    (Body::from_stream(chunks), polled_signal)
}

/// A run is admitted only once its body is in hand. Uploads trickled by one
/// caller -- as many as the replica has slots -- hold none of them, so the
/// same caller's next complete run is admitted while they are still open,
/// and each stalled upload is refused once its body deadline passes.
#[tokio::test]
async fn a_stalled_body_is_refused_within_its_deadline_and_holds_no_slot() {
    let harness = harness();
    let limiter = Arc::new(PolicyEvaluationLimiter::new(
        MAX_CONCURRENT_POLICY_TEST_RUNS,
    ));
    let router = limited_router(&harness, Arc::clone(&limiter), 1024 * 1024);
    let started = tokio::time::Instant::now();
    let mut stalled = Vec::new();
    for _ in 0..MAX_CONCURRENT_POLICY_TEST_RUNS {
        let (body, polled) = stalled_body();
        let request = policy_admin_request_with_body(Method::POST, RUNS, tester(), body, None);
        stalled.push(tokio::spawn(router.clone().oneshot(request)));
        polled.await.expect("the handler reads the stalled body");
    }

    // Every stalled upload is being read, and none holds a slot: not the
    // caller's own, and not one of the replica's.
    let probe = limiter.try_acquire(policy_evaluation_actor(&test_principal(&["tester"])));
    assert!(probe.is_some(), "a stalled upload holds the caller's slot");
    drop(probe);
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            RUNS,
            tester(),
            Some(json!({ "suite": passing_suite() }).to_string()),
            None,
        ))
        .await
        .expect("policy test run should complete");
    assert_eq!(response.status(), StatusCode::OK);

    for request in stalled {
        let response = request
            .await
            .expect("the stalled request task completes")
            .expect("the stalled request completes");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            refusal_reason(response).await,
            json!("policy_tests_request_timeout")
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= POLICY_TEST_RUN_BODY_DEADLINE,
        "refused after {elapsed:?}, before the body deadline"
    );
    assert!(
        elapsed < POLICY_TEST_RUN_BODY_DEADLINE + Duration::from_secs(5),
        "refused after {elapsed:?}, long past the body deadline"
    );
    // The completed run is the only one recorded.
    drain_audit(&harness).await;
    assert_eq!(test_run_events(&harness).len(), 1);
}

/// One caller holds at most one run slot, so a second concurrent run from the
/// same actor is refused while another actor is still admitted, and the
/// replica-wide bound holds across actors.
#[tokio::test]
async fn one_actor_holds_one_run_slot_while_others_are_admitted() {
    let harness = harness();
    let limiter = Arc::new(PolicyEvaluationLimiter::new(
        MAX_CONCURRENT_POLICY_TEST_RUNS,
    ));
    let router = limited_router(&harness, Arc::clone(&limiter), 1024 * 1024);
    let body = json!({ "suite": passing_suite() }).to_string();
    let run = |principal: auth::Principal| {
        router.clone().oneshot(policy_admin_request(
            Method::POST,
            RUNS,
            Some(principal),
            Some(body.clone()),
            None,
        ))
    };

    // A run of this caller's in flight holds exactly this slot.
    let in_flight = limiter
        .try_acquire(policy_evaluation_actor(&tester_named("alice")))
        .expect("the first run is admitted");
    let response = run(tester_named("alice")).await.expect("run completes");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refusal_reason(response).await, json!("policy_tests_busy"));
    let response = run(tester_named("bob")).await.expect("run completes");
    assert_eq!(response.status(), StatusCode::OK);
    // The same subject under another issuer is another actor.
    let mut federated = tester_named("alice");
    federated.issuer = Some("https://idp.example.test".to_owned());
    let response = run(federated).await.expect("run completes");
    assert_eq!(response.status(), StatusCode::OK);

    // With every replica slot held, any actor is refused.
    let others: Vec<_> = (1..MAX_CONCURRENT_POLICY_TEST_RUNS)
        .map(|index| {
            limiter
                .try_acquire(format!("\u{0}other-{index}"))
                .expect("a slot is free")
        })
        .collect();
    let response = run(tester_named("carol")).await.expect("run completes");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refusal_reason(response).await, json!("policy_tests_busy"));

    drop((in_flight, others));
    let response = run(tester_named("alice")).await.expect("run completes");
    assert_eq!(response.status(), StatusCode::OK);
    drain_audit(&harness).await;
    assert_eq!(test_run_events(&harness).len(), 3);
}

/// A run's body is bounded by its own limit even where the deployment's
/// `MAX_BODY_SIZE` is higher.
#[tokio::test]
async fn a_body_over_the_run_bound_is_refused_whatever_the_deployment_limit() {
    let harness = harness();
    let limiter = Arc::new(PolicyEvaluationLimiter::new(
        MAX_CONCURRENT_POLICY_TEST_RUNS,
    ));
    let router = limited_router(&harness, limiter, 4 * MAX_POLICY_TEST_RUN_BODY_BYTES);
    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            RUNS,
            tester(),
            Some(" ".repeat(MAX_POLICY_TEST_RUN_BODY_BYTES + 1)),
            None,
        ))
        .await
        .expect("policy test run should complete");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    drain_audit(&harness).await;
    assert!(test_run_events(&harness).is_empty());
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
