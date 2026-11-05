//! `POLICY_TESTS_REQUIRED` (issue #243) through the application in
//! standalone mode: every publication path the policy routes serve runs the
//! stored suite inside its commit precondition, and with the setting off the
//! same changes publish as before. A promotion bound to a shadow review is in
//! `admin_policy_app_tests`, suggestion acceptance (both modes) in
//! `admin_observability_app_tests`, and the cluster commit in
//! `cluster_policy_tests`.
use super::*;

/// A fixture value no response or audit record may repeat.
const SUBJECT_CANARY: &str = "required-tests-subject-canary-91c4";

fn roles() -> Value {
    json!({
        "admin": {
            "permissions": [
                ADMIN_POLICY_READ_PERMISSION,
                ADMIN_POLICY_WRITE_PERMISSION,
                ADMIN_POLICY_SIMULATE_PERMISSION
            ]
        },
        "orders-reader": { "permissions": ["orders:read"] }
    })
}

fn policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "required-policy-tests",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": roles(),
        "rules": [
            { "id": "public-health", "methods": ["GET"], "path": "/health", "action": "allow" },
            { "id": "deny-health", "methods": ["GET"], "path": "/health", "action": "deny" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ]
    })
}

fn http_case(id: &str, path: &str, expect: Value) -> Value {
    json!({
        "id": id,
        "kind": "http",
        "request": { "method": "GET", "path": path },
        "principal": "anonymous",
        "expect": expect
    })
}

fn cases() -> Vec<Value> {
    vec![
        http_case(
            "health-is-public",
            "/health",
            json!({ "logical": "allow", "matched": { "rule": "public-health" } }),
        ),
        http_case("status-is-denied", "/status", json!({ "logical": "deny" })),
        json!({
            "id": "orders-need-a-reader",
            "kind": "http",
            "request": { "method": "GET", "path": "/orders/7" },
            "principal": {
                "subject": SUBJECT_CANARY,
                "roles": ["orders-reader"],
                "auth_method": "bearer_token"
            },
            "expect": { "logical": "allow", "matched": { "route": 0 } }
        }),
    ]
}

fn suite_of(cases: Vec<Value>) -> Value {
    json!({ "schema_version": "policy-tests.v1", "cases": cases })
}

/// The suite every test here stores: the active policy passes it.
fn suite() -> Value {
    suite_of(cases())
}

struct Harness {
    router: Router,
    capture: audit::sink::tests::CaptureSink,
    policy: TempPolicyFile,
}

fn harness_with(required: bool, configure: impl FnOnce(&mut config::Config)) -> Harness {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&policy_document()).expect("policy serializes"),
    );
    // The history, the drafts and the stored suite default to a database
    // beside the policy file.
    let mut config = policy_admin_config_with_sqlite(Some(&policy), None);
    config.rate_limit_write_burst = 1_000;
    config.policy_tests_required = required;
    configure(&mut config);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build");
    Harness {
        router,
        capture,
        policy,
    }
}

fn harness(required: bool) -> Harness {
    harness_with(required, |_| {})
}

async fn send(harness: &Harness, request: Request<Body>) -> Response {
    harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("request should complete")
}

fn admin() -> Option<auth::Principal> {
    Some(test_principal(&["admin"]))
}

fn request_with(
    method: Method,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> Request<Body> {
    let mut request = policy_admin_request(method, uri, admin(), body, None);
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    request
}

async fn store_suite(harness: &Harness, document: &Value) -> Response {
    let response = send(
        harness,
        request_with(
            Method::PUT,
            POLICY_TESTS_ADMIN_ROUTE,
            Some(document.to_string()),
            &[("if-none-match", "*")],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    response
}

async fn replace_suite(harness: &Harness, document: &Value) -> Response {
    let current = send(
        harness,
        request_with(Method::GET, POLICY_TESTS_ADMIN_ROUTE, None, &[]),
    )
    .await;
    assert_eq!(current.status(), StatusCode::OK);
    let etag = policy_etag_header(&current);
    let response = send(
        harness,
        request_with(
            Method::PUT,
            POLICY_TESTS_ADMIN_ROUTE,
            Some(document.to_string()),
            &[("if-match", &etag)],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response
}

fn active_status(response: &Response) -> Option<String> {
    response
        .headers()
        .get(POLICY_TESTS_ACTIVE_STATUS_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

async fn live_etag(harness: &Harness) -> String {
    current_policy(&harness.router).await.0
}

async fn current_rules(harness: &Harness) -> Value {
    current_policy(&harness.router).await.1["rules"].clone()
}

fn without_rule(rule_id: &str) -> Value {
    let mut policy = policy_document();
    if let Some(rules) = policy["rules"].as_array_mut() {
        rules.retain(|rule| rule["id"] != json!(rule_id));
    }
    policy
}

fn allow_rule(id: &str, path: &str) -> Value {
    json!({ "id": id, "methods": ["GET"], "path": path, "action": "allow" })
}

async fn put_policy(harness: &Harness, policy: &Value) -> Response {
    let etag = live_etag(harness).await;
    send(
        harness,
        request_with(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(policy.to_string()),
            &[("if-match", &etag)],
        ),
    )
    .await
}

async fn create_rule(harness: &Harness, rule: &Value) -> Response {
    let etag = live_etag(harness).await;
    send(
        harness,
        request_with(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            Some(rule.to_string()),
            &[("if-match", &etag)],
        ),
    )
    .await
}

/// Every way the policy routes publish a change.
#[derive(Clone, Copy, Debug)]
enum PublicationPath {
    Replace,
    Rollback,
    RuleCreate,
    RuleUpdate,
    RuleDelete,
    RuleOrder,
    DraftPublish,
}

const PATHS: [PublicationPath; 7] = [
    PublicationPath::Replace,
    PublicationPath::Rollback,
    PublicationPath::RuleCreate,
    PublicationPath::RuleUpdate,
    PublicationPath::RuleDelete,
    PublicationPath::RuleOrder,
    PublicationPath::DraftPublish,
];

/// Prepare `path` so that its change is one the stored suite fails, then
/// make that change. Returns the live ETag just before it and the response.
async fn failing_change(harness: &Harness, path: PublicationPath) -> (String, Response) {
    if let PublicationPath::Rollback = path {
        // Two published versions the stored suite passes, then a suite that
        // the first one fails: the rollback target is a policy the suite now
        // refuses.
        let about = create_rule(harness, &allow_rule("public-about", "/about")).await;
        assert_eq!(about.status(), StatusCode::CREATED);
        let docs = create_rule(harness, &allow_rule("public-docs", "/docs")).await;
        assert_eq!(docs.status(), StatusCode::CREATED);
        let mut stricter = cases();
        stricter.push(http_case(
            "docs-is-public",
            "/docs",
            json!({ "logical": "allow", "matched": { "rule": "public-docs" } }),
        ));
        let replaced = replace_suite(harness, &suite_of(stricter)).await;
        if harness_requires_tests(&replaced) {
            assert_eq!(active_status(&replaced).as_deref(), Some("passed"));
        }
    }
    let etag = live_etag(harness).await;
    let response = match path {
        PublicationPath::Replace => put_policy(harness, &without_rule("public-health")).await,
        PublicationPath::Rollback => {
            send(
                harness,
                request_with(
                    Method::POST,
                    &format!("{POLICY_ROLLBACK_ADMIN_ROUTE_PREFIX}/1"),
                    None,
                    &[("if-match", &etag)],
                ),
            )
            .await
        }
        PublicationPath::RuleCreate => {
            create_rule(harness, &allow_rule("public-status", "/status")).await
        }
        PublicationPath::RuleUpdate => {
            send(
                harness,
                request_with(
                    Method::PATCH,
                    &format!("{POLICY_RULES_ADMIN_ROUTE}/public-health"),
                    Some(json!({ "action": "deny" }).to_string()),
                    &[("if-match", &etag)],
                ),
            )
            .await
        }
        PublicationPath::RuleDelete => {
            send(
                harness,
                request_with(
                    Method::DELETE,
                    &format!("{POLICY_RULES_ADMIN_ROUTE}/public-health"),
                    None,
                    &[("if-match", &etag)],
                ),
            )
            .await
        }
        PublicationPath::RuleOrder => {
            send(
                harness,
                request_with(
                    Method::PUT,
                    POLICY_RULES_ORDER_ADMIN_ROUTE,
                    Some(json!(["deny-health", "public-health"]).to_string()),
                    &[("if-match", &etag)],
                ),
            )
            .await
        }
        PublicationPath::DraftPublish => {
            let (draft_id, draft_etag) =
                create_draft(harness, &etag, without_rule("public-health")).await;
            send(
                harness,
                request_with(
                    Method::POST,
                    &format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}/publish"),
                    None,
                    &[(POLICY_DRAFT_ETAG_HEADER, &draft_etag), ("if-match", &etag)],
                ),
            )
            .await
        }
    };
    (etag, response)
}

/// Whether the suite write just answered says what the gate thinks: only a
/// deployment that requires tests reports it.
fn harness_requires_tests(response: &Response) -> bool {
    active_status(response).is_some()
}

async fn create_draft(harness: &Harness, base: &str, candidate: Value) -> (String, String) {
    let response = send(
        harness,
        request_with(
            Method::POST,
            POLICY_DRAFTS_ADMIN_ROUTE,
            Some(json!({ "policy": candidate }).to_string()),
            &[("if-match", base)],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let etag = policy_etag_header(&response);
    let body = json_body(response).await;
    let draft_id = body["draft_id"]
        .as_str()
        .expect("a created draft names its id")
        .to_owned();
    (draft_id, etag)
}

fn events_of(capture: &audit::sink::tests::CaptureSink, event_type: &str) -> Vec<Value> {
    capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == event_type)
        .map(|event| event.payload)
        .collect()
}

/// The payloads of `event_type` once at least `expected` have arrived. The
/// audit writer is a thread of its own and delivers in order, so every record
/// emitted before the last one waited for has arrived too.
fn delivered(
    capture: &audit::sink::tests::CaptureSink,
    event_type: &str,
    expected: usize,
) -> Vec<Value> {
    assert_eventually(Duration::from_secs(5), || {
        events_of(capture, event_type).len() >= expected
    });
    events_of(capture, event_type)
}

/// The refusal a failed required suite answers with: counts and codes only.
async fn assert_required_tests_refusal(response: Response, status: &str) -> Value {
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let text = body_string(response).await;
    for value in [
        SUBJECT_CANARY,
        "health-is-public",
        "/health",
        "public-health",
    ] {
        assert!(!text.contains(value), "the refusal repeats {value}: {text}");
    }
    let body: Value = serde_json::from_str(&text).expect("body is JSON");
    assert_eq!(
        body["reason"],
        json!("policy_tests_required_failed"),
        "{body}"
    );
    assert_eq!(body["required_tests"]["status"], json!(status), "{body}");
    body
}

#[tokio::test]
async fn every_publication_path_is_refused_when_the_stored_suite_fails() {
    for path in PATHS {
        let harness = harness(true);
        let stored = store_suite(&harness, &suite()).await;
        assert_eq!(active_status(&stored).as_deref(), Some("passed"));
        let rules_before = current_rules(&harness).await;

        let (etag, response) = failing_change(&harness, path).await;
        let body = assert_required_tests_refusal(response, "failed").await;
        let summary = &body["required_tests"]["summary"];
        assert_eq!(summary["failed"], json!(1), "{path:?}: {body}");
        assert_eq!(
            summary["total"],
            json!(summary["passed"].as_u64().unwrap_or_default() + 1),
            "{path:?}: {body}"
        );
        assert_eq!(summary["incomplete"], json!(0), "{path:?}");
        assert_eq!(summary["errors"], json!(0), "{path:?}");
        assert!(
            body["required_tests"]["suite_etag"]
                .as_str()
                .is_some_and(|etag| etag.starts_with("\"sha256:")),
            "{path:?}: {body}"
        );

        // Nothing was written: the live policy is the one the change was
        // made against.
        assert_eq!(live_etag(&harness).await, etag, "{path:?}");
        if !matches!(path, PublicationPath::Rollback) {
            assert_eq!(current_rules(&harness).await, rules_before, "{path:?}");
        }

        let refusals = delivered(
            &harness.capture,
            audit::event::POLICY_PUBLICATION_REFUSED,
            1,
        );
        let [refusal] = refusals.as_slice() else {
            panic!("{path:?}: one refusal is audited, not {refusals:?}");
        };
        assert_eq!(refusal["codes"], json!(["policy_tests_required_failed"]));
        assert_eq!(refusal["policy_etag"], json!(etag));
        assert_eq!(refusal["required_tests"], body["required_tests"]);
        assert!(!refusal.to_string().contains(SUBJECT_CANARY));
        if let PublicationPath::DraftPublish = path {
            let drafts = delivered(
                &harness.capture,
                audit::event::POLICY_DRAFT_PUBLISH_REFUSED,
                1,
            );
            let [draft] = drafts.as_slice() else {
                panic!("one draft refusal is audited, not {drafts:?}");
            };
            assert_eq!(draft["reason"], json!("policy_tests_required_failed"));
        }
    }
}

#[tokio::test]
async fn with_tests_not_required_every_path_publishes_what_the_suite_fails() {
    for path in PATHS {
        let harness = harness(false);
        let stored = store_suite(&harness, &suite()).await;
        // Off, a suite write reports nothing about the active policy.
        assert_eq!(active_status(&stored), None);

        let (etag, response) = failing_change(&harness, path).await;
        assert!(
            response.status().is_success(),
            "{path:?}: {}",
            response.status()
        );
        assert_ne!(live_etag(&harness).await, etag, "{path:?}");
        let changes = delivered(&harness.capture, audit::event::POLICY_CHANGED, 1);
        assert!(events_of(&harness.capture, audit::event::POLICY_PUBLICATION_REFUSED).is_empty());
        assert!(
            changes
                .iter()
                .all(|change| change.get("required_tests").is_none()),
            "{path:?}: {changes:?}"
        );
    }
}

#[tokio::test]
async fn a_publication_with_no_stored_suite_is_refused() {
    let harness = harness(true);
    let etag = live_etag(&harness).await;

    let response = put_policy(&harness, &policy_document()).await;
    let body = assert_required_tests_refusal(response, "suite_missing").await;
    assert_eq!(
        body["required_tests"],
        json!({
            "status": "suite_missing",
            "suite_version": null,
            "suite_etag": null,
            "summary": null
        })
    );
    assert_eq!(live_etag(&harness).await, etag);
    let refusals = delivered(
        &harness.capture,
        audit::event::POLICY_PUBLICATION_REFUSED,
        1,
    );
    let [refusal] = refusals.as_slice() else {
        panic!("one refusal is audited, not {refusals:?}");
    };
    assert_eq!(refusal["action"], json!("policy_replaced"));
    assert_eq!(refusal["required_tests"]["status"], json!("suite_missing"));
}

#[tokio::test]
async fn a_publication_the_stored_suite_passes_commits_and_names_the_suite() {
    let harness = harness(true);
    let stored = store_suite(&harness, &suite()).await;
    let suite_etag = policy_etag_header(&stored);
    let etag = live_etag(&harness).await;

    let created = create_rule(&harness, &allow_rule("public-about", "/about")).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_ne!(live_etag(&harness).await, etag);

    let mut changed = policy_document();
    changed["id"] = json!("required-policy-tests-renamed");
    let replaced = put_policy(&harness, &changed).await;
    assert_eq!(replaced.status(), StatusCode::OK);

    let changes = delivered(&harness.capture, audit::event::POLICY_CHANGED, 2);
    assert_eq!(changes.len(), 2, "{changes:?}");
    for change in &changes {
        assert_eq!(
            change["required_tests"],
            json!({ "suite_version": 1, "suite_etag": suite_etag, "total": 3, "passed": 3 })
        );
        assert!(!change.to_string().contains(SUBJECT_CANARY));
    }
    assert!(events_of(&harness.capture, audit::event::POLICY_PUBLICATION_REFUSED).is_empty());
}

#[tokio::test]
async fn incomplete_results_never_satisfy_the_gate() {
    // An egress destination the static checks admit, with no resolution
    // evidence, is undecided whatever the case expects.
    let harness = harness_with(true, |config| {
        config.egress_allowed_hosts = vec!["api.example.test".to_owned()];
    });
    let mut undecided = cases();
    undecided.push(json!({
        "id": "egress-undecided",
        "kind": "egress",
        "destination": { "scheme": "https", "host": "api.example.test", "port": 443 },
        "expect": { "logical": "allow" }
    }));
    // The suite is stored even though the active policy cannot pass it, and
    // the write says so.
    let stored = store_suite(&harness, &suite_of(undecided)).await;
    assert_eq!(active_status(&stored).as_deref(), Some("incomplete"));
    let changed = delivered(&harness.capture, audit::event::POLICY_TESTS_CHANGED, 1);
    let [changed] = changed.as_slice() else {
        panic!("one suite change is audited, not {changed:?}");
    };
    assert_eq!(changed["active_policy"]["status"], json!("incomplete"));
    assert_eq!(changed["active_policy"]["summary"]["incomplete"], json!(1));

    let etag = live_etag(&harness).await;
    let response = put_policy(&harness, &policy_document()).await;
    let body = assert_required_tests_refusal(response, "incomplete").await;
    assert_eq!(
        body["required_tests"]["summary"],
        json!({ "total": 4, "passed": 3, "failed": 0, "incomplete": 1, "errors": 0 })
    );
    assert_eq!(live_etag(&harness).await, etag);
}

#[tokio::test]
async fn a_suite_the_active_policy_fails_is_stored_and_reported() {
    let harness = harness(true);
    let mut failing = cases();
    failing.push(http_case(
        "about-is-public",
        "/about",
        json!({ "logical": "allow" }),
    ));
    let stored = store_suite(&harness, &suite_of(failing)).await;
    assert_eq!(active_status(&stored).as_deref(), Some("failed"));
    let suite_etag = policy_etag_header(&stored);

    // Stored, so the next policy is held to it: one that still fails is
    // refused, one that passes is committed.
    let read = send(
        &harness,
        request_with(Method::GET, POLICY_TESTS_ADMIN_ROUTE, None, &[]),
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&read), suite_etag);
    let mut same = policy_document();
    same["id"] = json!("still-failing");
    let refused = put_policy(&harness, &same).await;
    assert_required_tests_refusal(refused, "failed").await;
    let created = create_rule(&harness, &allow_rule("public-about", "/about")).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let changed = delivered(&harness.capture, audit::event::POLICY_TESTS_CHANGED, 1);
    let [changed] = changed.as_slice() else {
        panic!("one suite change is audited, not {changed:?}");
    };
    assert_eq!(
        changed["active_policy"],
        json!({
            "status": "failed",
            "suite_version": 1,
            "suite_etag": suite_etag,
            "summary": { "total": 4, "passed": 3, "failed": 1, "incomplete": 0, "errors": 0 }
        })
    );
}

#[tokio::test]
async fn a_stored_suite_that_no_longer_verifies_refuses_publication() {
    let harness = harness(true);
    store_suite(&harness, &suite()).await;
    // Edit the stored row out of band: its ETag no longer names its suite.
    let history = PathBuf::from(format!(
        "{}.history.sqlite",
        harness.policy.path.to_string_lossy()
    ));
    let connection = Connection::open(&history).expect("history database opens");
    let edited = connection
        .execute(
            "UPDATE policy_test_suite_versions SET suite_json = replace(suite_json, '/status', '/elsewhere')",
            [],
        )
        .expect("the stored suite row updates");
    assert_eq!(edited, 1);
    let etag = live_etag(&harness).await;

    let response = put_policy(&harness, &policy_document()).await;
    let body = assert_required_tests_refusal(response, "suite_invalid").await;
    assert_eq!(body["required_tests"]["suite_version"], json!(null));
    assert_eq!(live_etag(&harness).await, etag);
}

/// The verdict a run yields, judged without an application.
mod verdict {
    use super::*;
    use crate::policy_testing::runner::Summary;

    fn suite() -> RequiredSuite {
        RequiredSuite {
            version: 4,
            etag: "\"sha256:verdict\"".to_owned(),
        }
    }

    fn summary(total: usize, passed: usize, failed: usize, incomplete: usize) -> Summary {
        Summary {
            total,
            passed,
            failed,
            incomplete,
            errors: total - passed - failed - incomplete,
        }
    }

    fn status(end: RequiredRunEnd, case_count: usize) -> &'static str {
        required_tests_verdict(suite(), end, case_count).status()
    }

    #[test]
    fn only_every_case_decided_and_passed_is_a_pass() {
        let completed = |summary| RequiredRunEnd::Completed(summary);
        assert_eq!(status(completed(summary(3, 3, 0, 0)), 3), "passed");
        assert_eq!(status(completed(summary(3, 2, 1, 0)), 3), "failed");
        assert_eq!(status(completed(summary(3, 2, 0, 1)), 3), "incomplete");
        assert_eq!(status(completed(summary(3, 2, 0, 0)), 3), "error");
        // An evaluator error outranks every other outcome, and an undecided
        // case outranks a failed one.
        assert_eq!(status(completed(summary(3, 0, 1, 1)), 3), "error");
        assert_eq!(status(completed(summary(3, 1, 1, 1)), 3), "incomplete");
    }

    #[test]
    fn a_run_that_decided_fewer_cases_than_the_suite_holds_is_incomplete() {
        let completed = |summary| RequiredRunEnd::Completed(summary);
        assert_eq!(status(completed(summary(2, 2, 0, 0)), 3), "incomplete");
        assert_eq!(status(completed(summary(0, 0, 0, 0)), 0), "failed");
        assert_eq!(
            status(completed(Summary::default()), 3),
            "failed",
            "an empty run is never a pass"
        );
    }

    #[test]
    fn a_run_without_a_result_is_never_a_pass() {
        let deadline = required_tests_verdict(suite(), RequiredRunEnd::DeadlineExceeded, 3);
        assert_eq!(deadline.status(), "deadline_exceeded");
        assert_eq!(
            deadline.to_json(),
            json!({
                "status": "deadline_exceeded",
                "suite_version": 4,
                "suite_etag": "\"sha256:verdict\"",
                "summary": null
            })
        );
        assert_eq!(
            status(RequiredRunEnd::EvaluationFailed, 3),
            "evaluation_failed"
        );
    }
}
