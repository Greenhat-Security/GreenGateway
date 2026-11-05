//! `GET`/`PUT /v1{ADMIN_PREFIX}/policy/tests` (issue #243) through the
//! application in standalone mode, and the stored suite named by a test run
//! and by an evidence package. The store contract is covered in
//! `storage::policy_tests::tests`, the cluster commit in
//! `cluster_policy_tests`.
use super::*;

const SUITE: &str = POLICY_TESTS_ADMIN_ROUTE;
/// A fixture value no response header, audit record or report may repeat.
const SUBJECT_CANARY: &str = "stored-suite-subject-canary-5be2";

fn roles() -> Value {
    json!({
        "admin": {
            "permissions": [
                ADMIN_POLICY_READ_PERMISSION,
                ADMIN_POLICY_WRITE_PERMISSION,
                ADMIN_POLICY_SIMULATE_PERMISSION,
                ADMIN_POLICY_EVIDENCE_READ_PERMISSION
            ]
        },
        "tester": {
            "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_SIMULATE_PERMISSION]
        },
        "writer": { "permissions": [ADMIN_POLICY_WRITE_PERMISSION] },
        "evidence-reader": {
            "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_EVIDENCE_READ_PERMISSION]
        },
        "policy-reader": { "permissions": [ADMIN_POLICY_READ_PERMISSION] },
        "simulator-only": { "permissions": [ADMIN_POLICY_SIMULATE_PERMISSION] },
        "orders-reader": { "permissions": ["orders:read"] }
    })
}

fn policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "stored-policy-tests",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": roles(),
        "rules": [
            { "id": "public-health", "methods": ["GET"], "path": "/health", "action": "allow" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ]
    })
}

fn suite(description: &str) -> Value {
    json!({
        "schema_version": "policy-tests.v1",
        "description": description,
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
            },
            {
                "id": "orders-rate",
                "kind": "rate",
                "request": { "method": "GET", "path": "/orders/7" },
                "principal": {
                    "subject": SUBJECT_CANARY,
                    "roles": ["orders-reader"],
                    "auth_method": "bearer_token"
                },
                "expect": { "rate_override": null }
            }
        ]
    })
}

struct Harness {
    router: Router,
    audit: audit::AuditLog,
    capture: audit::sink::tests::CaptureSink,
    _policy: TempPolicyFile,
}

fn harness_with(configure: impl FnOnce(&mut config::Config)) -> Harness {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&policy_document()).expect("policy serializes"),
    );
    // The history, the drafts and the stored suite default to a database
    // beside the policy file.
    let mut config = policy_admin_config_with_sqlite(Some(&policy), None);
    // These tests send more writes than the global write lane's default
    // burst admits; that lane is not what they test.
    config.rate_limit_write_burst = 1_000;
    configure(&mut config);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log.clone(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    Harness {
        router,
        audit: audit_log,
        capture,
        _policy: policy,
    }
}

fn harness() -> Harness {
    harness_with(|_| {})
}

fn principal(roles: &[&str]) -> Option<auth::Principal> {
    Some(test_principal(roles))
}

async fn send(harness: &Harness, request: Request<Body>) -> Response {
    harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("request should complete")
}

async fn get_suite(harness: &Harness, roles: &[&str]) -> Response {
    send(
        harness,
        policy_admin_request(Method::GET, SUITE, principal(roles), None, None),
    )
    .await
}

/// A `PUT` with the given precondition headers.
fn put_request(roles: &[&str], body: String, headers: &[(HeaderName, &str)]) -> Request<Body> {
    let mut request = policy_admin_request(Method::PUT, SUITE, principal(roles), Some(body), None);
    for (name, value) in headers {
        request.headers_mut().append(
            name.clone(),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    request
}

async fn put_suite(
    harness: &Harness,
    document: &Value,
    headers: &[(HeaderName, &str)],
) -> Response {
    send(
        harness,
        put_request(&["admin"], document.to_string(), headers),
    )
    .await
}

async fn create_suite(harness: &Harness, document: &Value) -> String {
    let response = put_suite(harness, document, &[(header::IF_NONE_MATCH, "*")]).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    etag_of(&response)
}

fn etag_of(response: &Response) -> String {
    response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("ETag header")
        .to_owned()
}

fn version_of(response: &Response) -> i64 {
    response
        .headers()
        .get(POLICY_TESTS_VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .expect("version header")
}

async fn reason_of(response: Response) -> Value {
    json_body(response).await["reason"].clone()
}

fn events(harness: &Harness, event_type: &str) -> Vec<audit::AuditEvent> {
    harness
        .capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == event_type)
        .collect()
}

/// Close the log and wait, bounded, until the writer has delivered every
/// queued record. Only for the end of a test.
async fn drain_audit(harness: &Harness) {
    harness
        .audit
        .close_and_drain(Duration::from_secs(5))
        .await
        .expect("the audit log drains");
}

#[test]
fn the_suite_route_follows_the_admin_prefix() {
    let routes = AdminRoutes::from_prefix(config::DEFAULT_ADMIN_PREFIX);
    assert_eq!(routes.policy_tests_route, POLICY_TESTS_ADMIN_ROUTE);
    let custom = AdminRoutes::from_prefix("/ops");
    assert_eq!(custom.policy_tests_route, "/v1/ops/policy/tests");
}

/// A read needs `admin:policy:read` and `admin:policy:simulate` together, a
/// write needs `admin:policy:write`, and both are decided before anything
/// else: a refused write is `403` whatever its precondition, and a refused
/// read learns nothing about whether a suite is stored.
#[tokio::test]
async fn reads_need_read_and_simulate_and_writes_need_write() {
    let harness = harness();
    let unauthenticated = send(
        &harness,
        policy_admin_request(Method::GET, SUITE, None, None, None),
    )
    .await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    for roles in [
        &["policy-reader"][..],
        &["simulator-only"][..],
        &["writer"][..],
    ] {
        assert_eq!(
            get_suite(&harness, roles).await.status(),
            StatusCode::FORBIDDEN,
            "{roles:?}"
        );
    }
    assert_eq!(
        reason_of(get_suite(&harness, &["tester"]).await).await,
        json!("policy_tests_not_found")
    );

    let body = suite("permissions").to_string();
    let unauthenticated = send(
        &harness,
        policy_admin_request(Method::PUT, SUITE, None, Some(body.clone()), None),
    )
    .await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    for roles in [&["tester"][..], &["policy-reader"][..]] {
        // No precondition at all: still `403`, not `428`.
        let response = send(&harness, put_request(roles, body.clone(), &[])).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
    }
    let created = send(
        &harness,
        put_request(&["writer"], body, &[(header::IF_NONE_MATCH, "*")]),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let etag = etag_of(&created);

    for roles in [
        &["policy-reader"][..],
        &["simulator-only"][..],
        &["writer"][..],
    ] {
        assert_eq!(
            get_suite(&harness, roles).await.status(),
            StatusCode::FORBIDDEN,
            "{roles:?}"
        );
    }
    let read = get_suite(&harness, &["tester"]).await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(etag_of(&read), etag);
}

/// `PUT` requires exactly one precondition; `If-None-Match: *` stores the
/// first suite and `If-Match` replaces the stored one, and a precondition
/// that no longer holds is `412` and writes nothing.
#[tokio::test]
async fn a_write_needs_one_precondition_and_a_stale_one_writes_nothing() {
    let harness = harness();
    let first = suite("first");
    let response = put_suite(&harness, &first, &[]).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(
        reason_of(response).await,
        json!("policy_tests_precondition_required")
    );
    let strong = format!("\"sha256:{}\"", "0".repeat(64));
    let weak = format!("W/{strong}");
    let list = format!("{strong}, {strong}");
    for headers in [
        vec![
            (header::IF_MATCH, strong.as_str()),
            (header::IF_NONE_MATCH, "*"),
        ],
        vec![(header::IF_MATCH, weak.as_str())],
        vec![(header::IF_MATCH, list.as_str())],
        vec![(header::IF_MATCH, "*")],
        vec![(header::IF_NONE_MATCH, strong.as_str())],
        vec![(header::IF_NONE_MATCH, "*"), (header::IF_NONE_MATCH, "*")],
    ] {
        let response = put_suite(&harness, &first, &headers).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{headers:?}");
        assert_eq!(
            reason_of(response).await,
            json!("policy_tests_precondition_invalid")
        );
    }
    // Nothing is stored yet, so no ETag can match.
    let response = put_suite(&harness, &first, &[(header::IF_MATCH, strong.as_str())]).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        reason_of(response).await,
        json!("policy_tests_etag_mismatch")
    );

    let created = put_suite(&harness, &first, &[(header::IF_NONE_MATCH, "*")]).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(
        created.headers()[header::CACHE_CONTROL],
        "private, no-store"
    );
    let first_etag = etag_of(&created);
    let first_version = version_of(&created);
    let body = json_body(created).await;
    assert_eq!(body, first);
    assert_eq!(
        first_etag,
        format!(
            "\"{}\"",
            policy_testing::suite::parse_suite(&first)
                .expect("parses")
                .digest
        ),
        "the ETag is the suite digest"
    );

    let response = put_suite(&harness, &suite("second"), &[(header::IF_NONE_MATCH, "*")]).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(reason_of(response).await, json!("policy_tests_exist"));

    let replaced = put_suite(
        &harness,
        &suite("second"),
        &[(header::IF_MATCH, first_etag.as_str())],
    )
    .await;
    assert_eq!(replaced.status(), StatusCode::OK);
    let second_etag = etag_of(&replaced);
    assert_ne!(second_etag, first_etag);
    assert!(version_of(&replaced) > first_version);

    // The first ETag is stale: refused, and the stored suite is the second.
    let stale = put_suite(
        &harness,
        &suite("third"),
        &[(header::IF_MATCH, first_etag.as_str())],
    )
    .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(reason_of(stale).await, json!("policy_tests_etag_mismatch"));
    let read = get_suite(&harness, &["tester"]).await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(etag_of(&read), second_etag);
    assert_content_type_starts_with(read.headers(), "application/json");
    let canonical = body_string(read).await;
    assert_eq!(
        canonical.as_bytes(),
        canonical_json::canonical_json_bytes(&suite("second"))
            .expect("canonical")
            .as_slice(),
        "the representation is the suite's RFC 8785 bytes"
    );
}

/// Writers presenting one ETag at once: exactly one stores its suite; every
/// other is `412` and writes nothing.
#[tokio::test]
async fn concurrent_writes_under_one_etag_produce_exactly_one_winner() {
    let harness = harness();
    let base = create_suite(&harness, &suite("base")).await;
    let writers: Vec<_> = (0..8)
        .map(|index| {
            let router = harness.router.clone();
            let request = put_request(
                &["admin"],
                suite(&format!("racer-{index}")).to_string(),
                &[(header::IF_MATCH, base.as_str())],
            );
            tokio::spawn(async move { router.oneshot(request).await })
        })
        .collect();
    let mut won = Vec::new();
    let mut lost = 0;
    for writer in writers {
        let response = writer
            .await
            .expect("the writer task completes")
            .expect("the request completes");
        match response.status() {
            StatusCode::OK => won.push(etag_of(&response)),
            StatusCode::PRECONDITION_FAILED => lost += 1,
            other => panic!("a racing write answered {other}"),
        }
    }
    assert_eq!((won.len(), lost), (1, 7));
    let read = get_suite(&harness, &["tester"]).await;
    assert_eq!(etag_of(&read), won[0]);
}

/// The body is bounded, read once with unique member names, and parsed by
/// the suite parser a run uses; whatever it refuses is never stored.
#[tokio::test]
async fn the_body_is_bounded_and_parsed_strictly() {
    let harness = harness();
    let none = [(header::IF_NONE_MATCH, "*")];
    let repeated = r#"{"schema_version":"policy-tests.v1","cases":[],"cases":[]}"#.to_owned();
    let response = send(&harness, put_request(&["admin"], repeated, &none)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        reason_of(response).await,
        json!("policy_tests_request_invalid")
    );
    let response = send(
        &harness,
        put_request(&["admin"], "not json".to_owned(), &none),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let mut empty = suite("empty");
    empty["cases"] = json!([]);
    let mut too_many = suite("too many");
    too_many["cases"] = Value::Array(
        (0..=policy_testing::suite::MAX_CASES)
            .map(|index| {
                json!({
                    "id": format!("case-{index}"),
                    "kind": "http",
                    "request": { "method": "GET", "path": "/health" },
                    "principal": "anonymous",
                    "expect": { "logical": "allow" }
                })
            })
            .collect(),
    );
    let mut credential = suite("credential");
    credential["cases"][0]["token"] = json!("abc");
    let mut nul = suite("nul");
    nul["description"] = json!("a\u{0}b");
    for (document, code) in [
        (&empty, "empty_suite"),
        (&too_many, "too_many_cases"),
        (&credential, "forbidden_field"),
        (&nul, "invalid_value"),
    ] {
        let response = put_suite(&harness, document, &none).await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{code}"
        );
        let body = json_body(response).await;
        assert_eq!(body["reason"], json!("policy_tests_invalid"));
        assert!(
            body["diagnostics"]
                .as_array()
                .expect("diagnostics")
                .iter()
                .any(|diagnostic| diagnostic["code"] == json!(code)),
            "{body}"
        );
        assert!(!body.to_string().contains("a\u{0}b"));
    }
    let oversized = format!(
        "{{\"schema_version\":\"policy-tests.v1\",\"description\":\"{}\",\"cases\":[]}}",
        "x".repeat(MAX_POLICY_TESTS_BODY_BYTES)
    );
    let response = send(&harness, put_request(&["admin"], oversized, &none)).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    assert_eq!(
        reason_of(get_suite(&harness, &["tester"]).await).await,
        json!("policy_tests_not_found")
    );
}

/// Each write emits one `policy.tests_changed` with the version, the new and
/// replaced digests and case counts, and nothing a case says; refused writes
/// emit none, and storing a suite is never a policy change.
#[tokio::test]
async fn writes_are_audited_by_digest_and_counts_only() {
    let harness = harness();
    let first_etag = create_suite(&harness, &suite("first")).await;
    let replaced = put_suite(
        &harness,
        &suite("second"),
        &[(header::IF_MATCH, first_etag.as_str())],
    )
    .await;
    assert_eq!(replaced.status(), StatusCode::OK);
    let second_etag = etag_of(&replaced);
    let stale = put_suite(
        &harness,
        &suite("third"),
        &[(header::IF_MATCH, first_etag.as_str())],
    )
    .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    drain_audit(&harness).await;

    let digest = |etag: &str| etag.trim_matches('"').to_owned();
    let changes = events(&harness, audit::event::POLICY_TESTS_CHANGED);
    assert_eq!(changes.len(), 2);
    let kinds = json!({ "http": 2, "tool": 0, "tool_http": 0, "rate": 1, "egress": 0 });
    assert_eq!(changes[0].payload["action"], json!("created"));
    assert_eq!(
        changes[0].payload["suite_digest"],
        json!(digest(&first_etag))
    );
    assert_eq!(changes[0].payload["previous_suite_digest"], Value::Null);
    assert_eq!(changes[0].payload["case_count"], json!(3));
    assert_eq!(changes[0].payload["case_kinds"], kinds);
    assert_eq!(changes[1].payload["action"], json!("replaced"));
    assert_eq!(
        changes[1].payload["suite_digest"],
        json!(digest(&second_etag))
    );
    assert_eq!(
        changes[1].payload["previous_suite_digest"],
        json!(digest(&first_etag))
    );
    assert!(changes[1].payload["version"].as_i64() > changes[0].payload["version"].as_i64());
    assert!(changes[0].payload.get("security_revision").is_none());
    for change in &changes {
        let recorded = change.payload.to_string();
        for absent in [
            SUBJECT_CANARY,
            "health-is-public",
            "/orders/7",
            "first",
            "second",
        ] {
            assert!(
                !recorded.contains(absent),
                "the audit record repeats {absent}"
            );
        }
        assert_eq!(
            change.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }
    assert!(events(&harness, audit::event::POLICY_CHANGED).is_empty());
}

/// Standalone mode records no evidence of a suite write beyond the version
/// row, so required authority evidence refuses it before anything is read.
#[tokio::test]
async fn required_authority_evidence_refuses_a_standalone_write() {
    let harness = harness_with(|config| {
        config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
    });
    let response = put_suite(&harness, &suite("refused"), &[(header::IF_NONE_MATCH, "*")]).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("authority_evidence_unsupported"));
    assert_eq!(body["operation"], json!("policy_tests.publish"));
    // Reads and runs are not authority changes.
    assert_eq!(
        reason_of(get_suite(&harness, &["tester"]).await).await,
        json!("policy_tests_not_found")
    );
    drain_audit(&harness).await;
    assert!(events(&harness, audit::event::POLICY_TESTS_CHANGED).is_empty());
    let refusals = events(&harness, audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED);
    assert_eq!(refusals.len(), 1);
    assert_eq!(
        refusals[0].payload["operation"],
        json!("policy_tests.publish")
    );
}

async fn run(harness: &Harness, roles: &[&str], body: Value) -> Response {
    send(
        harness,
        policy_admin_request(
            Method::POST,
            POLICY_TEST_RUNS_ADMIN_ROUTE,
            principal(roles),
            Some(body.to_string()),
            None,
        ),
    )
    .await
}

/// A run can decide the stored suite instead of one it carries, optionally
/// pinned to the ETag the caller reviewed; its report and audit record say
/// which stored version ran.
#[tokio::test]
async fn a_run_decides_the_stored_suite_pinned_by_its_etag() {
    let harness = harness();
    let stored = json!({ "suite": { "source": "stored" } });
    let response = run(&harness, &["tester"], stored.clone()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(reason_of(response).await, json!("policy_tests_not_found"));

    let created = put_suite(&harness, &suite("stored"), &[(header::IF_NONE_MATCH, "*")]).await;
    let etag = etag_of(&created);
    let version = version_of(&created);
    for body in [
        stored.clone(),
        json!({ "suite": { "source": "stored", "etag": etag }, "format": "json" }),
    ] {
        let response = run(&harness, &["tester"], body).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[POLICY_TESTS_STATUS_HEADER], "passed");
        let report = json_body(response).await;
        assert_eq!(report["summary"]["passed"], json!(3));
        assert_eq!(report["suite"]["digest"], json!(etag.trim_matches('"')));
        assert_eq!(
            report["suite"]["stored"],
            json!({ "version": version, "etag": etag })
        );
        assert!(!report.to_string().contains(SUBJECT_CANARY));
    }
    // An inline run's report has no stored binding.
    let inline =
        json_body(run(&harness, &["tester"], json!({ "suite": suite("stored") })).await).await;
    assert!(inline["suite"].get("stored").is_none());
    assert_eq!(inline["suite"]["digest"], json!(etag.trim_matches('"')));

    let stale = format!("\"sha256:{}\"", "0".repeat(64));
    let response = run(
        &harness,
        &["tester"],
        json!({ "suite": { "source": "stored", "etag": stale } }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        reason_of(response).await,
        json!("policy_tests_etag_mismatch")
    );
    for reference in [
        json!({ "source": "inline" }),
        json!({ "source": "stored", "version": 1 }),
        json!({ "source": "stored", "etag": "unquoted" }),
        json!({ "source": "stored", "etag": 7 }),
    ] {
        let response = run(&harness, &["tester"], json!({ "suite": reference })).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{reference}");
        assert_eq!(
            reason_of(response).await,
            json!("policy_tests_request_invalid")
        );
    }
    // Running the stored suite needs exactly what a run needs.
    for roles in [&["policy-reader"][..], &["writer"][..]] {
        assert_eq!(
            run(&harness, roles, stored.clone()).await.status(),
            StatusCode::FORBIDDEN,
            "{roles:?}"
        );
    }

    drain_audit(&harness).await;
    let runs = events(&harness, audit::event::POLICY_TESTS_RUN);
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].payload["suite_source"], json!("stored"));
    assert_eq!(runs[0].payload["suite_version"], json!(version));
    assert_eq!(runs[2].payload["suite_source"], json!("inline"));
    assert!(runs[2].payload.get("suite_version").is_none());
}

/// An evidence package can bind the stored suite by the ETag its reader
/// reviewed: the report's test results name the stored version, a stale pin
/// is `409` and produces no package.
#[tokio::test]
async fn an_evidence_package_binds_the_stored_suite_by_its_etag() {
    let harness = harness();
    // History version 1: the live policy, replaced by itself.
    let (live, _) = current_policy(&harness.router).await;
    let replaced = send(
        &harness,
        policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            principal(&["admin"]),
            Some(policy_document().to_string()),
            Some(&live),
        ),
    )
    .await;
    assert_eq!(replaced.status(), StatusCode::OK);
    let etag = create_suite(&harness, &suite("evidence")).await;
    let request = |suite_etag: &str| {
        json!({
            "schema_version": "policy-evidence-request.v1",
            "publication": { "version": 1 },
            "suite": { "source": "stored", "etag": suite_etag }
        })
    };
    let evidence = |body: Value| {
        policy_admin_request(
            Method::POST,
            POLICY_EVIDENCE_ADMIN_ROUTE,
            principal(&["admin"]),
            Some(body.to_string()),
            None,
        )
    };
    let response = send(&harness, evidence(request(&etag))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let package: Value = serde_json::from_str(&body_string(response).await).expect("package");
    let results = &package["report"]["tests"]["results"];
    assert_eq!(package["report"]["tests"]["included"], json!(true));
    assert_eq!(results["status"], json!("passed"));
    assert_eq!(results["suite"]["stored"]["etag"], json!(etag));
    assert_eq!(results["policy"]["source"], json!("publication"));

    let stale = format!("\"sha256:{}\"", "0".repeat(64));
    let response = send(&harness, evidence(request(&stale))).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        reason_of(response).await,
        json!("policy_evidence_suite_mismatch")
    );
    // The reference is a suite section, so it needs `admin:policy:simulate`.
    let response = send(
        &harness,
        policy_admin_request(
            Method::POST,
            POLICY_EVIDENCE_ADMIN_ROUTE,
            principal(&["evidence-reader"]),
            Some(request(&etag).to_string()),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
