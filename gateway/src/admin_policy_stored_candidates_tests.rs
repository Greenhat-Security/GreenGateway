//! Server-side drafts and policy history versions as the candidate of a
//! simulation, a policy test run, an analysis and a replay job (issue #243),
//! through the application in standalone mode: the file authority, and the
//! SQLite draft store and history beside it. The request parser is covered in
//! `policy_simulation::tests`, the renderings in `policy_testing::tests` and
//! `policy_analysis::tests`, and a cluster read in `cluster_policy_tests`.
use super::*;

/// A path only the stored candidates hold. No audit record of a run may
/// repeat it: records carry identifiers and digests, never policy content.
const CANDIDATE_CANARY: &str = "/stored-candidate-canary-5e0b";
/// The drafts store identifier format, naming no draft that exists.
const ABSENT_DRAFT_ID: &str = "pd_00000000000000000000000000000000";

fn stored_policy_document(id: &str) -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": id,
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION,
                    ADMIN_POLICY_SIMULATE_PERMISSION,
                    ADMIN_POLICY_ANALYZE_PERMISSION,
                    ADMIN_AUDIT_READ_PERMISSION
                ]
            },
            "evaluator": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_SIMULATE_PERMISSION,
                    ADMIN_POLICY_ANALYZE_PERMISSION,
                    ADMIN_AUDIT_READ_PERMISSION
                ]
            },
            "unreading-evaluator": {
                "permissions": [
                    ADMIN_POLICY_SIMULATE_PERMISSION,
                    ADMIN_POLICY_ANALYZE_PERMISSION,
                    ADMIN_AUDIT_READ_PERMISSION
                ]
            },
            "caller": { "permissions": ["orders:read"] }
        },
        "rules": [
            { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ]
    })
}

/// The live policy with one rule only the candidate has, ahead of the rest.
fn candidate_document(id: &str) -> Value {
    let mut candidate = stored_policy_document(id);
    candidate["rules"] = json!([
        { "id": "canary", "methods": ["GET"], "path": format!("{CANDIDATE_CANARY}/**"), "action": "deny" },
        { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" }
    ]);
    candidate
}

fn cases() -> Value {
    json!([
        {
            "id": "canary-page",
            "kind": "http",
            "request": { "method": "GET", "path": format!("{CANDIDATE_CANARY}/a") },
            "principal": "anonymous"
        },
        {
            "id": "public-page",
            "kind": "http",
            "request": { "method": "GET", "path": "/public/a" },
            "principal": "anonymous"
        }
    ])
}

fn suite() -> Value {
    json!({
        "schema_version": "policy-tests.v1",
        "cases": [{
            "id": "canary-is-denied",
            "kind": "http",
            "request": { "method": "GET", "path": format!("{CANDIDATE_CANARY}/a") },
            "principal": "anonymous",
            "expect": { "logical": "deny", "matched": { "rule": "canary" } }
        }]
    })
}

fn draft_source(draft_id: &str, draft_etag: &str) -> Value {
    json!({ "source": "draft", "draft_id": draft_id, "draft_etag": draft_etag })
}

fn revision_source(version: i64) -> Value {
    json!({ "source": "revision", "version": version })
}

struct Harness {
    router: Router,
    capture: audit::sink::tests::CaptureSink,
    policy: TempPolicyFile,
    _audit_db: TempDb,
}

fn harness() -> Harness {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&stored_policy_document("live")).expect("policy serializes"),
    );
    // A replay job reads a SQLite audit log; the application's own records
    // go to the capture.
    let audit_db = TempDb::new("stored-candidates");
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
    // These tests write drafts and policies faster than the global write
    // lane's default burst refills; that lane is not what they test.
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
        panic!("the stored candidate test app should be unified");
    };
    Harness {
        router,
        capture,
        policy,
        _audit_db: audit_db,
    }
}

fn admin() -> Option<auth::Principal> {
    Some(test_principal(&["admin"]))
}

/// The admin's identity with evaluation permissions and no write.
fn evaluator() -> Option<auth::Principal> {
    Some(test_principal(&["evaluator"]))
}

fn other_owner() -> Option<auth::Principal> {
    let mut principal = test_principal(&["admin"]);
    principal.user_id = "another-owner".to_owned();
    Some(principal)
}

async fn send(harness: &Harness, request: Request<Body>) -> Response {
    harness
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("request should complete")
}

async fn post(
    harness: &Harness,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Value,
    if_match: Option<&str>,
) -> Response {
    send(
        harness,
        policy_admin_request(
            Method::POST,
            uri,
            principal,
            Some(body.to_string()),
            if_match,
        ),
    )
    .await
}

async fn refusal(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    (status, json_body(response).await)
}

fn simulation(base_etag: &str, candidate: Value) -> Value {
    json!({
        "schema_version": "policy-simulation.v1",
        "base_etag": base_etag,
        "candidate": candidate,
        "trace": "matched",
        "cases": cases()
    })
}

fn analysis(base_etag: &str, candidate: Value) -> Value {
    json!({
        "schema_version": "policy-analysis.v1",
        "base_etag": base_etag,
        "candidate": candidate
    })
}

fn replay(base_etag: &str, candidate: Value) -> Value {
    let from = (OffsetDateTime::now_utc() - time::Duration::hours(1))
        .format(&Rfc3339)
        .expect("a window bound formats");
    json!({
        "schema_version": "policy-replay.v1",
        "base_etag": base_etag,
        "candidate": candidate,
        "window": { "from": from }
    })
}

fn test_run(candidate: Value) -> Value {
    json!({ "suite": suite(), "candidate": candidate })
}

/// Every evaluation endpoint's request for `candidate` on `base_etag`, with
/// the route it goes to.
fn evaluations(base_etag: &str, candidate: &Value) -> [(&'static str, Value); 4] {
    [
        (
            POLICY_SIMULATIONS_ADMIN_ROUTE,
            simulation(base_etag, candidate.clone()),
        ),
        (POLICY_TEST_RUNS_ADMIN_ROUTE, test_run(candidate.clone())),
        (
            POLICY_ANALYSES_ADMIN_ROUTE,
            analysis(base_etag, candidate.clone()),
        ),
        (
            POLICY_REPLAYS_ADMIN_ROUTE,
            replay(base_etag, candidate.clone()),
        ),
    ]
}

/// A draft of `candidate` owned by the admin, pinned to `base_etag`: its id
/// and strong ETag.
async fn create_draft(harness: &Harness, base_etag: &str, candidate: Value) -> (String, String) {
    let response = post(
        harness,
        POLICY_DRAFTS_ADMIN_ROUTE,
        admin(),
        json!({ "policy": candidate }),
        Some(base_etag),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let etag = policy_etag_header(&response);
    let body = json_body(response).await;
    let draft_id = body["draft_id"].as_str().expect("a draft id").to_owned();
    (draft_id, etag)
}

/// The admin's draft as the drafts API serves it: its ETag and view.
async fn read_draft(harness: &Harness, draft_id: &str) -> (String, Value) {
    let response = send(
        harness,
        policy_admin_request(
            Method::GET,
            &format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}"),
            admin(),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = policy_etag_header(&response);
    (etag, json_body(response).await)
}

/// Replace the live policy with `document`, returning the new ETag.
async fn replace_policy(harness: &Harness, current_etag: &str, document: &Value) -> String {
    let response = send(
        harness,
        policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            admin(),
            Some(document.to_string()),
            Some(current_etag),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    policy_etag_header(&response)
}

/// The history version holding the policy with `id`.
async fn history_version_of(harness: &Harness, id: &str) -> i64 {
    policy_history_entries(&harness.router, None)
        .await
        .iter()
        .find(|entry| entry["policy"]["id"] == json!(id))
        .and_then(|entry| entry["version"].as_i64())
        .expect("the history holds the policy")
}

/// The records of `event_type` delivered so far, waiting up to a bound for
/// `count` of them: the audit writer delivers on its own thread.
fn records(harness: &Harness, event_type: &str, count: usize) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let records: Vec<Value> = harness
            .capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .map(|event| event.payload)
            .collect();
        if records.len() >= count || Instant::now() >= deadline {
            return records;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Poll the admin's replay job until it is no longer queued or running.
async fn finished_job(harness: &Harness, job_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let response = send(
            harness,
            policy_admin_request(
                Method::GET,
                &format!("{POLICY_REPLAYS_ADMIN_ROUTE}/{job_id}"),
                evaluator(),
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

/// A saved draft is a candidate every evaluation reads as it was saved: the
/// same candidate ETag and decisions as the inline document, reported with
/// the draft's id and revision and audited without its content. Reading it
/// writes nothing: the draft keeps its ETag, revision and expiry, and no
/// `policy.draft_changed` follows its creation.
#[tokio::test]
async fn a_draft_candidate_is_judged_as_saved_by_every_evaluation_and_never_written() {
    let harness = harness();
    let (live_etag, _) = current_policy(&harness.router).await;
    let candidate = candidate_document("drafted");
    let (draft_id, draft_etag) = create_draft(&harness, &live_etag, candidate.clone()).await;
    let (_, saved) = read_draft(&harness, &draft_id).await;
    let candidate_etag = saved["candidate_etag"].as_str().expect("a candidate ETag");
    let source = draft_source(&draft_id, &draft_etag);
    let identity = json!({
        "source": "draft",
        "etag": candidate_etag,
        "draft_id": draft_id,
        "draft_revision": 1
    });

    let simulated = post(
        &harness,
        POLICY_SIMULATIONS_ADMIN_ROUTE,
        evaluator(),
        simulation(&live_etag, source.clone()),
        None,
    )
    .await;
    assert_eq!(simulated.status(), StatusCode::OK);
    let simulated = json_body(simulated).await;
    assert_eq!(simulated["candidate"], identity);
    let inline = post(
        &harness,
        POLICY_SIMULATIONS_ADMIN_ROUTE,
        evaluator(),
        simulation(
            &live_etag,
            json!({ "source": "inline", "policy": candidate }),
        ),
        None,
    )
    .await;
    assert_eq!(inline.status(), StatusCode::OK);
    let inline = json_body(inline).await;
    assert_eq!(inline["candidate"]["etag"], json!(candidate_etag));
    assert_eq!(simulated["summary"], inline["summary"]);
    assert_eq!(simulated["cases"], inline["cases"]);
    assert_eq!(
        simulated["cases"][0]["results"][0]["candidate"]["effective_action"],
        json!("would_block")
    );

    let tested = post(
        &harness,
        POLICY_TEST_RUNS_ADMIN_ROUTE,
        evaluator(),
        test_run(source.clone()),
        None,
    )
    .await;
    assert_eq!(tested.status(), StatusCode::OK);
    let tested = json_body(tested).await;
    assert_eq!(tested["status"], json!("passed"));
    assert_eq!(tested["policy"], identity);

    let analyzed = post(
        &harness,
        POLICY_ANALYSES_ADMIN_ROUTE,
        evaluator(),
        analysis(&live_etag, source.clone()),
        None,
    )
    .await;
    assert_eq!(analyzed.status(), StatusCode::OK);
    assert_eq!(json_body(analyzed).await["analyzed"], identity);

    let started = post(
        &harness,
        POLICY_REPLAYS_ADMIN_ROUTE,
        evaluator(),
        replay(&live_etag, source.clone()),
        None,
    )
    .await;
    assert_eq!(started.status(), StatusCode::ACCEPTED);
    let started = json_body(started).await;
    assert_eq!(started["candidate"], identity);
    let job = finished_job(&harness, started["job_id"].as_str().expect("a job id")).await;
    // An empty window is a finished job with a result that says so.
    assert_eq!(job["state"], json!("completed_incomplete"), "{job}");
    assert_eq!(job["result"]["limitations"], json!(["no_data"]), "{job}");
    assert_eq!(job["candidate"], identity);

    // Audited by identity, never by content.
    for (event_type, prefix) in [
        (audit::event::POLICY_SIMULATION_RUN, "candidate_"),
        (audit::event::POLICY_TESTS_RUN, "policy_"),
        (audit::event::POLICY_ANALYSIS_RUN, "candidate_"),
        (audit::event::POLICY_REPLAY_STARTED, "candidate_"),
    ] {
        let records = records(&harness, event_type, 1);
        let record = records
            .iter()
            .find(|record| record[format!("{prefix}source")] == json!("draft"))
            .unwrap_or_else(|| panic!("a {event_type} record of the draft run"));
        assert_eq!(record[format!("{prefix}draft_id")], json!(draft_id));
        assert_eq!(record[format!("{prefix}draft_revision")], json!(1));
        assert_eq!(record[format!("{prefix}etag")], json!(candidate_etag));
        let text = record.to_string();
        assert!(!text.contains(CANDIDATE_CANARY), "{event_type}: {text}");
        assert!(!text.contains(&draft_etag), "{event_type}: {text}");
    }

    // Nothing was written to the draft.
    assert_eq!(read_draft(&harness, &draft_id).await, (draft_etag, saved));
    assert_eq!(
        records(&harness, audit::event::POLICY_DRAFT_CHANGED, 1).len(),
        1,
        "only the draft's creation changed it"
    );
    assert!(records(&harness, audit::event::POLICY_CHANGED, 0).is_empty());
}

/// A draft is a candidate only for its owner, at the ETag the request names,
/// and on the base the request is pinned to. Another owner's draft is the
/// `404` a missing one is, a draft that moved on is `412
/// policy_draft_stale`, and one pinned to another base is `409
/// policy_draft_base_stale`: never rebased, and never written by the
/// refusal. A refused request runs nothing and records no run.
#[tokio::test]
async fn a_draft_candidate_is_the_callers_current_draft_on_the_requests_base() {
    let harness = harness();
    let (live_etag, _) = current_policy(&harness.router).await;
    let (draft_id, first_etag) =
        create_draft(&harness, &live_etag, candidate_document("drafted")).await;

    for principal in [other_owner(), {
        let mut issued = test_principal(&["admin"]);
        issued.issuer = Some("https://issuer.test".to_owned());
        Some(issued)
    }] {
        for (route, body) in evaluations(&live_etag, &draft_source(&draft_id, &first_etag)) {
            let (status, body) =
                refusal(post(&harness, route, principal.clone(), body, None).await).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{route}: {body}");
            assert_eq!(body["reason"], json!("policy_draft_not_found"), "{route}");
        }
    }
    for missing in [ABSENT_DRAFT_ID, "not-a-draft-id"] {
        for (route, body) in evaluations(&live_etag, &draft_source(missing, &first_etag)) {
            let (status, body) = refusal(post(&harness, route, admin(), body, None).await).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{route}: {body}");
            assert_eq!(body["reason"], json!("policy_draft_not_found"), "{route}");
        }
    }

    // The draft moves on: the ETag a request read is stale.
    let patched = send(
        &harness,
        policy_admin_request(
            Method::PATCH,
            &format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}"),
            admin(),
            Some(json!({ "policy": candidate_document("drafted-again") }).to_string()),
            Some(&first_etag),
        ),
    )
    .await;
    assert_eq!(patched.status(), StatusCode::OK);
    let (draft_etag, patched) = read_draft(&harness, &draft_id).await;
    assert_eq!(patched["revision"], json!(2));
    for (route, body) in evaluations(&live_etag, &draft_source(&draft_id, &first_etag)) {
        let (status, body) = refusal(post(&harness, route, admin(), body, None).await).await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{route}: {body}");
        assert_eq!(body["reason"], json!("policy_draft_stale"), "{route}");
    }

    // The live policy moves on: the draft is pinned to a base that is no
    // longer the request's.
    let moved_etag = replace_policy(&harness, &live_etag, &stored_policy_document("moved")).await;
    for (route, body) in evaluations(&moved_etag, &draft_source(&draft_id, &draft_etag)) {
        let (status, body) = refusal(post(&harness, route, admin(), body, None).await).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {body}");
        assert_eq!(body["reason"], json!("policy_draft_base_stale"), "{route}");
        assert_eq!(body["base_etag"], json!(live_etag), "{route}");
        assert_eq!(body["policy_etag"], json!(moved_etag), "{route}");
    }
    // A request still pinned to the old base is stale itself, first.
    let (status, body) = refusal(
        post(
            &harness,
            POLICY_SIMULATIONS_ADMIN_ROUTE,
            admin(),
            simulation(&live_etag, draft_source(&draft_id, &draft_etag)),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");
    assert_eq!(body["reason"], json!("policy_simulation_base_stale"));

    // No refusal ran anything, recorded a run, or wrote the draft.
    for event_type in [
        audit::event::POLICY_SIMULATION_RUN,
        audit::event::POLICY_TESTS_RUN,
        audit::event::POLICY_ANALYSIS_RUN,
        audit::event::POLICY_REPLAY_STARTED,
    ] {
        assert!(
            records(&harness, event_type, 0).is_empty(),
            "{event_type} after a refusal"
        );
    }
    assert_eq!(read_draft(&harness, &draft_id).await, (draft_etag, patched));
    assert_eq!(
        records(&harness, audit::event::POLICY_DRAFT_CHANGED, 2).len(),
        2,
        "only the create and the patch changed the draft"
    );
}

/// A history version is read from the history and validated again under
/// this build: it is reported by its version and the ETag it has, compared
/// with the live base, and refused as `422 policy_revision_incompatible`
/// once the history holds a document this build does not accept. A version
/// the history does not hold is `404 policy_revision_not_found`. Nothing is
/// reactivated.
#[tokio::test]
async fn a_revision_candidate_is_read_from_the_history_and_validated_again() {
    let harness = harness();
    let (live_etag, _) = current_policy(&harness.router).await;
    let recorded = candidate_document("recorded");
    let recorded_etag = replace_policy(&harness, &live_etag, &recorded).await;
    let base_etag =
        replace_policy(&harness, &recorded_etag, &stored_policy_document("current")).await;
    let version = history_version_of(&harness, "recorded").await;
    let identity = json!({ "source": "revision", "etag": recorded_etag, "version": version });

    let simulated = post(
        &harness,
        POLICY_SIMULATIONS_ADMIN_ROUTE,
        evaluator(),
        simulation(&base_etag, revision_source(version)),
        None,
    )
    .await;
    assert_eq!(simulated.status(), StatusCode::OK);
    let simulated = json_body(simulated).await;
    assert_eq!(simulated["candidate"], identity);
    assert_eq!(simulated["base"]["etag"], json!(base_etag));
    let canary = &simulated["cases"][0]["results"][0];
    assert_eq!(canary["changed"], json!(true));
    assert_eq!(
        canary["candidate"]["effective_action"],
        json!("would_block")
    );

    let tested = post(
        &harness,
        POLICY_TEST_RUNS_ADMIN_ROUTE,
        evaluator(),
        test_run(revision_source(version)),
        None,
    )
    .await;
    assert_eq!(tested.status(), StatusCode::OK);
    let tested = json_body(tested).await;
    assert_eq!(tested["status"], json!("passed"));
    assert_eq!(tested["policy"], identity);
    let analyzed = post(
        &harness,
        POLICY_ANALYSES_ADMIN_ROUTE,
        evaluator(),
        analysis(&base_etag, revision_source(version)),
        None,
    )
    .await;
    assert_eq!(analyzed.status(), StatusCode::OK);
    assert_eq!(json_body(analyzed).await["analyzed"], identity);
    let started = post(
        &harness,
        POLICY_REPLAYS_ADMIN_ROUTE,
        evaluator(),
        replay(&base_etag, revision_source(version)),
        None,
    )
    .await;
    assert_eq!(started.status(), StatusCode::ACCEPTED);
    let started = json_body(started).await;
    assert_eq!(started["candidate"], identity);
    // The job holds this caller's replay slot until it ends.
    let job = finished_job(&harness, started["job_id"].as_str().expect("a job id")).await;
    // An empty window is a finished job with a result that says so.
    assert_eq!(job["state"], json!("completed_incomplete"), "{job}");
    assert_eq!(job["result"]["limitations"], json!(["no_data"]), "{job}");
    let record = records(&harness, audit::event::POLICY_SIMULATION_RUN, 1)
        .into_iter()
        .next()
        .expect("the simulation is recorded");
    assert_eq!(record["candidate_source"], json!("revision"));
    assert_eq!(record["candidate_version"], json!(version));
    assert!(!record.to_string().contains(CANDIDATE_CANARY), "{record}");

    for (route, body) in evaluations(&base_etag, &revision_source(1_000_000)) {
        let (status, body) = refusal(post(&harness, route, evaluator(), body, None).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{route}: {body}");
        assert_eq!(
            body["reason"],
            json!("policy_revision_not_found"),
            "{route}"
        );
    }

    // The history now holds, as this version, a document this build refuses.
    let history =
        rusqlite::Connection::open(format!("{}.history.sqlite", harness.policy.path.display()))
            .expect("the history opens");
    let changed = history
        .execute(
            "UPDATE policy_versions SET policy_json = ?1 WHERE version = ?2",
            rusqlite::params![
                json!({ "schema_version": "0.1.0", "default_action": "sometimes" }).to_string(),
                version
            ],
        )
        .expect("the history row is rewritten");
    assert_eq!(changed, 1);
    for (route, body) in evaluations(&base_etag, &revision_source(version)) {
        let (status, body) = refusal(post(&harness, route, evaluator(), body, None).await).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{route}: {body}");
        assert_eq!(
            body["reason"],
            json!("policy_revision_incompatible"),
            "{route}"
        );
        assert_eq!(body["version"], json!(version), "{route}");
    }

    // Nothing was reactivated.
    assert_eq!(current_policy(&harness.router).await.0, base_etag);
}

/// Naming a stored candidate asks for nothing beyond what the evaluation
/// already needs, which includes `admin:policy:read`, the permission that
/// reads a draft or a history version directly. A caller without it is
/// refused before anything is read, whether or not the draft exists, and
/// using a draft needs no write permission.
#[tokio::test]
async fn stored_candidates_need_no_permission_beyond_the_evaluation_and_reading_them() {
    let harness = harness();
    let (live_etag, _) = current_policy(&harness.router).await;
    let (draft_id, draft_etag) =
        create_draft(&harness, &live_etag, candidate_document("drafted")).await;
    let unreading = Some(test_principal(&["unreading-evaluator"]));
    for candidate in [
        draft_source(&draft_id, &draft_etag),
        draft_source(ABSENT_DRAFT_ID, &draft_etag),
        revision_source(1),
    ] {
        for (route, body) in evaluations(&live_etag, &candidate) {
            let (status, body) =
                refusal(post(&harness, route, unreading.clone(), body, None).await).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
            assert!(
                !body.to_string().contains("policy_draft"),
                "{route}: a refusal before any read says nothing of the draft: {body}"
            );
        }
    }
    // The owner, with read and the evaluation's permissions but no write.
    for (route, body) in evaluations(&live_etag, &draft_source(&draft_id, &draft_etag)) {
        let response = post(&harness, route, evaluator(), body, None).await;
        assert!(
            response.status().is_success(),
            "{route}: {}",
            response.status()
        );
    }
}

/// A test run takes a stored candidate in its `candidate` member, a draft or
/// a revision only, beside neither an inline `policy` nor an `If-Match`.
#[tokio::test]
async fn a_test_run_names_a_stored_candidate_only_in_its_candidate_member() {
    let harness = harness();
    let (live_etag, _) = current_policy(&harness.router).await;
    let (draft_id, draft_etag) =
        create_draft(&harness, &live_etag, candidate_document("drafted")).await;
    let draft = draft_source(&draft_id, &draft_etag);
    let mut both = test_run(draft.clone());
    both["policy"] = candidate_document("inline");
    for body in [
        both,
        test_run(json!({ "source": "active" })),
        test_run(json!({ "source": "inline", "policy": candidate_document("inline") })),
        test_run(json!({ "source": "draft", "draft_id": draft_id })),
        test_run(json!({ "source": "revision", "version": 0 })),
    ] {
        let (status, refused) = refusal(
            post(
                &harness,
                POLICY_TEST_RUNS_ADMIN_ROUTE,
                evaluator(),
                body.clone(),
                None,
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {refused}");
        assert_eq!(refused["reason"], json!("policy_tests_request_invalid"));
    }
    let (status, refused) = refusal(
        post(
            &harness,
            POLICY_TEST_RUNS_ADMIN_ROUTE,
            evaluator(),
            test_run(json!({ "source": "revision", "version": "1" })),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        refused["diagnostics"][0]["pointer"],
        json!("/candidate/version")
    );
    let (status, refused) = refusal(
        post(
            &harness,
            POLICY_TEST_RUNS_ADMIN_ROUTE,
            evaluator(),
            test_run(draft),
            Some(&live_etag),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["reason"], json!("policy_tests_request_invalid"));
    assert!(records(&harness, audit::event::POLICY_TESTS_RUN, 0).is_empty());
}
