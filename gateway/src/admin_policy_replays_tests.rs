//! `POST /v1{ADMIN_PREFIX}/policy/replays` and `GET` and `DELETE
//! /v1{ADMIN_PREFIX}/policy/replays/{id}` (issue #243, slice 13) through the
//! application in standalone mode. The engine, its bounds and the audit-log
//! reader are covered in `policy_replay::job_tests`.
use super::*;

const REPLAYS: &str = POLICY_REPLAYS_ADMIN_ROUTE;
/// Values a retained record carries that no job response or record may
/// repeat.
const SUBJECT_CANARY: &str = "replay-api-subject-canary-4c7d";
const PATH_CANARY: &str = "/orders/replay-api-path-canary-81aa";

fn replays_policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "policy-replays",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION,
                    ADMIN_POLICY_SIMULATE_PERMISSION,
                    ADMIN_AUDIT_READ_PERMISSION
                ]
            },
            "replayer": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_SIMULATE_PERMISSION,
                    ADMIN_AUDIT_READ_PERMISSION
                ]
            },
            "simulator": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_SIMULATE_PERMISSION]
            },
            "audit-policy-reader": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_AUDIT_READ_PERMISSION]
            },
            "simulate-audit": {
                "permissions": [ADMIN_POLICY_SIMULATE_PERMISSION, ADMIN_AUDIT_READ_PERMISSION]
            },
            "caller": { "permissions": ["orders:read"] }
        },
        "rules": [
            { "id": "limited-allow", "methods": ["GET"], "path": "/limited/**", "action": "allow" },
            { "id": "orders-watch", "methods": ["GET"], "path": "/orders/watched", "action": "shadow" },
            { "id": "search-tool", "tool_name": "search", "action": "allow" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ],
        "rate_limits": [
            { "path": "/limited/**", "requests_per_second": 0.001, "burst": 1 }
        ],
        "tools": { "search": { "enabled": true } }
    })
}

fn caller_actor() -> audit::Actor {
    audit::Actor {
        user_id: SUBJECT_CANARY.to_owned(),
        issuer: None,
        email: None,
        roles: Some(vec!["caller".to_owned()]),
        auth_mode: "bearer_token".to_owned(),
    }
}

fn observed(
    method: &str,
    path: &str,
    decision: &str,
    actor: Option<audit::Actor>,
) -> audit::AuditEvent {
    audit::AuditEvent::new(
        "http.request_observed",
        "retained-request",
        "192.0.2.10",
        actor,
        json!({
            "method": method,
            "path": path,
            "status": 200,
            "policy_decision": decision,
            "routing_context_known": true,
        }),
    )
}

/// Retained records that would, if a replay were live, charge the
/// one-request rate bucket, record a would-deny, admit a tool and reach the
/// upstream.
fn retained_window() -> Vec<audit::AuditEvent> {
    let mut events = Vec::new();
    for _ in 0..4 {
        events.push(observed(
            "GET",
            "/limited/a",
            "allowed",
            Some(caller_actor()),
        ));
    }
    events.push(observed(
        "GET",
        "/orders/watched",
        "would_deny",
        Some(caller_actor()),
    ));
    events.push(observed(
        "GET",
        PATH_CANARY,
        "allowed",
        Some(caller_actor()),
    ));
    events.push(observed("GET", "/orders/1", "denied", None));
    events.push(audit::AuditEvent::new(
        audit::event::TOOL_INVOKE_START,
        "retained-tool",
        "192.0.2.10",
        Some(caller_actor()),
        json!({ "tool_name": "search", "outcome": "started" }),
    ));
    events.push(audit::AuditEvent::new(
        "authz.allowed",
        "retained-request",
        "192.0.2.10",
        None,
        json!({ "method": "GET", "path": "/limited/a", "matched_rule_id": "limited-allow" }),
    ));
    events
}

fn lockdown_edits() -> Value {
    json!({ "source": "edits", "edits": [{
        "op": "insert", "section": "rules", "position": 0,
        "value": { "id": "lockdown", "methods": ["GET"], "path": "/orders/**", "action": "deny" }
    }] })
}

fn window_from() -> String {
    (OffsetDateTime::now_utc() - time::Duration::hours(1))
        .format(&Rfc3339)
        .expect("a window bound formats")
}

fn replay_body(base_etag: &str, candidate: Value) -> Value {
    json!({
        "schema_version": "policy-replay.v1",
        "base_etag": base_etag,
        "candidate": candidate,
        "window": { "from": window_from() }
    })
}

struct Harness {
    router: Router,
    capture: audit::sink::tests::CaptureSink,
    audit_db: TempDb,
    _policy: TempPolicyFile,
}

fn harness_with_config(mut config: config::Config) -> Harness {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&replays_policy_document()).expect("policy serializes"),
    );
    // The retained source: a SQLite audit log the application reads. The
    // application's own records go to the capture, so the log changes only
    // when a test writes to it.
    let audit_db = TempDb::new("policy-replays");
    config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
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
        panic!("the replay test app should be unified");
    };
    Harness {
        router,
        capture,
        audit_db,
        _policy: policy,
    }
}

fn harness() -> Harness {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    harness_with_config(config)
}

fn seed(path: &FsPath, events: &[audit::AuditEvent]) {
    let mut connection = rusqlite::Connection::open(path).expect("audit log opens");
    audit::sqlite_sink::write_events(&mut connection, events).expect("retained events are written");
}

fn audit_row_count(path: &FsPath) -> i64 {
    rusqlite::Connection::open(path)
        .expect("audit log opens")
        .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
        .expect("audit log counts")
}

fn replayer() -> Option<auth::Principal> {
    Some(test_principal(&["replayer"]))
}

async fn send(router: &Router, request: Request<Body>) -> Response {
    router
        .clone()
        .oneshot(request)
        .await
        .expect("policy replay request should complete")
}

async fn start(router: &Router, principal: Option<auth::Principal>, body: String) -> Response {
    send(
        router,
        policy_admin_request(Method::POST, REPLAYS, principal, Some(body), None),
    )
    .await
}

fn job_uri(job_id: &str) -> String {
    format!("{REPLAYS}/{job_id}")
}

async fn get_job(router: &Router, principal: Option<auth::Principal>, job_id: &str) -> Response {
    send(
        router,
        policy_admin_request(Method::GET, &job_uri(job_id), principal, None, None),
    )
    .await
}

async fn delete_job(router: &Router, principal: Option<auth::Principal>, job_id: &str) -> Response {
    send(
        router,
        policy_admin_request(Method::DELETE, &job_uri(job_id), principal, None, None),
    )
    .await
}

/// Poll a job until it is no longer queued or running.
async fn finished(router: &Router, principal: Option<auth::Principal>, job_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let response = get_job(router, principal.clone(), job_id).await;
        assert_eq!(response.status(), StatusCode::OK);
        let job = json_body(response).await;
        if !matches!(job["state"].as_str(), Some("queued" | "running")) {
            return job;
        }
        assert!(Instant::now() < deadline, "the replay job should finish");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn lifecycle_events(capture: &audit::sink::tests::CaptureSink) -> Vec<audit::AuditEvent> {
    capture
        .events()
        .into_iter()
        .filter(|event| event.event_type.starts_with("policy.replay_"))
        .collect()
}

/// Block until the capture holds `count` lifecycle events. The audit writer
/// delivers on its own thread, so an event can land after the job state it
/// precedes is visible.
fn wait_for_lifecycle(
    capture: &audit::sink::tests::CaptureSink,
    count: usize,
) -> Vec<audit::AuditEvent> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events = lifecycle_events(capture);
        if events.len() >= count {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "the audit writer should deliver {count} lifecycle event(s)"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// How many records the capture holds once the policy read a test starts
/// with has been delivered: that read's access record is the last record it
/// emits, and the writer is one FIFO queue.
fn events_after_policy_read(capture: &audit::sink::tests::CaptureSink) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let events = capture.events();
        if events.iter().any(|event| {
            event.event_type == "http.request_observed"
                && event.payload["path"] == json!(POLICY_ADMIN_ROUTE)
        }) {
            return events.len();
        }
        assert!(
            Instant::now() < deadline,
            "the policy read's access record should be delivered"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn job_id(job: &Value) -> String {
    job["job_id"].as_str().expect("job id").to_owned()
}

#[tokio::test]
async fn a_replay_needs_authentication_policy_read_simulate_and_audit_read() {
    let harness = harness();
    let etag = current_policy(&harness.router).await.0;
    let body = replay_body(&etag, json!({ "source": "active" })).to_string();
    let response = start(&harness.router, None, body.clone()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for roles in [
        &["simulator"][..],
        &["audit-policy-reader"][..],
        &["simulate-audit"][..],
        &["caller"][..],
    ] {
        let principal = Some(test_principal(roles));
        let response = start(&harness.router, principal.clone(), body.clone()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
        let id = "rpl_00000000000000000000000000000000";
        let response = get_job(&harness.router, principal.clone(), id).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
        let response = delete_job(&harness.router, principal, id).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
    }
    let response = get_job(
        &harness.router,
        None,
        "rpl_00000000000000000000000000000000",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(lifecycle_events(&harness.capture).is_empty());
}

#[tokio::test]
async fn a_replay_without_an_audit_store_is_unavailable_not_empty() {
    let capture = audit::sink::tests::CaptureSink::new();
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&replays_policy_document()).expect("policy serializes"),
    );
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
    let router = app(
        config,
        PrometheusBuilder::new().build_recorder().handle(),
        audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let etag = current_policy(&router).await.0;
    let response = start(
        &router,
        replayer(),
        replay_body(&etag, json!({ "source": "active" })).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(response).await["reason"],
        json!("audit_evidence_unavailable")
    );
    assert!(lifecycle_events(&capture).is_empty());
}

#[tokio::test]
async fn a_replay_request_is_validated_and_pinned_before_any_job_exists() {
    let harness = harness();
    let etag = current_policy(&harness.router).await.0;

    let stale = replay_body("\"sha256:0000\"", json!({ "source": "active" }));
    let response = start(&harness.router, replayer(), stale.to_string()).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_replay_base_stale"));
    assert_eq!(body["current_etag"], json!(etag));

    let mut future = replay_body(&etag, json!({ "source": "active" }));
    future["window"]["to"] = json!((OffsetDateTime::now_utc() + time::Duration::hours(1))
        .format(&Rfc3339)
        .expect("formats"));
    let response = start(&harness.router, replayer(), future.to_string()).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_replay_invalid"));
    assert_eq!(body["diagnostics"][0]["code"], json!("window_in_future"));

    let out_of_range = json!({ "source": "edits", "edits": [
        { "op": "delete", "section": "routes", "position": 1 }
    ] });
    let response = start(
        &harness.router,
        replayer(),
        replay_body(&etag, out_of_range).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_replay_invalid"));
    assert_eq!(
        body["diagnostics"][0]["pointer"],
        json!("/candidate/edits/0/position")
    );

    let mut invalid = replays_policy_document();
    invalid["rules"][0]["action"] = json!("permit");
    let response = start(
        &harness.router,
        replayer(),
        replay_body(&etag, json!({ "source": "inline", "policy": invalid })).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_candidate_invalid")
    );

    let duplicated = format!(
        "{{\"schema_version\":\"policy-replay.v1\",\"base_etag\":{},\"base_etag\":{},\"candidate\":{{\"source\":\"active\"}},\"window\":{{\"from\":{}}}}}",
        json!(etag),
        json!("\"sha256:other\""),
        json!(window_from())
    );
    let response = start(&harness.router, replayer(), duplicated).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_replay_request_invalid")
    );
    assert!(lifecycle_events(&harness.capture).is_empty());
}

#[tokio::test]
async fn a_replay_job_runs_to_an_aggregate_deterministic_result_and_audits_its_lifecycle() {
    let harness = harness();
    seed(&harness.audit_db.path, &retained_window());
    let etag = current_policy(&harness.router).await.0;
    // A closed window, so a second job over it states the same window.
    let mut body = replay_body(&etag, lockdown_edits());
    body["window"]["to"] = json!(OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("a window bound formats"));
    let body = body.to_string();

    let response = start(&harness.router, replayer(), body.clone()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location")
        .to_owned();
    let accepted = json_body(response).await;
    let id = job_id(&accepted);
    assert!(id.starts_with("rpl_"));
    assert_eq!(location, job_uri(&id));
    assert!(matches!(
        accepted["state"].as_str(),
        Some("queued" | "running" | "completed")
    ));
    assert_eq!(accepted["schema_version"], json!("policy-replay-job.v1"));
    assert_eq!(accepted["base"]["etag"], json!(etag));
    assert_eq!(accepted["candidate"]["source"], json!("edits"));
    assert_eq!(accepted["candidate"]["edits"], json!(1));
    assert_eq!(accepted["cutoff"]["selected_records"], json!(9));
    assert_eq!(accepted["projections"], json!(["as_authored"]));
    assert_eq!(accepted["freshness"], json!({ "state": "current" }));

    let job = finished(&harness.router, replayer(), &id).await;
    assert_eq!(job["state"], json!("completed"), "{job}");
    assert_eq!(job["base"]["current"], json!(true));
    let result = &job["result"];
    assert_eq!(result["complete"], json!(true));
    assert_eq!(result["records"]["selected"], json!(9));
    assert_eq!(result["records"]["scanned"], json!(9));
    assert_eq!(result["records"]["replayable"], json!(8));
    assert_eq!(result["records"]["duplicate"], json!(1));
    assert_eq!(result["replayed"]["http"]["replayable"], json!(7));
    assert_eq!(result["replayed"]["tool"]["replayable"], json!(1));
    // Under the lockdown candidate every order path is blocked, including
    // the one the active policy only observed.
    let outcomes = result["replayed"]["http"]["outcomes"]
        .as_array()
        .expect("outcomes");
    let blocked: u64 = outcomes
        .iter()
        .filter(|outcome| outcome["effective_action"] == json!("would_block"))
        .map(|outcome| outcome["count"].as_u64().expect("count"))
        .sum();
    assert_eq!(blocked, 3);
    assert_eq!(result["replayed"]["rate"]["override"], json!(4));
    // Against the active policy it was written against, the lockdown
    // blocks the order the route allowed and the one a shadow rule only
    // observed, re-attributes the anonymous denial, and allows nothing new.
    let impact = &result["impact"]["projections"]["as_authored"];
    let transitions = &impact["http"]["transitions"];
    assert_eq!(transitions["newly_denied"], json!(1));
    assert_eq!(transitions["enforcement_only_change"], json!(1));
    assert_eq!(transitions["attribution_only_change"], json!(1));
    assert_eq!(transitions["unchanged_allow"], json!(4));
    assert_eq!(transitions["newly_allowed"], json!(0));
    assert_eq!(
        impact["http"]["forwarding"],
        json!({ "newly_forwarded": 0, "newly_blocked": 2 })
    );
    assert_eq!(
        impact["statement"]["text"],
        json!("No newly allowed decisions were observed among 8 replayable events.")
    );
    assert_eq!(
        result["impact"]["recorded"]["http"]["comparisons"]["agrees"],
        json!(7)
    );
    assert_eq!(job["freshness"], json!({ "state": "current" }));
    assert_eq!(job["progress"]["scanned_records"], json!(9));
    let digest = job["result_digest"].as_str().expect("digest").to_owned();
    let rendered = job.to_string();
    for canary in [
        SUBJECT_CANARY,
        PATH_CANARY,
        "retained-request",
        "192.0.2.10",
    ] {
        assert!(!rendered.contains(canary), "the job repeats {canary}");
    }

    // The job's lifecycle is its only record, carrying digests and counts.
    let events = wait_for_lifecycle(&harness.capture, 2);
    let types: Vec<_> = events
        .iter()
        .map(|event| event.event_type.as_str())
        .collect();
    assert_eq!(
        types,
        [
            audit::event::POLICY_REPLAY_STARTED,
            audit::event::POLICY_REPLAY_COMPLETED
        ]
    );
    assert_eq!(events[0].payload["job_id"], json!(id));
    assert_eq!(events[0].payload["base_etag"], json!(etag));
    assert_eq!(events[0].payload["selected_records"], json!(9));
    assert_eq!(events[1].payload["state"], json!("completed"));
    assert_eq!(events[1].payload["result_digest"], json!(digest));
    assert_eq!(events[1].payload["replayed_records"], json!(8));
    assert_eq!(
        events[1].payload["impact"]["as_authored"]["newly_denied"],
        json!(1)
    );
    assert_eq!(
        events[1].payload["impact"]["as_authored"]["newly_allowed"],
        json!(0)
    );
    assert_eq!(events[0].payload["projections"], json!(["as_authored"]));
    for event in &events {
        let recorded = event.payload.to_string();
        for absent in [
            SUBJECT_CANARY,
            PATH_CANARY,
            "/limited/a",
            "lockdown",
            "orders-watch",
        ] {
            assert!(
                !recorded.contains(absent),
                "a lifecycle event repeats {absent}"
            );
        }
        assert_eq!(
            event.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    // The same request over the same retained records is the same result.
    let response = start(&harness.router, replayer(), body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let second = finished(
        &harness.router,
        replayer(),
        &job_id(&json_body(response).await),
    )
    .await;
    assert_eq!(second["result_digest"], json!(digest));
    assert_eq!(second["result"], job["result"]);

    // A policy change after the job leaves its result as it was, and says
    // the result describes a base that is no longer active.
    let mut changed = replays_policy_document();
    changed["default_action"] = json!("allow");
    let response = send(
        &harness.router,
        policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(changed.to_string()),
            Some(&etag),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let stale = json_body(get_job(&harness.router, replayer(), &id).await).await;
    assert_eq!(stale["base"]["current"], json!(false));
    assert_eq!(
        stale["freshness"],
        json!({ "state": "stale", "reason": "base_changed" })
    );
    assert_eq!(stale["result_digest"], json!(digest));
}

#[tokio::test]
async fn a_replay_compares_every_shadow_projected_as_enforced_on_request() {
    let harness = harness();
    seed(&harness.audit_db.path, &retained_window());
    let etag = current_policy(&harness.router).await.0;
    let mut body = replay_body(&etag, lockdown_edits());
    body["projections"] = json!(["as_authored", "enforce_all_shadow"]);
    let response = start(&harness.router, replayer(), body.to_string()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let id = job_id(&json_body(response).await);
    let job = finished(&harness.router, replayer(), &id).await;
    assert_eq!(job["state"], json!("completed"), "{job}");
    assert_eq!(
        job["projections"],
        json!(["as_authored", "enforce_all_shadow"])
    );
    let projected = &job["result"]["impact"]["projections"]["enforce_all_shadow"];
    // With the watched rule enforced in the base too, the lockdown only
    // changes which rule blocks it.
    assert_eq!(
        projected["http"]["transitions"]["enforcement_only_change"],
        json!(0)
    );
    assert_eq!(
        projected["http"]["transitions"]["attribution_only_change"],
        json!(2)
    );
    assert!(projected.get("statement").is_none());

    // An unknown projection is refused before any job exists.
    let mut body = replay_body(&etag, lockdown_edits());
    body["projections"] = json!(["promote_all"]);
    let response = start(&harness.router, replayer(), body.to_string()).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_replay_invalid")
    );
}

#[tokio::test]
async fn an_idempotent_retry_names_the_same_job_and_a_reused_key_conflicts() {
    let harness = harness();
    seed(&harness.audit_db.path, &retained_window());
    let etag = current_policy(&harness.router).await.0;
    let mut body = replay_body(&etag, json!({ "source": "active" }));
    body["idempotency_key"] = json!("nightly-replay");
    let response = start(&harness.router, replayer(), body.to_string()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let id = job_id(&json_body(response).await);

    let response = start(&harness.router, replayer(), body.to_string()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(job_id(&json_body(response).await), id);

    let mut different = body.clone();
    different["max_records"] = json!(5);
    let response = start(&harness.router, replayer(), different.to_string()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_replay_idempotency_conflict")
    );
    finished(&harness.router, replayer(), &id).await;
    let started = lifecycle_events(&harness.capture)
        .into_iter()
        .filter(|event| event.event_type == audit::event::POLICY_REPLAY_STARTED)
        .count();
    assert_eq!(started, 1, "a retry starts nothing");
}

#[tokio::test]
async fn a_job_is_served_only_to_the_principal_that_started_it() {
    let harness = harness();
    seed(&harness.audit_db.path, &retained_window());
    let etag = current_policy(&harness.router).await.0;
    let response = start(
        &harness.router,
        replayer(),
        replay_body(&etag, json!({ "source": "active" })).to_string(),
    )
    .await;
    let id = job_id(&json_body(response).await);
    let mut other = test_principal(&["replayer"]);
    other.user_id = "another-operator".to_owned();
    let response = get_job(&harness.router, Some(other.clone()), &id).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_replay_job_not_found")
    );
    let response = delete_job(&harness.router, Some(other), &id).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    for unknown in ["rpl_00000000000000000000000000000000", "not-a-job", "RPL_0"] {
        let response = get_job(&harness.router, replayer(), unknown).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{unknown}");
    }

    // Its owner discards it once it has finished.
    finished(&harness.router, replayer(), &id).await;
    let response = delete_job(&harness.router, replayer(), &id).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = get_job(&harness.router, replayer(), &id).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The replay routes over a registry the test holds, so it can keep the
/// replica's run slot and see a job wait, be cancelled, or expire.
struct RegistryHarness {
    router: Router,
    jobs: Arc<PolicyReplayJobs>,
    capture: audit::sink::tests::CaptureSink,
    audit_db: TempDb,
}

/// The replay routes alone, over `jobs`.
fn replay_routes(jobs: &Arc<PolicyReplayJobs>) -> Router<PolicyAdminState> {
    Router::new()
        .route(
            POLICY_REPLAYS_ADMIN_ROUTE,
            post(policy_replay_create_endpoint).layer(Extension(Arc::clone(jobs))),
        )
        .route(
            POLICY_REPLAY_ADMIN_ROUTE,
            get(policy_replay_get_endpoint)
                .delete(policy_replay_delete_endpoint)
                .layer(Extension(Arc::clone(jobs))),
        )
}

/// A standalone policy admin state over the replay test policy and `store`.
fn replay_admin_state(
    store: Arc<storage::SqliteAuditEventStore>,
    audit_log: audit::AuditLog,
) -> PolicyAdminState {
    let policy = rbac::Policy::validate_json_value(replays_policy_document())
        .expect("the test policy validates");
    let rbac_state = middleware::rbac::RbacState::new(policy, Vec::new(), false, test_audit_log());
    PolicyAdminState {
        policy_file: None,
        rbac_state: Some(rbac_state),
        history_store: None,
        draft_store: None,
        #[cfg(feature = "postgres")]
        control_plane: None,
        #[cfg(feature = "postgres")]
        membership: None,
        event_store: Some(store.clone() as Arc<dyn storage::AuditEventStore>),
        query_store: Some(store),
        audit: audit_log,
        client_ip_policy: client_ip::ClientIpPolicy::default(),
        max_body_size: 1024 * 1024,
    }
}

fn registry_harness() -> RegistryHarness {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let audit_db = TempDb::new("policy-replay-registry");
    let store =
        Arc::new(storage::SqliteAuditEventStore::open(&audit_db.path).expect("audit store opens"));
    let jobs = Arc::new(PolicyReplayJobs::new());
    let router = replay_routes(&jobs).with_state(replay_admin_state(store, audit_log));
    seed(&audit_db.path, &retained_window());
    RegistryHarness {
        router,
        jobs,
        capture,
        audit_db,
    }
}

fn registry_etag() -> String {
    policy_etag(
        &rbac::Policy::validate_json_value(replays_policy_document())
            .expect("the test policy validates"),
    )
    .expect("the policy has an ETag")
}

fn operator(subject: &str) -> Option<auth::Principal> {
    let mut principal = test_principal(&["replayer"]);
    principal.user_id = subject.to_owned();
    Some(principal)
}

#[tokio::test]
async fn a_queued_job_is_cancelled_and_quotas_refuse_rather_than_evict() {
    let harness = registry_harness();
    let body = replay_body(&registry_etag(), json!({ "source": "active" })).to_string();
    let slot = harness.jobs.occupy_run_slot();

    let response = start(&harness.router, operator("op-0"), body.clone()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let first = job_id(&json_body(response).await);
    // One pending job per principal.
    let response = start(&harness.router, operator("op-0"), body.clone()).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_replay_busy")
    );
    // At most four pending across the replica.
    let mut queued = vec![first.clone()];
    for index in 1..MAX_PENDING_POLICY_REPLAYS {
        let response = start(
            &harness.router,
            operator(&format!("op-{index}")),
            body.clone(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        queued.push(job_id(&json_body(response).await));
    }
    let response = start(&harness.router, operator("op-late"), body.clone()).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_replay_busy")
    );

    // The first job waits for the slot; cancelling it ends it without a
    // result, and its cancellation is recorded.
    let waiting = json_body(get_job(&harness.router, operator("op-0"), &first).await).await;
    assert_eq!(waiting["state"], json!("queued"));
    let response = delete_job(&harness.router, operator("op-0"), &first).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(response).await["cancel_requested"], json!(true));
    let cancelled = finished(&harness.router, operator("op-0"), &first).await;
    assert_eq!(cancelled["state"], json!("cancelled"));
    assert!(cancelled.get("result").is_none());
    // Four starts, then the cancellation.
    assert!(
        wait_for_lifecycle(&harness.capture, MAX_PENDING_POLICY_REPLAYS + 1)
            .iter()
            .any(|event| {
                event.event_type == audit::event::POLICY_REPLAY_CANCELLED
                    && event.payload["job_id"] == json!(first)
            })
    );

    // Releasing the slot lets every other queued job run, one at a time.
    drop(slot);
    for (index, id) in queued.iter().enumerate().skip(1) {
        let job = finished(&harness.router, operator(&format!("op-{index}")), id).await;
        assert_eq!(job["state"], json!("completed"), "{job}");
    }
    assert_eq!(
        audit_row_count(&harness.audit_db.path),
        i64::try_from(retained_window().len()).expect("fits"),
        "a replay never writes to the log it reads"
    );
}

/// A body that never finishes arriving, and a signal for when the handler
/// first asks for it: the moment a request that admitted before reading its
/// body would already hold a slot.
fn stalled_replay_body() -> (Body, tokio::sync::oneshot::Receiver<()>) {
    let (polled, polled_signal) = tokio::sync::oneshot::channel();
    let chunks = stream::once(async move {
        let _ = polled.send(());
        std::future::pending::<Result<Bytes, Infallible>>().await
    });
    (Body::from_stream(chunks), polled_signal)
}

/// A job is admitted only once its body is in hand. Uploads trickled by one
/// actor -- as many as the replica admits jobs -- hold no admission slot, so
/// the same actor's complete request is admitted while they are still open,
/// and each stalled upload is refused once its body deadline passes, having
/// started nothing.
#[tokio::test]
async fn a_stalled_body_is_refused_within_its_deadline_and_holds_no_slot() {
    let harness = registry_harness();
    let actor = operator("op-0").expect("a principal");
    let started = tokio::time::Instant::now();
    let mut stalled = Vec::new();
    for _ in 0..MAX_PENDING_POLICY_REPLAYS {
        let (body, polled) = stalled_replay_body();
        let request =
            policy_admin_request_with_body(Method::POST, REPLAYS, Some(actor.clone()), body, None);
        stalled.push(tokio::spawn(harness.router.clone().oneshot(request)));
        polled.await.expect("the handler reads the stalled body");
    }

    let probe = harness
        .jobs
        .admission()
        .try_acquire(policy_evaluation_actor(&actor));
    assert!(probe.is_some(), "a stalled upload holds the actor's slot");
    drop(probe);
    let body = replay_body(&registry_etag(), json!({ "source": "active" })).to_string();
    let response = start(&harness.router, Some(actor.clone()), body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let id = job_id(&json_body(response).await);

    for request in stalled {
        let response = request
            .await
            .expect("the stalled request task completes")
            .expect("the stalled request completes");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(
            json_body(response).await["reason"],
            json!("policy_replay_request_timeout")
        );
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= POLICY_REPLAY_BODY_DEADLINE,
        "refused after {elapsed:?}, before the body deadline"
    );
    assert!(
        elapsed < POLICY_REPLAY_BODY_DEADLINE + Duration::from_secs(5),
        "refused after {elapsed:?}, long past the body deadline"
    );
    let job = finished(&harness.router, Some(actor), &id).await;
    assert_eq!(job["state"], json!("completed"), "{job}");
    let started_jobs = wait_for_lifecycle(&harness.capture, 2)
        .into_iter()
        .filter(|event| event.event_type == audit::event::POLICY_REPLAY_STARTED)
        .count();
    assert_eq!(started_jobs, 1, "a stalled upload starts nothing");
}

/// A job holds its actor's admission slot from the moment it is admitted,
/// through the wait for the run slot, until its evaluation has ended -- and
/// gives it back before it reads as finished.
#[tokio::test]
async fn a_job_holds_its_admission_slot_until_its_evaluation_ends() {
    let harness = registry_harness();
    let actor = operator("op-0").expect("a principal");
    let body = replay_body(&registry_etag(), json!({ "source": "active" })).to_string();
    let run_slot = harness.jobs.occupy_run_slot();
    let response = start(&harness.router, Some(actor.clone()), body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let id = job_id(&json_body(response).await);

    let queued = json_body(get_job(&harness.router, Some(actor.clone()), &id).await).await;
    assert_eq!(queued["state"], json!("queued"));
    assert!(
        harness
            .jobs
            .admission()
            .try_acquire(policy_evaluation_actor(&actor))
            .is_none(),
        "a queued job holds its actor's slot"
    );
    drop(run_slot);
    let job = finished(&harness.router, Some(actor.clone()), &id).await;
    assert_eq!(job["state"], json!("completed"), "{job}");
    assert!(
        harness
            .jobs
            .admission()
            .try_acquire(policy_evaluation_actor(&actor))
            .is_some(),
        "a finished job has given its slot back"
    );
}

#[tokio::test]
async fn finished_results_are_bounded_per_principal_and_expire() {
    let harness = registry_harness();
    let body = replay_body(&registry_etag(), json!({ "source": "active" })).to_string();
    let mut ids = Vec::new();
    for _ in 0..MAX_RETAINED_POLICY_REPLAYS_PER_ACTOR {
        let response = start(&harness.router, operator("op-0"), body.clone()).await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let id = job_id(&json_body(response).await);
        finished(&harness.router, operator("op-0"), &id).await;
        ids.push(id);
    }
    let response = start(&harness.router, operator("op-0"), body.clone()).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_replay_quota_exhausted")
    );
    // Another principal is not held back by this one's results.
    let response = start(&harness.router, operator("op-1"), body.clone()).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let other = job_id(&json_body(response).await);
    finished(&harness.router, operator("op-1"), &other).await;

    // A result is dropped after its TTL: the job reads `expired`, with no
    // result, and no longer counts against its principal.
    harness.jobs.sweep_after(POLICY_REPLAY_RESULT_TTL);
    let expired = json_body(get_job(&harness.router, operator("op-0"), &ids[0]).await).await;
    assert_eq!(expired["state"], json!("expired"));
    assert!(expired.get("result").is_none());
    assert!(expired.get("result_digest").is_none());
    let response = start(&harness.router, operator("op-0"), body).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    // And it is forgotten after its retention.
    harness
        .jobs
        .sweep_after(POLICY_REPLAY_RESULT_TTL + POLICY_REPLAY_EXPIRED_RETENTION);
    let response = get_job(&harness.router, operator("op-0"), &ids[0]).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// A cluster control plane a replay must never consult: every call counts
/// and fails.
#[cfg(feature = "postgres")]
#[derive(Default)]
struct UnconsultedControlPlane {
    calls: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "postgres")]
impl UnconsultedControlPlane {
    fn refuse(&self, operation: &'static str) -> storage::RepositoryError {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        storage::RepositoryError::new(storage::RepositoryErrorKind::Unavailable, operation)
    }
}

#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl storage::PolicyHistory for UnconsultedControlPlane {
    async fn append_version(
        &self,
        _actor_user_id: &str,
        _diff_summary: &Value,
        _policy: &rbac::Policy,
    ) -> Result<rbac::policy_history::PolicyVersion, storage::RepositoryError> {
        Err(self.refuse("policy_history_append"))
    }

    async fn list_versions(
        &self,
        _filters: &rbac::PolicyHistoryListFilters,
    ) -> Result<rbac::PolicyHistoryPage, storage::RepositoryError> {
        Err(self.refuse("policy_history_list"))
    }

    async fn get_version(
        &self,
        _version: i64,
    ) -> Result<Option<rbac::policy_history::PolicyVersion>, storage::RepositoryError> {
        Err(self.refuse("policy_history_get"))
    }
}

#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl storage::PolicyControlPlane for UnconsultedControlPlane {
    async fn active(&self) -> Result<Option<storage::ActivePolicy>, storage::RepositoryError> {
        Err(self.refuse("policy_control_plane_active"))
    }

    async fn commit(
        &self,
        _request: storage::PolicyCommitRequest<'_>,
    ) -> Result<storage::ActivePolicy, storage::PolicyCommitError> {
        Err(storage::PolicyCommitError::Store(
            self.refuse("policy_control_plane_commit"),
        ))
    }
}

/// Fail closed in cluster mode: a replica-local job would read one
/// replica's view of a shared audit authority, and replicated jobs need the
/// durable leases of #241. Every route answers `503` with a stable reason
/// after the permission checks and before any work -- no body is parsed, no
/// cutoff read, no job admitted, no lifecycle recorded and no authority
/// consulted.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn cluster_mode_refuses_every_replay_route_before_any_work() {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let audit_db = TempDb::new("policy-replay-cluster");
    let store =
        Arc::new(storage::SqliteAuditEventStore::open(&audit_db.path).expect("audit store opens"));
    seed(&audit_db.path, &retained_window());
    let control_plane = Arc::new(UnconsultedControlPlane::default());
    let mut state = replay_admin_state(store, audit_log);
    state.control_plane = Some(Arc::clone(&control_plane) as Arc<dyn storage::PolicyControlPlane>);
    let jobs = Arc::new(PolicyReplayJobs::new());
    let router = replay_routes(&jobs).with_state(state);
    let body = replay_body(&registry_etag(), json!({ "source": "active" })).to_string();
    let id = "rpl_00000000000000000000000000000000";

    let mut responses = vec![
        start(&router, replayer(), body.clone()).await,
        // Not even a body that would be refused is read.
        start(&router, replayer(), "not json".to_owned()).await,
        get_job(&router, replayer(), id).await,
        delete_job(&router, replayer(), id).await,
    ];
    for response in responses.drain(..) {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            json_body(response).await["reason"],
            json!("policy_replay_unsupported_in_cluster")
        );
    }
    // The permission checks still come first.
    let simulator = Some(test_principal(&["simulator"]));
    let response = start(&router, simulator.clone(), body).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = get_job(&router, simulator, id).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    assert_eq!(
        control_plane
            .calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a refused replay never consults the cluster authority"
    );
    assert_eq!(jobs.job_count(), 0, "no job is admitted");
    assert!(lifecycle_events(&capture).is_empty());
    assert_eq!(
        audit_row_count(&audit_db.path),
        i64::try_from(retained_window().len()).expect("fits")
    );
}

/// The acceptance criterion of #243 slice 13, after the simulation API's: a
/// replay job leaves no audit record but its own lifecycle, no metric beyond
/// its requests' own admission, no rate-bucket charge, no upstream traffic,
/// and no write to the log it reads -- over retained records that, live,
/// would do all of them. The audit, egress and bucket "none"s are checked
/// against the live path afterwards, so they cannot pass vacuously. The run
/// itself, on its blocking thread, is covered by
/// `policy_replay::job_tests::the_run_records_no_metric`.
#[test]
fn a_replay_job_has_no_side_effect_but_its_own_lifecycle_records() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");
    let (harness, mut upstream, etag) = runtime.block_on(async {
        let (upstream_addr, upstream) = spawn_capture_upstream().await;
        let harness = harness_with_config(proxy_config(upstream_addr));
        let etag = current_policy(&harness.router).await.0;
        (harness, upstream, etag)
    });
    seed(&harness.audit_db.path, &retained_window());
    let rows_before = audit_row_count(&harness.audit_db.path);
    let events_before = events_after_policy_read(&harness.capture);

    let job = ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let response = start(
                &harness.router,
                replayer(),
                replay_body(&etag, lockdown_edits()).to_string(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            let id = job_id(&json_body(response).await);
            finished(&harness.router, replayer(), &id).await
        })
    });
    assert_eq!(job["state"], json!("completed"), "{job}");
    assert_eq!(job["result"]["records"]["replayable"], json!(8));

    // Audit: the job's two lifecycle records, and otherwise only the access
    // records of its own requests -- no would-deny, authorization, tool or
    // upstream record for any replayed record.
    let deadline = Instant::now() + Duration::from_secs(10);
    let new_records = loop {
        let records: Vec<_> = harness.capture.events()[events_before..]
            .iter()
            .filter(|event| {
                let own_access_record = event.event_type == "http.request_observed"
                    && event.payload["path"]
                        .as_str()
                        .is_some_and(|path| path.starts_with(REPLAYS));
                !own_access_record
            })
            .map(|event| event.event_type.clone())
            .collect();
        // The completion is the job's last record: once it is delivered,
        // everything the job emitted before it is too.
        let completed = records
            .iter()
            .any(|record| record == audit::event::POLICY_REPLAY_COMPLETED);
        if completed || Instant::now() >= deadline {
            break records;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(
        new_records,
        [
            audit::event::POLICY_REPLAY_STARTED,
            audit::event::POLICY_REPLAY_COMPLETED
        ]
    );

    // Metrics: only the replay requests' own envelope moved -- their admin
    // request counts, the in-flight gauge and the generic limiter buckets
    // every admin request is admitted through. A replayed record that
    // reached the policy rate lane would add a `limiter="policy"` bucket;
    // one that reached authorization, a tool or an upstream, its own series.
    let rendered = handle.render();
    for line in rendered.lines().filter(|line| !line.starts_with('#')) {
        let name = rendered_metric_name(line);
        if name.is_empty() {
            continue;
        }
        let labels = rendered_labels(line);
        let label = |key: &str| {
            labels
                .iter()
                .find(|(label, _)| label == key)
                .map(|(_, value)| value.as_str())
        };
        let own_envelope = (name == REQUEST_COUNTER
            && matches!(
                label("route"),
                Some(POLICY_REPLAYS_ADMIN_ROUTE | POLICY_REPLAY_ADMIN_ROUTE)
            ))
            || name == metrics::INFLIGHT_REQUESTS
            || (name == metrics::RATE_LIMIT_BUCKETS
                && matches!(label("limiter"), Some("read" | "write")));
        assert!(own_envelope, "a replay recorded {line}");
    }

    // Egress: the upstream saw nothing.
    assert!(
        upstream.try_recv().is_err(),
        "a replay reached the upstream"
    );
    // The log it read is unchanged, and so is the policy.
    assert_eq!(audit_row_count(&harness.audit_db.path), rows_before);
    assert_eq!(runtime.block_on(current_policy(&harness.router)).0, etag);

    // Rate buckets: the one-request bucket every replayed `/limited/a`
    // record selected was never charged. The first live request passes it --
    // and reaches the upstream, so the check above was not vacuous -- and the
    // second is refused, so the bucket really does hold one.
    let live = |harness: &Harness| {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/limited/a")
            .body(Body::empty())
            .expect("request should build");
        request.extensions_mut().insert(test_principal(&["caller"]));
        harness.router.clone().oneshot(request)
    };
    let first = runtime
        .block_on(live(&harness))
        .expect("live request should complete");
    assert_ne!(first.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        runtime.block_on(upstream.recv()).is_some(),
        "the live request reaches the upstream"
    );
    let second = runtime
        .block_on(live(&harness))
        .expect("live request should complete");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    // Audit, against the live path: the same capture records the live
    // requests, so the audit trail above was not empty by accident.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let live_records = harness.capture.events()[events_before..]
            .iter()
            .filter(|event| event.payload["path"] == json!("/limited/a"))
            .count();
        if live_records >= 2 {
            break;
        }
        assert!(Instant::now() < deadline, "the live requests are recorded");
        std::thread::sleep(Duration::from_millis(5));
    }
}
