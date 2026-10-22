//! `POST /v1{ADMIN_PREFIX}/policy/simulations` (issue #243, slice 10)
//! through the application in standalone mode. The request parser, edits,
//! projections and runner are covered in `policy_simulation::tests`.
use super::*;

const SIMULATIONS: &str = POLICY_SIMULATIONS_ADMIN_ROUTE;
/// A fixture value a simulation must never repeat in a response or record.
const SUBJECT_CANARY: &str = "simulation-subject-canary-93d2";

fn simulations_policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "policy-simulations",
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
            "simulator": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_SIMULATE_PERMISSION]
            },
            "policy-reader": { "permissions": [ADMIN_POLICY_READ_PERMISSION] },
            "simulator-only": { "permissions": [ADMIN_POLICY_SIMULATE_PERMISSION] },
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
        "tools": {
            "search": { "enabled": true }
        }
    })
}

fn caller() -> Value {
    json!({ "subject": SUBJECT_CANARY, "roles": ["caller"], "auth_method": "bearer_token" })
}

/// Cases that would, if anything here were live, consume the one-request
/// rate bucket, record a would-deny, admit a tool and dispatch upstream.
fn side_effect_cases(upstream_origin: &str) -> Value {
    let mut cases = Vec::new();
    for index in 0..4 {
        cases.push(json!({
            "id": format!("limited-{index}"),
            "kind": "http",
            "request": { "method": "GET", "path": "/limited/a" },
            "principal": caller()
        }));
        cases.push(json!({
            "id": format!("limited-rate-{index}"),
            "kind": "rate",
            "request": { "method": "GET", "path": "/limited/a" },
            "principal": caller()
        }));
    }
    cases.push(json!({
        "id": "watched-dispatch",
        "kind": "http",
        "request": {
            "method": "GET",
            "path": "/orders/watched",
            "target": { "kind": "proxy_dispatch", "upstream_origin": upstream_origin }
        },
        "principal": caller()
    }));
    cases.push(json!({
        "id": "search-invocation",
        "kind": "tool",
        "tool": { "name": "search" },
        "principal": caller()
    }));
    cases.push(json!({
        "id": "search-rendered",
        "kind": "tool_http",
        "tool": { "name": "search" },
        "request": { "method": "GET", "path": "/orders/watched" },
        "principal": caller()
    }));
    Value::Array(cases)
}

fn simulation(base_etag: &str, candidate: Value, cases: Value) -> Value {
    json!({
        "schema_version": "policy-simulation.v1",
        "base_etag": base_etag,
        "candidate": candidate,
        "trace": "full",
        "projections": ["as_authored", "enforce_all_shadow"],
        "cases": cases
    })
}

fn lockdown_edits() -> Value {
    json!({ "source": "edits", "edits": [{
        "op": "insert", "section": "rules", "position": 0,
        "value": { "id": "lockdown", "methods": ["GET"], "path": "/orders/**", "action": "deny" }
    }] })
}

struct Harness {
    router: Router,
    capture: audit::sink::tests::CaptureSink,
    policy: TempPolicyFile,
}

fn harness_with_config(mut config: config::Config) -> Harness {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&simulations_policy_document()).expect("policy serializes"),
    );
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    // No background upstream health probe: it would reach the capture
    // upstream and record health transitions on its own schedule, which the
    // side-effect test would otherwise have to tell apart from the simulation.
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
        panic!("the simulation test app should be unified");
    };
    Harness {
        router,
        capture,
        policy,
    }
}

fn harness() -> Harness {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    harness_with_config(config)
}

fn simulator() -> Option<auth::Principal> {
    Some(test_principal(&["simulator"]))
}

async fn simulate_request(
    harness: &Harness,
    principal: Option<auth::Principal>,
    body: String,
) -> Response {
    harness
        .router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            SIMULATIONS,
            principal,
            Some(body),
            None,
        ))
        .await
        .expect("policy simulation should complete")
}

async fn current_etag(harness: &Harness) -> String {
    current_policy(&harness.router).await.0
}

fn simulation_run_events(harness: &Harness) -> Vec<audit::AuditEvent> {
    harness
        .capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == audit::event::POLICY_SIMULATION_RUN)
        .collect()
}

fn is_access_record(event: &audit::AuditEvent, method: &str, path: &str) -> bool {
    event.event_type == "http.request_observed"
        && event.payload["method"] == json!(method)
        && event.payload["path"] == json!(path)
}

/// Block until the capture holds `count` access records for `method` `path`.
///
/// The audit writer delivers on its own thread, so a record can land after
/// the snapshot it belongs before. It drains one FIFO queue and a request's
/// access record is the last record the request emits, so once that record
/// is in the capture every earlier one is too.
fn wait_for_access_records(harness: &Harness, method: &str, path: &str, count: usize) {
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let delivered = harness
            .capture
            .events()
            .iter()
            .filter(|event| is_access_record(event, method, path))
            .count();
        if delivered >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the audit writer should deliver {count} access record(s) for {method} {path}"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// How many records the capture holds once the one policy read every
/// side-effect test starts with has been delivered.
fn events_after_policy_read(harness: &Harness) -> usize {
    wait_for_access_records(harness, "GET", POLICY_ADMIN_ROUTE, 1);
    harness.capture.events().len()
}

/// The records the gateway wrote since `start`, less the access record every
/// HTTP request gets: the observation middleware's `http.request_observed`
/// for the `POST` to the simulations route itself. That record describes the
/// request, not anything the simulation did, and it is asserted to be the only
/// one dropped. Waits for it first, so every record the simulation wrote has
/// been delivered.
fn records_since(harness: &Harness, start: usize) -> Vec<String> {
    let before = harness.capture.events()[..start]
        .iter()
        .filter(|event| is_access_record(event, "POST", SIMULATIONS))
        .count();
    wait_for_access_records(harness, "POST", SIMULATIONS, before + 1);
    let events = harness.capture.events();
    let mut access_records = 0;
    let records = events[start..]
        .iter()
        .filter(|event| {
            let own_access_record = is_access_record(event, "POST", SIMULATIONS);
            if own_access_record {
                access_records += 1;
            }
            !own_access_record
        })
        .map(|event| event.event_type.clone())
        .collect();
    assert_eq!(
        access_records, 1,
        "one simulation request, one access record"
    );
    records
}

fn cases_by_id(report: &Value) -> HashMap<String, Value> {
    report["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|case| {
            (
                case["id"].as_str().expect("case id").to_owned(),
                case.clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_simulation_needs_authentication_policy_read_and_simulate() {
    let harness = harness();
    let etag = current_etag(&harness).await;
    let body = simulation(
        &etag,
        json!({ "source": "active" }),
        side_effect_cases("pool:x"),
    )
    .to_string();
    let response = simulate_request(&harness, None, body.clone()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for roles in [&["policy-reader"][..], &["simulator-only"][..]] {
        let response = simulate_request(&harness, Some(test_principal(roles)), body.clone()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
    }
    assert!(simulation_run_events(&harness).is_empty());
}

#[tokio::test]
async fn a_simulation_is_pinned_to_the_active_policy_it_was_written_against() {
    let harness = harness();
    let etag = current_etag(&harness).await;
    let stale = simulation(
        "\"sha256:0000\"",
        json!({ "source": "active" }),
        side_effect_cases("pool:x"),
    );
    let response = simulate_request(&harness, simulator(), stale.to_string()).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_simulation_base_stale"));
    assert_eq!(body["current_etag"], json!(etag));

    let mut unpinned = simulation(
        &etag,
        json!({ "source": "active" }),
        side_effect_cases("pool:x"),
    );
    unpinned
        .as_object_mut()
        .expect("object")
        .remove("base_etag");
    let response = simulate_request(&harness, simulator(), unpinned.to_string()).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_simulation_invalid"));
    assert_eq!(body["diagnostics"][0]["pointer"], json!("/base_etag"));
    assert!(simulation_run_events(&harness).is_empty());
}

#[tokio::test]
async fn a_simulation_explains_both_projections_and_audits_digests_and_counts_only() {
    let harness = harness();
    let before = fs::read_to_string(&harness.policy.path).expect("policy reads");
    let etag = current_etag(&harness).await;
    let events_before = events_after_policy_read(&harness);
    let response = simulate_request(
        &harness,
        simulator(),
        simulation(&etag, lockdown_edits(), side_effect_cases("pool:x")).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_content_type_starts_with(response.headers(), "application/json");
    let body = body_string(response).await;
    assert!(!body.contains(SUBJECT_CANARY));
    let report: Value = serde_json::from_str(&body).expect("report is JSON");
    assert_eq!(
        report["schema_version"],
        json!("policy-simulation-results.v1")
    );
    assert_eq!(report["mode"], json!("synthetic"));
    assert_eq!(report["base"]["etag"], json!(etag));
    assert_eq!(report["candidate"]["source"], json!("edits"));
    assert_eq!(report["candidate"]["edits"], json!(1));
    assert_ne!(report["candidate"]["etag"], json!(etag));
    assert_eq!(report["trace"]["level"], json!("full"));
    assert_eq!(
        report["projections"],
        json!(["as_authored", "enforce_all_shadow"])
    );
    assert!(report["not_evaluated"]
        .as_array()
        .expect("not_evaluated")
        .contains(&json!("mutable_capacity")));

    let cases = cases_by_id(&report);
    let watched = &cases["watched-dispatch"];
    let authored = &watched["results"][0];
    assert_eq!(authored["projection"], json!("as_authored"));
    // The base forwards an observed deny; the candidate's lockdown blocks it.
    assert_eq!(authored["base"]["logical"], json!("deny"));
    assert_eq!(authored["base"]["enforcement"], json!("shadowed"));
    assert_eq!(authored["base"]["effective_action"], json!("would_forward"));
    assert_eq!(
        authored["candidate"]["effective_action"],
        json!("would_block")
    );
    assert_eq!(authored["candidate"]["matched"]["id"], json!("lockdown"));
    assert_eq!(authored["changed"], json!(true));
    let enforced = &watched["results"][1];
    assert_eq!(enforced["projection"], json!("enforce_all_shadow"));
    assert_eq!(enforced["base"]["effective_action"], json!("would_block"));
    assert_eq!(
        authored["base"]["stages"][2],
        json!({
            "stage": "direct_rules",
            "status": "matched",
            "element": { "kind": "rule", "position": 1, "id": "orders-watch", "action": "shadow" },
            "action": "shadow"
        })
    );
    let rate = &cases["limited-rate-3"]["results"][0]["candidate"];
    assert_eq!(rate["selected"], json!("override"));
    assert_eq!(rate["rate_override"]["burst"], json!(1));

    // The only new record is the simulation's own, and nothing was written
    // or activated.
    assert_eq!(
        records_since(&harness, events_before),
        [audit::event::POLICY_SIMULATION_RUN]
    );
    assert_eq!(
        fs::read_to_string(&harness.policy.path).expect("policy reads"),
        before
    );
    assert_eq!(current_etag(&harness).await, etag);
    let simulated = simulation_run_events(&harness);
    assert_eq!(simulated.len(), 1);
    let payload = &simulated[0].payload;
    assert_eq!(payload["base_etag"], json!(etag));
    assert_eq!(payload["candidate_source"], json!("edits"));
    assert_eq!(payload["candidate_etag"], report["candidate"]["etag"]);
    assert_eq!(payload["request_digest"], report["request_digest"]);
    assert_eq!(payload["cases"], json!(11));
    assert_eq!(payload["summary"], report["summary"]);
    let recorded = payload.to_string();
    for absent in [
        SUBJECT_CANARY,
        "/limited/a",
        "watched-dispatch",
        "lockdown",
        "orders-watch",
    ] {
        assert!(
            !recorded.contains(absent),
            "the audit record repeats {absent}"
        );
    }
    assert_eq!(
        simulated[0]
            .actor
            .as_ref()
            .map(|actor| actor.user_id.as_str()),
        Some("user-123")
    );
}

#[tokio::test]
async fn an_inline_candidate_is_validated_like_a_policy_write_and_never_stored() {
    let harness = harness();
    let etag = current_etag(&harness).await;
    let mut candidate = simulations_policy_document();
    candidate["default_action"] = json!("allow");
    let response = simulate_request(
        &harness,
        simulator(),
        simulation(
            &etag,
            json!({ "source": "inline", "policy": candidate }),
            side_effect_cases("pool:x"),
        )
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_body(response).await;
    assert_eq!(report["candidate"]["source"], json!("inline"));

    let mut invalid = simulations_policy_document();
    invalid["rules"][0]["action"] = json!("permit");
    let response = simulate_request(
        &harness,
        simulator(),
        simulation(
            &etag,
            json!({ "source": "inline", "policy": invalid }),
            side_effect_cases("pool:x"),
        )
        .to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_candidate_invalid")
    );
    assert_eq!(current_etag(&harness).await, etag);
    // The second policy read is the last request: once its access record is
    // delivered, so is the first simulation's record.
    wait_for_access_records(&harness, "GET", POLICY_ADMIN_ROUTE, 2);
    assert_eq!(simulation_run_events(&harness).len(), 1);
}

#[tokio::test]
async fn edits_that_do_not_apply_or_do_not_validate_are_refused_without_a_record() {
    let harness = harness();
    let etag = current_etag(&harness).await;
    let out_of_range = json!({ "source": "edits", "edits": [
        { "op": "delete", "section": "routes", "position": 1 }
    ] });
    let response = simulate_request(
        &harness,
        simulator(),
        simulation(&etag, out_of_range, side_effect_cases("pool:x")).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_simulation_invalid"));
    assert_eq!(
        body["diagnostics"][0],
        json!({
            "code": "position_out_of_range",
            "pointer": "/candidate/edits/0/position",
            "message": "no element is at this position in the section as edited so far"
        })
    );

    let invalid_rule = json!({ "source": "edits", "edits": [
        { "op": "replace", "section": "rules", "position": 0, "expect_id": "limited-allow",
          "value": { "id": "limited-allow", "path": "/limited/**", "action": "permit" } }
    ] });
    let response = simulate_request(
        &harness,
        simulator(),
        simulation(&etag, invalid_rule, side_effect_cases("pool:x")).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_candidate_invalid")
    );

    // A repeated member is refused before anything reads the request.
    let duplicated = format!(
        "{{\"schema_version\":\"policy-simulation.v1\",\"base_etag\":{},\"base_etag\":{},\"candidate\":{{\"source\":\"active\"}},\"cases\":{}}}",
        json!(etag),
        json!("\"sha256:other\""),
        side_effect_cases("pool:x")
    );
    let response = simulate_request(&harness, simulator(), duplicated).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_simulation_request_invalid")
    );
    assert!(simulation_run_events(&harness).is_empty());
}

#[test]
fn the_limiter_admits_one_simulation_per_actor_within_a_bounded_total() {
    let limiter = Arc::new(PolicySimulationLimiter::new());
    let first = limiter.try_acquire("issuer\u{0}alice".to_owned());
    assert!(first.is_some());
    assert!(
        limiter.try_acquire("issuer\u{0}alice".to_owned()).is_none(),
        "one actor holds one slot"
    );
    let others: Vec<_> = (1..MAX_CONCURRENT_POLICY_SIMULATIONS)
        .map(|index| limiter.try_acquire(format!("issuer\u{0}actor-{index}")))
        .collect();
    assert!(others.iter().all(Option::is_some));
    assert!(
        limiter.try_acquire("issuer\u{0}late".to_owned()).is_none(),
        "the per-replica bound holds"
    );
    drop(first);
    assert!(limiter.try_acquire("issuer\u{0}alice".to_owned()).is_some());
}

/// The acceptance criterion of #243 slice 10: a simulation produces no audit
/// record but its own, no metric beyond its own request's admission, no
/// rate-bucket charge, and no upstream traffic -- for cases that, live, would
/// do all of them. The audit, egress and bucket "none"s are checked against
/// the live path afterwards, so they cannot pass vacuously.
#[test]
fn a_simulation_has_no_side_effect_but_its_own_audit_record() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    // The recorder is installed per thread; a current-thread runtime polls
    // every task on this one, so the handler's and the middleware's emissions
    // land in it. The evaluation itself runs on a blocking thread, which
    // `policy_simulation::tests::the_run_records_no_metric` covers.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");
    let (harness, mut upstream, etag, upstream_origin) = runtime.block_on(async {
        let (upstream_addr, upstream) = spawn_capture_upstream().await;
        let harness = harness_with_config(proxy_config(upstream_addr));
        let etag = current_etag(&harness).await;
        (
            harness,
            upstream,
            etag,
            format!("http://127.0.0.1:{}", upstream_addr.port()),
        )
    });
    let events_before = events_after_policy_read(&harness);

    let response = ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(simulate_request(
            &harness,
            simulator(),
            simulation(&etag, lockdown_edits(), side_effect_cases(&upstream_origin)).to_string(),
        ))
    });
    assert_eq!(response.status(), StatusCode::OK);

    // Audit: exactly one new record, the simulation's own -- no would-deny,
    // authorization, tool or upstream record for any simulated case.
    assert_eq!(
        records_since(&harness, events_before),
        [audit::event::POLICY_SIMULATION_RUN]
    );

    // Metrics: only the simulation request's own envelope moved -- its admin
    // request count, the in-flight gauge, and the bucket the generic `write`
    // limiter admits every POST with. A simulated case that reached the
    // policy rate lane would add a `limiter="policy"` bucket; one that reached
    // authorization, a tool or an upstream would add its own series.
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
        let own_envelope = (name == REQUEST_COUNTER && label("route") == Some(SIMULATIONS))
            || name == metrics::INFLIGHT_REQUESTS
            || (name == metrics::RATE_LIMIT_BUCKETS && label("limiter") == Some("write"));
        assert!(own_envelope, "a simulation recorded {line}");
    }

    // Egress: the upstream every proxy-dispatch case names saw nothing.
    assert!(
        upstream.try_recv().is_err(),
        "a simulation reached the upstream"
    );
    // Policy: unchanged and still the same revision.
    assert_eq!(runtime.block_on(current_etag(&harness)), etag);

    // Rate buckets: the one-request bucket the simulated cases selected was
    // never charged. The first live request passes it -- and reaches the
    // upstream, so the check above was not vacuous -- and the second is
    // refused, so the bucket really does hold one.
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
    // Audit, against the live path: the same capture records each live
    // request, so the audit trail above was not empty by accident.
    wait_for_access_records(&harness, "GET", "/limited/a", 2);
    let live_records = harness.capture.events()[events_before..]
        .iter()
        .filter(|event| event.payload["path"] == json!("/limited/a"))
        .count();
    assert!(live_records >= 2, "the live requests are recorded");
}
