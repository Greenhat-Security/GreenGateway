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

/// Cases that would, if anything here were live, spend the one-request
/// bucket, resolve a name, or connect to the upstream: isolated sequences on
/// the policy override and on the global read lane, and egress cases for the
/// upstream's own address with and without hypothetical evidence.
fn synthetic_side_effect_cases(upstream_port: u16) -> Vec<Value> {
    let upstream = json!({ "scheme": "http", "host": "127.0.0.1", "port": upstream_port });
    vec![
        json!({
            "id": "limited-sequence",
            "kind": "rate",
            "request": { "method": "GET", "path": "/limited/a" },
            "principal": caller(),
            "sequence": { "at_ms": [0, 0, 0] }
        }),
        json!({
            "id": "anonymous-sequence",
            "kind": "rate",
            "request": { "method": "GET", "path": "/limited/a" },
            "principal": "anonymous",
            "sequence": { "at_ms": [0, 0] }
        }),
        json!({
            "id": "upstream-egress-hypothetical",
            "kind": "egress",
            "destination": upstream,
            "resolution": {
                "hypothetical_addresses": [format!("127.0.0.1:{upstream_port}")]
            }
        }),
        json!({
            "id": "upstream-egress-unresolved",
            "kind": "egress",
            "destination": upstream
        }),
        json!({
            "id": "named-egress-unresolved",
            "kind": "egress",
            "destination": { "scheme": "https", "host": "resolver-canary.example.test" }
        }),
    ]
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

fn harness_with_config(config: config::Config) -> Harness {
    harness_with_resolver(config, None)
}

fn harness_with_resolver(
    mut config: config::Config,
    egress_resolver: Option<Arc<dyn egress::DnsResolver>>,
) -> Harness {
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
            egress_resolver,
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
async fn simulation_metrics_count_authorized_responses_with_fixed_labels() {
    let harness = harness();
    let etag = current_etag(&harness).await;
    let recorder = metrics_recorder_builder().build_recorder();
    let handle = recorder.handle();
    let _guard = ::metrics::set_default_local_recorder(&recorder);
    let stale = simulation(
        "\"sha256:0000\"",
        json!({ "source": "active" }),
        side_effect_cases("pool:x"),
    );
    for (principal, body, status) in [
        (None, SUBJECT_CANARY.to_owned(), StatusCode::UNAUTHORIZED),
        (
            Some(test_principal(&["policy-reader"])),
            SUBJECT_CANARY.to_owned(),
            StatusCode::FORBIDDEN,
        ),
        (
            simulator(),
            SUBJECT_CANARY.to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            simulator(),
            stale.to_string(),
            StatusCode::PRECONDITION_FAILED,
        ),
    ] {
        let response = simulate_request(&harness, principal, body).await;
        assert_eq!(response.status(), status);
    }
    let rendered = handle.render();
    let outcomes: Vec<_> = rendered
        .lines()
        .filter(|line| rendered_metric_name(line) == metrics::POLICY_SIMULATIONS_TOTAL)
        .collect();
    assert_eq!(outcomes.len(), 2);
    for outcome in ["conflict", "refused"] {
        let metric = metrics::POLICY_SIMULATIONS_TOTAL;
        let expected = format!("{metric}{{outcome=\"{outcome}\"}} 1");
        assert!(outcomes.contains(&expected.as_str()));
    }
    let duration = metrics::POLICY_SIMULATION_DURATION_SECONDS;
    assert!(rendered.contains(&format!("{duration}_count 2\n")));
    assert!(rendered.contains(&format!("{duration}_bucket{{le=\"2\"}}")));
    assert!(!rendered.contains(SUBJECT_CANARY));

    let cases = (0..policy_simulation::request::MAX_SIMULATION_CASES)
        .map(|index| {
            json!({
                "id": format!("case-{index}"),
                "kind": "http",
                "request": {"method": "GET", "path": "/orders/7"},
                "principal": caller(),
            })
        })
        .collect();
    let edits = json!({
        "source": "edits",
        "edits": [{"op": "set", "field": "default_action", "value": "allow"}]
    });
    let request = simulation(&etag, edits, Value::Array(cases));
    let response = simulate_request(&harness, simulator(), request.to_string()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["trace"]["stages_truncated"], true);
    let rendered = handle.render();
    assert!(rendered.contains(&format!(
        "{} 1\n",
        metrics::POLICY_SIMULATION_TRACES_TRUNCATED_TOTAL
    )));
    assert!(rendered.contains(&format!("{duration}_count 3\n")));
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

async fn capabilities_for(harness: &Harness, role: &str) -> Value {
    let response = harness
        .router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            ADMIN_CAPABILITIES_ROUTE,
            Some(test_principal(&[role])),
            None,
            None,
        ))
        .await
        .expect("capabilities request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    json_body(response).await
}

#[tokio::test]
async fn a_partial_simulation_grant_omits_the_capability() {
    let harness = harness();
    for (role, permission) in [
        ("policy-reader", ADMIN_POLICY_READ_PERMISSION),
        ("simulator-only", ADMIN_POLICY_SIMULATE_PERMISSION),
    ] {
        let capabilities = capabilities_for(&harness, role).await;
        assert_eq!(capabilities["permissions"], json!([permission]));
        assert!(capabilities.get("policy_simulation").is_none(), "{role}");
    }
}

#[tokio::test]
async fn simulation_capabilities_report_the_request_limit_enforced_by_this_gateway() {
    for (configured, effective) in [(1024, 1024), (4 * 1024 * 1024, 2 * 1024 * 1024)] {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.max_body_size = configured;
        let harness = harness_with_config(config);
        let capabilities = capabilities_for(&harness, "simulator").await;
        assert_eq!(
            capabilities["policy_simulation"],
            json!({
                "request_schema": policy_simulation::SIMULATION_SCHEMA_VERSION,
                "result_schema": policy_simulation::RESULT_SCHEMA_VERSION,
                "max_request_bytes": effective,
                "max_result_bytes": MAX_POLICY_SIMULATION_RESULT_BYTES,
                "max_cases": policy_simulation::request::MAX_SIMULATION_CASES,
                "max_edits": policy_simulation::edits::MAX_EDITS,
                "max_trace_stages": policy_simulation::run::MAX_TRACE_STAGES,
                "max_concurrent_per_replica": MAX_CONCURRENT_POLICY_SIMULATIONS,
                "max_concurrent_per_actor": 1,
                "evaluation_deadline_ms": POLICY_SIMULATION_DEADLINE.as_millis()
            })
        );

        let mut body = simulation(
            &current_etag(&harness).await,
            json!({ "source": "active" }),
            json!([{
                "id": "orders", "kind": "http", "principal": "anonymous",
                "request": { "method": "GET", "path": "/orders/7" }
            }]),
        )
        .to_string();
        body.push_str(&" ".repeat(effective - body.len()));
        let accepted = simulate_request(&harness, simulator(), body.clone()).await;
        assert_eq!(accepted.status(), StatusCode::OK, "{configured}");
        body.push(' ');
        let refused = simulate_request(&harness, simulator(), body).await;
        assert_eq!(
            refused.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{configured}"
        );
    }
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

/// An inline candidate is read from its own bytes by the parser
/// `PUT /policy` reads a body with. Through a `Value`, a v1 number spelled as
/// serde_json's private tag reads as the number; read as bytes it is an
/// object where a number belongs, and the candidate is refused with the
/// error `PUT` gives it. Spelled plainly, the same candidate is simulated.
/// (A repeated member anywhere in the body is refused before the request is
/// read at all; see the next test.)
#[tokio::test]
async fn an_inline_candidate_is_read_from_its_bytes_like_a_policy_write() {
    let harness = harness();
    let etag = current_etag(&harness).await;
    let cases = json!([{
        "id": "limited",
        "kind": "http",
        "request": { "method": "GET", "path": "/limited/a" },
        "principal": caller()
    }]);
    let request = |requests_per_second: &str| {
        format!(
            r#"{{"schema_version":"policy-simulation.v1","base_etag":{},"candidate":{{"source":"inline","policy":{{"schema_version":"1.0.0","default_action":"deny","rate_limits":[{{"id":"limited","path":"/limited/**","requests_per_second":{requests_per_second},"burst":1}}]}}}},"cases":{}}}"#,
            json!(etag),
            cases
        )
    };

    let response = simulate_request(
        &harness,
        simulator(),
        request(r#"{"$serde_json::private::Number":"0.5"}"#),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_candidate_invalid"));
    assert_eq!(
        body["errors"],
        json!(["the value is not one this location accepts"])
    );

    let response = simulate_request(&harness, simulator(), request("0.5")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["candidate"]["source"],
        json!("inline")
    );
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
    let limiter = Arc::new(PolicyEvaluationLimiter::new(
        MAX_CONCURRENT_POLICY_SIMULATIONS,
    ));
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

/// A client that goes away drops its request at the next `.await`, but the
/// blocking evaluation it started runs on. The slot belongs to that work, so
/// it stays taken -- for the actor and against the replica's bound -- until
/// the work ends, and a caller cannot stack evaluations on the blocking pool
/// past the bound by cancelling each request once its work has started.
#[tokio::test]
async fn a_cancelled_request_keeps_its_slot_until_its_blocking_work_ends() {
    let limiter = Arc::new(PolicyEvaluationLimiter::new(1));
    let slot = limiter
        .try_acquire("issuer\u{0}alice".to_owned())
        .expect("the first evaluation is admitted");
    let (started, started_signal) = tokio::sync::oneshot::channel();
    let (release, release_signal) = std::sync::mpsc::channel::<()>();
    let request = tokio::spawn(slot.run_blocking(move || {
        let _ = started.send(());
        // Stands in for an evaluation still deciding cases.
        let _ = release_signal.recv();
    }));
    started_signal
        .await
        .expect("the blocking work starts and signals");

    // The request is dropped, as a disconnect drops it.
    request.abort();
    assert!(request
        .await
        .expect_err("the request was cancelled")
        .is_cancelled());
    assert!(
        limiter.try_acquire("issuer\u{0}alice".to_owned()).is_none(),
        "the actor's slot is held while its work runs"
    );
    assert!(
        limiter.try_acquire("issuer\u{0}bob".to_owned()).is_none(),
        "the replica's slot is held while the work runs"
    );

    release
        .send(())
        .expect("the blocking work is still waiting");
    let readmitted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(slot) = limiter.try_acquire("issuer\u{0}alice".to_owned()) {
                return slot;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        readmitted.is_ok(),
        "the slot comes back once the blocking work ends"
    );
}

/// The acceptance criterion of #243 slices 10 and 12: a simulation produces
/// no audit record but its own, no data-plane metric or rate-bucket
/// charge, no tool admission or permit, no name
/// resolution and no upstream traffic -- for cases that, live, would do all
/// of them, isolated rate sequences and egress cases for the upstream's own
/// address included. The audit, resolver, egress and bucket "none"s are
/// checked against the live path afterwards, so they cannot pass vacuously.
/// Tool admission is covered by the audit check: the tool runtime records
/// every admission and refusal, and acquires a permit only after admission.
#[test]
fn a_simulation_has_no_side_effect_but_its_own_audit_record() {
    let recorder = metrics_recorder_builder().build_recorder();
    let handle = recorder.handle();
    // The recorder is installed per thread; a current-thread runtime polls
    // every task on this one, so the handler's and the middleware's emissions
    // land in it. The evaluation itself runs on a blocking thread, which
    // `policy_simulation::tests::the_run_records_no_metric` covers.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");
    let resolver = Arc::new(CountingDnsResolver {
        calls: AtomicUsize::new(0),
        address_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    });
    let (harness, mut upstream, etag, upstream_origin, upstream_port) = runtime.block_on(async {
        let (upstream_addr, upstream) = spawn_capture_upstream().await;
        let harness = harness_with_resolver(
            proxy_config(upstream_addr),
            Some(Arc::clone(&resolver) as Arc<dyn egress::DnsResolver>),
        );
        let etag = current_etag(&harness).await;
        (
            harness,
            upstream,
            etag,
            format!("http://127.0.0.1:{}", upstream_addr.port()),
            upstream_addr.port(),
        )
    });
    let events_before = events_after_policy_read(&harness);
    let resolutions_before = resolver.calls.load(Ordering::SeqCst);
    let mut cases = side_effect_cases(&upstream_origin);
    if let Some(cases) = cases.as_array_mut() {
        cases.extend(synthetic_side_effect_cases(upstream_port));
    }

    let response = ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(simulate_request(
            &harness,
            simulator(),
            simulation(&etag, lockdown_edits(), cases).to_string(),
        ))
    });
    assert_eq!(response.status(), StatusCode::OK);
    let report = runtime.block_on(json_body(response));
    let by_id = cases_by_id(&report);
    let candidate = |id: &str| by_id[id]["results"][0]["candidate"].clone();
    // The synthetic bucket ran out; the live one, below, did not.
    assert_eq!(
        candidate("limited-sequence")["sequence"]["steps"],
        json!(["allowed", "limited", "limited"])
    );
    assert_eq!(
        candidate("anonymous-sequence")["sequence"]["lane"],
        json!("global_read")
    );
    assert_eq!(
        candidate("upstream-egress-hypothetical")["logical"],
        json!("allow")
    );
    assert_eq!(
        candidate("upstream-egress-unresolved")["limitation"],
        json!("missing_resolution_evidence")
    );
    assert_eq!(
        candidate("named-egress-unresolved")["reason"],
        json!("host_not_allowed")
    );
    assert_eq!(
        report["synthetic_resources"]["global_rate_lanes"],
        json!("configured")
    );
    assert!(report["synthetic_resources"]["egress_controls_digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
    // Resolver: no case -- not the one without evidence, not the one with a
    // name -- asked it anything.
    assert_eq!(
        resolver.calls.load(Ordering::SeqCst),
        resolutions_before,
        "a simulation consulted the resolver"
    );

    // Audit: exactly one new record, the simulation's own -- no would-deny,
    // authorization, tool or upstream record for any simulated case.
    assert_eq!(
        records_since(&harness, events_before),
        [audit::event::POLICY_SIMULATION_RUN]
    );

    // Only the admin request's envelope and its control-plane response metrics
    // moved. Evaluating individual cases must never create a data-plane series.
    let rendered = handle.render();
    let duration = metrics::POLICY_SIMULATION_DURATION_SECONDS;
    assert!(rendered.contains(&format!(
        "{}{{outcome=\"completed\"}} 1\n",
        metrics::POLICY_SIMULATIONS_TOTAL
    )));
    assert!(rendered.contains(&format!("{duration}_count 1\n")));
    assert!(!rendered.contains(metrics::POLICY_SIMULATION_TRACES_TRUNCATED_TOTAL));
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
        let own_envelope = (name == format!("{REQUEST_COUNTER}_total")
            && label("route") == Some(SIMULATIONS))
            || name == metrics::INFLIGHT_REQUESTS
            || (name == metrics::RATE_LIMIT_BUCKETS && label("limiter") == Some("write"))
            || (name == metrics::POLICY_SIMULATIONS_TOTAL && label("outcome") == Some("completed"))
            || name == format!("{duration}_sum")
            || name == format!("{duration}_count")
            || (name == format!("{duration}_bucket") && label("le").is_some());
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
    assert!(
        resolver.calls.load(Ordering::SeqCst) > resolutions_before,
        "the live request resolves its upstream through the same resolver"
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
