//! Analyzer finding suppressions (issue #243, slice 15) through the
//! application in standalone mode: the suppression routes, and how
//! `POST .../policy/analyses` reports a finding once one exists. The
//! matching rules themselves are covered in `policy_analysis::tests`, and
//! both stores' contract in `storage::contract_tests`.
use super::*;

const ANALYSES: &str = POLICY_ANALYSES_ADMIN_ROUTE;
const SUPPRESSIONS: &str = POLICY_ANALYSIS_SUPPRESSIONS_ADMIN_ROUTE;
/// A reason an operator wrote. It must never reach an audit event or a
/// report.
const REASON_CANARY: &str = "reviewed by suppression-reason-canary-7d21";

fn suppressions_policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "policy-suppressions",
        "default_action": "deny",
        "roles": {
            // `current_policy` reads the policy as `admin`.
            "admin": { "permissions": [ADMIN_POLICY_READ_PERMISSION] },
            "analyst": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_ANALYZE_PERMISSION]
            },
            "writer": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_WRITE_PERMISSION]
            },
            "policy-reader": { "permissions": [ADMIN_POLICY_READ_PERMISSION] },
            "analyst-only": { "permissions": [ADMIN_POLICY_ANALYZE_PERMISSION] }
        },
        "rules": [
            { "methods": ["GET"], "path": "/reports/**", "action": "allow" },
            { "methods": ["GET"], "path": "/reports/admin", "action": "deny" }
        ]
    })
}

struct Harness {
    router: Router,
    capture: audit::sink::tests::CaptureSink,
    _policy: TempPolicyFile,
}

fn harness() -> Harness {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&suppressions_policy_document()).expect("policy serializes"),
    );
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
        panic!("the suppression test app should be unified");
    };
    Harness {
        router,
        capture,
        _policy: policy,
    }
}

fn analyst() -> Option<auth::Principal> {
    Some(test_principal(&["analyst"]))
}

fn writer() -> Option<auth::Principal> {
    Some(test_principal(&["writer"]))
}

async fn send(
    harness: &Harness,
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Option<Value>,
    if_match: Option<&str>,
) -> Response {
    harness
        .router
        .clone()
        .oneshot(policy_admin_request(
            method,
            uri,
            principal,
            body.map(|body| body.to_string()),
            if_match,
        ))
        .await
        .expect("request should complete")
}

/// An analysis of the active policy, as a JSON report or SARIF.
async fn analyze(harness: &Harness, etag: &str, format: &str) -> Value {
    let response = send(
        harness,
        Method::POST,
        ANALYSES,
        analyst(),
        Some(json!({
            "schema_version": "policy-analysis.v1",
            "base_etag": etag,
            "candidate": { "source": "active" },
            "format": format,
        })),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

fn rfc3339_in(duration: time::Duration) -> String {
    (OffsetDateTime::now_utc() + duration)
        .format(&Rfc3339)
        .expect("formats")
}

/// The create body for the one finding `report` carries.
fn suppression_body(report: &Value) -> Value {
    json!({
        "fingerprint": report["findings"][0]["fingerprint"],
        "code": report["findings"][0]["code"],
        "reason": REASON_CANARY,
        "expires_at": rfc3339_in(time::Duration::days(7)),
        "resource_snapshot_digest": report["resource_snapshot"]["digest"],
    })
}

/// The events of `event_type` delivered so far, waiting up to a bound for
/// `count` of them: the audit writer delivers on its own thread.
fn events_of(harness: &Harness, event_type: &str, count: usize) -> Vec<audit::AuditEvent> {
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let events: Vec<audit::AuditEvent> = harness
            .capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .collect();
        if events.len() >= count || Instant::now() >= deadline {
            return events;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[tokio::test]
async fn suppressions_need_authentication_and_their_permissions() {
    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    let response = send(&harness, Method::GET, SUPPRESSIONS, None, None, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Listing is an analysis read: policy read and analyze, both.
    for roles in [
        &["policy-reader"][..],
        &["analyst-only"][..],
        &["writer"][..],
    ] {
        let response = send(
            &harness,
            Method::GET,
            SUPPRESSIONS,
            Some(test_principal(roles)),
            None,
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
    }
    let response = send(&harness, Method::GET, SUPPRESSIONS, analyst(), None, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let listing = json_body(response).await;
    assert_eq!(listing["suppressions"], json!([]));
    assert_eq!(listing["limits"]["max_suppressions"], json!(256));
    assert_eq!(
        listing["limits"]["max_ttl_seconds"],
        json!(90 * 24 * 60 * 60)
    );

    // Creating and expiring are writes: the analysis permissions do not
    // stand in for policy write, and both are decided before the body.
    let report = analyze(&harness, &etag, "json").await;
    let response = send(
        &harness,
        Method::POST,
        SUPPRESSIONS,
        analyst(),
        Some(suppression_body(&report)),
        Some(&etag),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = send(
        &harness,
        Method::DELETE,
        &format!("{SUPPRESSIONS}/pas_{}", "0".repeat(32)),
        analyst(),
        None,
        Some("\"x\""),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(events_of(
        &harness,
        audit::event::POLICY_ANALYSIS_SUPPRESSION_REFUSED,
        0
    )
    .is_empty());
}

#[tokio::test]
async fn a_suppression_hides_nothing_once_it_ends_and_is_reported_throughout() {
    let harness = harness();
    let (etag, before) = current_policy(&harness.router).await;
    let report = analyze(&harness, &etag, "json").await;
    assert_eq!(
        report["suppressions"],
        json!({ "available": true, "records": 0 })
    );
    assert_eq!(report["resource_snapshot"]["complete"], json!(true));
    assert_eq!(report["findings"][0]["code"], json!("rule_shadowed"));
    assert_eq!(report["findings"][0]["suppression"], Value::Null);

    let response = send(
        &harness,
        Method::POST,
        SUPPRESSIONS,
        writer(),
        Some(suppression_body(&report)),
        Some(&etag),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let suppression_etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("a suppression has an ETag")
        .to_owned();
    let created = json_body(response).await;
    let id = created["suppression_id"].as_str().expect("id").to_owned();
    assert!(id.starts_with("pas_"));
    assert_eq!(created["state"], json!("active"));
    assert_eq!(created["etag"], json!(suppression_etag));
    assert_eq!(created["reason"], json!(REASON_CANARY));
    assert_eq!(created["created_by"]["subject"], json!("user-123"));
    assert_eq!(created["binding"]["policy_etag"], json!(etag));
    assert_eq!(created["binding"]["policy_semantic_digest"], Value::Null);
    assert_eq!(
        created["binding"]["resource_snapshot_digest"],
        report["resource_snapshot"]["digest"]
    );

    // Suppressed: still reported, marked with its record, and counted.
    let suppressed = analyze(&harness, &etag, "json").await;
    assert_eq!(suppressed["summary"]["findings"], json!(1));
    assert_eq!(
        suppressed["findings"][0]["suppression"],
        json!({ "state": "suppressed", "suppression_id": id })
    );
    assert_eq!(
        suppressed["summary"]["by_suppression_state"]["suppressed"],
        json!(1)
    );
    assert!(!suppressed.to_string().contains(REASON_CANARY));
    let sarif = analyze(&harness, &etag, "sarif").await;
    assert_eq!(
        sarif["runs"][0]["results"][0]["suppressions"],
        json!([{
            "kind": "external",
            "status": "accepted",
            "properties": { "suppression_id": id },
        }])
    );
    assert!(!sarif.to_string().contains(REASON_CANARY));

    // Another document with the same finding is not the policy that was
    // reviewed: the record no longer binds.
    let mut candidate = suppressions_policy_document();
    candidate["routes"] = json!([
        { "methods": ["GET"], "path_prefix": "/elsewhere", "permission": "elsewhere:read" }
    ]);
    let response = send(
        &harness,
        Method::POST,
        ANALYSES,
        analyst(),
        Some(json!({
            "schema_version": "policy-analysis.v1",
            "base_etag": etag,
            "candidate": { "source": "inline", "policy": candidate },
        })),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mismatched = json_body(response).await;
    assert_eq!(
        mismatched["findings"][0]["suppression"],
        json!({
            "state": "suppression_mismatched",
            "suppression_id": id,
            "mismatched": ["policy"],
        })
    );

    // Expiring it now ends it: the finding is reported again, with the
    // record that ended.
    let response = send(
        &harness,
        Method::DELETE,
        &format!("{SUPPRESSIONS}/{id}"),
        writer(),
        None,
        Some(&suppression_etag),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let withdrawn = json_body(response).await;
    assert_eq!(withdrawn["state"], json!("withdrawn"));
    assert!(withdrawn["withdrawn_at"].is_string());
    let expired = analyze(&harness, &etag, "json").await;
    assert_eq!(
        expired["findings"][0]["suppression"],
        json!({ "state": "suppression_expired", "suppression_id": id })
    );
    let sarif = analyze(&harness, &etag, "sarif").await;
    assert_eq!(sarif["runs"][0]["results"][0]["suppressions"], json!([]));

    // An ended suppression takes no second expiry.
    let response = send(
        &harness,
        Method::DELETE,
        &format!("{SUPPRESSIONS}/{id}"),
        writer(),
        None,
        withdrawn["etag"].as_str(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_analysis_suppression_ended")
    );

    // Nothing here changed the policy.
    let (after_etag, after) = current_policy(&harness.router).await;
    assert_eq!(after_etag, etag);
    assert_eq!(after, before);

    // Audit: ids and codes only, never the reason or the fingerprint.
    let created_events = events_of(
        &harness,
        audit::event::POLICY_ANALYSIS_SUPPRESSION_CREATED,
        1,
    );
    assert_eq!(created_events.len(), 1);
    assert_eq!(
        created_events[0].payload,
        json!({ "suppression_id": id, "code": "rule_shadowed" })
    );
    let withdrawn_events = events_of(
        &harness,
        audit::event::POLICY_ANALYSIS_SUPPRESSION_WITHDRAWN,
        1,
    );
    assert_eq!(
        withdrawn_events[0].payload,
        json!({ "suppression_id": id, "code": "rule_shadowed" })
    );
    let refused = events_of(
        &harness,
        audit::event::POLICY_ANALYSIS_SUPPRESSION_REFUSED,
        1,
    );
    assert_eq!(
        refused[0].payload["reason"],
        json!("policy_analysis_suppression_ended")
    );
    let runs = events_of(&harness, audit::event::POLICY_ANALYSIS_RUN, 6);
    assert!(runs
        .iter()
        .any(|run| run.payload["summary"]["by_suppression_state"]["suppressed"] == json!(1)));
    let fingerprint = report["findings"][0]["fingerprint"]
        .as_str()
        .expect("fingerprint");
    for event in harness.capture.events() {
        let recorded = event.payload.to_string();
        assert!(!recorded.contains(REASON_CANARY), "{recorded}");
        assert!(!recorded.contains(fingerprint), "{recorded}");
    }
}

#[tokio::test]
async fn a_suppression_is_created_only_against_the_live_policy_and_current_resources() {
    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    let report = analyze(&harness, &etag, "json").await;
    let body = suppression_body(&report);
    let create = |body: Value, if_match: Option<String>| {
        let harness = &harness;
        async move {
            send(
                harness,
                Method::POST,
                SUPPRESSIONS,
                writer(),
                Some(body),
                if_match.as_deref(),
            )
            .await
        }
    };

    let response = create(body.clone(), None).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
    let response = create(body.clone(), Some("W/\"weak\"".to_owned())).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = create(body.clone(), Some("\"sha256:stale\"".to_owned())).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let refusal = json_body(response).await;
    assert_eq!(refusal["reason"], json!("policy_etag_mismatch"));
    assert_eq!(refusal["current_etag"], json!(etag));

    let mut moved = body.clone();
    moved["resource_snapshot_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let response = create(moved, Some(etag.clone())).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let refusal = json_body(response).await;
    assert_eq!(refusal["reason"], json!("resource_snapshot_stale"));
    assert_eq!(
        refusal["resource_snapshot"]["digest"],
        report["resource_snapshot"]["digest"]
    );

    for expires_in in [time::Duration::days(-1), time::Duration::days(91)] {
        let mut out_of_window = body.clone();
        out_of_window["expires_at"] = json!(rfc3339_in(expires_in));
        let response = create(out_of_window, Some(etag.clone())).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let refusal = json_body(response).await;
        assert_eq!(
            refusal["reason"],
            json!("policy_analysis_suppression_expiry_out_of_range")
        );
        assert_eq!(refusal["max_ttl_seconds"], json!(90 * 24 * 60 * 60));
    }

    // Every member is checked on its own, without repeating its value.
    let response = create(
        json!({
            "fingerprint": "sha256:short",
            "code": "every_finding",
            "reason": "line one\nline two",
            "expires_at": "next week",
            "resource_snapshot_digest": "latest",
        }),
        Some(etag.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let refusal = json_body(response).await;
    assert_eq!(
        refusal["reason"],
        json!("policy_analysis_suppression_invalid")
    );
    let pointers: Vec<&str> = refusal["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter_map(|diagnostic| diagnostic["pointer"].as_str())
        .collect();
    assert_eq!(
        pointers,
        [
            "/fingerprint",
            "/code",
            "/reason",
            "/resource_snapshot_digest",
            "/expires_at"
        ]
    );
    assert!(!refusal.to_string().contains("every_finding"));
    let long_reason = json!({ "reason": "r".repeat(513) });
    let mut too_long = body.clone();
    too_long["reason"] = long_reason["reason"].clone();
    let response = create(too_long, Some(etag.clone())).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Unknown and repeated members are refused before anything is checked:
    // there is no member that widens a suppression.
    let mut widened = body.clone();
    widened["scope"] = json!("all");
    let response = create(widened, Some(etag.clone())).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = harness
        .router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            SUPPRESSIONS,
            writer(),
            Some(format!(
                r#"{{"code":"rule_shadowed","code":"default_allow","fingerprint":{},"reason":"r","expires_at":{},"resource_snapshot_digest":{}}}"#,
                body["fingerprint"], body["expires_at"], body["resource_snapshot_digest"]
            )),
            Some(&etag),
        ))
        .await
        .expect("request completes");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_analysis_suppression_request_invalid")
    );

    // One finding under one binding is suppressed once.
    let response = create(body.clone(), Some(etag.clone())).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let id = json_body(response).await["suppression_id"].clone();
    let response = create(body, Some(etag.clone())).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let refusal = json_body(response).await;
    assert_eq!(
        refusal["reason"],
        json!("policy_analysis_suppression_exists")
    );
    assert_eq!(refusal["suppression_id"], id);

    let reasons: Vec<Value> = events_of(
        &harness,
        audit::event::POLICY_ANALYSIS_SUPPRESSION_REFUSED,
        5,
    )
    .into_iter()
    .map(|event| event.payload["reason"].clone())
    .collect();
    assert_eq!(
        reasons,
        [
            json!("policy_etag_mismatch"),
            json!("resource_snapshot_stale"),
            json!("policy_analysis_suppression_expiry_out_of_range"),
            json!("policy_analysis_suppression_expiry_out_of_range"),
            json!("policy_analysis_suppression_exists"),
        ]
    );
}

#[tokio::test]
async fn expiring_a_suppression_is_compare_and_set_on_its_etag() {
    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    let report = analyze(&harness, &etag, "json").await;
    let response = send(
        &harness,
        Method::POST,
        SUPPRESSIONS,
        writer(),
        Some(suppression_body(&report)),
        Some(&etag),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;
    let uri = format!(
        "{SUPPRESSIONS}/{}",
        created["suppression_id"].as_str().expect("id")
    );

    let response = send(&harness, Method::DELETE, &uri, writer(), None, None).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
    let response = send(
        &harness,
        Method::DELETE,
        &uri,
        writer(),
        None,
        Some("\"other\""),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_analysis_suppression_etag_mismatch")
    );
    for missing in [
        format!("{SUPPRESSIONS}/pas_{}", "0".repeat(32)),
        format!("{SUPPRESSIONS}/not-a-suppression"),
    ] {
        let response = send(
            &harness,
            Method::DELETE,
            &missing,
            writer(),
            None,
            Some(created["etag"].as_str().expect("etag")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }

    // The listing shows the record and the ETag an expiry names.
    let response = send(&harness, Method::GET, SUPPRESSIONS, analyst(), None, None).await;
    let listing = json_body(response).await;
    assert_eq!(listing["suppressions"][0]["etag"], created["etag"]);
    assert_eq!(listing["suppressions"][0]["state"], json!("active"));
    let response = send(
        &harness,
        Method::DELETE,
        &uri,
        writer(),
        None,
        Some(created["etag"].as_str().expect("etag")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(&harness, Method::GET, SUPPRESSIONS, analyst(), None, None).await;
    let listing = json_body(response).await;
    assert_eq!(listing["suppressions"][0]["state"], json!("withdrawn"));
    assert_eq!(listing["suppressions"][0]["revision"], json!(2));
}

fn suppression_request_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/policy-analysis-suppression.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// The published request schema names exactly the codes this analyzer
/// reports, and it and the gateway's checks agree on every request both can
/// judge: what the schema refuses the gateway refuses as malformed or
/// invalid, and what it admits the gateway admits.
#[tokio::test]
async fn the_published_suppression_schema_agrees_with_the_gateway() {
    let schema = suppression_request_schema();
    let codes: Vec<&str> = schema["properties"]["code"]["enum"]
        .as_array()
        .expect("the code enum")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        codes,
        policy_analysis::FindingCode::ALL
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>()
    );
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");

    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    let report = analyze(&harness, &etag, "json").await;
    let valid = suppression_body(&report);
    let with = |member: &str, value: Value| {
        let mut body = valid.clone();
        body[member] = value;
        body
    };
    let mut missing = valid.clone();
    missing.as_object_mut().expect("object").remove("reason");
    let cases = [
        (valid.clone(), true),
        (with("code", json!("default_allow")), true),
        (with("reason", json!("é".repeat(256))), true),
        (with("code", json!("all_findings")), false),
        (with("fingerprint", json!("sha256:ABC")), false),
        (with("reason", json!("")), false),
        (with("reason", json!("tab\tseparated")), false),
        (with("reason", json!(5)), false),
        (with("resource_snapshot_digest", Value::Null), false),
        (with("scope", json!("all")), false),
        (missing, false),
    ];
    for (body, admitted) in cases {
        assert_eq!(
            validator.is_valid(&body),
            admitted,
            "the schema's judgement of {body}"
        );
        let response = send(
            &harness,
            Method::POST,
            SUPPRESSIONS,
            writer(),
            Some(body.clone()),
            Some(&etag),
        )
        .await;
        let status = response.status();
        let refused_as_request = matches!(
            json_body(response).await["reason"].as_str(),
            Some("policy_analysis_suppression_request_invalid")
                | Some("policy_analysis_suppression_invalid")
        );
        assert_eq!(
            !refused_as_request, admitted,
            "the gateway's judgement of {body}: {status}"
        );
    }
}
