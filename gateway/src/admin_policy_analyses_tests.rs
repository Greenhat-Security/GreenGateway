//! `POST /v1{ADMIN_PREFIX}/policy/analyses` (issue #243, slice 15) through
//! the application in standalone mode. The checks, patches and renderings
//! are covered in `policy_analysis::tests`.
use super::*;

const ANALYSES: &str = POLICY_ANALYSES_ADMIN_ROUTE;
/// A policy value an analysis must never repeat in a response or record.
const PATH_CANARY: &str = "analysis-path-canary-5c1e";

fn analyses_policy_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "id": "policy-analyses",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION,
                    ADMIN_POLICY_ANALYZE_PERMISSION
                ]
            },
            "analyst": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_ANALYZE_PERMISSION]
            },
            "policy-reader": { "permissions": [ADMIN_POLICY_READ_PERMISSION] },
            "analyst-only": { "permissions": [ADMIN_POLICY_ANALYZE_PERMISSION] },
            "simulator": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_SIMULATE_PERMISSION]
            }
        },
        "rules": [
            { "methods": ["GET"], "path": format!("/{PATH_CANARY}/**"), "action": "allow" },
            { "methods": ["GET"], "path": format!("/{PATH_CANARY}/admin"), "action": "deny" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ]
    })
}

fn analysis(base_etag: &str, candidate: Value) -> Value {
    json!({
        "schema_version": "policy-analysis.v1",
        "base_etag": base_etag,
        "candidate": candidate,
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
        &serde_json::to_string_pretty(&analyses_policy_document()).expect("policy serializes"),
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
        panic!("the analysis test app should be unified");
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

async fn analyze_request(
    harness: &Harness,
    principal: Option<auth::Principal>,
    body: String,
) -> Response {
    harness
        .router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            ANALYSES,
            principal,
            Some(body),
            None,
        ))
        .await
        .expect("policy analysis should complete")
}

/// The `policy.analysis_run` records delivered so far, waiting up to a
/// bound for `count` of them: the audit writer delivers on its own thread.
fn analysis_run_events(harness: &Harness, count: usize) -> Vec<audit::AuditEvent> {
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let events: Vec<audit::AuditEvent> = harness
            .capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == audit::event::POLICY_ANALYSIS_RUN)
            .collect();
        if events.len() >= count || Instant::now() >= deadline {
            return events;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[tokio::test]
async fn an_analysis_needs_authentication_policy_read_and_analyze() {
    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    let body = analysis(&etag, json!({ "source": "active" })).to_string();
    let response = analyze_request(&harness, None, body.clone()).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for roles in [
        &["policy-reader"][..],
        &["analyst-only"][..],
        &["simulator"][..],
    ] {
        let response = analyze_request(&harness, Some(test_principal(roles)), body.clone()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{roles:?}");
    }
    assert!(analysis_run_events(&harness, 0).is_empty());
}

#[tokio::test]
async fn an_analysis_is_pinned_to_the_active_policy_it_was_written_against() {
    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    let response = analyze_request(
        &harness,
        analyst(),
        analysis("\"sha256:0000\"", json!({ "source": "active" })).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_analysis_base_stale"));
    assert_eq!(body["current_etag"], json!(etag));

    let mut unpinned = analysis(&etag, json!({ "source": "active" }));
    unpinned
        .as_object_mut()
        .expect("object")
        .remove("base_etag");
    let response = analyze_request(&harness, analyst(), unpinned.to_string()).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("policy_analysis_invalid"));
    assert_eq!(body["diagnostics"][0]["pointer"], json!("/base_etag"));

    let duplicate = format!(
        r#"{{"schema_version":"policy-analysis.v1","base_etag":{etag:?},"base_etag":{etag:?},"candidate":{{"source":"active"}}}}"#
    );
    let response = analyze_request(&harness, analyst(), duplicate).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(analysis_run_events(&harness, 0).is_empty());
}

#[tokio::test]
async fn analyzing_the_active_policy_reports_findings_applies_nothing_and_audits_counts_only() {
    let harness = harness();
    let (etag, before) = current_policy(&harness.router).await;
    let response = analyze_request(
        &harness,
        analyst(),
        analysis(&etag, json!({ "source": "active" })).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    let report = json_body(response).await;
    assert_eq!(
        report["schema_version"],
        json!("policy-analysis-results.v1")
    );
    assert_eq!(report["base"]["etag"], json!(etag));
    assert_eq!(report["analyzed"]["source"], json!("active"));
    assert_eq!(report["analyzed"]["etag"], json!(etag));
    assert_eq!(report["complete"], json!(true));
    let codes: Vec<&str> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect();
    assert_eq!(codes, ["rule_shadowed"], "{report}");
    let finding = &report["findings"][0];
    assert_eq!(finding["proof_basis"], json!("proven"));
    assert_eq!(finding["element"]["pointer"], json!("/rules/1"));
    assert_eq!(finding["patch"]["applies_to_etag"], json!(etag));
    assert_eq!(
        finding["patch"]["edits"],
        json!([{ "op": "move", "section": "rules", "from": 1, "to": 0 }])
    );
    assert!(!report.to_string().contains(PATH_CANARY));

    // Nothing was applied: the active policy is the one analyzed.
    let (after_etag, after) = current_policy(&harness.router).await;
    assert_eq!(after_etag, etag);
    assert_eq!(after, before);

    let events = analysis_run_events(&harness, 1);
    assert_eq!(events.len(), 1);
    let payload = &events[0].payload;
    assert_eq!(payload["base_etag"], json!(etag));
    assert_eq!(payload["candidate_source"], json!("active"));
    assert_eq!(payload["complete"], json!(true));
    assert_eq!(payload["summary"]["findings"], json!(1));
    assert_eq!(payload["summary"]["by_code"]["rule_shadowed"], json!(1));
    let recorded = payload.to_string();
    for absent in [PATH_CANARY, "/rules/1", "fingerprint"] {
        assert!(!recorded.contains(absent), "{absent} in {recorded}");
    }
}

#[tokio::test]
async fn an_edited_candidate_is_analyzed_as_edited_and_an_invalid_one_refused() {
    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    // Moving the deny first resolves the finding the active policy has, and
    // a permissive default introduces one.
    let edits = json!({ "source": "edits", "edits": [
        { "op": "move", "section": "rules", "from": 1, "to": 0 },
        { "op": "set", "field": "default_action", "value": "allow" }
    ] });
    let response = analyze_request(&harness, analyst(), analysis(&etag, edits).to_string()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_body(response).await;
    assert_eq!(report["analyzed"]["source"], json!("edits"));
    assert_eq!(report["analyzed"]["edits"], json!(2));
    assert_ne!(report["analyzed"]["etag"], json!(etag));
    let codes: Vec<&str> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|finding| finding["code"].as_str())
        .collect();
    assert_eq!(codes, ["default_allow"], "{report}");
    assert_eq!(
        report["findings"][0]["patch"]["applies_to_etag"],
        report["analyzed"]["etag"]
    );

    let invalid = json!({ "source": "inline", "policy": { "schema_version": "0.1.0", "default_action": "sometimes" } });
    let response = analyze_request(&harness, analyst(), analysis(&etag, invalid).to_string()).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_candidate_invalid")
    );

    let out_of_range = json!({ "source": "edits", "edits": [
        { "op": "delete", "section": "rules", "position": 9 }
    ] });
    let response = analyze_request(
        &harness,
        analyst(),
        analysis(&etag, out_of_range).to_string(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        json_body(response).await["reason"],
        json!("policy_analysis_invalid")
    );
    assert_eq!(analysis_run_events(&harness, 1).len(), 1);
}

#[tokio::test]
async fn an_analysis_answers_sarif_on_request() {
    let harness = harness();
    let (etag, _) = current_policy(&harness.router).await;
    let mut body = analysis(&etag, json!({ "source": "active" }));
    body["format"] = json!("sarif");
    let response = analyze_request(&harness, analyst(), body.to_string()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/sarif+json"))
    );
    let sarif = json_body(response).await;
    assert_eq!(sarif["version"], json!("2.1.0"));
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        json!("policy-analysis/rule_shadowed")
    );
    assert_eq!(sarif["runs"][0]["properties"]["analyzed_etag"], json!(etag));
    let events = analysis_run_events(&harness, 1);
    assert_eq!(events[0].payload["format"], json!("sarif"));
}
