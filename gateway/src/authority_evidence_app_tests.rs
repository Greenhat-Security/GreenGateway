//! `AUTHORITY_EVIDENCE_DURABILITY=required` through the real admin handlers
//! (issue #425, PR 4): every standalone change the evidence inventory marks
//! refused is answered `409 authority_evidence_unsupported` before anything
//! is written, and audited once with its operation code; the changes the
//! standalone stores record in their own transactions are admitted.

use super::*;

fn required(mut config: config::Config) -> config::Config {
    config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
    config
}

fn router_with(config: config::Config, audit_log: audit::AuditLog) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
}

fn captured_audit() -> (audit::AuditLog, audit::sink::tests::CaptureSink) {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    (audit_log, capture)
}

/// Asserts the response is the refusal of `operation`, and returns nothing
/// so a caller cannot mistake it for a result.
async fn assert_refused(response: Response, operation: &str) {
    assert_eq!(response.status(), StatusCode::CONFLICT, "{operation}");
    let body = json_body(response).await;
    assert_eq!(
        body["reason"],
        json!("authority_evidence_unsupported"),
        "{body}"
    );
    assert_eq!(body["operation"], json!(operation), "{body}");
    assert_eq!(
        body["error"],
        json!(format!(
            "AUTHORITY_EVIDENCE_DURABILITY=required refuses {operation}: standalone mode records no durable evidence of it; nothing was changed"
        )),
        "{body}"
    );
}

/// The operations of the refusal events captured so far, in order, once
/// `expected` of them have arrived.
fn refused_operations(capture: &audit::sink::tests::CaptureSink, expected: usize) -> Vec<String> {
    let refusals = || {
        capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED)
            .collect::<Vec<_>>()
    };
    assert_eventually(Duration::from_secs(5), || refusals().len() >= expected);
    let refusals = refusals();
    for event in &refusals {
        assert_eq!(event.payload["deployment_mode"], json!("standalone"));
        assert_eq!(event.payload["trigger"], json!("admin_api"));
        assert_eq!(
            event.payload["reason"],
            json!("authority_evidence_unsupported")
        );
        assert!(event.actor.is_some(), "a request refusal names its caller");
    }
    refusals
        .iter()
        .map(|event| {
            event.payload["operation"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

#[tokio::test]
async fn required_evidence_refuses_every_standalone_policy_change_and_writes_nothing() {
    let rules = json!([
        direct_rule_json(Some("first-rule"), &["GET"], "/first", "allow"),
        direct_rule_json(Some("second-rule"), &["GET"], "/second", "allow"),
    ]);
    let policy = TempPolicyFile::new(&policy_document_with_rules_string(
        "initial-policy",
        rules.clone(),
    ));
    let history_db = TempDb::new("authority-evidence-policy-history");
    // A best-effort gateway leaves one version to roll back to.
    let best_effort = router_with(
        policy_admin_config_with_history(Some(&policy), Some(&history_db.path)),
        test_audit_log(),
    );
    let (etag, _) = current_policy(&best_effort).await;
    let published = best_effort
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_with_rules_string("published-policy", rules)),
            Some(&etag),
        ))
        .await
        .expect("best-effort policy PUT should complete");
    assert_eq!(published.status(), StatusCode::OK);
    drop(best_effort);

    let (audit_log, capture) = captured_audit();
    let mut config = required(policy_admin_config_with_history(
        Some(&policy),
        Some(&history_db.path),
    ));
    config.rate_limit_write_burst = 1_000;
    let router = router_with(config, audit_log);
    let (live_etag, live_policy) = current_policy(&router).await;
    let disk_before = fs::read(&policy.path).expect("policy file should read");
    let history_before = policy_history_entries(&router, None).await;

    let admin = || Some(test_principal(&["admin"]));
    let requests = [
        (
            policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                admin(),
                Some(policy_document_string("refused-policy", "test:new")),
                Some(&live_etag),
            ),
            "policy.publish",
        ),
        (
            policy_admin_request(
                Method::POST,
                &format!("{POLICY_ROLLBACK_ADMIN_ROUTE_PREFIX}/1"),
                admin(),
                None,
                Some(&live_etag),
            ),
            "policy.rollback",
        ),
        (
            policy_admin_request(
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE,
                admin(),
                Some(
                    json!({ "id": "refused-rule", "path": "/refused", "action": "allow" })
                        .to_string(),
                ),
                Some(&live_etag),
            ),
            "policy.rule.create",
        ),
        (
            policy_admin_request(
                Method::PATCH,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/first-rule"),
                admin(),
                Some(json!({ "action": "deny" }).to_string()),
                Some(&live_etag),
            ),
            "policy.rule.update",
        ),
        (
            policy_admin_request(
                Method::DELETE,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/first-rule"),
                admin(),
                None,
                Some(&live_etag),
            ),
            "policy.rule.delete",
        ),
        (
            policy_admin_request(
                Method::PUT,
                POLICY_RULES_ORDER_ADMIN_ROUTE,
                admin(),
                Some(json!(["second-rule", "first-rule"]).to_string()),
                Some(&live_etag),
            ),
            "policy.rule.reorder",
        ),
    ];
    let mut expected = Vec::new();
    for (request, operation) in requests {
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("refused policy request should complete");
        assert_refused(response, operation).await;
        expected.push(operation.to_owned());
    }

    // A draft changes no enforcement, so it is saved; publishing it is
    // `PUT /policy` and is refused the same way.
    let draft = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(POLICY_DRAFTS_ADMIN_ROUTE)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer test-token")
                .header(header::IF_MATCH, &live_etag)
                .extension(test_principal(&["admin"]))
                .body(Body::from(
                    json!({ "policy": policy_document("draft-policy", "test:new") }).to_string(),
                ))
                .expect("draft request should build"),
        )
        .await
        .expect("draft create should complete");
    assert_eq!(draft.status(), StatusCode::CREATED);
    let draft_etag = policy_etag_header(&draft);
    let draft_id = json_body(draft).await["draft_id"]
        .as_str()
        .expect("a created draft names its id")
        .to_owned();
    let publish = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}/publish"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer test-token")
                .header(header::IF_MATCH, &live_etag)
                .header(POLICY_DRAFT_ETAG_HEADER, &draft_etag)
                .extension(test_principal(&["admin"]))
                .body(Body::empty())
                .expect("publish request should build"),
        )
        .await
        .expect("draft publish should complete");
    assert_refused(publish, "policy.publish").await;
    expected.push("policy.publish".to_owned());

    // Nothing moved: the file, the live policy and its history.
    assert_eq!(
        fs::read(&policy.path).expect("policy file should read"),
        disk_before
    );
    assert_eq!(current_policy(&router).await, (live_etag, live_policy));
    assert_eq!(policy_history_entries(&router, None).await, history_before);
    assert_eq!(refused_operations(&capture, expected.len()), expected);
    // The draft publication records its own refusal under the same reason,
    // after the gate's.
    let draft_refusals = || {
        capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == audit::event::POLICY_DRAFT_PUBLISH_REFUSED)
            .collect::<Vec<_>>()
    };
    assert_eventually(Duration::from_secs(5), || !draft_refusals().is_empty());
    let draft_refusals = draft_refusals();
    assert_eq!(draft_refusals.len(), 1, "{draft_refusals:?}");
    assert_eq!(
        draft_refusals[0].payload["reason"],
        json!("authority_evidence_unsupported")
    );
}

#[tokio::test]
async fn required_evidence_refuses_a_standalone_suggestion_acceptance_before_the_rule_is_written() {
    let discovery_db = TempDb::new("authority-evidence-suggestion");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-refused",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/refused/{id}",
            role: Some("refused-reader"),
            action: "allow",
            rationale: "Observed refused-reader calls to GET /refused/{id}.",
            evidence: json!({ "observation_count": 4 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let (audit_log, capture) = captured_audit();
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let router = router_with(
        required(suggestions_admin_config(
            Some(&discovery_db.path),
            None,
            &policy,
        )),
        audit_log,
    );
    let disk_before = fs::read(&policy.path).expect("policy file should read");
    let current_etag = suggestions_policy_etag(&router).await;

    let accepted = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-refused/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&current_etag),
        ))
        .await
        .expect("accept request should complete");
    assert_refused(accepted, "policy.suggestion.accept").await;

    assert_eq!(
        fs::read(&policy.path).expect("policy file should read"),
        disk_before
    );
    let open = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=open",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(suggestion_ids(&open), vec!["sug-refused".to_owned()]);
    assert_eq!(
        refused_operations(&capture, 1),
        ["policy.suggestion.accept"]
    );
}

#[tokio::test]
async fn required_evidence_refuses_a_standalone_tools_registration_and_keeps_the_file() {
    let (audit_log, capture) = captured_audit();
    let harness = tools_admin_harness_with_options(
        empty_tools_document(),
        audit_log,
        "http://127.0.0.1:65535".to_owned(),
        tools_policy_document(),
        |config| config.authority_events.durability = config::AuthorityEvidenceDurability::Required,
        GatewayAppBuildOverrides::default(),
    )
    .await;
    let before = fs::read(&harness.tools.path).expect("tools file should read");

    let register = harness
        .router
        .clone()
        .oneshot(tools_openapi_register_request(
            &harness.admin_token,
            json!({
                "spec": widget_openapi_spec(),
                "selected_tool_names": ["createWidget"]
            }),
            Some("\"any-etag\""),
        ))
        .await
        .expect("OpenAPI tools register request should complete");
    assert_refused(register, "tools.publish").await;

    assert_eq!(
        fs::read(&harness.tools.path).expect("tools file should read"),
        before
    );
    assert_eq!(refused_operations(&capture, 1), ["tools.publish"]);
}

#[tokio::test]
async fn required_evidence_refuses_standalone_catalog_changes_and_admits_evidenced_connection_changes(
) {
    let connection_db = TempDb::new("authority-evidence-connections");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    // A best-effort gateway creates the managed OpenAPI Connection the
    // catalog requests name.
    let best_effort = connection_admin_router(&connection_db, &policy, test_audit_log());
    let collection_etag = connection_collection_etag(&best_effort).await;
    let created = best_effort
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some(managed_openapi_connection_body("Evidence target")),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("best-effort connection create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let connection_etag = response_etag(&created);
    let connection_id = json_body(created).await["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();
    drop(best_effort);

    let (audit_log, capture) = captured_audit();
    let mut config = required(connection_admin_config(
        &connection_db,
        &policy,
        config::DEFAULT_ADMIN_PREFIX,
    ));
    config.rate_limit_write_burst = 1_000;
    let router = router_with(config, audit_log);
    let superadmin = || Some(test_principal(&["connections-superadmin"]));
    let connection_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}");
    let requests = [
        (
            Method::POST,
            format!("{connection_uri}/refresh"),
            None,
            connection_etag.clone(),
            "catalog.openapi.publish",
        ),
        (
            Method::POST,
            format!("{connection_uri}/openapi/register"),
            Some(json!({ "spec": widget_openapi_spec() }).to_string()),
            connection_etag.clone(),
            "catalog.openapi.publish",
        ),
        (
            Method::PUT,
            format!("{connection_uri}/overlay"),
            Some(json!({}).to_string()),
            "\"overlay-etag\"".to_owned(),
            "catalog.overlay.replace",
        ),
        (
            Method::DELETE,
            format!("{connection_uri}/overlay"),
            None,
            "\"overlay-etag\"".to_owned(),
            "catalog.overlay.delete",
        ),
    ];
    let mut expected = Vec::new();
    for (method, uri, body, if_match, operation) in requests {
        let response = router
            .clone()
            .oneshot(connection_admin_request(
                method,
                &uri,
                superadmin(),
                body,
                Some(&if_match),
                true,
            ))
            .await
            .expect("refused catalog request should complete");
        assert_refused(response, operation).await;
        expected.push(operation.to_owned());
    }

    // The Connection is still at the revision it was created at.
    let detail = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &connection_uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("connection detail should complete");
    assert_eq!(detail.status(), StatusCode::OK);
    assert_eq!(response_etag(&detail), connection_etag);

    // The Connections database records who changes a Connection or a local
    // secret in the change's own transaction, so required mode admits them.
    let (evidence_before, _) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    let collection_etag = connection_collection_etag(&router).await;
    let admitted = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            superadmin(),
            Some(plain_connection_body("Admitted create")),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("connection create should complete");
    assert_eq!(admitted.status(), StatusCode::CREATED);
    let admitted_etag = response_etag(&admitted);
    let admitted_id = json_body(admitted).await["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();
    let deleted = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{admitted_id}"),
            superadmin(),
            None,
            Some(&admitted_etag),
            true,
        ))
        .await
        .expect("connection delete should complete");
    assert_eq!(deleted.status(), StatusCode::OK);
    let (evidence_after, _) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    assert_eq!(
        evidence_after[evidence_before.len()..]
            .iter()
            .map(|change| change.action.as_str())
            .collect::<Vec<_>>(),
        ["connection.create", "connection.delete"]
    );

    let secrets = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            superadmin(),
            None,
            None,
            false,
        ))
        .await
        .expect("secret list should complete");
    let secret_collection_etag = secrets
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("secret list should include a mutation collection ETag")
        .to_owned();
    let secret = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            superadmin(),
            Some(
                json!({ "label": "Admitted", "purpose": "static_bearer", "value": "admitted-value" })
                    .to_string(),
            ),
            Some(&secret_collection_etag),
            true,
        ))
        .await
        .expect("secret create should complete");
    assert_eq!(secret.status(), StatusCode::CREATED);
    let (secret_evidence, _) = standalone_change_evidence(
        &connection_db.path,
        "connection_local_secret_change_evidence",
    );
    assert_eq!(
        secret_evidence
            .iter()
            .map(|change| change.action.as_str())
            .collect::<Vec<_>>(),
        ["secret.create"]
    );

    // The audit writer delivers in order: once the secret's own event has
    // arrived, a refusal of an admitted change before it would have too.
    assert_eventually(Duration::from_secs(5), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::CONNECTION_SECRET_CHANGED)
    });
    assert_eq!(refused_operations(&capture, expected.len()), expected);
}

async fn connection_collection_etag(router: &Router) -> String {
    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    list.headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned()
}

fn response_etag(response: &Response) -> String {
    response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("the response should include an ETag")
        .to_owned()
}

/// Token changes record their evidence in the token store's own
/// transaction in standalone mode too, so required mode admits them.
#[tokio::test]
async fn required_evidence_admits_standalone_service_token_changes() {
    let token_db = TempDb::new("authority-evidence-tokens");
    let policy = TempPolicyFile::new(&token_policy_document_string());
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(TOKENS_ADMIN_ROUTE.to_owned());
    let (audit_log, capture) = captured_audit();
    let router = router_with(required(config), audit_log);

    let created = router
        .clone()
        .oneshot(token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(test_principal(&["tokens-writer", "probe-reader"])),
            Some(json!({ "scopes": ["probe-reader"] }).to_string()),
        ))
        .await
        .expect("token create request should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    // The audit writer delivers in order: once the change's own event has
    // arrived, a refusal before it would have too.
    assert_eventually(Duration::from_secs(5), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::SERVICE_TOKEN_CHANGED)
    });
    assert!(capture
        .events()
        .iter()
        .all(|event| event.event_type != audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED));
}
