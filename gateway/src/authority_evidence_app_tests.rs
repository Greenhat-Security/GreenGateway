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

/// The standalone Connections database records managed catalog and overlay
/// publication in the publication's own transaction (its migration 13), so
/// required mode admits each of them: an OpenAPI registration, a refresh
/// from the stored document, an overlay put and an overlay delete commit with
/// one `catalog_change_evidence` row naming the authenticated principal, and
/// a stale overlay write is refused by its own precondition and records
/// nothing. Nothing is refused for its evidence.
#[tokio::test]
async fn required_evidence_admits_standalone_catalog_publication_and_records_it() {
    let connection_db = TempDb::new("authority-evidence-catalogs");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let mut config = required(connection_admin_config(
        &connection_db,
        &policy,
        config::DEFAULT_ADMIN_PREFIX,
    ));
    config.rate_limit_write_burst = 1_000;
    let router = router_with(config, audit_log);
    let (connection_id, connection_etag) =
        create_managed_openapi_connection(&router, "Evidence target").await;
    let connection_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}");
    let overlay_uri = format!("{connection_uri}/overlay");

    let registered = preview_and_register_managed_openapi(
        &router,
        &connection_id,
        &connection_etag,
        widget_openapi_spec(),
        &["createWidget"],
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    // The Connection has no discovery path, so a refresh recompiles the
    // stored document and reaches no upstream.
    let refreshed = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{connection_uri}/refresh"),
            Some(test_principal(&["connections-refresher"])),
            None,
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("catalog refresh should complete");
    assert_eq!(refreshed.status(), StatusCode::OK);

    let current = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &overlay_uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("overlay read should complete");
    assert_eq!(current.status(), StatusCode::OK);
    let initial_overlay_etag = response_etag(&current);
    let document = json!({
        "schema_version": "0.1.0",
        "tools": {
            "createWidget": {
                "rename": "overlay_widget",
                "description": "Widget operation compiled from the overlay.",
                "visibility": "listed"
            }
        }
    });
    let stored = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            Some(document.to_string()),
            Some(&initial_overlay_etag),
            true,
        ))
        .await
        .expect("overlay put should complete");
    assert_eq!(stored.status(), StatusCode::OK);
    let stored_overlay_etag = response_etag(&stored);
    let stale = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            Some(document.to_string()),
            Some(&initial_overlay_etag),
            true,
        ))
        .await
        .expect("stale overlay put should complete");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    let removed = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            None,
            Some(&stored_overlay_etag),
            true,
        ))
        .await
        .expect("overlay delete should complete");
    assert_eq!(removed.status(), StatusCode::OK);

    let (changes, stored_evidence) =
        standalone_change_evidence(&connection_db.path, "catalog_change_evidence");
    assert_eq!(
        changes
            .iter()
            .map(|change| change.action.as_str())
            .collect::<Vec<_>>(),
        [
            "catalog.openapi.publish",
            "catalog.openapi.publish",
            "catalog.overlay.replace",
            "catalog.overlay.delete",
        ]
    );
    assert!(
        changes.iter().all(|change| change.subject == "user-123"
            && change.metadata() == (None, "principal".to_owned(), "bearer_token".to_owned())),
        "{changes:?}"
    );
    for material in [
        "createWidget",
        "overlay_widget",
        "Widget",
        "openapi.example.test",
        "user@example.com",
        "org-456",
        "session-789",
    ] {
        assert!(
            !stored_evidence.contains(material),
            "{material} reached the evidence"
        );
    }

    // The audit writer delivers in order: once the overlay delete's own
    // event (the fourth catalog revision) has arrived, a refusal of any
    // change before it would have too.
    assert_eventually(Duration::from_secs(5), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::TOOL_REGISTRY_CHANGED
                && event.payload["connection_id"] == json!(connection_id)
                && event.payload["catalog_revision"] == json!(4)
        })
    });
    assert!(capture
        .events()
        .iter()
        .all(|event| event.event_type != audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED));
}

/// The Connections database records who changes a Connection or a local
/// secret in the change's own transaction, so required mode admits them.
#[tokio::test]
async fn required_evidence_admits_standalone_connection_and_secret_changes() {
    let connection_db = TempDb::new("authority-evidence-connections");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let mut config = required(connection_admin_config(
        &connection_db,
        &policy,
        config::DEFAULT_ADMIN_PREFIX,
    ));
    config.rate_limit_write_burst = 1_000;
    let router = router_with(config, audit_log);
    let superadmin = || Some(test_principal(&["connections-superadmin"]));
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
    assert!(capture
        .events()
        .iter()
        .all(|event| event.event_type != audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED));
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

// --- the keyed-change helpers every operation family uses (issue #425) -----

fn keyed_parts(keys: &[&str]) -> http::request::Parts {
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri("/v1/admin/fixture/fixture-id")
        .body(())
        .expect("request builds");
    for key in keys {
        request
            .headers_mut()
            .append("idempotency-key", key.parse().unwrap());
    }
    request.into_parts().0
}

fn issuer_bound_owner() -> auth::Principal {
    let mut owner = test_principal(&["superadmin"]);
    owner.issuer = Some("https://issuer.example.test".to_owned());
    owner
}

/// `caller_operation` binds the header to its request: no header is no key;
/// a malformed or repeated header is `400`; a principal without a canonical
/// issuer cannot own a key (`403`, as for the keyed revoke); an issuer-bound
/// principal or a service token can. The same key over two different
/// requests gives two different bindings.
#[test]
fn a_caller_key_is_bound_to_its_request_or_refused_before_anything_is_read() {
    let key = crate::auth::tokens::test_revoke_operation_id(3).to_string();
    let owner = issuer_bound_owner();
    let actor = auth::change_actor::ChangeActor::from_principal(&owner);
    let bind = |keys: &[&str], actor: &auth::change_actor::ChangeActor, body: &[u8]| {
        caller_operation(
            &keyed_parts(keys).headers,
            actor,
            "connection.replace",
            "fixture-id",
            "\"etag\"",
            body,
        )
    };
    assert_eq!(bind(&[], &actor, b"{}").expect("no key"), None);
    let first = bind(&[&key], &actor, b"{}").expect("binds").expect("a key");
    assert_eq!(first.id().to_string(), key);
    assert_eq!(first.action(), "connection.replace");
    let other = bind(&[&key], &actor, br#"{"name":"other"}"#)
        .expect("binds")
        .expect("a key");
    assert_ne!(first.binding_digest(), other.binding_digest());

    for keys in [
        vec!["not-a-uuid"],
        vec![key.as_str(), key.as_str()],
        vec!["AAAAAAAA-AAAA-7AAA-8AAA-AAAAAAAAAAAA"],
        vec!["00000000-0000-4000-8000-000000000000"],
    ] {
        let refused = bind(&keys, &actor, b"{}").expect_err("refused");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{keys:?}");
    }
    let unbound = auth::change_actor::ChangeActor::from_principal(&test_principal(&["superadmin"]));
    let refused = bind(&[&key], &unbound, b"{}").expect_err("no canonical issuer");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let mut service = test_principal(&["superadmin"]);
    service.auth_method = auth::AuthMethod::ServiceToken;
    let service = auth::change_actor::ChangeActor::from_principal(&service);
    assert!(bind(&[&key], &service, b"{}").expect("binds").is_some());
}

/// Ask `admit_keyed_authority_change` as a handler would, with no cluster
/// membership.
async fn admit_keyed(
    evidence: authority_events::required::AuthorityEvidenceGate,
    change: KeyedChange,
    caller: Option<&authority_events::caller_operation::CallerOperation>,
    request: (&audit::AuditLog, &http::request::Parts, &auth::Principal),
) -> ResponseResult<()> {
    let (audit_log, parts, principal) = request;
    let policy = client_ip::ClientIpPolicy::default();
    let gates = KeyedChangeGates {
        evidence: &evidence,
        #[cfg(feature = "postgres")]
        membership: None,
        audit: audit_log,
        client_ip_policy: &policy,
    };
    let actor = auth::change_actor::ChangeActor::from_principal(principal);
    admit_keyed_authority_change(&gates, change, caller, &actor, parts, principal).await
}

/// `admit_keyed_authority_change` asks the evidence gate with the request's
/// form, and a withdrawal never asks it. In standalone mode there is no
/// operation gate to ask; in cluster mode a keyed request with no
/// membership to ask is refused (`503 roster_unavailable`), never admitted,
/// and an unkeyed one does not ask. A change cannot be called a withdrawal
/// to skip the evidence gate: a key bound to another action, or a gated
/// change whose key is bound to a withdrawal, is refused before anything is
/// asked.
#[tokio::test]
async fn a_keyed_change_is_admitted_through_the_evidence_gate_then_the_operation_gate() {
    use authority_events::required::{AuthorityEvidenceGate, AuthorityOperation, Withdrawal};

    let (audit_log, _capture) = captured_audit();
    let owner = issuer_bound_owner();
    let actor = auth::change_actor::ChangeActor::from_principal(&owner);
    let key = crate::auth::tokens::test_revoke_operation_id(4).to_string();
    let parts = keyed_parts(&[&key]);
    let caller = caller_operation(&parts.headers, &actor, "connection.create", "", "", b"{}")
        .expect("binds")
        .expect("keyed");
    let delete = caller_operation(
        &parts.headers,
        &actor,
        "connection.delete",
        "fixture-id",
        "",
        b"",
    )
    .expect("binds")
    .expect("keyed");
    let publish = KeyedChange::Gated(AuthorityOperation::PolicyPublish);
    let withdrawal = KeyedChange::Withdrawal(Withdrawal::ConnectionDelete);
    let request = (&audit_log, &parts, &owner);
    let required = |backend| {
        AuthorityEvidenceGate::new(config::AuthorityEvidenceDurability::Required, backend)
    };

    // Standalone: the gate decides, and nothing else is asked.
    let standalone = required(config::StateBackend::Sqlite);
    let refused = admit_keyed(standalone, publish, Some(&caller), request)
        .await
        .expect_err("standalone mode records no policy evidence");
    assert_refused(*refused, "policy.publish").await;
    admit_keyed(standalone, withdrawal, Some(&delete), request)
        .await
        .expect("a withdrawal never asks the evidence gate");
    admit_keyed(standalone, withdrawal, None, request)
        .await
        .expect("an unkeyed withdrawal never asks it either");
    admit_keyed(
        AuthorityEvidenceGate::best_effort(),
        publish,
        Some(&caller),
        request,
    )
    .await
    .expect("best_effort admits");

    // A key bound to `connection.create` is not a withdrawal, and a gated
    // change cannot carry a withdrawal's key: both are handler defects,
    // refused even where every gate would admit.
    for (change, bound) in [(withdrawal, &caller), (publish, &delete)] {
        let refused = admit_keyed(
            AuthorityEvidenceGate::best_effort(),
            change,
            Some(bound),
            request,
        )
        .await
        .expect_err("the change and its key disagree");
        assert_eq!(
            refused.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "{change:?} {}",
            bound.action()
        );
    }

    // Cluster mode: an unkeyed change does not ask the operation gate; a
    // keyed one with no membership to ask is refused.
    let cluster = required(config::StateBackend::Postgres);
    admit_keyed(cluster, publish, None, request)
        .await
        .expect("cluster mode admits an unkeyed policy publication");
    let refused = admit_keyed(cluster, withdrawal, Some(&delete), request)
        .await
        .expect_err("a keyed change with no membership to ask is refused");
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    #[cfg(feature = "postgres")]
    assert_eq!(
        json_body(*refused).await["reason"],
        json!("roster_unavailable")
    );
}

/// `replayed_receipt` is the read-only pre-check: an unused key goes on; an
/// exact retry is answered with the receipt read from the committed evidence
/// (and only then is the evidence read); a key bound to anything else is
/// `409`; a failed read, or a reservation with no evidence row, is `503`.
#[tokio::test]
async fn the_pre_check_answers_an_exact_retry_with_its_receipt_and_any_other_use_with_a_conflict() {
    use authority_events::caller_operation::{CallerKeyState, OperationReceipt};
    use std::future::ready;

    let receipt = OperationReceipt {
        operation_id: crate::auth::tokens::test_revoke_operation_id(5).to_string(),
        operation: "connection.replace".to_owned(),
        resource_id: "fixture-id".to_owned(),
        revision: Some(2),
        committed_at: "2026-11-20T12:00:00Z".to_owned(),
    };
    let unread = || async { panic!("the evidence is read only for an exact retry") };
    replayed_receipt(ready(Ok(CallerKeyState::Unused)), unread())
        .await
        .expect("an unused key goes on");

    let replayed = replayed_receipt(
        ready(Ok(CallerKeyState::SameBinding)),
        ready(Ok(Some(receipt.clone()))),
    )
    .await
    .expect_err("an exact retry is answered");
    assert_eq!(replayed.status(), StatusCode::OK);
    assert_eq!(
        replayed.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(
        json_body(*replayed).await,
        json!({
            "operation_id": receipt.operation_id,
            "operation": "connection.replace",
            "resource_id": "fixture-id",
            "revision": 2,
            "committed_at": "2026-11-20T12:00:00Z",
        })
    );

    let conflict = replayed_receipt(ready(Ok(CallerKeyState::OtherBinding)), unread())
        .await
        .expect_err("another binding conflicts");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(*conflict).await["reason"],
        json!(CALLER_OPERATION_CONFLICT_REASON)
    );

    let failed = replayed_receipt(
        ready(Err(storage::RepositoryError::new(
            storage::RepositoryErrorKind::Unavailable,
            "fixture",
        ))),
        unread(),
    )
    .await
    .expect_err("an unreadable key refuses");
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let orphan = replayed_receipt(ready(Ok(CallerKeyState::SameBinding)), ready(Ok(None)))
        .await
        .expect_err("a reservation without its evidence refuses");
    assert_eq!(orphan.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// The gate a deployment runs is built from its configuration, and only the
/// file sink meets the sink criterion: a keyed, issuer-bound preparation
/// under `qualified_v1` is refused with the log sink or no sink, naming the
/// sink, and admitted with the file sink on a Unix build (on any other build
/// it is refused for the filesystem instead).
#[test]
fn the_configured_gate_admits_a_keyed_change_only_with_the_file_sink() {
    use authority_events::required::{
        AuthorityEvidenceGate, AuthorityOperation, KeyedAdmission, RequestForm,
    };

    let form = RequestForm::of(
        true,
        &auth::change_actor::ChangeActor::from_principal(&issuer_bound_owner()),
    );
    assert_eq!(
        form,
        RequestForm {
            keyed: true,
            issuer_bound_principal: true
        }
    );
    let unmet = |sink: config::AuthorityEventSinkSetting| {
        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
        config.authority_events.format = config::AuthorityEventFormat::QualifiedV1;
        config.authority_events.sink = sink;
        AuthorityEvidenceGate::from_config(&config)
            .refusal_for(AuthorityOperation::MutationApprovalPrepare, form)
            .and_then(|refusal| refusal.unmet())
    };
    assert_eq!(
        unmet(config::AuthorityEventSinkSetting::Log),
        Some(KeyedAdmission::FileSink)
    );
    assert_eq!(
        unmet(config::AuthorityEventSinkSetting::None),
        Some(KeyedAdmission::FileSink)
    );
    assert_eq!(
        unmet(config::AuthorityEventSinkSetting::File(
            "/var/lib/greengateway/authority-events.jsonl".to_owned()
        )),
        (!cfg!(unix)).then_some(KeyedAdmission::SyncedFilesystem)
    );
}
