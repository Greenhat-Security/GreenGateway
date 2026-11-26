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
    // The gate is asked before the draft is read (I4): publishing a draft
    // that does not exist is the same refusal, not `404`.
    let missing = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("{POLICY_DRAFTS_ADMIN_ROUTE}/no-such-draft/publish"))
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
    assert_refused(missing, "policy.publish").await;
    expected.push("policy.publish".to_owned());

    // Nothing moved: the file, the live policy and its history.
    assert_eq!(
        fs::read(&policy.path).expect("policy file should read"),
        disk_before
    );
    assert_eq!(current_policy(&router).await, (live_etag, live_policy));
    assert_eq!(policy_history_entries(&router, None).await, history_before);
    assert_eq!(refused_operations(&capture, expected.len()), expected);
    // Each draft publication records its own refusal under the same reason,
    // after the gate's, naming the draft from its path; the draft was not
    // read, so nothing else about it is recorded.
    let draft_refusals = || {
        capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == audit::event::POLICY_DRAFT_PUBLISH_REFUSED)
            .collect::<Vec<_>>()
    };
    assert_eventually(Duration::from_secs(5), || draft_refusals().len() >= 2);
    let draft_refusals = draft_refusals();
    assert_eq!(draft_refusals.len(), 2, "{draft_refusals:?}");
    let mut refused_ids = Vec::new();
    for refusal in &draft_refusals {
        assert_eq!(
            refusal.payload["reason"],
            json!("authority_evidence_unsupported")
        );
        assert_eq!(refusal.payload["draft_revision"], Value::Null);
        refused_ids.push(refusal.payload["draft_id"].clone());
    }
    refused_ids.sort_by_key(|id| id.to_string());
    let mut expected_ids = vec![json!(draft_id), json!("no-such-draft")];
    expected_ids.sort_by_key(|id| id.to_string());
    assert_eq!(refused_ids, expected_ids);
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
    bind_seeded_suggestions(&router, &discovery_db.path).await;
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

/// Required mode admits a catalog publication or overlay change only in its
/// keyed form (issue #425): an unkeyed OpenAPI registration, refresh, overlay
/// put and overlay delete are each refused before anything is read or
/// written, audited once with their operation code, and record nothing.
#[tokio::test]
async fn required_evidence_refuses_every_unkeyed_standalone_catalog_publication() {
    let connection_db = TempDb::new("authority-evidence-catalogs");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let mut config = connection_admin_config(&connection_db, &policy, config::DEFAULT_ADMIN_PREFIX);
    config.rate_limit_write_burst = 1_000;
    // Required mode admits a Connection create only in its keyed form, so the
    // target is created before required mode is on.
    let best_effort = router_with(config.clone(), test_audit_log());
    let (id, etag) = create_managed_openapi_connection(&best_effort, "Evidence target").await;
    let registration = openapi_registration_body(&best_effort, &id, &["createWidget"]).await;
    let overlay = overlay_etag(&best_effort, &id).await;
    drop(best_effort);
    let router = router_with(required(config), audit_log);

    for (call, if_match, body) in [
        (CatalogCall::Register, &etag, Some(registration)),
        (CatalogCall::Refresh, &etag, None),
        (
            CatalogCall::OverlayPut,
            &overlay,
            Some(catalog_overlay_document()),
        ),
        (CatalogCall::OverlayDelete, &overlay, None),
    ] {
        let (status, _, refused) = exchange(
            &router,
            call.request(&id, if_match, body, keyed_admin(CATALOG_ROLES), None),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{call:?}: {refused}");
        assert_eq!(refused["reason"], json!("authority_evidence_unsupported"));
        assert_eq!(refused["operation"], json!(call.operation()));
        assert_eq!(
            refused["error"],
            json!(format!(
                "AUTHORITY_EVIDENCE_DURABILITY=required refuses {}: standalone mode admits it only with an Idempotency-Key, on a route that honours one; nothing was changed",
                call.operation()
            ))
        );
    }
    let (evidence, _) = standalone_change_evidence(&connection_db.path, "catalog_change_evidence");
    assert!(evidence.is_empty(), "{evidence:?}");
    assert!(standalone_reservations(&connection_db.path).is_empty());
    assert_eq!(
        refused_operations(&capture, 4),
        CatalogCall::ALL.map(CatalogCall::operation)
    );
}

/// Every role the four catalog routes need between them.
const CATALOG_ROLES: &[&str] = &[
    "connections-reader",
    "connections-editor",
    "connections-refresher",
    "openapi-tools-reader",
    "openapi-tools-writer",
];

/// The four keyed catalog routes (issue #425).
#[derive(Clone, Copy, Debug)]
enum CatalogCall {
    Register,
    Refresh,
    OverlayPut,
    OverlayDelete,
}

impl CatalogCall {
    const ALL: [Self; 4] = [
        Self::Register,
        Self::Refresh,
        Self::OverlayPut,
        Self::OverlayDelete,
    ];

    fn operation(self) -> &'static str {
        match self {
            Self::Register | Self::Refresh => "catalog.openapi.publish",
            Self::OverlayPut => "catalog.overlay.replace",
            Self::OverlayDelete => "catalog.overlay.delete",
        }
    }

    /// The route's request on Connection `id`; `if_match` is the Connection's
    /// ETag for a registration or refresh, the overlay's for an overlay change.
    fn request(
        self,
        id: &str,
        if_match: &str,
        body: Option<String>,
        principal: auth::Principal,
        key: Option<&str>,
    ) -> Request<Body> {
        let (method, uri) = self.route(id);
        keyed_connection_request(method, &uri, principal, body, Some(if_match), key)
    }

    /// The route's method and URI on Connection `id`.
    fn route(self, id: &str) -> (Method, String) {
        let route = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");
        match self {
            Self::Register => (Method::POST, format!("{route}/openapi/register")),
            Self::Refresh => (Method::POST, format!("{route}/refresh")),
            Self::OverlayPut => (Method::PUT, format!("{route}/overlay")),
            Self::OverlayDelete => (Method::DELETE, format!("{route}/overlay")),
        }
    }
}

/// A registration body for the widget specification on Connection `id`,
/// taken from a preview of it, selecting `selected`.
async fn openapi_registration_body(router: &Router, id: &str, selected: &[&str]) -> String {
    let spec = widget_openapi_spec();
    let (status, _, preview) = exchange(
        router,
        connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{id}/openapi/preview"),
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": spec }).to_string()),
            None,
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let confirmations = preview["security_confirmations"]
        .as_array()
        .expect("the preview lists security confirmations")
        .iter()
        .filter(|confirmation| {
            selected
                .iter()
                .any(|name| confirmation["tool_name"] == json!(name))
        })
        .cloned()
        .collect::<Vec<_>>();
    json!({
        "spec": spec,
        "spec_digest": preview["spec_digest"],
        "expected_spec_revision": preview["spec_revision"],
        "expected_catalog_revision": preview["catalog_revision"],
        "selected_tool_names": selected,
        "security_confirmations": confirmations,
    })
    .to_string()
}

/// The current overlay ETag of Connection `id`.
async fn overlay_etag(router: &Router, id: &str) -> String {
    let (status, etag, body) = exchange(
        router,
        connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{id}/overlay"),
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    etag.expect("the overlay names its ETag")
}

fn catalog_overlay_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "tools": {
            "createWidget": {
                "rename": "overlay_widget",
                "description": "Widget operation compiled from the overlay.",
                "visibility": "listed"
            }
        }
    })
    .to_string()
}

/// Asserts `receipt` is the five-field receipt of `operation` under `key`
/// on Connection `id` at catalog revision `revision`.
fn assert_catalog_receipt(receipt: &Value, key: &str, operation: &str, id: &str, revision: u64) {
    assert_eq!(receipt["operation_id"], json!(key), "{receipt}");
    assert_eq!(receipt["operation"], json!(operation), "{receipt}");
    assert_eq!(receipt["resource_id"], json!(id), "{receipt}");
    assert_eq!(receipt["revision"], json!(revision), "{receipt}");
    assert_eq!(
        receipt.as_object().map(serde_json::Map::len),
        Some(5),
        "{receipt}"
    );
}

/// The managed catalog publications audited for Connection `id` (a
/// registration or overlay change as a registry change, a refresh as a
/// refresh), once the one at `revision` has arrived; the audit writer
/// delivers in order.
fn catalog_changes_through(
    capture: &audit::sink::tests::CaptureSink,
    id: &str,
    revision: u64,
) -> usize {
    let changes = || {
        capture
            .events()
            .into_iter()
            .filter(|event| {
                (event.event_type == audit::event::TOOL_REGISTRY_CHANGED
                    || event.event_type == audit::event::CONNECTION_REFRESHED)
                    && event.payload["connection_id"] == json!(id)
            })
            .collect::<Vec<_>>()
    };
    assert_eventually(Duration::from_secs(5), || {
        changes()
            .iter()
            .any(|event| event.payload["catalog_revision"] == json!(revision))
    });
    changes().len()
}

/// An exact retry of a keyed OpenAPI registration, refresh, overlay put and
/// overlay delete is answered `200` with the receipt read from the committed
/// catalog evidence, and repeats no side effect: no second publication,
/// evidence row, reservation or audit event. A key used on another catalog
/// route is `409 caller_operation_conflict` and changes nothing.
#[tokio::test]
async fn a_replayed_catalog_change_repeats_no_side_effect() {
    let connection_db = TempDb::new("keyed-catalog-replay");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |_| {});
    let admin = keyed_admin(CATALOG_ROLES);
    let (id, etag) = create_managed_openapi_connection(&router, "Keyed catalog").await;
    let registration = openapi_registration_body(&router, &id, &["createWidget"]).await;
    let keys: Vec<String> = (60..64).map(caller_key).collect();
    let mut receipts = Vec::new();

    let register = || {
        CatalogCall::Register.request(
            &id,
            &etag,
            Some(registration.clone()),
            admin.clone(),
            Some(&keys[0]),
        )
    };
    let (status, _, registered) = exchange(&router, register()).await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    let (status, _, receipt) = exchange(&router, register()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_catalog_receipt(&receipt, &keys[0], "catalog.openapi.publish", &id, 1);
    receipts.push(receipt);
    // The registration's key on the refresh route is not this request.
    let (status, _, conflict) = exchange(
        &router,
        CatalogCall::Refresh.request(&id, &etag, None, admin.clone(), Some(&keys[0])),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["reason"], json!(CALLER_OPERATION_CONFLICT_REASON));

    let refresh = || CatalogCall::Refresh.request(&id, &etag, None, admin.clone(), Some(&keys[1]));
    let (status, _, refreshed) = exchange(&router, refresh()).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let (status, _, receipt) = exchange(&router, refresh()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_catalog_receipt(&receipt, &keys[1], "catalog.openapi.publish", &id, 2);
    receipts.push(receipt);

    let initial_overlay = overlay_etag(&router, &id).await;
    let put = || {
        CatalogCall::OverlayPut.request(
            &id,
            &initial_overlay,
            Some(catalog_overlay_document()),
            admin.clone(),
            Some(&keys[2]),
        )
    };
    let (status, stored_overlay, stored) = exchange(&router, put()).await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    let stored_overlay = stored_overlay.expect("the overlay put names its ETag");
    let (status, _, receipt) = exchange(&router, put()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_catalog_receipt(&receipt, &keys[2], "catalog.overlay.replace", &id, 3);
    receipts.push(receipt);
    // `allow_unresolved_enum_sources` is bound: the same put with the flag
    // set is another request.
    let (_, overlay_route) = CatalogCall::OverlayPut.route(&id);
    let (status, _, conflict) = exchange(
        &router,
        keyed_connection_request(
            Method::PUT,
            &format!("{overlay_route}?allow_unresolved_enum_sources=true"),
            admin.clone(),
            Some(catalog_overlay_document()),
            Some(&initial_overlay),
            Some(&keys[2]),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["reason"], json!(CALLER_OPERATION_CONFLICT_REASON));

    let delete = || {
        CatalogCall::OverlayDelete.request(
            &id,
            &stored_overlay,
            None,
            admin.clone(),
            Some(&keys[3]),
        )
    };
    let (status, _, removed) = exchange(&router, delete()).await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    let (status, _, receipt) = exchange(&router, delete()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_catalog_receipt(&receipt, &keys[3], "catalog.overlay.delete", &id, 4);
    receipts.push(receipt);

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
        ],
        "each change committed once"
    );
    assert!(
        changes.iter().all(|change| change.subject == "user-123"
            && change.metadata()
                == (
                    Some(KEYED_ISSUER.to_owned()),
                    "principal".to_owned(),
                    "bearer_token".to_owned()
                )),
        "{changes:?}"
    );
    let reservations = standalone_reservations(&connection_db.path);
    assert_eq!(
        reservations
            .iter()
            .map(|(key, action, _)| (key.clone(), action.clone()))
            .collect::<std::collections::BTreeSet<_>>(),
        keys.iter()
            .cloned()
            .zip(CatalogCall::ALL.map(|call| call.operation().to_owned()))
            .collect::<std::collections::BTreeSet<_>>()
    );
    assert_eq!(
        catalog_changes_through(&capture, &id, 4),
        4,
        "no replay audited a second change"
    );

    // I5: no specification, overlay or caller detail reached the evidence,
    // and the binding digests stay in the reservation rows.
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
    let audited = format!("{:?}", capture.events());
    let receipts = format!("{receipts:?}");
    for (_, _, digest) in reservations {
        let digest = digest.expect("every catalog key is bound by digest");
        assert!(
            !audited.contains(&digest),
            "a digest reached the audit stream"
        );
        assert!(!receipts.contains(&digest), "a digest reached a receipt");
        assert!(
            !stored_evidence.contains(&digest),
            "a digest reached the evidence"
        );
    }
}

/// A standalone router whose managed OpenAPI Connection discovers its
/// specification at a loopback upstream that counts every fetch, with the
/// widget catalog registered unkeyed: the router, the audit capture, the
/// Connection's ID and ETag, and the fetch count.
struct DiscoveringCatalog {
    router: Router,
    capture: audit::sink::tests::CaptureSink,
    id: String,
    etag: String,
    body: Value,
    fetches: Arc<std::sync::atomic::AtomicUsize>,
    _connection_db: TempDb,
    _policy: TempPolicyFile,
}

impl DiscoveringCatalog {
    async fn new(name: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let fetches = Arc::new(AtomicUsize::new(0));
        let served = Arc::clone(&fetches);
        let upstream = spawn_router(Router::new().fallback(any(move || {
            served.fetch_add(1, Ordering::SeqCst);
            async { widget_openapi_spec() }
        })))
        .await;
        let connection_db = TempDb::new(name);
        let policy = TempPolicyFile::new(&connection_policy_document_string());
        let (audit_log, capture) = captured_audit();
        let router = keyed_connection_router(&connection_db, &policy, audit_log, |config| {
            config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
            config.egress_deny_private_ips = false;
        });
        let mut body: Value =
            serde_json::from_str(&managed_openapi_connection_body("Discovering catalog"))
                .expect("the managed OpenAPI body parses");
        body["endpoint"]["base_url"] = json!(format!("http://{upstream}"));
        body["discovery"]["path"] = json!("/openapi.json");
        let collection_etag = connection_collection_etag(&router).await;
        let (status, etag, created) = exchange(
            &router,
            connection_admin_request(
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE,
                Some(test_principal(&["connections-editor"])),
                Some(body.to_string()),
                Some(&collection_etag),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().expect("an ID").to_owned();
        let etag = etag.expect("the create names its ETag");
        Self {
            router,
            capture,
            id,
            etag,
            body,
            fetches,
            _connection_db: connection_db,
            _policy: policy,
        }
    }

    fn fetches(&self) -> usize {
        self.fetches.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn route(&self) -> String {
        format!("{CONNECTIONS_ADMIN_ROUTE}/{}", self.id)
    }

    /// Replace the Connection with a new display name, which moves its ETag.
    async fn replace(&mut self, display_name: &str) {
        self.body["display_name"] = json!(display_name);
        let (status, etag, replaced) = exchange(
            &self.router,
            connection_admin_request(
                Method::PUT,
                &self.route(),
                Some(test_principal(&["connections-editor"])),
                Some(self.body.to_string()),
                Some(&self.etag),
                true,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{replaced}");
        self.etag = etag.expect("the replacement names its ETag");
    }

    /// An unkeyed refresh, which fetches the upstream and publishes.
    async fn refresh_unkeyed(&self) {
        let (status, _, body) = exchange(
            &self.router,
            CatalogCall::Refresh.request(
                &self.id,
                &self.etag,
                None,
                test_principal(CATALOG_ROLES),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

/// The handler answers an exact retry of a keyed refresh from its receipt
/// before it contacts the upstream (issue #425): the retry fetches nothing
/// and audits no second catalog change. The key is looked up before its
/// `If-Match` is compared with the Connection's ETag, so the retry is
/// answered so even after the Connection was replaced; an unused key with
/// the stale precondition is `412`.
#[tokio::test]
async fn a_replayed_refresh_does_not_fetch_the_upstream_again_or_audit_a_second_change() {
    let mut catalog = DiscoveringCatalog::new("keyed-refresh-upstream").await;
    let registration =
        openapi_registration_body(&catalog.router, &catalog.id, &["createWidget"]).await;
    let (status, _, registered) = exchange(
        &catalog.router,
        CatalogCall::Register.request(
            &catalog.id,
            &catalog.etag,
            Some(registration),
            test_principal(CATALOG_ROLES),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    let key = caller_key(64);
    let (id, first_etag) = (catalog.id.clone(), catalog.etag.clone());
    let refresh = || {
        CatalogCall::Refresh.request(
            &id,
            &first_etag,
            None,
            keyed_admin(CATALOG_ROLES),
            Some(&key),
        )
    };
    let before = catalog.fetches();
    let (status, _, refreshed) = exchange(&catalog.router, refresh()).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    let per_refresh = catalog.fetches() - before;
    assert!(per_refresh > 0, "a first refresh fetches the upstream");

    catalog.replace("Discovering catalog, renamed").await;
    let before = catalog.fetches();
    let (status, _, receipt) = exchange(&catalog.router, refresh()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_catalog_receipt(&receipt, &key, "catalog.openapi.publish", &catalog.id, 2);
    assert_eq!(
        catalog.fetches(),
        before,
        "the retry contacted the upstream"
    );
    // One more publication, so that any event the retry emitted would have
    // arrived before its own.
    catalog.refresh_unkeyed().await;
    assert_eq!(
        catalog_changes_through(&catalog.capture, &catalog.id, 3),
        3,
        "the retry audited a second change"
    );
    let (status, _, stale) = exchange(
        &catalog.router,
        CatalogCall::Refresh.request(
            &id,
            &first_etag,
            None,
            keyed_admin(CATALOG_ROLES),
            Some(&caller_key(66)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{stale}");
}

/// The same for an OpenAPI registration: an exact retry is answered from its
/// receipt before anything is generated, contacts no upstream, and audits no
/// second catalog change. The retry follows a replacement of the Connection,
/// so its `If-Match` is stale: only the handler's pre-check, which runs
/// before the precondition and before the catalog service, can answer it
/// with the receipt.
#[tokio::test]
async fn a_replayed_openapi_registration_does_not_fetch_the_upstream_again_or_audit_a_second_change(
) {
    let mut catalog = DiscoveringCatalog::new("keyed-registration-upstream").await;
    let registration =
        openapi_registration_body(&catalog.router, &catalog.id, &["createWidget"]).await;
    let key = caller_key(65);
    let (id, first_etag) = (catalog.id.clone(), catalog.etag.clone());
    let register = || {
        CatalogCall::Register.request(
            &id,
            &first_etag,
            Some(registration.clone()),
            keyed_admin(CATALOG_ROLES),
            Some(&key),
        )
    };
    let (status, _, registered) = exchange(&catalog.router, register()).await;
    assert_eq!(status, StatusCode::CREATED, "{registered}");
    catalog.replace("Discovering catalog, renamed").await;
    let fetched = catalog.fetches();
    let (status, _, receipt) = exchange(&catalog.router, register()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_catalog_receipt(&receipt, &key, "catalog.openapi.publish", &catalog.id, 1);
    assert_eq!(
        catalog.fetches(),
        fetched,
        "the retry contacted the upstream"
    );
    catalog.refresh_unkeyed().await;
    assert_eq!(
        catalog_changes_through(&catalog.capture, &catalog.id, 2),
        2,
        "the retry audited a second change"
    );
}

/// I4 end to end: required mode refuses each unkeyed catalog publication and
/// overlay change before anything is written, and admits the keyed request
/// of an issuer-bound principal under `qualified_v1` with the file sink.
#[tokio::test]
#[cfg_attr(
    not(unix),
    ignore = "required mode admits keyed catalog changes only on a Unix build, where the file sink syncs its directory"
)]
async fn required_mode_refuses_the_unkeyed_catalog_publication_and_admits_the_keyed_principal() {
    let connection_db = TempDb::new("keyed-catalog-required");
    let events = TempDb::new("keyed-catalog-required-events");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let best_effort = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let (id, etag) = create_managed_openapi_connection(&best_effort, "Required catalog").await;
    let registration = openapi_registration_body(&best_effort, &id, &["createWidget"]).await;
    drop(best_effort);
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |config| {
        qualified_required(config, &events)
    });
    let admin = keyed_admin(CATALOG_ROLES);
    let mut overlay = String::new();
    for (seed, call) in (66..).zip(CatalogCall::ALL) {
        if matches!(call, CatalogCall::OverlayPut) {
            overlay = overlay_etag(&router, &id).await;
        }
        let (if_match, body) = match call {
            CatalogCall::Register => (&etag, Some(registration.clone())),
            CatalogCall::Refresh => (&etag, None),
            CatalogCall::OverlayPut => (&overlay, Some(catalog_overlay_document())),
            CatalogCall::OverlayDelete => (&overlay, None),
        };
        let (status, _, refused) = exchange(
            &router,
            call.request(&id, if_match, body.clone(), admin.clone(), None),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{call:?}: {refused}");
        assert_eq!(refused["operation"], json!(call.operation()));
        let (status, next_overlay, admitted) = exchange(
            &router,
            call.request(&id, if_match, body, admin.clone(), Some(&caller_key(seed))),
        )
        .await;
        assert!(status.is_success(), "{call:?}: {status} {admitted}");
        if matches!(call, CatalogCall::OverlayPut) {
            overlay = next_overlay.expect("the overlay put names its ETag");
        }
    }
    let (evidence, _) = standalone_change_evidence(&connection_db.path, "catalog_change_evidence");
    assert_eq!(
        evidence
            .iter()
            .map(|change| change.action.as_str())
            .collect::<Vec<_>>(),
        CatalogCall::ALL.map(CatalogCall::operation)
    );
    assert_eq!(standalone_reservations(&connection_db.path).len(), 4);
    assert_eq!(
        refused_operations(&capture, 4),
        CatalogCall::ALL.map(CatalogCall::operation)
    );
}

/// The rest of the gate: required mode refuses each keyed catalog change by
/// a gateway service token, under `delivery_v1`, or with the log sink, and
/// each refusal names the criterion; nothing is written or reserved.
#[tokio::test]
async fn required_mode_refuses_a_keyed_catalog_publication_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink(
) {
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let events = TempDb::new("keyed-catalog-refused-events");
    for (case, requirement) in [
        (
            "service token",
            "from a provider-authenticated principal with a canonical issuer",
        ),
        ("delivery_v1", "with AUTHORITY_EVENT_FORMAT=qualified_v1"),
        ("log sink", "with AUTHORITY_EVENT_SINK=file"),
    ] {
        let principal = match case {
            "service token" => service_token_admin(CATALOG_ROLES),
            _ => keyed_admin(CATALOG_ROLES),
        };
        let connection_db = TempDb::new("keyed-catalog-refused");
        let best_effort =
            keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
        let (id, etag) = create_managed_openapi_connection(&best_effort, "Refused catalog").await;
        let registration = openapi_registration_body(&best_effort, &id, &["createWidget"]).await;
        let overlay = overlay_etag(&best_effort, &id).await;
        drop(best_effort);
        let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |config| {
            qualified_required(config, &events);
            match case {
                "delivery_v1" => {
                    config.authority_events.format = config::AuthorityEventFormat::DeliveryV1;
                }
                "log sink" => config.authority_events.sink = config::AuthorityEventSinkSetting::Log,
                _ => {}
            }
        });
        for (seed, (call, if_match, body)) in (70..).zip([
            (CatalogCall::Register, &etag, Some(registration)),
            (CatalogCall::Refresh, &etag, None),
            (
                CatalogCall::OverlayPut,
                &overlay,
                Some(catalog_overlay_document()),
            ),
            (CatalogCall::OverlayDelete, &overlay, None),
        ]) {
            let (status, _, refused) = exchange(
                &router,
                call.request(
                    &id,
                    if_match,
                    body,
                    principal.clone(),
                    Some(&caller_key(seed)),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{case} {call:?}: {refused}");
            assert_eq!(
                refused["error"],
                json!(format!(
                    "AUTHORITY_EVIDENCE_DURABILITY=required refuses {}: standalone mode admits it only {requirement}; nothing was changed",
                    call.operation()
                )),
                "{case} {call:?}"
            );
        }
        let (evidence, _) =
            standalone_change_evidence(&connection_db.path, "catalog_change_evidence");
        assert!(evidence.is_empty(), "{case}");
        assert!(
            standalone_reservations(&connection_db.path).is_empty(),
            "{case}"
        );
    }
}

/// Authorization comes before the key: each catalog change below was first
/// committed under its key by an authorized caller, so a handler that bound
/// and pre-checked the key before authorizing would answer the exact retry
/// of a caller without the route's permission with its receipt. It is `403`,
/// asks no gate and reserves nothing (in cluster mode it leaves the contract
/// fence unchanged; `cluster_connection_keys` proves that against
/// PostgreSQL).
#[tokio::test]
async fn a_keyed_catalog_change_without_the_routes_permission_is_forbidden_and_reserves_nothing() {
    let connection_db = TempDb::new("keyed-catalog-forbidden");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let admin = keyed_admin(CATALOG_ROLES);
    let reader = keyed_admin(&["connections-reader", "openapi-tools-reader"]);
    let (id, etag) = create_managed_openapi_connection(&router, "Forbidden catalog").await;
    let registration = openapi_registration_body(&router, &id, &["createWidget"]).await;
    let mut overlay = String::new();
    for (seed, call) in (74..).zip(CatalogCall::ALL) {
        if matches!(call, CatalogCall::OverlayPut) {
            overlay = overlay_etag(&router, &id).await;
        }
        let (if_match, body) = match call {
            CatalogCall::Register => (etag.clone(), Some(registration.clone())),
            CatalogCall::Refresh => (etag.clone(), None),
            CatalogCall::OverlayPut => (overlay.clone(), Some(catalog_overlay_document())),
            CatalogCall::OverlayDelete => (overlay.clone(), None),
        };
        let key = caller_key(seed);
        let (status, next_overlay, committed) = exchange(
            &router,
            call.request(&id, &if_match, body.clone(), admin.clone(), Some(&key)),
        )
        .await;
        assert!(status.is_success(), "{call:?}: {status} {committed}");
        if matches!(call, CatalogCall::OverlayPut) {
            overlay = next_overlay.expect("the overlay put names its ETag");
        }
        let (status, _, refused) = exchange(
            &router,
            call.request(&id, &if_match, body, reader.clone(), Some(&key)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{call:?}: {refused}");
    }
    assert_eq!(standalone_reservations(&connection_db.path).len(), 4);
}

/// The Connections database records who changes a Connection or a local
/// secret in the change's own transaction. Required mode admits the local
/// secret changes and every form of a Connection deletion; a Connection
/// create is admitted only in its keyed form (issue #425), so an unkeyed one
/// is refused before anything is written.
#[tokio::test]
async fn required_evidence_admits_standalone_withdrawals_and_refuses_unkeyed_creates() {
    let connection_db = TempDb::new("authority-evidence-connections");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let mut config = connection_admin_config(&connection_db, &policy, config::DEFAULT_ADMIN_PREFIX);
    config.rate_limit_write_burst = 1_000;
    let superadmin = || Some(test_principal(&["connections-superadmin"]));
    // The Connection to delete is created before required mode is on.
    let best_effort = router_with(config.clone(), test_audit_log());
    let collection_etag = connection_collection_etag(&best_effort).await;
    let admitted = best_effort
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
    drop(best_effort);
    let router = router_with(required(config), audit_log);
    let (evidence_before, _) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    let collection_etag = connection_collection_etag(&router).await;
    let refused = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            superadmin(),
            Some(plain_connection_body("Refused create")),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("connection create should complete");
    assert_eq!(refused.status(), StatusCode::CONFLICT);
    let refused = json_body(refused).await;
    assert_eq!(refused["reason"], json!("authority_evidence_unsupported"));
    assert_eq!(refused["operation"], json!("connection.create"));
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
        ["connection.delete"],
        "the refused create wrote nothing; the unkeyed delete is admitted"
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
    // An unkeyed local-secret create is refused too (issue #425, plan P8).
    assert_eq!(secret.status(), StatusCode::CONFLICT);
    let refused = json_body(secret).await;
    assert_eq!(refused["operation"], json!("secret.create"));
    let (secret_evidence, _) = standalone_change_evidence(
        &connection_db.path,
        "connection_local_secret_change_evidence",
    );
    assert!(secret_evidence.is_empty());
    assert_eq!(
        refused_operations(&capture, 2),
        ["connection.create", "secret.create"],
        "only the unkeyed creates were refused"
    );
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
/// asked. Nor can a gated change be asked about under another operation's
/// name: its key must be bound to that operation's code.
#[tokio::test]
async fn a_keyed_change_is_admitted_through_the_evidence_gate_then_the_operation_gate() {
    use authority_events::required::{AuthorityEvidenceGate, AuthorityOperation, Withdrawal};

    let (audit_log, capture) = captured_audit();
    let owner = issuer_bound_owner();
    let actor = auth::change_actor::ChangeActor::from_principal(&owner);
    let key = crate::auth::tokens::test_revoke_operation_id(4).to_string();
    let parts = keyed_parts(&[&key]);
    let caller = caller_operation(&parts.headers, &actor, "connection.create", "", "", b"{}")
        .expect("binds")
        .expect("keyed");
    let publish_key = caller_operation(&parts.headers, &actor, "policy.publish", "", "", b"{}")
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
    let refused = admit_keyed(standalone, publish, Some(&publish_key), request)
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
        Some(&publish_key),
        request,
    )
    .await
    .expect("best_effort admits");

    // A key bound to `connection.create` is not a withdrawal, a gated
    // change cannot carry a withdrawal's key, and a policy publication
    // cannot carry a key bound to `connection.create`: all are handler
    // defects, refused even where every gate would admit.
    for (change, bound) in [
        (withdrawal, &caller),
        (publish, &delete),
        (publish, &caller),
    ] {
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
    // The mismatch is refused before any gate is asked: where the evidence
    // gate would refuse, it is still the 500, not that gate's 409, and no
    // evidence refusal is audited for it. The publication that follows is
    // the second audited refusal of this test, not the third.
    let refused = admit_keyed(standalone, publish, Some(&caller), request)
        .await
        .expect_err("the change and its key disagree");
    assert_eq!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let refused = admit_keyed(standalone, publish, Some(&publish_key), request)
        .await
        .expect_err("standalone mode records no policy evidence");
    assert_refused(*refused, "policy.publish").await;
    assert_eq!(
        refused_operations(&capture, 2),
        ["policy.publish", "policy.publish"]
    );

    // Cluster mode: an unkeyed change does not ask the operation gate; a
    // keyed one with no membership to ask is refused.
    // (Required mode admits a policy publication only keyed since issue
    // #425, so the unkeyed one is asked under best effort.)
    let cluster = required(config::StateBackend::Postgres);
    admit_keyed(
        AuthorityEvidenceGate::new(
            config::AuthorityEvidenceDurability::BestEffort,
            config::StateBackend::Postgres,
        ),
        publish,
        None,
        request,
    )
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

// --- keyed Connection create, replace and delete (issue #425) --------------

const KEYED_ISSUER: &str = "https://issuer.example.test";

/// A provider-authenticated principal with a canonical issuer and `roles`.
fn keyed_admin(roles: &[&str]) -> auth::Principal {
    let mut principal = test_principal(roles);
    principal.issuer = Some(KEYED_ISSUER.to_owned());
    principal
}

/// A gateway service token holding `roles`.
fn service_token_admin(roles: &[&str]) -> auth::Principal {
    let mut principal = test_principal(roles);
    principal.auth_method = auth::AuthMethod::ServiceToken;
    principal
}

/// A Connection admin request, with `key` as its `Idempotency-Key`.
fn keyed_connection_request(
    method: Method,
    uri: &str,
    principal: auth::Principal,
    body: Option<String>,
    if_match: Option<&str>,
    key: Option<&str>,
) -> Request<Body> {
    let mut request = connection_admin_request(method, uri, Some(principal), body, if_match, true);
    if let Some(key) = key {
        request
            .headers_mut()
            .insert("idempotency-key", key.parse().expect("the key is a header"));
    }
    request
}

/// The status, ETag (if any) and JSON body of one request.
async fn exchange(router: &Router, request: Request<Body>) -> (StatusCode, Option<String>, Value) {
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the request completes");
    let status = response.status();
    let etag = response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (status, etag, json_body(response).await)
}

/// A disabled HTTP Connection whose credential and proxy header name the
/// given aliases.
fn aliased_connection_body(display_name: &str, secret_id: &str, header_secret_id: &str) -> String {
    json!({
        "display_name": display_name,
        "enabled": false,
        "kind": "http_api",
        "endpoint": {"base_url": "https://keyed.example.test", "base_path": "/v1"},
        "authentication": {"type": "static_bearer", "secret_id": secret_id},
        "additional_headers": [{"header_name": "x-proxy-token", "secret_id": header_secret_id}]
    })
    .to_string()
}

/// Every reservation in a standalone Connections database.
fn standalone_reservations(path: &FsPath) -> Vec<(String, String, Option<String>)> {
    let connection = rusqlite::Connection::open(path).expect("the database opens");
    let mut statement = connection
        .prepare(
            "SELECT operation_id, action, binding_digest \
             FROM authority_caller_operation_ids ORDER BY operation_id",
        )
        .expect("the reservation query prepares");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("the reservations read")
        .collect::<Result<_, _>>()
        .expect("every reservation reads")
}

fn caller_key(seed: u8) -> String {
    crate::authority_events::caller_operation::test_caller_key(seed).to_string()
}

/// A standalone Connections router with the connection admin policy.
fn keyed_connection_router(
    connection_db: &TempDb,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
    configure: impl FnOnce(&mut config::Config),
) -> Router {
    let mut config = connection_admin_config(connection_db, policy, config::DEFAULT_ADMIN_PREFIX);
    config.rate_limit_write_burst = 1_000;
    configure(&mut config);
    router_with(config, audit_log)
}

/// Required mode with every delivery criterion a keyed change needs: the
/// negotiated format and the file sink at `events`.
fn qualified_required(config: &mut config::Config, events: &TempDb) {
    config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
    config.authority_events.format = config::AuthorityEventFormat::QualifiedV1;
    config.authority_events.sink =
        config::AuthorityEventSinkSetting::File(events.path.to_string_lossy().into_owned());
}

/// An exact retry of a keyed create, replace and delete is answered `200`
/// with the receipt read from the committed evidence, and repeats no side
/// effect: no second change, evidence row or audit event. A conflicting use
/// of a key is `409 caller_operation_conflict` and changes nothing.
#[tokio::test]
async fn a_replayed_connection_change_repeats_no_side_effect() {
    let connection_db = TempDb::new("keyed-connection-replay");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |_| {});
    let admin = keyed_admin(&["connections-superadmin"]);
    let collection_etag = connection_collection_etag(&router).await;
    let create_key = caller_key(1);
    let body = aliased_connection_body("Keyed API", "keyed-alias", "keyed-header-alias");
    let create = || {
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            admin.clone(),
            Some(body.clone()),
            Some(&collection_etag),
            Some(&create_key),
        )
    };
    let (status, etag, created) = exchange(&router, create()).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("an ID").to_owned();
    let etag = etag.expect("the create names its ETag");
    let (status, _, receipt) = exchange(&router, create()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["operation_id"], json!(create_key));
    assert_eq!(receipt["operation"], json!("connection.create"));
    assert_eq!(receipt["resource_id"], json!(id));
    assert_eq!(receipt["revision"], json!(1));
    assert_eq!(receipt.as_object().map(|object| object.len()), Some(5));

    let route = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");
    let replace_key = caller_key(2);
    let replacement =
        aliased_connection_body("Keyed API", "keyed-alias-next", "keyed-header-alias");
    let replace = |body: &str| {
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(body.to_owned()),
            Some(&etag),
            Some(&replace_key),
        )
    };
    let (status, replaced_etag, replaced) = exchange(&router, replace(&replacement)).await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    let replaced_etag = replaced_etag.expect("the replace names its ETag");
    let (status, _, receipt) = exchange(&router, replace(&replacement)).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["operation"], json!("connection.replace"));
    assert_eq!(receipt["operation_id"], json!(replace_key));
    // The same key over another body is not this request.
    let other = aliased_connection_body("Keyed API", "keyed-alias-other", "keyed-header-alias");
    let (status, _, conflict) = exchange(&router, replace(&other)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["reason"], json!(CALLER_OPERATION_CONFLICT_REASON));

    let delete_key = caller_key(3);
    let delete = || {
        keyed_connection_request(
            Method::DELETE,
            &route,
            admin.clone(),
            None,
            Some(&replaced_etag),
            Some(&delete_key),
        )
    };
    let (status, _, deleted) = exchange(&router, delete()).await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    let (status, _, receipt) = exchange(&router, delete()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a committed delete is answered after the record is gone: {receipt}"
    );
    assert_eq!(receipt["operation"], json!("connection.delete"));
    assert_eq!(receipt["resource_id"], json!(id));
    // Unkeyed, the same delete finds no record.
    let (status, _, _) = exchange(
        &router,
        keyed_connection_request(
            Method::DELETE,
            &route,
            admin.clone(),
            None,
            Some(&replaced_etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A committed replacement is answered from its receipt after the record
    // is gone too; unkeyed, the same replacement finds no record.
    let (status, _, receipt) = exchange(&router, replace(&replacement)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a committed replacement is answered after the record is gone: {receipt}"
    );
    assert_eq!(receipt["operation"], json!("connection.replace"));
    assert_eq!(receipt["operation_id"], json!(replace_key));
    assert_eq!(receipt["resource_id"], json!(id));
    let (status, _, conflict) = exchange(&router, replace(&other)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    let (status, _, _) = exchange(
        &router,
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(replacement.clone()),
            Some(&etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (evidence, _) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    assert_eq!(
        evidence
            .iter()
            .map(|change| change.action.as_str())
            .collect::<Vec<_>>(),
        [
            "connection.create",
            "connection.replace",
            "credential.binding_change",
            "connection.delete"
        ],
        "each change committed once"
    );
    assert_eq!(standalone_reservations(&connection_db.path).len(), 3);
    // The audit writer delivers in order: once the delete's event has
    // arrived, every earlier one has too.
    let changes = || {
        capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_CHANGED)
            .count()
    };
    assert_eventually(Duration::from_secs(5), || changes() >= 3);
    assert_eq!(changes(), 3, "no replay emitted a second change event");
    // I5: the binding digests stay in the reservation rows, and no alias
    // reached a receipt or the audit stream.
    let audited = format!("{:?}", capture.events());
    let receipts = format!("{receipt}");
    for (_, _, digest) in standalone_reservations(&connection_db.path) {
        let digest = digest.expect("every Connection key is bound by digest");
        assert!(
            !audited.contains(&digest),
            "a digest reached the audit stream"
        );
        assert!(!receipts.contains(&digest), "a digest reached a receipt");
    }
    for alias in ["keyed-alias", "keyed-header-alias"] {
        assert!(!audited.contains(alias), "{alias} reached the audit stream");
        assert!(!receipts.contains(alias), "{alias} reached a receipt");
    }
}

/// A retry that points the Connection at another credential under the same
/// key -- another `authentication.secret_id` or another additional header's
/// `secret_id` -- is `409` and keeps the binding the key committed. The
/// aliases are in the binding; so is a token exchange's `client_secret_id`.
#[tokio::test]
async fn a_different_credential_reference_under_the_same_key_conflicts_and_keeps_the_old_binding() {
    let connection_db = TempDb::new("keyed-connection-aliases");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let admin = keyed_admin(&["connections-superadmin"]);
    let collection_etag = connection_collection_etag(&router).await;
    let key = caller_key(10);
    let original = aliased_connection_body("Aliased API", "alias-original", "header-original");
    let (status, _, created) = exchange(
        &router,
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            admin.clone(),
            Some(original),
            Some(&collection_etag),
            Some(&key),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("an ID").to_owned();
    for changed in [
        aliased_connection_body("Aliased API", "alias-changed", "header-original"),
        aliased_connection_body("Aliased API", "alias-original", "header-changed"),
    ] {
        let (status, _, conflict) = exchange(
            &router,
            keyed_connection_request(
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE,
                admin.clone(),
                Some(changed),
                Some(&collection_etag),
                Some(&key),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
        assert_eq!(conflict["reason"], json!(CALLER_OPERATION_CONFLICT_REASON));
    }
    let stored = connections::store::SqliteConnectionStore::open(&connection_db.path)
        .expect("the store opens");
    let records = connections::store::ConnectionStore::list(&stored).expect("the store lists");
    assert_eq!(records.len(), 1, "no second Connection");
    assert_eq!(records[0].id.as_str(), id);
    assert_eq!(
        serde_json::to_value(&records[0].write).expect("the record serializes")["authentication"]
            ["secret_id"],
        json!("alias-original")
    );
    assert_eq!(
        records[0].write.additional_headers[0].secret_id.as_deref(),
        Some("header-original")
    );

    // A token exchange's client secret alias is bound the same way.
    let actor = auth::change_actor::ChangeActor::from_principal(&admin);
    let mut headers = HeaderMap::new();
    headers.insert("idempotency-key", key.parse().unwrap());
    headers.insert(header::IF_MATCH, "\"collection\"".parse().unwrap());
    let digest = |client_secret_id: &str| {
        let body = json!({"authentication": {"type": "delegated_issuer_token", "client_secret_id": client_secret_id}});
        caller_operation(
            &headers,
            &actor,
            "connection.create",
            "",
            "\"collection\"",
            &canonical_connection_request(body.to_string().as_bytes()).unwrap(),
        )
        .unwrap()
        .unwrap()
        .binding_digest()
        .to_owned()
    };
    assert_ne!(digest("exchange-secret-a"), digest("exchange-secret-b"));
}

/// The request a key is bound to is the body as canonical JSON: key order
/// and whitespace do not change it, any value does.
#[test]
fn the_canonical_connection_request_ignores_key_order_and_whitespace() {
    let ordered = br#"{"a":1,"b":{"c":[1,{"e":2,"d":3}]}}"#;
    let reordered = b"{ \"b\" : {\"c\":[1,{\"d\":3,\"e\":2}]},\n \"a\":1}";
    assert_eq!(
        canonical_connection_request(ordered).unwrap(),
        canonical_connection_request(reordered).unwrap()
    );
    assert_ne!(
        canonical_connection_request(ordered).unwrap(),
        canonical_connection_request(br#"{"a":2,"b":{"c":[1,{"e":2,"d":3}]}}"#).unwrap()
    );
    assert!(canonical_connection_request(b"").unwrap().is_empty());
    assert_eq!(
        canonical_connection_request(b"not json")
            .expect_err("invalid JSON")
            .status(),
        StatusCode::BAD_REQUEST
    );
}

/// I4 end to end: required mode refuses the unkeyed Connection create and
/// replace before anything is written, and admits the keyed request of an
/// issuer-bound principal under `qualified_v1` with the file sink.
#[tokio::test]
#[cfg_attr(
    not(unix),
    ignore = "required mode admits keyed Connection changes only on a Unix build, where the file sink syncs its directory"
)]
async fn required_mode_refuses_the_unkeyed_connection_create_and_replace_and_admits_the_keyed_principal(
) {
    let connection_db = TempDb::new("keyed-connection-required");
    let events = TempDb::new("keyed-connection-required-events");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |config| {
        qualified_required(config, &events)
    });
    let admin = keyed_admin(&["connections-superadmin"]);
    let collection_etag = connection_collection_etag(&router).await;
    let body = aliased_connection_body("Required API", "required-alias", "required-header");
    let (status, _, refused) = exchange(
        &router,
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            admin.clone(),
            Some(body.clone()),
            Some(&collection_etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["reason"], json!("authority_evidence_unsupported"));
    assert_eq!(
        refused["error"],
        json!("AUTHORITY_EVIDENCE_DURABILITY=required refuses connection.create: standalone mode admits it only with an Idempotency-Key, on a route that honours one; nothing was changed")
    );
    let (status, etag, created) = exchange(
        &router,
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            admin.clone(),
            Some(body),
            Some(&collection_etag),
            Some(&caller_key(20)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("an ID").to_owned();
    let etag = etag.expect("an ETag");
    let route = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");
    let replacement =
        aliased_connection_body("Required API renamed", "required-alias", "required-header");
    let (status, _, refused) = exchange(
        &router,
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(replacement.clone()),
            Some(&etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["operation"], json!("connection.replace"));
    let (status, _, replaced) = exchange(
        &router,
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(replacement),
            Some(&etag),
            Some(&caller_key(21)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    let (evidence, _) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    assert_eq!(
        evidence
            .iter()
            .map(|change| change.action.as_str())
            .collect::<Vec<_>>(),
        ["connection.create", "connection.replace"]
    );
    assert_eq!(
        refused_operations(&capture, 2),
        ["connection.create", "connection.replace"]
    );
}

/// The rest of the gate: required mode refuses a keyed Connection create by
/// a gateway service token, under `delivery_v1`, or with the log sink, and
/// each refusal names the criterion; nothing is written or reserved.
#[tokio::test]
async fn required_mode_refuses_a_keyed_connection_change_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink(
) {
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let events = TempDb::new("keyed-connection-refused-events");
    for (case, requirement) in [
        (
            "service token",
            "from a provider-authenticated principal with a canonical issuer",
        ),
        ("delivery_v1", "with AUTHORITY_EVENT_FORMAT=qualified_v1"),
        ("log sink", "with AUTHORITY_EVENT_SINK=file"),
    ] {
        let principal = match case {
            "service token" => service_token_admin(&["connections-superadmin"]),
            _ => keyed_admin(&["connections-superadmin"]),
        };
        let connection_db = TempDb::new("keyed-connection-refused");
        let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |config| {
            qualified_required(config, &events);
            match case {
                "delivery_v1" => {
                    config.authority_events.format = config::AuthorityEventFormat::DeliveryV1;
                }
                "log sink" => config.authority_events.sink = config::AuthorityEventSinkSetting::Log,
                _ => {}
            }
        });
        let collection_etag = connection_collection_etag(&router).await;
        let (status, _, refused) = exchange(
            &router,
            keyed_connection_request(
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE,
                principal,
                Some(aliased_connection_body(
                    "Refused API",
                    "refused-alias",
                    "refused-header",
                )),
                Some(&collection_etag),
                Some(&caller_key(30)),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{case}: {refused}");
        assert_eq!(
            refused["error"],
            json!(format!(
                "AUTHORITY_EVIDENCE_DURABILITY=required refuses connection.create: standalone mode admits it only {requirement}; nothing was changed"
            )),
            "{case}"
        );
        let (evidence, _) =
            standalone_change_evidence(&connection_db.path, "connection_change_evidence");
        assert!(evidence.is_empty(), "{case}");
        assert!(
            standalone_reservations(&connection_db.path).is_empty(),
            "{case}"
        );
    }
}

/// Connection deletion is a withdrawal: required mode admits every form of
/// it -- unkeyed, keyed, and by a gateway service token -- and each records
/// its evidence (owner ruling 4 on issue #425).
#[tokio::test]
async fn required_mode_admits_every_form_of_connection_delete() {
    let connection_db = TempDb::new("keyed-connection-withdrawal");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let best_effort = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let admin = keyed_admin(&["connections-superadmin"]);
    let mut created = Vec::new();
    for name in ["Unkeyed delete", "Keyed delete", "Service token delete"] {
        let collection_etag = connection_collection_etag(&best_effort).await;
        let (status, etag, body) = exchange(
            &best_effort,
            keyed_connection_request(
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE,
                admin.clone(),
                Some(plain_connection_body(name)),
                Some(&collection_etag),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        created.push((body["id"].as_str().unwrap().to_owned(), etag.unwrap()));
    }
    drop(best_effort);
    let events = TempDb::new("keyed-connection-withdrawal-events");
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |config| {
        qualified_required(config, &events);
        // Even where no keyed creation could be admitted, a withdrawal is.
        config.authority_events.sink = config::AuthorityEventSinkSetting::Log;
    });
    let forms = [
        (admin.clone(), None),
        (admin.clone(), Some(caller_key(40))),
        (service_token_admin(&["connections-superadmin"]), None),
    ];
    for ((id, etag), (principal, key)) in created.iter().zip(forms) {
        let (status, _, body) = exchange(
            &router,
            keyed_connection_request(
                Method::DELETE,
                &format!("{CONNECTIONS_ADMIN_ROUTE}/{id}"),
                principal,
                None,
                Some(etag),
                key.as_deref(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (evidence, _) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    let deletes: Vec<_> = evidence
        .iter()
        .filter(|change| change.action == "connection.delete")
        .map(|change| change.kind.as_str())
        .collect();
    assert_eq!(deletes, ["principal", "principal", "service_token"]);
    assert_eq!(standalone_reservations(&connection_db.path).len(), 1);
    assert_eventually(Duration::from_secs(5), || {
        capture
            .events()
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_CHANGED)
            .count()
            >= 3
    });
    assert!(capture
        .events()
        .iter()
        .all(|event| event.event_type != audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED));
}

/// Authorization comes before the key: a keyed request from a caller without
/// the route's permission is `403` and asks no gate, reads no key and
/// reserves nothing (in cluster mode it leaves the contract fence unchanged;
/// `cluster_connection_keys` proves that against PostgreSQL). Each key below
/// was first committed by an authorized caller with another body, so a
/// handler that bound and pre-checked the key before authorizing would
/// answer `409 caller_operation_conflict` instead.
#[tokio::test]
async fn a_keyed_connection_change_without_the_routes_permission_is_forbidden_and_reserves_nothing()
{
    let connection_db = TempDb::new("keyed-connection-forbidden");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let admin = keyed_admin(&["connections-superadmin"]);
    let reader = keyed_admin(&["connections-reader"]);
    let editor = keyed_admin(&["connections-editor"]);
    let plain_key = caller_key(50);
    let aliased_key = caller_key(51);
    let mut committed = Vec::new();
    for (key, body) in [
        (&plain_key, plain_connection_body("Committed API")),
        (
            &aliased_key,
            aliased_connection_body("Committed aliased API", "alias", "header"),
        ),
    ] {
        let collection_etag = connection_collection_etag(&router).await;
        let (status, etag, created) = exchange(
            &router,
            keyed_connection_request(
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE,
                admin.clone(),
                Some(body),
                Some(&collection_etag),
                Some(key),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        committed.push((
            format!(
                "{CONNECTIONS_ADMIN_ROUTE}/{}",
                created["id"].as_str().unwrap()
            ),
            etag.expect("an ETag"),
        ));
    }
    let reserved = standalone_reservations(&connection_db.path);
    assert_eq!(reserved.len(), 2);
    let collection_etag = connection_collection_etag(&router).await;
    let (route, etag) = &committed[1];
    let forbidden = [
        // No write permission at all.
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            reader.clone(),
            Some(plain_connection_body("Forbidden API")),
            Some(&collection_etag),
            Some(&plain_key),
        ),
        keyed_connection_request(
            Method::PUT,
            route,
            reader.clone(),
            Some(plain_connection_body("Forbidden API")),
            Some(etag),
            Some(&plain_key),
        ),
        keyed_connection_request(
            Method::DELETE,
            route,
            reader,
            None,
            Some(etag),
            Some(&plain_key),
        ),
        // Binding a credential needs secret authority too, and so does
        // replacing or deleting a Connection that holds one.
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            editor.clone(),
            Some(aliased_connection_body("Forbidden API", "alias", "header")),
            Some(&collection_etag),
            Some(&aliased_key),
        ),
        keyed_connection_request(
            Method::PUT,
            route,
            editor.clone(),
            Some(aliased_connection_body("Forbidden API", "alias", "header")),
            Some(etag),
            Some(&aliased_key),
        ),
        keyed_connection_request(
            Method::DELETE,
            route,
            editor,
            None,
            Some(etag),
            Some(&aliased_key),
        ),
    ];
    for request in forbidden {
        let what = format!("{} {}", request.method(), request.uri());
        let (status, _, body) = exchange(&router, request).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {body}");
    }
    assert_eq!(standalone_reservations(&connection_db.path), reserved);
    let (evidence, _) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    assert_eq!(
        evidence
            .iter()
            .map(|change| change.action.as_str())
            .collect::<Vec<_>>(),
        ["connection.create", "connection.create"],
        "nothing changed"
    );
}

/// Required mode authorizes before it asks the evidence gate: an unkeyed
/// Connection create by a caller without the route's permission, or without
/// secret authority for a credentialed body, is `403`, not `409
/// authority_evidence_unsupported`, and is not audited as an evidence
/// refusal. The authorized caller's unkeyed create is then refused by the
/// gate, and its refusal is the only one audited.
#[tokio::test]
async fn required_mode_authorizes_a_connection_change_before_it_asks_the_evidence_gate() {
    let connection_db = TempDb::new("keyed-connection-required-authz");
    let events = TempDb::new("keyed-connection-required-authz-events");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |config| {
        qualified_required(config, &events)
    });
    let collection_etag = connection_collection_etag(&router).await;
    for (principal, body) in [
        (
            keyed_admin(&["connections-reader"]),
            plain_connection_body("Unauthorized API"),
        ),
        (
            keyed_admin(&["connections-editor"]),
            aliased_connection_body("Unauthorized API", "alias", "header"),
        ),
    ] {
        let (status, _, body) = exchange(
            &router,
            keyed_connection_request(
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE,
                principal,
                Some(body),
                Some(&collection_etag),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
    let (status, _, refused) = exchange(
        &router,
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            keyed_admin(&["connections-superadmin"]),
            Some(plain_connection_body("Refused API")),
            Some(&collection_etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["reason"], json!("authority_evidence_unsupported"));
    // The audit writer delivers in order: the authorized caller's refusal
    // is the first and only one.
    assert_eq!(refused_operations(&capture, 1), ["connection.create"]);
    let (evidence, _) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    assert!(evidence.is_empty());
    assert!(standalone_reservations(&connection_db.path).is_empty());
}

/// Drive `request` through `router` until `committed` says its change is in
/// the store, then drop it: what a client that disconnects at that moment
/// leaves behind. The store's own transaction keeps running when a handler's
/// future is dropped (SQLite runs it on the blocking pool). Returns whether
/// the request was dropped unanswered; `false` means it was answered before
/// the commit was observed, so nothing was abandoned.
pub(super) async fn abandon_once_committed(
    router: &Router,
    request: Request<Body>,
    committed: impl Fn() -> bool,
) -> bool {
    let mut in_flight = std::pin::pin!(router.clone().oneshot(request));
    for _ in 0..10_000 {
        if committed() {
            return true;
        }
        let polled = std::future::poll_fn(|context| {
            std::task::Poll::Ready(std::future::Future::poll(in_flight.as_mut(), context))
        })
        .await;
        if polled.is_ready() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("the change never committed");
}

/// The status, ETag and body of `GET` on `route` once `settled` accepts
/// them, or the last answer after five seconds.
async fn settled_get(
    router: &Router,
    route: &str,
    principal: &auth::Principal,
    settled: impl Fn(StatusCode, &Value) -> bool,
) -> (StatusCode, Option<String>, Value) {
    let started = Instant::now();
    loop {
        let (status, etag, body) = exchange(
            router,
            keyed_connection_request(Method::GET, route, principal.clone(), None, None, None),
        )
        .await;
        if settled(status, &body) || started.elapsed() > Duration::from_secs(5) {
            return (status, etag, body);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A Connection change runs to completion once admitted, even when its
/// client goes away while the store is committing it: the runtime snapshot
/// this replica serves, and the audit stream, then show the change, and the
/// keyed retry's receipt describes what this replica serves. Before the
/// change ran on its own task, the dropped handler left the replica serving
/// the replaced or deleted Connection after the retry was told the change
/// had committed.
#[tokio::test]
async fn an_admitted_connection_change_finishes_after_its_client_goes_away() {
    let connection_db = TempDb::new("keyed-connection-abandoned");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |_| {});
    let admin = keyed_admin(&["connections-superadmin"]);
    let collection_etag = connection_collection_etag(&router).await;
    let (status, etag, created) = exchange(
        &router,
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            admin.clone(),
            Some(aliased_connection_body(
                "Abandoned API",
                "abandoned-alias",
                "abandoned-header",
            )),
            Some(&collection_etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("an ID").to_owned();
    let route = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");
    let etag = etag.expect("an ETag");
    let recorded = |action: &'static str| {
        let path = connection_db.path.clone();
        move || {
            standalone_change_evidence(&path, "connection_change_evidence")
                .0
                .iter()
                .any(|change| change.action == action)
        }
    };

    let replace_key = caller_key(60);
    let replacement = aliased_connection_body(
        "Abandoned API renamed",
        "abandoned-alias-next",
        "abandoned-header",
    );
    let replace = || {
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(replacement.clone()),
            Some(&etag),
            Some(&replace_key),
        )
    };
    abandon_once_committed(&router, replace(), recorded("connection.replace")).await;
    let (status, _, receipt) = exchange(&router, replace()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["operation"], json!("connection.replace"));
    let (status, replaced_etag, served) = settled_get(&router, &route, &admin, |status, body| {
        status == StatusCode::OK && body["display_name"] == json!("Abandoned API renamed")
    })
    .await;
    assert_eq!(status, StatusCode::OK, "{served}");
    assert_eq!(
        served["display_name"],
        json!("Abandoned API renamed"),
        "the replica serves the replacement its retry was told committed"
    );
    let replaced_etag = replaced_etag.expect("the detail names its ETag");

    let delete_key = caller_key(61);
    let delete = || {
        keyed_connection_request(
            Method::DELETE,
            &route,
            admin.clone(),
            None,
            Some(&replaced_etag),
            Some(&delete_key),
        )
    };
    abandon_once_committed(&router, delete(), recorded("connection.delete")).await;
    let (status, _, receipt) = exchange(&router, delete()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["operation"], json!("connection.delete"));
    let (status, _, served) = settled_get(&router, &route, &admin, |status, _| {
        status == StatusCode::NOT_FOUND
    })
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the replica no longer serves the Connection its retry was told is deleted: {served}"
    );
    let stored = connections::store::SqliteConnectionStore::open(&connection_db.path)
        .expect("the store opens");
    assert!(connections::store::ConnectionStore::list(&stored)
        .expect("the store lists")
        .is_empty());
    // Each change emitted its audit event once, though nobody waited for
    // its response.
    let changes = || {
        capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_CHANGED)
            .count()
    };
    assert_eventually(Duration::from_secs(5), || changes() >= 3);
    assert_eq!(changes(), 3);
}

/// Keyed Connection changes in cluster mode, through the admin handlers of a
/// PostgreSQL-backed replica with a real roster (issue #425). The verified-TLS
/// CI shard selects this module by its prefix.
/// A keyed replacement of a Connection that is no longer in the snapshot is
/// validated as a replacement before its key is admitted (issue #425):
/// admission can raise the cluster's contract fence on its first use, so an
/// invalid body must be refused first. Under required mode with the log
/// sink, where admission refuses every keyed replacement, an invalid body is
/// `400` and a valid one reaches admission and is refused there; neither
/// reserves anything.
#[tokio::test]
async fn a_keyed_replacement_of_a_missing_connection_is_validated_before_admission() {
    let connection_db = TempDb::new("keyed-connection-missing-replace");
    let events = TempDb::new("keyed-connection-missing-replace-events");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let admin = keyed_admin(&["connections-superadmin"]);
    let best_effort = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let collection_etag = connection_collection_etag(&best_effort).await;
    let (status, etag, created) = exchange(
        &best_effort,
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            admin.clone(),
            Some(plain_connection_body("Missing API")),
            Some(&collection_etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let route = format!(
        "{CONNECTIONS_ADMIN_ROUTE}/{}",
        created["id"].as_str().expect("an ID")
    );
    let etag = etag.expect("an ETag");
    let (status, _, deleted) = exchange(
        &best_effort,
        keyed_connection_request(
            Method::DELETE,
            &route,
            admin.clone(),
            None,
            Some(&etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    drop(best_effort);
    let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |config| {
        qualified_required(config, &events);
        config.authority_events.sink = config::AuthorityEventSinkSetting::Log;
    });

    let mut invalid: Value =
        serde_json::from_str(&plain_connection_body("Missing API")).expect("the body parses");
    invalid["endpoint"]["base_url"] = json!("not a URL");
    let (status, _, refused) = exchange(
        &router,
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(invalid.to_string()),
            Some(&etag),
            Some(&caller_key(90)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
    let (status, _, refused) = exchange(
        &router,
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(plain_connection_body("Missing API")),
            Some(&etag),
            Some(&caller_key(91)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["reason"], json!("authority_evidence_unsupported"));
    assert!(standalone_reservations(&connection_db.path).is_empty());
}

/// A keyed registration or overlay change aimed at a Connection without
/// managed OpenAPI discovery is refused before its key is admitted (issue
/// #425). Under required mode with the log sink, where admission refuses
/// every keyed catalog change, each is answered with the Connection's own
/// refusal, not admission's, and nothing is reserved.
#[tokio::test]
async fn a_keyed_catalog_change_on_a_connection_without_openapi_discovery_is_refused_before_admission(
) {
    let connection_db = TempDb::new("keyed-catalog-wrong-kind");
    let events = TempDb::new("keyed-catalog-wrong-kind-events");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let best_effort = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let collection_etag = connection_collection_etag(&best_effort).await;
    let (status, etag, created) = exchange(
        &best_effort,
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            keyed_admin(&["connections-superadmin"]),
            Some(plain_connection_body("Plain API")),
            Some(&collection_etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("an ID").to_owned();
    let etag = etag.expect("an ETag");
    drop(best_effort);
    let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |config| {
        qualified_required(config, &events);
        config.authority_events.sink = config::AuthorityEventSinkSetting::Log;
    });
    let registration = json!({
        "spec": "openapi: 3.0.0",
        "spec_digest": "0".repeat(64),
        "expected_spec_revision": 0,
        "expected_catalog_revision": 0,
        "selected_tool_names": [],
        "security_confirmations": [],
    })
    .to_string();
    for (seed, (call, if_match, body)) in (92..).zip([
        (CatalogCall::Register, etag.as_str(), Some(registration)),
        (
            CatalogCall::OverlayPut,
            "\"overlay\"",
            Some(catalog_overlay_document()),
        ),
        (CatalogCall::OverlayDelete, "\"overlay\"", None),
    ]) {
        let (status, _, refused) = exchange(
            &router,
            call.request(
                &id,
                if_match,
                body,
                keyed_admin(CATALOG_ROLES),
                Some(&caller_key(seed)),
            ),
        )
        .await;
        assert!(status.is_client_error(), "{call:?}: {status} {refused}");
        assert_ne!(
            refused["reason"],
            json!("authority_evidence_unsupported"),
            "{call:?} was admitted first"
        );
        assert!(
            refused.to_string().contains("discovery_not_configured"),
            "{call:?}: {refused}"
        );
    }
    assert!(standalone_reservations(&connection_db.path).is_empty());
}

/// Keyed local-secret changes (issue #425, plan P8).
#[path = "authority_evidence_secret_app_tests.rs"]
mod local_secret_keys;

/// Every keyed route's unkeyed form in required mode (issue #425, plan P10).
#[path = "authority_evidence_route_app_tests.rs"]
mod keyed_route_refusals;

#[cfg(feature = "postgres")]
mod cluster_connection_keys {
    use super::*;
    use storage::postgres::test_support::{locator, test_pool, test_settings};
    use storage::{
        MemberRegistration, PolicyControlPlane, PostgresMembershipStore, ToolControlPlane,
    };

    const CLUSTER_ISSUER: &str = "https://cluster-connection-keys.example.test";
    const DEPLOYMENT: &str = "deploy-cluster-connection-keys";

    /// A cluster replica over `pool` whose operation gate asks `membership`
    /// and which audits to `audit_log`.
    async fn replica(
        config: config::Config,
        pool: &deadpool_postgres::Pool,
        membership: Arc<cluster_membership::ClusterMembership>,
        audit_log: audit::AuditLog,
    ) -> Router {
        let policy = Arc::new(storage::PostgresPolicyStore::new(pool.clone()));
        let tools = Arc::new(storage::PostgresToolStore::new(pool.clone()));
        let connections = Arc::new(
            connections::pg_store::PostgresConnectionStore::new(
                pool.clone(),
                connections::model::MAX_CONNECTIONS,
            )
            .unwrap(),
        );
        let revision = connections.state_revision().await.unwrap();
        let records = connections.list().await.unwrap();
        let (openapi_catalogs, openapi_overlays) =
            connections.openapi_catalogs_with_overlays().await.unwrap();
        let boot = Arc::new(connections::managed_store::ClusterConnectionsBoot {
            mcp_catalogs: connections.mcp_catalogs().await.unwrap(),
            openapi_catalogs,
            openapi_inventory_catalogs: connections.openapi_inventory_catalogs().await.unwrap(),
            openapi_overlays,
            enum_source_values: std::sync::Mutex::new(Some(
                connections.enum_source_values().await.unwrap(),
            )),
        });
        let app = gateway_app_with_process_started_at_and_overrides(
            config,
            PrometheusBuilder::new().build_recorder().handle(),
            audit_log,
            test_audit_event_sender(),
            Instant::now(),
            GatewayAppBuildOverrides {
                pg_policy: Some(ClusterPolicySeed {
                    active: policy.active().await.unwrap().unwrap(),
                    store: policy,
                }),
                pg_tools: Some(ClusterToolsSeed {
                    active: tools.active_tools().await.unwrap().unwrap(),
                    store: tools,
                }),
                pg_connections: Some(ClusterConnectionsSeed {
                    store: connections,
                    records,
                    boot,
                    revision,
                }),
                pg_membership: Some(membership),
                disable_proxy_health_checks: true,
                ..Default::default()
            },
        )
        .unwrap();
        match app.http {
            GatewayApp::Unified(router) => router,
            GatewayApp::Split { .. } => panic!("expected a unified test router"),
        }
    }

    /// One admin request with a bearer token, an optional `If-Match` and an
    /// optional caller key: its status, ETag and JSON body.
    async fn call(
        router: &Router,
        method: Method,
        uri: &str,
        token: &str,
        body: Option<String>,
        if_match: Option<&str>,
        key: Option<&str>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut request = connection_admin_request(method, uri, None, body, if_match, false);
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        if let Some(key) = key {
            request
                .headers_mut()
                .insert("idempotency-key", key.parse().unwrap());
        }
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        (status, headers, json_body(response).await)
    }

    fn disabled_connection(display_name: &str) -> String {
        json!({
            "display_name": display_name,
            "enabled": false,
            "kind": "http_api",
            "endpoint": {"base_url": "https://cluster-keys.example.test", "base_path": "/v1"},
            "authentication": {"type": "none"}
        })
        .to_string()
    }

    async fn collection_etag(router: &Router, token: &str) -> String {
        let (status, headers, body) = call(
            router,
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            token,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        headers[CONNECTION_COLLECTION_ETAG_HEADER]
            .to_str()
            .unwrap()
            .to_owned()
    }

    async fn connection_reservations(pool: &deadpool_postgres::Pool) -> Vec<(String, String)> {
        pool.get()
            .await
            .unwrap()
            .query(
                "SELECT operation_id::text, action FROM greengateway.authority_caller_operation_ids \
                 WHERE action LIKE 'connection.%' ORDER BY operation_id",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }

    /// A cluster replica over the migrated `pool`, with the connection admin
    /// policy (default action allow), an empty tools document and a second,
    /// live member built before caller keys: the router and that member's
    /// instance ID, which [`stale`] ages out.
    async fn keyed_replica(pool: &deadpool_postgres::Pool) -> (Router, uuid::Uuid) {
        keyed_replica_with(pool, test_audit_log(), |_| {}).await
    }

    /// [`keyed_replica`] auditing to `audit_log`, with `configure` applied to
    /// its configuration last.
    async fn keyed_replica_with(
        pool: &deadpool_postgres::Pool,
        audit_log: audit::AuditLog,
        configure: impl FnOnce(&mut config::Config),
    ) -> (Router, uuid::Uuid) {
        storage::postgres_authority_events::PostgresAuthorityEventStore::new(pool.clone())
            .configure_capacity(100)
            .await
            .unwrap();
        // The requests carry real bearer tokens through the HTTP policy
        // layer, which answers a route no rule names with the policy's
        // default action. Allow it there, as the other cluster replica tests
        // do, so that every 403 below is the Connection handler's own
        // permission check.
        let mut document: Value =
            serde_json::from_str(&connection_policy_document_string()).unwrap();
        document["default_action"] = json!("allow");
        let policy = rbac::Policy::validate_json_value(document).unwrap();
        storage::PostgresPolicyStore::new(pool.clone())
            .commit(storage::PolicyCommitRequest {
                precondition: storage::PolicyCommitPrecondition::Initialize,
                candidate: &policy,
                change: storage::DocumentChange::test_policy("installer"),
                diff_summary: &json!({}),
            })
            .await
            .unwrap();
        storage::PostgresToolStore::new(pool.clone())
            .seed_empty_document()
            .await
            .unwrap();

        let membership = cluster_membership::ClusterMembership::new(
            PostgresMembershipStore::new(
                pool.clone(),
                DEPLOYMENT,
                crate::ha::InstanceIdentity::generate(),
            ),
            MemberRegistration {
                binary_version: env!("CARGO_PKG_VERSION").to_owned(),
                schema_version: storage::migrations::schema_version_range(),
                document_version: cluster_membership::DOCUMENT_VERSION_RANGE,
                fingerprint: "b".repeat(64),
                capabilities: storage::compatibility::BINARY_CAPABILITIES.to_vec(),
            },
            Duration::from_secs(1),
            Duration::from_secs(30),
        );
        membership.register_boot().await.expect("boot row");
        // A live member built before caller keys.
        let earlier = uuid::Uuid::new_v4();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO greengateway.cluster_members
                 (deployment_id, instance_id, boot_id, binary_version,
                  schema_version_min, schema_version_max,
                  document_version_min, document_version_max, fingerprint,
                  capabilities)
             VALUES ($1, $2::text::uuid, $3::text::uuid, '1.0.1', 18, 18, 0, 0,
                     repeat('b', 64), 'operation_requirements,policy_role_descriptions')",
                &[
                    &DEPLOYMENT,
                    &earlier.to_string(),
                    &uuid::Uuid::new_v4().to_string(),
                ],
            )
            .await
            .expect("an earlier member row inserts");

        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some(DEPLOYMENT.into());
        configure_test_jwt_provider(&mut config, spawn_test_jwks_server().await);
        config.auth_providers[0].issuer = Some(CLUSTER_ISSUER.into());
        // The test JWKS server listens on loopback; the Connections name
        // their own hosts.
        config.egress_allowed_hosts = vec![
            "127.0.0.1".into(),
            "cluster-keys.example.test".into(),
            "keyed.example.test".into(),
        ];
        config.egress_deny_private_ips = false;
        config.rate_limit_write_burst = 1000;
        config.rate_limit_write_rps = 1000.0;
        configure(&mut config);
        (replica(config, pool, membership, audit_log).await, earlier)
    }

    /// Age member `instance` out of the live fleet.
    async fn stale(pool: &deadpool_postgres::Pool, instance: uuid::Uuid) {
        let updated = pool
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE greengateway.cluster_members
                 SET last_heartbeat_at = now() - make_interval(secs => 60)
                 WHERE instance_id = $1::text::uuid",
                &[&instance.to_string()],
            )
            .await
            .unwrap();
        assert_eq!(updated, 1);
    }

    /// The keyed Connection routes in cluster mode, end to end:
    ///
    /// - while a live member lacks `caller_operation_keys`, a keyed create,
    ///   replace and delete are `409 capability_not_advertised`, change
    ///   nothing and reserve nothing, and the unkeyed forms still commit;
    /// - once that member is stale, so that the operation gate would admit a
    ///   key and raise the contract fence, a keyed request from a caller
    ///   without the route's permission (or without secret authority for a
    ///   credentialed body) is still `403`, and the fence is unchanged byte
    ///   for byte: authorization comes before admission;
    /// - the first authorized keyed create raises the fence once; exact
    ///   retries of the create, replace and delete are answered from their
    ///   receipts, a replacement's and a deletion's after the record is gone,
    ///   and nothing raises the fence again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn postgres_keyed_connection_changes_wait_for_the_fleet_and_authorize_before_the_fence() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database =
            storage::contract_tests::postgres_audit_tests::create_test_database(&admin_dsn).await;
        let foundation = test_pool(&database.dsn).await;
        let pool = foundation.pool();
        storage::migrations::apply_missing_for_startup(pool, &test_settings())
            .await
            .unwrap();
        let (router, earlier) = keyed_replica(pool).await;
        let admin =
            signed_token_with_issuer("operator", &["connections-superadmin"], CLUSTER_ISSUER);
        let reader = signed_token_with_issuer("reader", &["connections-reader"], CLUSTER_ISSUER);
        let editor = signed_token_with_issuer("editor", &["connections-editor"], CLUSTER_ISSUER);
        let read_fence = || async move {
            storage::read_contract_fence(pool)
                .await
                .expect("the fence reads")
        };
        let fence = read_fence().await;
        let key = |seed: u8| caller_key(seed);

        // A live member lacks the capability: every keyed form waits, the
        // unkeyed forms commit.
        let etag = collection_etag(&router, &admin).await;
        let (status, _, body) = call(
            &router,
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            &admin,
            Some(disabled_connection("Held API")),
            Some(&etag),
            Some(&key(70)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], json!("capability_not_advertised"));
        let (status, headers, created) = call(
            &router,
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            &admin,
            Some(disabled_connection("Unkeyed API")),
            Some(&etag),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let unkeyed = format!(
            "{CONNECTIONS_ADMIN_ROUTE}/{}",
            created["id"].as_str().unwrap()
        );
        let mut unkeyed_etag = headers[header::ETAG].to_str().unwrap().to_owned();
        for (method, body) in [
            (
                Method::PUT,
                Some(disabled_connection("Unkeyed API renamed")),
            ),
            (Method::DELETE, None),
        ] {
            let (status, _, refused) = call(
                &router,
                method.clone(),
                &unkeyed,
                &admin,
                body,
                Some(&unkeyed_etag),
                Some(&key(71)),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{method}: {refused}");
            assert_eq!(refused["reason"], json!("capability_not_advertised"));
        }
        let (status, headers, replaced) = call(
            &router,
            Method::PUT,
            &unkeyed,
            &admin,
            Some(disabled_connection("Unkeyed API renamed")),
            Some(&unkeyed_etag),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{replaced}");
        unkeyed_etag = headers[header::ETAG].to_str().unwrap().to_owned();
        assert!(connection_reservations(pool).await.is_empty());
        assert_eq!(read_fence().await, fence, "a refused key raises nothing");

        // The lacking member goes stale: the gate would now admit a key and
        // raise the fence. A caller without the route's permission is still
        // refused first, and the fence does not move.
        stale(pool, earlier).await;
        let etag = collection_etag(&router, &admin).await;
        let forbidden = [
            (
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE.to_owned(),
                &reader,
                Some(disabled_connection("Forbidden API")),
                etag.clone(),
            ),
            (
                Method::PUT,
                unkeyed.clone(),
                &reader,
                Some(disabled_connection("Forbidden API")),
                unkeyed_etag.clone(),
            ),
            (
                Method::DELETE,
                unkeyed.clone(),
                &reader,
                None,
                unkeyed_etag.clone(),
            ),
            (
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE.to_owned(),
                &editor,
                Some(aliased_connection_body("Forbidden API", "alias", "header")),
                etag.clone(),
            ),
            (
                Method::PUT,
                unkeyed.clone(),
                &editor,
                Some(aliased_connection_body("Forbidden API", "alias", "header")),
                unkeyed_etag.clone(),
            ),
        ];
        for (seed, (method, uri, token, body, if_match)) in (72..).zip(forbidden) {
            let (status, _, refused) = call(
                &router,
                method.clone(),
                &uri,
                token,
                body,
                Some(&if_match),
                Some(&key(seed)),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {refused}");
        }
        assert_eq!(
            read_fence().await,
            fence,
            "a forbidden keyed request leaves the contract fence unchanged"
        );
        assert!(connection_reservations(pool).await.is_empty());

        // The first authorized keyed change raises the fence once; exact
        // retries are answered from their receipts.
        let create_key = key(80);
        let create = || {
            call(
                &router,
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE,
                &admin,
                Some(disabled_connection("Keyed API")),
                Some(&etag),
                Some(&create_key),
            )
        };
        let (status, headers, created) = create().await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let raised = read_fence().await;
        assert_eq!(raised.generation, fence.generation + 1);
        assert!(
            raised.capabilities.contains("caller_operation_keys"),
            "{raised:?}"
        );
        let id = created["id"].as_str().unwrap().to_owned();
        let route = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");
        let created_etag = headers[header::ETAG].to_str().unwrap().to_owned();
        let (status, _, receipt) = create().await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["operation"], json!("connection.create"));
        assert_eq!(receipt["operation_id"], json!(create_key));
        assert_eq!(receipt["resource_id"], json!(id));

        let replace_key = key(81);
        let replace = || {
            call(
                &router,
                Method::PUT,
                &route,
                &admin,
                Some(disabled_connection("Keyed API renamed")),
                Some(&created_etag),
                Some(&replace_key),
            )
        };
        let (status, headers, replaced) = replace().await;
        assert_eq!(status, StatusCode::OK, "{replaced}");
        let replaced_etag = headers[header::ETAG].to_str().unwrap().to_owned();
        let (status, _, receipt) = replace().await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["operation"], json!("connection.replace"));

        let delete_key = key(82);
        let delete = || {
            call(
                &router,
                Method::DELETE,
                &route,
                &admin,
                None,
                Some(&replaced_etag),
                Some(&delete_key),
            )
        };
        let (status, _, deleted) = delete().await;
        assert_eq!(status, StatusCode::OK, "{deleted}");
        let (status, _, receipt) = delete().await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["operation"], json!("connection.delete"));
        assert_eq!(receipt["resource_id"], json!(id));
        let (status, _, receipt) = replace().await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a committed replacement is answered after the record is gone: {receipt}"
        );
        assert_eq!(receipt["operation"], json!("connection.replace"));

        let mut expected = vec![
            (create_key.clone(), "connection.create".to_owned()),
            (replace_key.clone(), "connection.replace".to_owned()),
            (delete_key.clone(), "connection.delete".to_owned()),
        ];
        expected.sort();
        assert_eq!(connection_reservations(pool).await, expected);
        assert_eq!(read_fence().await, raised, "the fence was raised once");
        // The unkeyed delete still commits.
        let (status, _, body) = call(
            &router,
            Method::DELETE,
            &unkeyed,
            &admin,
            None,
            Some(&unkeyed_etag),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    async fn catalog_reservations(pool: &deadpool_postgres::Pool) -> Vec<(String, String)> {
        pool.get()
            .await
            .unwrap()
            .query(
                "SELECT operation_id::text, action FROM greengateway.authority_caller_operation_ids \
                 WHERE action LIKE 'catalog.%' ORDER BY operation_id",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }

    /// The keyed catalog routes in cluster mode (issue #425):
    ///
    /// - while a live member lacks `caller_operation_keys`, a keyed OpenAPI
    ///   registration, refresh, overlay put and overlay delete are each
    ///   `409 capability_not_advertised`: the operation gate is asked before
    ///   the store, and nothing is reserved;
    /// - once that member is stale, a keyed request from a caller without
    ///   the route's permission is still `403`, and the contract fence is
    ///   unchanged byte for byte: authorization comes before admission;
    /// - the first authorized keyed registration raises the fence once, and
    ///   its exact retry is answered from its receipt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn postgres_keyed_catalog_changes_wait_for_the_fleet_and_authorize_before_the_fence() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database =
            storage::contract_tests::postgres_audit_tests::create_test_database(&admin_dsn).await;
        let foundation = test_pool(&database.dsn).await;
        let pool = foundation.pool();
        storage::migrations::apply_missing_for_startup(pool, &test_settings())
            .await
            .unwrap();
        let (router, earlier) = keyed_replica(pool).await;
        let admin = signed_token_with_issuer("operator", CATALOG_ROLES, CLUSTER_ISSUER);
        let reader = signed_token_with_issuer(
            "reader",
            &["connections-reader", "openapi-tools-reader"],
            CLUSTER_ISSUER,
        );
        let read_fence = || async move {
            storage::read_contract_fence(pool)
                .await
                .expect("the fence reads")
        };
        let fence = read_fence().await;

        let collection = collection_etag(&router, &admin).await;
        let (status, headers, created) = call(
            &router,
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            &admin,
            Some(managed_openapi_connection_body("Cluster catalog")),
            Some(&collection),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_owned();
        let etag = headers[header::ETAG].to_str().unwrap().to_owned();
        let (status, _, preview) = call(
            &router,
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{id}/openapi/preview"),
            &admin,
            Some(json!({ "spec": widget_openapi_spec() }).to_string()),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        let registration = json!({
            "spec": widget_openapi_spec(),
            "spec_digest": preview["spec_digest"],
            "expected_spec_revision": preview["spec_revision"],
            "expected_catalog_revision": preview["catalog_revision"],
            "selected_tool_names": [],
            "security_confirmations": [],
        })
        .to_string();
        let (status, headers, overlay) = call(
            &router,
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{id}/overlay"),
            &admin,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{overlay}");
        let overlay = headers[header::ETAG].to_str().unwrap().to_owned();
        let requests = [
            (CatalogCall::Register, &etag, Some(registration.clone())),
            (CatalogCall::Refresh, &etag, None),
            (
                CatalogCall::OverlayPut,
                &overlay,
                Some(catalog_overlay_document()),
            ),
            (CatalogCall::OverlayDelete, &overlay, None),
        ];

        // A live member lacks the capability: every keyed form waits.
        for (seed, (catalog_call, if_match, body)) in (100..).zip(requests.clone()) {
            let (method, uri) = catalog_call.route(&id);
            let (status, _, refused) = call(
                &router,
                method,
                &uri,
                &admin,
                body,
                Some(if_match),
                Some(&caller_key(seed)),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{catalog_call:?}: {refused}");
            assert_eq!(refused["reason"], json!("capability_not_advertised"));
        }
        assert!(catalog_reservations(pool).await.is_empty());
        assert_eq!(read_fence().await, fence, "a refused key raises nothing");

        // The lacking member goes stale: the gate would now admit a key and
        // raise the fence. A caller without the route's permission is still
        // refused first, and the fence does not move.
        stale(pool, earlier).await;
        for (seed, (catalog_call, if_match, body)) in (110..).zip(requests) {
            let (method, uri) = catalog_call.route(&id);
            let (status, _, refused) = call(
                &router,
                method,
                &uri,
                &reader,
                body,
                Some(if_match),
                Some(&caller_key(seed)),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{catalog_call:?}: {refused}");
        }
        // A caller with the route's permission but without secret authority
        // is refused an overlay with a raw `request.path` source before its
        // key is admitted.
        let raw_source = json!({
            "schema_version": "0.1.0",
            "enum_sources": {
                "statuses": {
                    "request": {"path": "/metadata/statuses"},
                    "select": {"items": "/items/*", "value": "/value"}
                }
            }
        })
        .to_string();
        let (method, uri) = CatalogCall::OverlayPut.route(&id);
        let (status, _, refused) = call(
            &router,
            method,
            &uri,
            &admin,
            Some(raw_source),
            Some(&overlay),
            Some(&caller_key(119)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert_eq!(
            read_fence().await,
            fence,
            "a forbidden keyed request leaves the contract fence unchanged"
        );
        assert!(catalog_reservations(pool).await.is_empty());

        // The first authorized keyed registration raises the fence once; its
        // exact retry is answered from its receipt.
        let key = caller_key(120);
        let (method, uri) = CatalogCall::Register.route(&id);
        let register = || {
            call(
                &router,
                method.clone(),
                &uri,
                &admin,
                Some(registration.clone()),
                Some(&etag),
                Some(&key),
            )
        };
        let (status, _, registered) = register().await;
        assert_eq!(status, StatusCode::CREATED, "{registered}");
        let raised = read_fence().await;
        assert_eq!(raised.generation, fence.generation + 1);
        let (status, _, receipt) = register().await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_catalog_receipt(&receipt, &key, "catalog.openapi.publish", &id, 1);
        assert_eq!(
            catalog_reservations(pool).await,
            [(key.clone(), "catalog.openapi.publish".to_owned())]
        );
        assert_eq!(read_fence().await, raised, "the fence was raised once");
    }

    /// The local-secret item routes are mounted on a cluster replica, which
    /// has no local-secret store and can never rotate or delete one (plan
    /// P8). Once the operation gate would admit a key and raise the contract
    /// fence, a keyed rotation and a keyed delete -- the latter a
    /// withdrawal, which is never evidence-gated -- are still answered
    /// exactly as their unkeyed forms (`412`, or `428` without `If-Match`),
    /// leave the fence unchanged byte for byte and reserve nothing. A keyed
    /// Connection create on the same replica then raises the fence, so the
    /// gate was armed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn postgres_keyed_secret_changes_in_cluster_mode_leave_the_fence_alone() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database =
            storage::contract_tests::postgres_audit_tests::create_test_database(&admin_dsn).await;
        let foundation = test_pool(&database.dsn).await;
        let pool = foundation.pool();
        storage::migrations::apply_missing_for_startup(pool, &test_settings())
            .await
            .unwrap();
        let (router, earlier) = keyed_replica(pool).await;
        stale(pool, earlier).await;
        let secrets = signed_token_with_issuer(
            "secret-manager",
            &["connections-secret-manager"],
            CLUSTER_ISSUER,
        );
        let fence = storage::read_contract_fence(pool)
            .await
            .expect("the fence reads");
        let route = format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/never-stored");
        let rotation = json!({"purpose": "static_bearer", "value": "never-stored-value"});
        for (method, body) in [
            (Method::PUT, Some(rotation.to_string())),
            (Method::DELETE, None),
        ] {
            for (if_match, expected) in [
                (
                    Some("\"connection-secret:never-stored:v1\""),
                    StatusCode::PRECONDITION_FAILED,
                ),
                (None, StatusCode::PRECONDITION_REQUIRED),
            ] {
                let (status, _, unkeyed) = call(
                    &router,
                    method.clone(),
                    &route,
                    &secrets,
                    body.clone(),
                    if_match,
                    None,
                )
                .await;
                let case = format!("{method} If-Match={if_match:?}");
                assert_eq!(status, expected, "{case}: {unkeyed}");
                let (status, _, keyed) = call(
                    &router,
                    method.clone(),
                    &route,
                    &secrets,
                    body.clone(),
                    if_match,
                    Some(&caller_key(82)),
                )
                .await;
                assert_eq!((status, &keyed), (expected, &unkeyed), "{case}");
                assert_eq!(
                    storage::read_contract_fence(pool)
                        .await
                        .expect("the fence reads"),
                    fence,
                    "{case}: a keyed local-secret change leaves the contract fence unchanged"
                );
            }
        }
        let reservations: i64 = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT count(*) FROM greengateway.authority_caller_operation_ids",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(reservations, 0);

        // The gate was armed: a keyed Connection create raises the fence.
        let admin =
            signed_token_with_issuer("operator", &["connections-superadmin"], CLUSTER_ISSUER);
        let etag = collection_etag(&router, &admin).await;
        let (status, _, created) = call(
            &router,
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            &admin,
            Some(disabled_connection("Fence witness")),
            Some(&etag),
            Some(&caller_key(83)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(
            storage::read_contract_fence(pool)
                .await
                .expect("the fence reads")
                .generation,
            fence.generation + 1
        );
    }

    /// Installs a test-only trigger that refuses every insert into
    /// `greengateway.{table}`.
    async fn fail_inserts_into(pool: &deadpool_postgres::Pool, table: &str) {
        pool.get()
            .await
            .unwrap()
            .batch_execute(&format!(
                "CREATE FUNCTION greengateway.fail_{table}() \
                 RETURNS trigger LANGUAGE plpgsql AS $$ \
                 BEGIN RAISE EXCEPTION 'injected {table} failure'; END; $$; \
                 CREATE TRIGGER fail_{table} BEFORE INSERT ON greengateway.{table} \
                 FOR EACH ROW EXECUTE FUNCTION greengateway.fail_{table}();"
            ))
            .await
            .expect("the failure trigger installs");
    }

    /// Removes what [`fail_inserts_into`] installed.
    async fn admit_inserts_into(pool: &deadpool_postgres::Pool, table: &str) {
        pool.get()
            .await
            .unwrap()
            .batch_execute(&format!(
                "DROP TRIGGER fail_{table} ON greengateway.{table}; \
                 DROP FUNCTION greengateway.fail_{table}();"
            ))
            .await
            .expect("the failure trigger drops");
    }

    /// Creates, without a discovery path and without a key, the
    /// credentialed catalog Connection of
    /// `marker_keys::credentialed_catalog_connection_body`; returns its ID
    /// and ETag. Its answer names its references to its creator.
    async fn create_cluster_catalog_connection(router: &Router, admin: &str) -> (String, String) {
        let collection = collection_etag(router, admin).await;
        let (status, headers, created) = call(
            router,
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            admin,
            Some(super::marker_keys::credentialed_catalog_connection_body(
                None,
            )),
            Some(&collection),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        (
            created["id"].as_str().unwrap().to_owned(),
            headers[header::ETAG].to_str().unwrap().to_owned(),
        )
    }

    /// The registration body of the widget specification for Connection
    /// `id`, selecting `tool`, from its preview.
    async fn cluster_openapi_registration(
        router: &Router,
        admin: &str,
        id: &str,
        tool: &str,
    ) -> String {
        let (status, _, preview) = call(
            router,
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{id}/openapi/preview"),
            admin,
            Some(json!({ "spec": widget_openapi_spec() }).to_string()),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        let confirmations: Vec<Value> = preview["security_confirmations"]
            .as_array()
            .expect("the preview lists security confirmations")
            .iter()
            .filter(|confirmation| confirmation["tool_name"] == json!(tool))
            .cloned()
            .collect();
        json!({
            "spec": widget_openapi_spec(),
            "spec_digest": preview["spec_digest"],
            "expected_spec_revision": preview["spec_revision"],
            "expected_catalog_revision": preview["catalog_revision"],
            "selected_tool_names": [tool],
            "security_confirmations": confirmations,
        })
        .to_string()
    }

    /// I5 for the Connection and catalog families on a PostgreSQL-backed
    /// cluster replica, the form of
    /// `marker_keys::a_keyed_connection_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics`
    /// and its catalog sibling that runs against the PostgreSQL store: the
    /// same marked requests (a keyed create naming a marker in each bearer
    /// credential reference, a keyed replacement to a delegated-issuer body
    /// naming its client secret, signing key and published key aliases, a
    /// keyed OpenAPI registration on an enabled Connection whose discovery
    /// uses its marked operator secret aliases, and a keyed overlay
    /// replacement with marked free text), each with its exact retry and a
    /// conflicting retry; a keyed replacement of the first Connection to an
    /// OAuth client-credentials body naming a marker as its client secret
    /// alias, a keyed delete of that Connection, a keyed refresh of the
    /// catalog's Connection, a keyed overlay replacement with a marked enum
    /// source request and a keyed overlay delete, each with its exact
    /// retry; then a keyed create whose
    /// caller key cannot be reserved and a keyed overlay replacement whose
    /// catalog evidence row cannot be inserted. Then, with that Connection
    /// replaced to name a discovery path: a keyed refresh refused at the
    /// egress preflight (`502 egress_denied`: its host is not admitted, so
    /// nothing is resolved or sent); a keyed refresh from a loopback HTTPS
    /// upstream the test controls, which records that it received the
    /// bearer value and the additional header's value read from the
    /// aliases' files, so the aliases were resolved and their files read;
    /// and a keyed refresh that fails after that (the upstream answers
    /// `500`, the refresh `502 request_failed`, and the upstream again
    /// received both values). No marker
    /// and no binding digest reaches a log line at any level, the rendered
    /// metrics, a receipt, a conflict or failure answer, or the audit
    /// stream. Each forced store failure is answered `503`, and both are
    /// counted on
    /// `greengateway_authority_event_evidence_failures_total` in the same
    /// rendering, so the capture saw the store's metrics. Connection IDs and
    /// caller keys are not secrets and are not searched for; each receipt
    /// names its key to its caller by design.
    #[test]
    fn postgres_keyed_connection_and_catalog_changes_keep_synthetic_markers_out_of_the_logs_and_metrics(
    ) {
        use super::marker_keys::{
            bound_digest, client_private_key_lines, configure_catalog_source_aliases,
            credentialed_catalog_connection_body, credentialed_catalog_connection_body_at,
            delegated_connection_body, enum_source_overlay_document, marked_connection_body,
            marked_overlay_document, oauth_connection_body, resolved_catalog_credentials,
            write_catalog_source_secrets, RecordingSpecUpstream, CATALOG_SOURCE_MARKERS,
            CLIENT_TLS_MARKERS, DELEGATED_MARKERS, ENUM_SOURCE_MARKERS, OAUTH_MARKERS,
            OVERLAY_MARKERS, REFERENCE_MARKERS, SUFFIXES,
        };
        let secrets = TempDb::new("cluster-catalog-markers");
        write_catalog_source_secrets(&secrets);
        let (audit_log, capture) = captured_audit();
        let (outcome, logged, rendered) =
            super::super::admin_tokens_app_tests::capture_logs_and_metrics_on_every_runtime_thread(
                async {
                    let Some(admin_dsn) = locator() else {
                        eprintln!("skipping: no test database locator; CI runs this test");
                        return None;
                    };
                    let database =
                        storage::contract_tests::postgres_audit_tests::create_test_database(
                            &admin_dsn,
                        )
                        .await;
                    let foundation = test_pool(&database.dsn).await;
                    let pool = foundation.pool();
                    storage::migrations::apply_missing_for_startup(pool, &test_settings())
                        .await
                        .unwrap();
                    // The replica's egress policy admits loopback, where
                    // this upstream listens, and not the Connection's own
                    // host.
                    let upstream = RecordingSpecUpstream::spawn(&secrets).await;
                    let (router, earlier) = keyed_replica_with(pool, audit_log, |config| {
                        config.connection_secrets_root =
                            Some(connections::secret::SecretRootConfig::new(
                                secrets.path.with_extension("secrets"),
                            ));
                        configure_catalog_source_aliases(config);
                    })
                    .await;
                    stale(pool, earlier).await;
                    let roles: Vec<&str> = std::iter::once("connections-superadmin")
                        .chain(CATALOG_ROLES.iter().copied())
                        .collect();
                    let admin = signed_token_with_issuer("operator", &roles, CLUSTER_ISSUER);
                    let actor = auth::change_actor::ChangeActor::for_test_with_issuer(
                        "operator",
                        CLUSTER_ISSUER,
                    );
                    let mut answers = Vec::new();
                    let mut committed = Vec::new();
                    let mut refused = Vec::new();

                    // A Connection create, its retries.
                    let collection = collection_etag(&router, &admin).await;
                    let create_key = caller_key(110);
                    let marked = marked_connection_body(SUFFIXES[0]);
                    let conflicting = marked_connection_body(SUFFIXES[1]);
                    let mut statuses = Vec::new();
                    let mut created = None;
                    for body in [&marked, &marked, &conflicting] {
                        let (status, headers, answer) = call(
                            &router,
                            Method::POST,
                            CONNECTIONS_ADMIN_ROUTE,
                            &admin,
                            Some(body.clone()),
                            Some(&collection),
                            Some(&create_key),
                        )
                        .await;
                        statuses.push(status);
                        if created.is_none() {
                            created = Some((answer, headers));
                        } else {
                            answers.push(answer);
                        }
                    }
                    assert_eq!(
                        statuses,
                        [StatusCode::CREATED, StatusCode::OK, StatusCode::CONFLICT],
                        "{answers:?}"
                    );
                    let (created, headers) = created.expect("the create answered");
                    let id = created["id"].as_str().expect("an ID").to_owned();
                    let etag = headers[header::ETAG].to_str().unwrap().to_owned();
                    committed.push(bound_digest(
                        &actor,
                        &create_key,
                        "connection.create",
                        "",
                        &collection,
                        &marked,
                    ));
                    refused.push(bound_digest(
                        &actor,
                        &create_key,
                        "connection.create",
                        "",
                        &collection,
                        &conflicting,
                    ));

                    // A replacement to a delegated-issuer body, its retries.
                    let route = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");
                    let replace_key = caller_key(111);
                    let delegated = delegated_connection_body(SUFFIXES[0]);
                    let conflicting = delegated_connection_body(SUFFIXES[1]);
                    let mut statuses = Vec::new();
                    let mut delegated_etag = None;
                    for (index, body) in [&delegated, &delegated, &conflicting]
                        .into_iter()
                        .enumerate()
                    {
                        let (status, headers, answer) = call(
                            &router,
                            Method::PUT,
                            &route,
                            &admin,
                            Some(body.clone()),
                            Some(&etag),
                            Some(&replace_key),
                        )
                        .await;
                        statuses.push(status);
                        if index > 0 {
                            answers.push(answer);
                        } else {
                            delegated_etag = headers
                                .get(header::ETAG)
                                .map(|value| value.to_str().unwrap().to_owned());
                        }
                    }
                    assert_eq!(
                        statuses,
                        [StatusCode::OK, StatusCode::OK, StatusCode::CONFLICT],
                        "{answers:?}"
                    );
                    let delegated_etag = delegated_etag.expect("the replacement names its ETag");
                    committed.push(bound_digest(
                        &actor,
                        &replace_key,
                        "connection.replace",
                        &id,
                        &etag,
                        &delegated,
                    ));
                    refused.push(bound_digest(
                        &actor,
                        &replace_key,
                        "connection.replace",
                        &id,
                        &etag,
                        &conflicting,
                    ));

                    // A replacement to an OAuth client-credentials body naming
                    // a marked client secret alias, then a delete of the
                    // Connection that still names it, each with its exact
                    // retry.
                    let oauth = oauth_connection_body(SUFFIXES[0]);
                    let oauth_key = caller_key(124);
                    let mut statuses = Vec::new();
                    let mut oauth_etag = None;
                    for index in 0..2 {
                        let (status, headers, answer) = call(
                            &router,
                            Method::PUT,
                            &route,
                            &admin,
                            Some(oauth.clone()),
                            Some(&delegated_etag),
                            Some(&oauth_key),
                        )
                        .await;
                        statuses.push(status);
                        if index > 0 {
                            answers.push(answer);
                        } else {
                            oauth_etag = headers
                                .get(header::ETAG)
                                .map(|value| value.to_str().unwrap().to_owned());
                        }
                    }
                    assert_eq!(statuses, [StatusCode::OK, StatusCode::OK], "{answers:?}");
                    let oauth_etag = oauth_etag.expect("the replacement names its ETag");
                    committed.push(bound_digest(
                        &actor,
                        &oauth_key,
                        "connection.replace",
                        &id,
                        &delegated_etag,
                        &oauth,
                    ));
                    let delete_key = caller_key(125);
                    for _ in 0..2 {
                        let (status, _, answer) = call(
                            &router,
                            Method::DELETE,
                            &route,
                            &admin,
                            None,
                            Some(&oauth_etag),
                            Some(&delete_key),
                        )
                        .await;
                        assert!(status.is_success(), "{status}: {answer}");
                        answers.push(answer);
                    }
                    committed.push(bound_digest(
                        &actor,
                        &delete_key,
                        "connection.delete",
                        &id,
                        &oauth_etag,
                        "",
                    ));

                    // An OpenAPI registration on a credentialed Connection,
                    // its retry, its key on the refresh route.
                    let (catalog_id, catalog_etag) =
                        create_cluster_catalog_connection(&router, &admin).await;
                    let registration =
                        cluster_openapi_registration(&router, &admin, &catalog_id, "createWidget")
                            .await;
                    let register_key = caller_key(112);
                    let mut statuses = Vec::new();
                    for (index, catalog_call) in [
                        CatalogCall::Register,
                        CatalogCall::Register,
                        CatalogCall::Refresh,
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let (method, uri) = catalog_call.route(&catalog_id);
                        let body = matches!(catalog_call, CatalogCall::Register)
                            .then(|| registration.clone());
                        let (status, _, answer) = call(
                            &router,
                            method,
                            &uri,
                            &admin,
                            body,
                            Some(&catalog_etag),
                            Some(&register_key),
                        )
                        .await;
                        statuses.push(status);
                        if index > 0 {
                            answers.push(answer);
                        }
                    }
                    assert_eq!(
                        statuses,
                        [StatusCode::CREATED, StatusCode::OK, StatusCode::CONFLICT],
                        "{answers:?}"
                    );
                    committed.push(bound_digest(
                        &actor,
                        &register_key,
                        "catalog.openapi.publish",
                        &catalog_id,
                        &catalog_etag,
                        &registration,
                    ));
                    // The refresh route binds no body.
                    refused.push(bound_digest(
                        &actor,
                        &register_key,
                        "catalog.openapi.publish",
                        &catalog_id,
                        &catalog_etag,
                        "",
                    ));

                    // A refresh, which loads the credentialed Connection and
                    // republishes the stored specification, and its retry.
                    let refresh_key = caller_key(116);
                    for _ in 0..2 {
                        let (method, uri) = CatalogCall::Refresh.route(&catalog_id);
                        let (status, _, answer) = call(
                            &router,
                            method,
                            &uri,
                            &admin,
                            None,
                            Some(&catalog_etag),
                            Some(&refresh_key),
                        )
                        .await;
                        assert_eq!(status, StatusCode::OK, "{answer}");
                        answers.push(answer);
                    }
                    committed.push(bound_digest(
                        &actor,
                        &refresh_key,
                        "catalog.openapi.publish",
                        &catalog_id,
                        &catalog_etag,
                        "",
                    ));

                    // An overlay replacement, its retries.
                    let overlay_route = format!("{CONNECTIONS_ADMIN_ROUTE}/{catalog_id}/overlay");
                    let overlay_etag = |router: Router, admin: String, route: String| async move {
                        let (status, headers, overlay) =
                            call(&router, Method::GET, &route, &admin, None, None, None).await;
                        assert_eq!(status, StatusCode::OK, "{overlay}");
                        headers[header::ETAG].to_str().unwrap().to_owned()
                    };
                    let overlay =
                        overlay_etag(router.clone(), admin.clone(), overlay_route.clone()).await;
                    let put_key = caller_key(113);
                    let marked = marked_overlay_document(SUFFIXES[0]);
                    let conflicting = marked_overlay_document(SUFFIXES[1]);
                    let mut statuses = Vec::new();
                    for (index, document) in
                        [&marked, &marked, &conflicting].into_iter().enumerate()
                    {
                        let (status, _, answer) = call(
                            &router,
                            Method::PUT,
                            &overlay_route,
                            &admin,
                            Some(document.clone()),
                            Some(&overlay),
                            Some(&put_key),
                        )
                        .await;
                        statuses.push(status);
                        if index > 0 {
                            answers.push(answer);
                        }
                    }
                    assert_eq!(
                        statuses,
                        [StatusCode::OK, StatusCode::OK, StatusCode::CONFLICT],
                        "{answers:?}"
                    );
                    for (document, digests) in
                        [(&marked, &mut committed), (&conflicting, &mut refused)]
                    {
                        digests.push(bound_digest(
                            &actor,
                            &put_key,
                            "catalog.overlay.replace",
                            &catalog_id,
                            &overlay,
                            document,
                        ));
                    }

                    // An enum source the gateway would fetch with the
                    // Connection's credentials, admitted unresolved, then a
                    // delete of the overlay holding it; each with its retry.
                    let overlay =
                        overlay_etag(router.clone(), admin.clone(), overlay_route.clone()).await;
                    let sourced_key = caller_key(117);
                    let sourced = enum_source_overlay_document();
                    for _ in 0..2 {
                        let (status, _, answer) = call(
                            &router,
                            Method::PUT,
                            &format!("{overlay_route}?allow_unresolved_enum_sources=true"),
                            &admin,
                            Some(sourced.clone()),
                            Some(&overlay),
                            Some(&sourced_key),
                        )
                        .await;
                        assert_eq!(status, StatusCode::OK, "{answer}");
                        answers.push(answer);
                    }
                    committed.push(bound_digest(
                        &actor,
                        &sourced_key,
                        "catalog.overlay.replace",
                        &catalog_id,
                        &overlay,
                        &json!([
                            serde_json::from_str::<Value>(&sourced).expect("the overlay is JSON"),
                            {"allow_unresolved_enum_sources": true}
                        ])
                        .to_string(),
                    ));
                    let overlay =
                        overlay_etag(router.clone(), admin.clone(), overlay_route.clone()).await;
                    let delete_key = caller_key(118);
                    for _ in 0..2 {
                        let (method, uri) = CatalogCall::OverlayDelete.route(&catalog_id);
                        let (status, _, answer) = call(
                            &router,
                            method,
                            &uri,
                            &admin,
                            None,
                            Some(&overlay),
                            Some(&delete_key),
                        )
                        .await;
                        assert_eq!(status, StatusCode::OK, "{answer}");
                        answers.push(answer);
                    }
                    committed.push(bound_digest(
                        &actor,
                        &delete_key,
                        "catalog.overlay.delete",
                        &catalog_id,
                        &overlay,
                        "",
                    ));

                    // Test-only fault injection: a create whose key cannot
                    // be reserved, then an overlay replacement whose catalog
                    // evidence cannot be inserted.
                    fail_inserts_into(pool, "authority_caller_operation_ids").await;
                    let collection = collection_etag(&router, &admin).await;
                    let failed_key = caller_key(114);
                    let failing = marked_connection_body(SUFFIXES[2]);
                    let (status, _, failed) = call(
                        &router,
                        Method::POST,
                        CONNECTIONS_ADMIN_ROUTE,
                        &admin,
                        Some(failing.clone()),
                        Some(&collection),
                        Some(&failed_key),
                    )
                    .await;
                    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
                    answers.push(failed);
                    refused.push(bound_digest(
                        &actor,
                        &failed_key,
                        "connection.create",
                        "",
                        &collection,
                        &failing,
                    ));
                    admit_inserts_into(pool, "authority_caller_operation_ids").await;
                    fail_inserts_into(pool, "catalog_change_evidence").await;
                    let overlay =
                        overlay_etag(router.clone(), admin.clone(), overlay_route.clone()).await;
                    let failed_key = caller_key(115);
                    let failing = marked_overlay_document(SUFFIXES[2]);
                    let (status, _, failed) = call(
                        &router,
                        Method::PUT,
                        &overlay_route,
                        &admin,
                        Some(failing.clone()),
                        Some(&overlay),
                        Some(&failed_key),
                    )
                    .await;
                    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
                    answers.push(failed);
                    refused.push(bound_digest(
                        &actor,
                        &failed_key,
                        "catalog.overlay.replace",
                        &catalog_id,
                        &overlay,
                        &failing,
                    ));

                    admit_inserts_into(pool, "catalog_change_evidence").await;
                    // The Connection, replaced without a key, names a
                    // discovery path at its own host, which the replica's
                    // egress policy does not admit: a keyed refresh is
                    // refused at the egress preflight, before any secret is
                    // resolved, and the upstream hears nothing.
                    let connection_route = format!("{CONNECTIONS_ADMIN_ROUTE}/{catalog_id}");
                    let (status, headers, replaced) = call(
                        &router,
                        Method::PUT,
                        &connection_route,
                        &admin,
                        Some(credentialed_catalog_connection_body(Some("/openapi.json"))),
                        Some(&catalog_etag),
                        None,
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{replaced}");
                    let refused_etag = headers[header::ETAG].to_str().unwrap().to_owned();
                    let (method, uri) = CatalogCall::Refresh.route(&catalog_id);
                    let keyed_refresh = |key: String, if_match: String| {
                        let (router, admin, method, uri) =
                            (router.clone(), admin.clone(), method.clone(), uri.clone());
                        async move {
                            call(
                                &router,
                                method,
                                &uri,
                                &admin,
                                None,
                                Some(&if_match),
                                Some(&key),
                            )
                            .await
                        }
                    };
                    let refused_key = caller_key(119);
                    let (status, _, failed) =
                        keyed_refresh(refused_key.clone(), refused_etag.clone()).await;
                    assert_eq!(status, StatusCode::BAD_GATEWAY, "{failed}");
                    assert_eq!(failed["reason"], "egress_denied", "{failed}");
                    assert!(upstream.take_received().is_empty());
                    answers.push(failed);
                    refused.push(bound_digest(
                        &actor,
                        &refused_key,
                        "catalog.openapi.publish",
                        &catalog_id,
                        &refused_etag,
                        "",
                    ));

                    // Replaced to fetch from the upstream the test controls,
                    // a keyed refresh resolves both operator aliases, reads
                    // their files and sends their values: the upstream
                    // received them.
                    let (status, headers, replaced) = call(
                        &router,
                        Method::PUT,
                        &connection_route,
                        &admin,
                        Some(credentialed_catalog_connection_body_at(
                            &upstream.base_url(),
                            Some("/openapi.json"),
                        )),
                        Some(&refused_etag),
                        None,
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{replaced}");
                    let fetched_etag = headers[header::ETAG].to_str().unwrap().to_owned();
                    let fetched_key = caller_key(122);
                    let (status, _, fetched) =
                        keyed_refresh(fetched_key.clone(), fetched_etag.clone()).await;
                    assert_eq!(status, StatusCode::OK, "{fetched}");
                    assert_eq!(upstream.take_received(), [resolved_catalog_credentials()]);
                    let fetched_revision = fetched["catalog_revision"]
                        .as_u64()
                        .expect("the refresh names its catalog revision");
                    answers.push(fetched);
                    committed.push(bound_digest(
                        &actor,
                        &fetched_key,
                        "catalog.openapi.publish",
                        &catalog_id,
                        &fetched_etag,
                        "",
                    ));

                    // A keyed refresh whose fetch fails after the
                    // credentials were resolved and sent: the upstream
                    // answers `500`.
                    upstream.fail();
                    let failed_key = caller_key(123);
                    let (status, _, failed) =
                        keyed_refresh(failed_key.clone(), fetched_etag.clone()).await;
                    assert_eq!(status, StatusCode::BAD_GATEWAY, "{failed}");
                    assert_eq!(failed["reason"], "request_failed", "{failed}");
                    assert_eq!(upstream.take_received(), [resolved_catalog_credentials()]);
                    answers.push(failed);
                    refused.push(bound_digest(
                        &actor,
                        &failed_key,
                        "catalog.openapi.publish",
                        &catalog_id,
                        &fetched_etag,
                        "",
                    ));
                    // The audit writer delivers in order: wait until it has
                    // delivered the publication of the fetched refresh.
                    catalog_changes_through(&capture, &catalog_id, fetched_revision);

                    let mut stored: Vec<String> = pool
                        .get()
                        .await
                        .unwrap()
                        .query(
                            "SELECT binding_digest FROM greengateway.authority_caller_operation_ids",
                            &[],
                        )
                        .await
                        .unwrap()
                        .iter()
                        .map(|row| row.get::<_, Option<String>>(0).expect("a bound digest"))
                        .collect();
                    stored.sort();
                    Some((answers, committed, refused, stored))
                },
            );
        let Some((answers, mut committed, refused, stored)) = outcome else {
            return;
        };

        // The digests computed here are the ones the handlers bound: each
        // committed key's reservation holds the one computed for its request.
        committed.sort();
        assert_eq!(stored, committed);

        assert!(!logged.is_empty(), "the handlers' log lines were captured");
        let failures = format!(
            "{} ",
            crate::metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL
        );
        // Once for the refused reservation, once for the refused catalog
        // evidence insert; the two failed refreshes are answered before any
        // evidence.
        assert_eq!(
            rendered
                .lines()
                .filter_map(|line| line.strip_prefix(failures.as_str()))
                .collect::<Vec<_>>(),
            ["2"],
            "both forced failures were counted where the capture saw them"
        );
        let answered = format!("{answers:?}");
        let audited = format!("{:?}", capture.events());
        let markers = SUFFIXES
            .iter()
            .flat_map(|suffix| {
                REFERENCE_MARKERS
                    .iter()
                    .chain(DELEGATED_MARKERS.iter())
                    .chain(OAUTH_MARKERS.iter())
                    .chain(OVERLAY_MARKERS.iter())
                    .map(move |marker| format!("{marker}{suffix}"))
            })
            .chain(
                CATALOG_SOURCE_MARKERS
                    .iter()
                    .chain(ENUM_SOURCE_MARKERS.iter())
                    .chain(CLIENT_TLS_MARKERS.iter())
                    .map(|marker| (*marker).to_owned()),
            );
        // Read only if the PostgreSQL run spawned the upstream that wrote it.
        let key_lines = secrets
            .path
            .with_extension("secrets")
            .join(CLIENT_TLS_MARKERS[3])
            .exists()
            .then(|| client_private_key_lines(&secrets))
            .unwrap_or_default();
        for marker in markers.chain(key_lines) {
            assert!(!answered.contains(&marker), "{marker} reached an answer");
            assert!(
                !audited.contains(&marker),
                "{marker} reached the audit stream"
            );
            assert!(!logged.contains(&marker), "{marker} reached the logs");
            assert!(!rendered.contains(&marker), "{marker} reached the metrics");
        }
        for digest in committed.iter().chain(&refused) {
            assert!(!answered.contains(digest), "a digest reached an answer");
            assert!(
                !audited.contains(digest),
                "a digest reached the audit stream"
            );
            assert!(!logged.contains(digest), "a digest reached the logs");
            assert!(!rendered.contains(digest), "a digest reached the metrics");
        }
    }
}

/// Keyed service-token issue and rotation in cluster mode, through the admin
/// handlers of a PostgreSQL-backed replica with a real roster (issue #425,
/// plan P5). The verified-TLS CI shard selects this module by its prefix.
#[cfg(feature = "postgres")]
mod cluster_token_keys {
    use super::*;
    use storage::postgres::test_support::{locator, test_pool, test_settings};
    use storage::{
        MemberRegistration, PolicyControlPlane, PostgresMembershipStore, ToolControlPlane,
    };

    const CLUSTER_ISSUER: &str = "https://cluster-token-keys.example.test";
    const DEPLOYMENT: &str = "deploy-cluster-token-keys";

    /// A cluster replica over `pool` that serves service tokens from the
    /// authority and whose operation gate asks `membership`.
    async fn replica(
        config: config::Config,
        pool: &deadpool_postgres::Pool,
        membership: Arc<cluster_membership::ClusterMembership>,
        audit_log: audit::AuditLog,
    ) -> Router {
        let policy = Arc::new(storage::PostgresPolicyStore::new(pool.clone()));
        let tools = Arc::new(storage::PostgresToolStore::new(pool.clone()));
        let connections = Arc::new(
            connections::pg_store::PostgresConnectionStore::new(
                pool.clone(),
                connections::model::MAX_CONNECTIONS,
            )
            .unwrap(),
        );
        let revision = connections.state_revision().await.unwrap();
        let records = connections.list().await.unwrap();
        let (openapi_catalogs, openapi_overlays) =
            connections.openapi_catalogs_with_overlays().await.unwrap();
        let boot = Arc::new(connections::managed_store::ClusterConnectionsBoot {
            mcp_catalogs: connections.mcp_catalogs().await.unwrap(),
            openapi_catalogs,
            openapi_inventory_catalogs: connections.openapi_inventory_catalogs().await.unwrap(),
            openapi_overlays,
            enum_source_values: std::sync::Mutex::new(Some(
                connections.enum_source_values().await.unwrap(),
            )),
        });
        let service_tokens = Arc::new(storage::PostgresServiceTokenStore::new(pool.clone()));
        let service_token_revision = service_tokens.state_revision().await.unwrap();
        let app = gateway_app_with_process_started_at_and_overrides(
            config,
            PrometheusBuilder::new().build_recorder().handle(),
            audit_log,
            test_audit_event_sender(),
            Instant::now(),
            GatewayAppBuildOverrides {
                pg_policy: Some(ClusterPolicySeed {
                    active: policy.active().await.unwrap().unwrap(),
                    store: policy,
                }),
                pg_tools: Some(ClusterToolsSeed {
                    active: tools.active_tools().await.unwrap().unwrap(),
                    store: tools,
                }),
                pg_connections: Some(ClusterConnectionsSeed {
                    store: connections,
                    records,
                    boot,
                    revision,
                }),
                pg_service_tokens: Some(ClusterServiceTokenSeed {
                    store: service_tokens,
                    revision: service_token_revision,
                    pool: pool.clone(),
                    deployment_id: DEPLOYMENT.to_owned(),
                }),
                pg_membership: Some(membership),
                disable_proxy_health_checks: true,
                ..Default::default()
            },
        )
        .unwrap();
        match app.http {
            GatewayApp::Unified(router) => router,
            GatewayApp::Split { .. } => panic!("expected a unified test router"),
        }
    }

    /// One token admin `POST` with a bearer token and an optional caller
    /// key: its status and JSON body.
    async fn call(
        router: &Router,
        uri: &str,
        token: &str,
        body: Option<String>,
        key: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = connection_admin_request(Method::POST, uri, None, body, None, false);
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        if let Some(key) = key {
            request
                .headers_mut()
                .insert("idempotency-key", key.parse().unwrap());
        }
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        (status, json_body(response).await)
    }

    async fn token_reservations(pool: &deadpool_postgres::Pool) -> Vec<(String, String)> {
        pool.get()
            .await
            .unwrap()
            .query(
                "SELECT operation_id::text, action FROM greengateway.authority_caller_operation_ids \
                 WHERE action LIKE 'service_token.%' ORDER BY operation_id",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }

    /// The service tokens and the token evidence rows the authority holds.
    async fn token_rows(pool: &deadpool_postgres::Pool) -> (i64, i64) {
        let client = pool.get().await.unwrap();
        let tokens: i64 = client
            .query_one("SELECT count(*) FROM greengateway.service_tokens", &[])
            .await
            .unwrap()
            .get(0);
        let evidence: i64 = client
            .query_one(
                "SELECT count(*) FROM greengateway.service_token_change_evidence",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        (tokens, evidence)
    }

    /// The replica the tests here build over the migrated `pool`: the token
    /// policy, whose HTTP default is `allow` so that every `403` is the token
    /// handler's own, an empty tools document, room in the journal, and
    /// `earlier`, a live member built before caller keys, in the roster. The
    /// router and that member's ID.
    async fn keyed_replica(
        pool: &deadpool_postgres::Pool,
        audit_log: audit::AuditLog,
    ) -> (Router, uuid::Uuid) {
        storage::postgres_authority_events::PostgresAuthorityEventStore::new(pool.clone())
            .configure_capacity(100)
            .await
            .unwrap();
        // The requests carry real bearer tokens through the HTTP policy
        // layer, which answers a route no rule names with the policy's
        // default action. Allow it there, as the Connection replica test
        // does, so that every 403 in these tests is the token handler's own.
        let mut document: Value = serde_json::from_str(&token_policy_document_string()).unwrap();
        document["default_action"] = json!("allow");
        let policy = rbac::Policy::validate_json_value(document).unwrap();
        storage::PostgresPolicyStore::new(pool.clone())
            .commit(storage::PolicyCommitRequest {
                precondition: storage::PolicyCommitPrecondition::Initialize,
                candidate: &policy,
                change: storage::DocumentChange::test_policy("installer"),
                diff_summary: &json!({}),
            })
            .await
            .unwrap();
        storage::PostgresToolStore::new(pool.clone())
            .seed_empty_document()
            .await
            .unwrap();

        let membership = cluster_membership::ClusterMembership::new(
            PostgresMembershipStore::new(
                pool.clone(),
                DEPLOYMENT,
                crate::ha::InstanceIdentity::generate(),
            ),
            MemberRegistration {
                binary_version: env!("CARGO_PKG_VERSION").to_owned(),
                schema_version: storage::migrations::schema_version_range(),
                document_version: cluster_membership::DOCUMENT_VERSION_RANGE,
                fingerprint: "b".repeat(64),
                capabilities: storage::compatibility::BINARY_CAPABILITIES.to_vec(),
            },
            Duration::from_secs(1),
            Duration::from_secs(30),
        );
        membership.register_boot().await.expect("boot row");
        // A live member built before caller keys.
        let earlier = uuid::Uuid::new_v4();
        pool.get()
            .await
            .unwrap()
            .execute(
                "INSERT INTO greengateway.cluster_members
                     (deployment_id, instance_id, boot_id, binary_version,
                      schema_version_min, schema_version_max,
                      document_version_min, document_version_max, fingerprint,
                      capabilities)
                 VALUES ($1, $2::text::uuid, $3::text::uuid, '1.0.1', 18, 18, 0, 0,
                         repeat('b', 64), 'operation_requirements,policy_role_descriptions')",
                &[
                    &DEPLOYMENT,
                    &earlier.to_string(),
                    &uuid::Uuid::new_v4().to_string(),
                ],
            )
            .await
            .expect("an earlier member row inserts");

        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some(DEPLOYMENT.into());
        configure_test_jwt_provider(&mut config, spawn_test_jwks_server().await);
        config.auth_providers[0].issuer = Some(CLUSTER_ISSUER.into());
        // The test JWKS server listens on loopback.
        config.egress_allowed_hosts = vec!["127.0.0.1".into()];
        config.egress_deny_private_ips = false;
        config.rate_limit_write_burst = 1000;
        config.rate_limit_write_rps = 1000.0;
        (replica(config, pool, membership, audit_log).await, earlier)
    }

    /// The keyed token routes in cluster mode, end to end:
    ///
    /// - while a live member lacks `caller_operation_keys`, a keyed issue and
    ///   a keyed rotation are `409 capability_not_advertised`, mint nothing,
    ///   record nothing and reserve nothing, and the unkeyed forms still
    ///   commit;
    /// - once that member is stale, so that the operation gate would admit a
    ///   key and raise the contract fence, a keyed issue or rotation from a
    ///   caller without `admin:tokens:write`, or from a writer who may not
    ///   delegate the token's scopes, is still `403`, a keyed issue with a
    ///   malformed `expires_at` is `400`, and the fence is unchanged byte for
    ///   byte: authorization and validation come before admission;
    /// - the first authorized keyed issue raises the fence once, and exact
    ///   retries of the issue and of a keyed rotation are answered from
    ///   their receipts with `secret_returned: false` and no plaintext.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn postgres_keyed_token_changes_wait_for_the_fleet_and_authorize_and_validate_before_the_fence(
    ) {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database =
            storage::contract_tests::postgres_audit_tests::create_test_database(&admin_dsn).await;
        let foundation = test_pool(&database.dsn).await;
        let pool = foundation.pool();
        storage::migrations::apply_missing_for_startup(pool, &test_settings())
            .await
            .unwrap();
        let (router, earlier) = keyed_replica(pool, test_audit_log()).await;
        let admin = signed_token_with_issuer("operator", &["superadmin"], CLUSTER_ISSUER);
        let reader = signed_token_with_issuer("reader", &["tokens-reader"], CLUSTER_ISSUER);
        // Holds `admin:tokens:write` but not the `probe-reader` role the
        // tokens below carry, so it may not delegate their scopes.
        let writer = signed_token_with_issuer("writer", &["tokens-writer"], CLUSTER_ISSUER);
        let read_fence = || async move {
            storage::read_contract_fence(pool)
                .await
                .expect("the fence reads")
        };
        let fence = read_fence().await;
        let key = |seed: u8| caller_key(seed);
        let body = json!({ "scopes": ["probe-reader"] }).to_string();

        // A live member lacks the capability: every keyed form waits, the
        // unkeyed forms commit.
        let (status, refused) = call(
            &router,
            TOKENS_ADMIN_ROUTE,
            &admin,
            Some(body.clone()),
            Some(&key(110)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert_eq!(refused["reason"], json!("capability_not_advertised"));
        assert_eq!(token_rows(pool).await, (0, 0));
        let (status, created) = call(
            &router,
            TOKENS_ADMIN_ROUTE,
            &admin,
            Some(body.clone()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let unkeyed_rotate = format!(
            "{TOKENS_ADMIN_ROUTE}/{}/rotate",
            created["token"]["id"].as_str().expect("an ID")
        );
        let (status, refused) = call(&router, &unkeyed_rotate, &admin, None, Some(&key(111))).await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        assert_eq!(refused["reason"], json!("capability_not_advertised"));
        let (status, rotated) = call(&router, &unkeyed_rotate, &admin, None, None).await;
        assert_eq!(status, StatusCode::OK, "{rotated}");
        assert_eq!(token_rows(pool).await, (1, 2));
        assert!(token_reservations(pool).await.is_empty());
        assert_eq!(read_fence().await, fence, "a refused key raises nothing");

        // The lacking member goes stale: the gate would now admit a key and
        // raise the fence. A request the handler refuses is still refused
        // first, and the fence does not move.
        let updated = pool
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE greengateway.cluster_members
                 SET last_heartbeat_at = now() - make_interval(secs => 60)
                 WHERE instance_id = $1::text::uuid",
                &[&earlier.to_string()],
            )
            .await
            .unwrap();
        assert_eq!(updated, 1);
        let malformed =
            json!({ "scopes": ["probe-reader"], "expires_at": "not-a-time" }).to_string();
        let refusals = [
            (
                TOKENS_ADMIN_ROUTE,
                &reader,
                Some(body.clone()),
                StatusCode::FORBIDDEN,
            ),
            (
                unkeyed_rotate.as_str(),
                &reader,
                None,
                StatusCode::FORBIDDEN,
            ),
            (
                TOKENS_ADMIN_ROUTE,
                &writer,
                Some(body.clone()),
                StatusCode::FORBIDDEN,
            ),
            (
                unkeyed_rotate.as_str(),
                &writer,
                None,
                StatusCode::FORBIDDEN,
            ),
            (
                TOKENS_ADMIN_ROUTE,
                &admin,
                Some(malformed),
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (seed, (uri, token, body, expected)) in (112..).zip(refusals) {
            let (status, refused) = call(&router, uri, token, body, Some(&key(seed))).await;
            assert_eq!(status, expected, "{uri}: {refused}");
        }
        assert_eq!(
            read_fence().await,
            fence,
            "a forbidden or malformed keyed request leaves the contract fence unchanged"
        );
        assert!(token_reservations(pool).await.is_empty());
        assert_eq!(token_rows(pool).await, (1, 2));

        // The first authorized keyed change raises the fence once; exact
        // retries are answered from their receipts, never with a plaintext.
        let issue_key = key(120);
        let (status, issued) = call(
            &router,
            TOKENS_ADMIN_ROUTE,
            &admin,
            Some(body.clone()),
            Some(&issue_key),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let raised = read_fence().await;
        assert_eq!(raised.generation, fence.generation + 1);
        assert!(
            raised.capabilities.contains("caller_operation_keys"),
            "{raised:?}"
        );
        let id = issued["token"]["id"].as_str().expect("an ID").to_owned();
        let plaintext = issued["plaintext_token"]
            .as_str()
            .expect("the first response carries the plaintext")
            .to_owned();
        let (status, receipt) = call(
            &router,
            TOKENS_ADMIN_ROUTE,
            &admin,
            Some(body.clone()),
            Some(&issue_key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["operation"], json!("service_token.issue"));
        assert_eq!(receipt["operation_id"], json!(issue_key));
        assert_eq!(receipt["resource_id"], json!(id));
        assert_eq!(receipt["revision"], json!(1));
        assert_eq!(receipt["secret_returned"], json!(false));
        assert!(!receipt.to_string().contains(&plaintext));

        let rotate_key = key(121);
        let rotate = format!("{TOKENS_ADMIN_ROUTE}/{id}/rotate");
        let (status, rotated) = call(&router, &rotate, &admin, None, Some(&rotate_key)).await;
        assert_eq!(status, StatusCode::OK, "{rotated}");
        let rotated_plaintext = rotated["plaintext_token"]
            .as_str()
            .expect("the first rotation carries the plaintext")
            .to_owned();
        let (status, receipt) = call(&router, &rotate, &admin, None, Some(&rotate_key)).await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["operation"], json!("service_token.rotate"));
        assert_eq!(receipt["resource_id"], json!(id));
        assert_eq!(receipt["revision"], json!(2));
        assert_eq!(receipt["secret_returned"], json!(false));
        assert!(!receipt.to_string().contains(&rotated_plaintext));

        let mut expected = vec![
            (issue_key.clone(), "service_token.issue".to_owned()),
            (rotate_key.clone(), "service_token.rotate".to_owned()),
        ];
        expected.sort();
        assert_eq!(token_reservations(pool).await, expected);
        assert_eq!(token_rows(pool).await, (2, 4));
        assert_eq!(read_fence().await, raised, "the fence was raised once");
    }

    /// I5 for keyed service-token issue and rotation in their PostgreSQL
    /// form, where both are qualified rows: the form of
    /// `admin_tokens_app_tests::a_replayed_token_issue_or_rotation_repeats_no_side_effect_and_never_returns_the_plaintext`
    /// that runs against the PostgreSQL token store. A keyed issue, its
    /// exact retry and its key reused for other scopes; a keyed rotation,
    /// its exact retry and its key reused on another token. No plaintext
    /// and no binding digest reaches a log line at any level or the
    /// rendered metrics, and none reaches a receipt, a conflict answer or
    /// the audit stream. Token IDs and caller keys are not secrets; each
    /// receipt names its key to its caller by design.
    #[test]
    fn postgres_keyed_token_changes_keep_the_plaintext_and_digests_out_of_the_logs_and_metrics() {
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let (outcome, logged, rendered) =
            super::super::admin_tokens_app_tests::capture_logs_and_metrics_on_every_runtime_thread(
                async {
                    let Some(admin_dsn) = locator() else {
                        eprintln!("skipping: no test database locator; CI runs this test");
                        return None;
                    };
                    let database =
                        storage::contract_tests::postgres_audit_tests::create_test_database(
                            &admin_dsn,
                        )
                        .await;
                    let foundation = test_pool(&database.dsn).await;
                    let pool = foundation.pool();
                    storage::migrations::apply_missing_for_startup(pool, &test_settings())
                        .await
                        .unwrap();
                    let (router, earlier) = keyed_replica(pool, audit_log).await;
                    // The member built before caller keys goes stale, so the
                    // operation gate admits a key.
                    let updated = pool
                        .get()
                        .await
                        .unwrap()
                        .execute(
                            "UPDATE greengateway.cluster_members
                             SET last_heartbeat_at = now() - make_interval(secs => 60)
                             WHERE instance_id = $1::text::uuid",
                            &[&earlier.to_string()],
                        )
                        .await
                        .unwrap();
                    assert_eq!(updated, 1);
                    let admin =
                        signed_token_with_issuer("operator", &["superadmin"], CLUSTER_ISSUER);
                    let body = json!({ "scopes": ["probe-reader"] }).to_string();
                    let mut answers = Vec::new();
                    let mut plaintexts = Vec::new();
                    let plaintext_of = |answer: &Value| {
                        answer["plaintext_token"]
                            .as_str()
                            .expect("the first response carries the plaintext")
                            .to_owned()
                    };

                    // A keyed issue, its exact retry, its key for other scopes.
                    let issue_key = caller_key(130);
                    let (status, issued) = call(
                        &router,
                        TOKENS_ADMIN_ROUTE,
                        &admin,
                        Some(body.clone()),
                        Some(&issue_key),
                    )
                    .await;
                    assert_eq!(status, StatusCode::CREATED, "{issued}");
                    let id = issued["token"]["id"].as_str().expect("an ID").to_owned();
                    plaintexts.push(plaintext_of(&issued));
                    let (status, receipt) = call(
                        &router,
                        TOKENS_ADMIN_ROUTE,
                        &admin,
                        Some(body.clone()),
                        Some(&issue_key),
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{receipt}");
                    assert_eq!(receipt["operation"], json!("service_token.issue"));
                    assert_eq!(receipt["secret_returned"], json!(false));
                    answers.push(receipt);
                    let (status, conflict) = call(
                        &router,
                        TOKENS_ADMIN_ROUTE,
                        &admin,
                        Some(json!({ "scopes": ["tokens-reader"] }).to_string()),
                        Some(&issue_key),
                    )
                    .await;
                    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                    assert_eq!(conflict["reason"], json!("caller_operation_conflict"));
                    answers.push(conflict);

                    // A keyed rotation, its exact retry, its key on another
                    // token.
                    let rotate_key = caller_key(131);
                    let rotate = format!("{TOKENS_ADMIN_ROUTE}/{id}/rotate");
                    let (status, rotated) =
                        call(&router, &rotate, &admin, None, Some(&rotate_key)).await;
                    assert_eq!(status, StatusCode::OK, "{rotated}");
                    plaintexts.push(plaintext_of(&rotated));
                    let (status, receipt) =
                        call(&router, &rotate, &admin, None, Some(&rotate_key)).await;
                    assert_eq!(status, StatusCode::OK, "{receipt}");
                    assert_eq!(receipt["operation"], json!("service_token.rotate"));
                    assert_eq!(receipt["secret_returned"], json!(false));
                    answers.push(receipt);
                    let (status, other) = call(
                        &router,
                        TOKENS_ADMIN_ROUTE,
                        &admin,
                        Some(body.clone()),
                        None,
                    )
                    .await;
                    assert_eq!(status, StatusCode::CREATED, "{other}");
                    plaintexts.push(plaintext_of(&other));
                    let other_rotate = format!(
                        "{TOKENS_ADMIN_ROUTE}/{}/rotate",
                        other["token"]["id"].as_str().expect("an ID")
                    );
                    let (status, conflict) =
                        call(&router, &other_rotate, &admin, None, Some(&rotate_key)).await;
                    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                    assert_eq!(conflict["reason"], json!("caller_operation_conflict"));
                    answers.push(conflict);

                    assert_eventually(Duration::from_secs(5), || {
                        capture
                            .events()
                            .iter()
                            .filter(|event| event.event_type == audit::event::SERVICE_TOKEN_CHANGED)
                            .count()
                            == 3
                    });
                    let digests: Vec<String> = pool
                        .get()
                        .await
                        .unwrap()
                        .query(
                            "SELECT binding_digest FROM greengateway.authority_caller_operation_ids \
                             WHERE action LIKE 'service_token.%'",
                            &[],
                        )
                        .await
                        .unwrap()
                        .iter()
                        .map(|row| row.get::<_, Option<String>>(0).expect("a bound digest"))
                        .collect();
                    assert_eq!(digests.len(), 2, "the issue and the rotation are reserved");
                    Some((answers, plaintexts, digests))
                },
            );
        let Some((answers, plaintexts, digests)) = outcome else {
            return;
        };

        assert!(
            logged
                .lines()
                .any(|line| !line.contains("capture sentinel on the")),
            "the handlers logged"
        );
        let answered = format!("{answers:?}");
        let audited = format!("{:?}", capture.events());
        for marker in plaintexts.iter().chain(&digests) {
            assert!(
                !answered.contains(marker),
                "a secret marker reached an answer"
            );
            assert!(
                !audited.contains(marker),
                "a secret marker reached the audit stream"
            );
            assert!(!logged.contains(marker), "a secret marker reached the logs");
            assert!(
                !rendered.contains(marker),
                "a secret marker reached the metrics"
            );
        }
    }
}

/// Synthetic markers and binding digests kept out of the logs and metrics of
/// keyed Connection and catalog changes (issue #425).
#[path = "authority_evidence_marker_app_tests.rs"]
mod marker_keys;
