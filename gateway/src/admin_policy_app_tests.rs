//! Policy administration in `admin_policy.rs`: policy and rule CRUD, history
//! and rollback, validate and convert, the rule preview, rule hits and the
//! shadow review with its bound promotions, and the startup refusal of an
//! invalid policy file. Cluster-mode publication against a real
//! PostgreSQL is the `cluster_policy_tests` module at the end. Shared
//! fixtures stay in `app_tests.rs`.
use super::*;

#[tokio::test]
async fn startup_returns_actionable_error_for_invalid_policy_file() {
    let policy = TempPolicyFile::new(r#"{ "schema_version": "#);
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();

    let error = match app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    ) {
        Ok(_) => panic!("app startup should reject invalid policy file"),
        Err(error) => error,
    };
    let message = error.to_string();

    assert!(
        message.contains("failed to parse policy file"),
        "unexpected startup error: {message}"
    );
    assert!(
        message.contains(&policy.path.to_string_lossy().into_owned()),
        "startup error should name the policy file: {message}"
    );
    assert!(
        !message.contains("panicked"),
        "startup error should not be a panic: {message}"
    );
}

#[tokio::test]
async fn policy_get_capability_uses_mapped_jwt_roles_and_service_token_roles() {
    let jwks_addr = spawn_test_jwks_server().await;
    let token_db = TempDb::new("policy-capability-tokens");
    let token_store = auth::SqliteTokenStore::open(&token_db.path).expect("token store");
    let service_writer = create_service_token(&token_store, &["admin"]);
    let service_reader = create_service_token(&token_store, &["policy-reader"]);
    let policy = TempPolicyFile::new(&policy_document_string("capabilities", "test:old"));
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.egress_deny_private_ips = false;
    config.roles_claim = "realm_access.roles".to_owned();
    configure_test_jwt_provider(&mut config, jwks_addr);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app");
    let jwt = |role: &str, misleading_role: &str| {
        signed_token_with_claims(json!({
            "sub": "mapped-user", "jti": format!("mapped-{role}"),
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "roles": [misleading_role], "realm_access": {"roles": [role]}
        }))
    };
    let mut etag = None;
    for (token, expected) in [
        (jwt("admin", "policy-reader"), "true"),
        (jwt("policy-reader", "admin"), "false"),
        (service_writer, "true"),
        (service_reader, "false"),
    ] {
        let response = router
            .clone()
            .oneshot(bearer_get_request(POLICY_ADMIN_ROUTE, &token))
            .await
            .expect("policy read");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-greengateway-policy-write"], expected);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        let current_etag = policy_etag_header(&response);
        if let Some(previous) = &etag {
            assert_eq!(&current_etag, previous);
        }
        etag = Some(current_etag);
        assert!(json_body(response).await.get("can_write").is_none());
        if expected == "false" {
            let denied = router
                .clone()
                .oneshot(bearer_json_request(
                    Method::POST,
                    POLICY_RULES_ADMIN_ROUTE,
                    &token,
                    json!({"methods": ["GET"], "path": "/orders", "action": "deny"}).to_string(),
                ))
                .await
                .expect("write remains authorized independently");
            assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        }
    }
}

#[tokio::test]
async fn policy_get_returns_current_policy_with_stable_etag_and_requires_read_permission() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router(Some(&policy), test_audit_log());

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let etag = policy_etag_header(&response);
    assert!(etag.starts_with("\"sha256:"));
    assert!(etag.ends_with('"'));
    let body = json_body(response).await;
    assert_eq!(body["id"], json!("initial-policy"));

    let second_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("second policy GET should complete");
    assert_eq!(second_response.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&second_response), etag);

    let read_only_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            None,
            None,
        ))
        .await
        .expect("read-only policy GET should complete");
    assert_eq!(read_only_response.status(), StatusCode::OK);

    let forbidden_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["reader"])),
            None,
            None,
        ))
        .await
        .expect("forbidden policy GET should complete");
    assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);

    let unauthenticated_response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            None,
            None,
            None,
        ))
        .await
        .expect("unauthenticated policy GET should complete");
    assert_eq!(unauthenticated_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn policy_put_with_valid_if_match_updates_live_policy_and_emits_audit_event() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);

    let before_new_reader = router
        .clone()
        .oneshot(audit_query_request(
            "/__test/principal",
            Some(test_principal(&["new-reader"])),
        ))
        .await
        .expect("pre-update test request should complete");
    assert_eq!(before_new_reader.status(), StatusCode::FORBIDDEN);

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let current_etag = policy_etag_header(&get_response);

    let candidate = policy_document_string("updated-policy", "test:new");
    let put_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(candidate),
            Some(&current_etag),
        ))
        .await
        .expect("policy PUT should complete");
    assert_eq!(put_response.status(), StatusCode::OK);
    let new_etag = policy_etag_header(&put_response);
    assert_ne!(new_etag, current_etag);
    let put_body = json_body(put_response).await;
    assert_eq!(put_body["id"], json!("updated-policy"));

    let after_new_reader = router
        .clone()
        .oneshot(audit_query_request(
            "/__test/principal",
            Some(test_principal(&["new-reader"])),
        ))
        .await
        .expect("post-update new-reader request should complete");
    assert_eq!(after_new_reader.status(), StatusCode::OK);

    let after_old_reader = router
        .oneshot(audit_query_request(
            "/__test/principal",
            Some(test_principal(&["old-reader"])),
        ))
        .await
        .expect("post-update old-reader request should complete");
    assert_eq!(after_old_reader.status(), StatusCode::FORBIDDEN);

    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::POLICY_CHANGED)
    });
    let events = capture.events();
    let event = events
        .iter()
        .find(|event| event.event_type == audit::event::POLICY_CHANGED)
        .expect("policy.changed event should be captured");
    let actor = event.actor.as_ref().expect("actor should be set");
    assert_eq!(actor.user_id, "user-123");
    assert_eq!(actor.roles, Some(vec!["admin".to_owned()]));
    assert_eq!(event.payload["before"]["id"], json!("initial-policy"));
    assert_eq!(event.payload["after"]["id"], json!("updated-policy"));
    assert_eq!(event.payload["before"]["routes"], json!(6));
    assert_eq!(event.payload["after"]["routes"], json!(6));
    assert_eq!(event.payload["changed_sections"], json!(["id", "routes"]));
}

#[tokio::test]
async fn policy_put_rejects_egress_change_without_persisting_or_swapping() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let disk_before = fs::read_to_string(&policy.path).expect("policy file should read");
    let (etag_before, live_before) = current_policy(&router).await;

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_with_egress_string(
                "replacement-policy",
                "test:new",
                "replacement.example.test",
            )),
            Some(&etag_before),
        ))
        .await
        .expect("egress-changing policy PUT should complete");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert!(body["error"]
        .as_str()
        .is_some_and(|error| error.contains("restart")));
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should still read"),
        disk_before
    );

    let (etag_after, live_after) = current_policy(&router).await;
    assert_eq!(etag_after, etag_before);
    assert_eq!(live_after, live_before);
    assert!(live_after["egress"].is_null());
}

#[tokio::test]
async fn policy_history_records_every_policy_mutation_path_once() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([
            direct_rule_json(Some("managed-rule"), &["GET"], "/managed", "allow"),
            direct_rule_json(Some("second-rule"), &["POST"], "/second", "deny")
        ]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let history_db = TempDb::new("policy-history-all-mutations");
    let router = policy_admin_router_with_history(Some(&policy), &history_db);

    assert!(policy_history_entries(&router, None).await.is_empty());

    let (etag, _) = current_policy(&router).await;
    let put_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_with_rules_string(
                "whole-policy",
                json!([
                    direct_rule_json(Some("managed-rule"), &["GET"], "/managed", "allow"),
                    direct_rule_json(Some("second-rule"), &["POST"], "/second", "deny")
                ]),
            )),
            Some(&etag),
        ))
        .await
        .expect("policy PUT should complete");
    assert_eq!(put_response.status(), StatusCode::OK);
    assert_history_versions(&router, &["policy_replaced"]).await;

    let create_etag = policy_etag_header(&put_response);
    let create_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(
                json!({ "id": "created-rule", "path": "/created", "action": "allow" }).to_string(),
            ),
            Some(&create_etag),
        ))
        .await
        .expect("rule POST should complete");
    assert_eq!(create_response.status(), StatusCode::CREATED);
    assert_history_versions(&router, &["rule_created", "policy_replaced"]).await;

    let patch_etag = policy_etag_header(&create_response);
    let patch_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PATCH,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/created-rule"),
            Some(test_principal(&["admin"])),
            Some(json!({ "action": "deny" }).to_string()),
            Some(&patch_etag),
        ))
        .await
        .expect("rule PATCH should complete");
    assert_eq!(patch_response.status(), StatusCode::OK);
    assert_history_versions(
        &router,
        &["rule_updated", "rule_created", "policy_replaced"],
    )
    .await;

    let delete_etag = policy_etag_header(&patch_response);
    let delete_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::DELETE,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/created-rule"),
            Some(test_principal(&["admin"])),
            None,
            Some(&delete_etag),
        ))
        .await
        .expect("rule DELETE should complete");
    assert_eq!(delete_response.status(), StatusCode::OK);
    assert_history_versions(
        &router,
        &[
            "rule_deleted",
            "rule_updated",
            "rule_created",
            "policy_replaced",
        ],
    )
    .await;

    let reorder_etag = policy_etag_header(&delete_response);
    let reorder_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_RULES_ORDER_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(json!(["second-rule", "managed-rule"]).to_string()),
            Some(&reorder_etag),
        ))
        .await
        .expect("rule order PUT should complete");
    assert_eq!(reorder_response.status(), StatusCode::OK);

    let entries = policy_history_page(
        &router,
        POLICY_HISTORY_ADMIN_ROUTE,
        Some(test_principal(&["admin"])),
    )
    .await["versions"]
        .as_array()
        .expect("versions should be an array")
        .clone();
    assert_eq!(
        entries.len(),
        5,
        "every successful mutation should append exactly one version"
    );
    assert_eq!(
        history_actions(&entries),
        vec![
            "rules_reordered",
            "rule_deleted",
            "rule_updated",
            "rule_created",
            "policy_replaced",
        ]
    );
    for (expected_version, entry) in (1..=5).rev().zip(entries.iter()) {
        assert_eq!(entry["version"], json!(expected_version));
        assert_eq!(entry["actor"], json!("user-123"));
        assert_rfc3339_timestamp(
            entry["created_at"]
                .as_str()
                .expect("timestamp should exist"),
        );
        assert!(
            entry.get("policy").is_none(),
            "list entries should omit policy snapshots"
        );
    }
}

#[tokio::test]
async fn policy_put_succeeds_with_warning_when_history_append_fails_after_commit() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let history_db = TempDb::new("policy-history-append-failure");
    let router = policy_admin_router_with_history(Some(&policy), &history_db);

    let connection = rusqlite::Connection::open(&history_db.path).expect("history db should open");
    connection
        .execute_batch("DROP TABLE policy_versions;")
        .expect("history table should be droppable");
    drop(connection);

    let (current_etag, _) = current_policy(&router).await;
    let candidate = policy_document_string("updated-policy", "test:new");
    let expected_policy = serde_json::to_value(
        rbac::Policy::validate_json_value(
            serde_json::from_str::<Value>(&candidate).expect("candidate policy should be JSON"),
        )
        .expect("candidate policy should validate"),
    )
    .expect("validated candidate policy should serialize");
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(candidate),
            Some(&current_etag),
        ))
        .await
        .expect("policy PUT should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-greengateway-policy-history-warning")
            .and_then(|value| value.to_str().ok()),
        Some("policy_history_append_failed")
    );
    let new_etag = policy_etag_header(&response);
    assert_ne!(new_etag, current_etag);
    assert_eq!(json_body(response).await, expected_policy);

    let (live_etag, live_policy) = current_policy(&router).await;
    assert_eq!(live_etag, new_etag);
    assert_eq!(live_policy, expected_policy);
}

#[tokio::test]
async fn policy_rule_create_succeeds_with_warning_when_history_append_fails_after_commit() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let history_db = TempDb::new("policy-history-rule-append-failure");
    let router = policy_admin_router_with_history(Some(&policy), &history_db);

    let connection = rusqlite::Connection::open(&history_db.path).expect("history db should open");
    connection
        .execute_batch("DROP TABLE policy_versions;")
        .expect("history table should be droppable");
    drop(connection);

    let (current_etag, _) = current_policy(&router).await;
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(
                json!({ "id": "created-rule", "path": "/created", "action": "allow" }).to_string(),
            ),
            Some(&current_etag),
        ))
        .await
        .expect("rule POST should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        response
            .headers()
            .get("x-greengateway-policy-history-warning")
            .and_then(|value| value.to_str().ok()),
        Some("policy_history_append_failed")
    );
    let new_etag = policy_etag_header(&response);
    assert_ne!(new_etag, current_etag);
    let created_rule = json_body(response).await;
    assert_eq!(created_rule["id"], json!("created-rule"));
    assert_eq!(created_rule["path"], json!("/created"));
    assert_eq!(created_rule["action"], json!("allow"));

    let (live_etag, live_policy) = current_policy(&router).await;
    assert_eq!(live_etag, new_etag);
    assert_eq!(live_policy["rules"][0]["id"], json!("created-rule"));
    assert_eq!(live_policy["rules"][0]["path"], json!("/created"));
    assert_eq!(live_policy["rules"][0]["action"], json!("allow"));
}

#[tokio::test]
async fn policy_history_list_paginates_and_requires_read_permission() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let history_db = TempDb::new("policy-history-list");
    let router = policy_admin_router_with_history(Some(&policy), &history_db);

    for id in ["first-policy", "second-policy"] {
        let (etag, _) = current_policy(&router).await;
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(policy_document_string(id, "test:new")),
                Some(&etag),
            ))
            .await
            .expect("policy PUT should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    let first_page = policy_history_page(
        &router,
        "/v1/admin/policy/history?limit=1",
        Some(test_principal(&["policy-reader"])),
    )
    .await;
    assert_eq!(
        first_page["versions"]
            .as_array()
            .expect("versions array")
            .len(),
        1
    );
    assert_eq!(first_page["versions"][0]["version"], json!(2));
    let cursor = first_page["next_cursor"]
        .as_str()
        .expect("first page should include a cursor");

    let second_page = policy_history_page(
        &router,
        &format!("/v1/admin/policy/history?limit=1&cursor={cursor}"),
        Some(test_principal(&["policy-reader"])),
    )
    .await;
    assert_eq!(
        second_page["versions"]
            .as_array()
            .expect("versions array")
            .len(),
        1
    );
    assert_eq!(second_page["versions"][0]["version"], json!(1));
    assert!(second_page["next_cursor"].is_null());

    let forbidden = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            "/v1/admin/policy/history",
            Some(test_principal(&["reader"])),
            None,
            None,
        ))
        .await
        .expect("forbidden history request should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let unauthenticated = router
        .oneshot(policy_admin_request(
            Method::GET,
            "/v1/admin/policy/history",
            None,
            None,
            None,
        ))
        .await
        .expect("unauthenticated history request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn policy_rollback_restores_snapshot_appends_history_and_requires_write_permission() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let history_db = TempDb::new("policy-history-rollback");
    let router = policy_admin_router_with_history(Some(&policy), &history_db);

    let (first_etag, _) = current_policy(&router).await;
    let first_update = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_string("target-policy", "test:new")),
            Some(&first_etag),
        ))
        .await
        .expect("first policy PUT should complete");
    assert_eq!(first_update.status(), StatusCode::OK);

    let (second_etag, _) = current_policy(&router).await;
    let second_update = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_string("later-policy", "test:old")),
            Some(&second_etag),
        ))
        .await
        .expect("second policy PUT should complete");
    assert_eq!(second_update.status(), StatusCode::OK);

    let entries_before_rollback = policy_history_entries(&router, None).await;
    assert_eq!(entries_before_rollback.len(), 2);
    assert_eq!(entries_before_rollback[1]["version"], json!(1));
    let target_snapshot = entries_before_rollback[1]["policy"].clone();
    assert_eq!(target_snapshot["id"], json!("target-policy"));

    let (rollback_etag, _) = current_policy(&router).await;
    let forbidden = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            "/v1/admin/policy/rollback/1",
            Some(test_principal(&["policy-reader"])),
            None,
            Some(&rollback_etag),
        ))
        .await
        .expect("read-only rollback request should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let unknown = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            "/v1/admin/policy/rollback/404",
            Some(test_principal(&["admin"])),
            None,
            Some(&rollback_etag),
        ))
        .await
        .expect("unknown rollback request should complete");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let missing_if_match = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            "/v1/admin/policy/rollback/1",
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("missing If-Match rollback request should complete");
    assert_eq!(missing_if_match.status(), StatusCode::PRECONDITION_REQUIRED);

    let rollback = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            "/v1/admin/policy/rollback/1",
            Some(test_principal(&["admin"])),
            None,
            Some(&rollback_etag),
        ))
        .await
        .expect("rollback request should complete");
    assert_eq!(rollback.status(), StatusCode::OK);
    let rolled_back = json_body(rollback).await;
    assert_eq!(rolled_back, target_snapshot);

    let (_, live_policy) = current_policy(&router).await;
    assert_eq!(live_policy, target_snapshot);

    let entries_after_rollback = policy_history_entries(&router, None).await;
    assert_eq!(
        entries_after_rollback.len(),
        entries_before_rollback.len() + 1,
        "rollback should append history without deleting prior versions"
    );
    assert_eq!(
        history_actions(&entries_after_rollback),
        vec!["policy_rolled_back", "policy_replaced", "policy_replaced"]
    );
    assert_eq!(entries_after_rollback[0]["version"], json!(3));
    assert_eq!(
        entries_after_rollback[0]["diff_summary"]["target_version"],
        json!(1)
    );
    assert_eq!(entries_after_rollback[0]["policy"], target_snapshot);
    assert_eq!(entries_after_rollback[1], entries_before_rollback[0]);
    assert_eq!(entries_after_rollback[2], entries_before_rollback[1]);
}

#[tokio::test]
async fn policy_rollback_rejects_egress_change_without_persisting_or_swapping() {
    let policy = TempPolicyFile::new(&policy_document_with_egress_string(
        "initial-policy",
        "test:old",
        "initial.example.test",
    ));
    let history_db = TempDb::new("policy-history-egress-rollback");
    let router = policy_admin_router_with_history(Some(&policy), &history_db);

    let (etag, _) = current_policy(&router).await;
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_with_egress_string(
                "target-policy",
                "test:new",
                "initial.example.test",
            )),
            Some(&etag),
        ))
        .await
        .expect("same-egress policy PUT should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(policy_history_entries(&router, None).await.len(), 1);
    drop(router);

    policy.write(&policy_document_with_egress_string(
        "restarted-policy",
        "test:new",
        "restarted.example.test",
    ));
    let restarted_router = policy_admin_router_with_history(Some(&policy), &history_db);
    let disk_before = fs::read_to_string(&policy.path).expect("policy file should read");
    let (etag_before, live_before) = current_policy(&restarted_router).await;
    assert_eq!(
        live_before["egress"]["hosts"],
        json!(["restarted.example.test"])
    );

    let response = restarted_router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            "/v1/admin/policy/rollback/1",
            Some(test_principal(&["admin"])),
            None,
            Some(&etag_before),
        ))
        .await
        .expect("egress-changing rollback should complete");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert!(body["error"]
        .as_str()
        .is_some_and(|error| error.contains("restart")));
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should still read"),
        disk_before
    );

    let (etag_after, live_after) = current_policy(&restarted_router).await;
    assert_eq!(etag_after, etag_before);
    assert_eq!(live_after, live_before);
    assert_eq!(
        policy_history_entries(&restarted_router, None).await.len(),
        1
    );
}

#[tokio::test]
async fn policy_put_with_stale_if_match_returns_precondition_failed_without_changes() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let current_etag = policy_etag_header(&get_response);

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_string("updated-policy", "test:new")),
            Some("\"sha256:stale\""),
        ))
        .await
        .expect("stale policy PUT should complete");

    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );

    let after_get = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET after stale PUT should complete");
    assert_eq!(after_get.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&after_get), current_etag);
    assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_policy_puts_with_same_if_match_allow_only_one_update() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router(Some(&policy), test_audit_log());

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let current_etag = policy_etag_header(&get_response);

    let first_policy = policy_document("concurrent-policy-a", "test:new");
    let second_policy = policy_document("concurrent-policy-b", "test:new");
    let first_candidate =
        serde_json::to_string_pretty(&first_policy).expect("test policy should serialize");
    let second_candidate =
        serde_json::to_string_pretty(&second_policy).expect("test policy should serialize");
    let body_barrier = Arc::new(tokio::sync::Barrier::new(3));

    let first_task = tokio::spawn({
        let router = router.clone();
        let current_etag = current_etag.clone();
        let body_barrier = Arc::clone(&body_barrier);

        async move {
            router
                .oneshot(synchronized_policy_put_request(
                    first_candidate,
                    &current_etag,
                    body_barrier,
                ))
                .await
                .expect("first policy PUT should complete")
        }
    });
    let second_task = tokio::spawn({
        let router = router.clone();
        let current_etag = current_etag.clone();
        let body_barrier = Arc::clone(&body_barrier);

        async move {
            router
                .oneshot(synchronized_policy_put_request(
                    second_candidate,
                    &current_etag,
                    body_barrier,
                ))
                .await
                .expect("second policy PUT should complete")
        }
    });

    tokio::time::timeout(Duration::from_secs(2), body_barrier.wait())
        .await
        .expect("both policy PUT bodies should reach the release barrier");

    let (first_response, second_response) = tokio::join!(first_task, second_task);
    let first_response = first_response.expect("first policy PUT task should join");
    let second_response = second_response.expect("second policy PUT task should join");

    let first_status = first_response.status();
    let first_etag = (first_status == StatusCode::OK).then(|| policy_etag_header(&first_response));
    let first_body = if first_status == StatusCode::OK {
        Some(json_body(first_response).await)
    } else {
        assert_eq!(first_status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            body_string(first_response).await,
            r#"{"error":"If-Match does not match the current policy ETag"}"#
        );
        None
    };

    let second_status = second_response.status();
    let second_etag =
        (second_status == StatusCode::OK).then(|| policy_etag_header(&second_response));
    let second_body = if second_status == StatusCode::OK {
        Some(json_body(second_response).await)
    } else {
        assert_eq!(second_status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            body_string(second_response).await,
            r#"{"error":"If-Match does not match the current policy ETag"}"#
        );
        None
    };

    assert_eq!(
        [first_status, second_status]
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        [first_status, second_status]
            .iter()
            .filter(|status| **status == StatusCode::PRECONDITION_FAILED)
            .count(),
        1
    );

    let (winning_id, winning_etag, winning_body, mut winning_policy) =
        if first_status == StatusCode::OK {
            (
                "concurrent-policy-a",
                first_etag.expect("successful PUT should include ETag"),
                first_body.expect("successful PUT should include JSON body"),
                first_policy,
            )
        } else {
            (
                "concurrent-policy-b",
                second_etag.expect("successful PUT should include ETag"),
                second_body.expect("successful PUT should include JSON body"),
                second_policy,
            )
        };

    assert_ne!(winning_etag, current_etag);
    assert_eq!(winning_body["id"], json!(winning_id));
    winning_policy["rules"] = json!([]);

    let persisted_policy: Value =
        serde_json::from_str(&fs::read_to_string(&policy.path).expect("policy file should read"))
            .expect("persisted policy should be JSON");
    assert_eq!(persisted_policy, winning_policy);

    let live_response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET after concurrent PUTs should complete");
    assert_eq!(live_response.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&live_response), winning_etag);
    assert_eq!(json_body(live_response).await, winning_policy);
}

#[tokio::test]
async fn policy_put_with_invalid_policy_returns_errors_without_persisting_or_swapping() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let current_etag = policy_etag_header(&get_response);

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(r#"{ "schema_version": "2.0.0" }"#.to_owned()),
            Some(&current_etag),
        ))
        .await
        .expect("invalid policy PUT should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(false));
    assert!(
        body["errors"][0]
            .as_str()
            .unwrap_or_default()
            .contains("schema_version must start with"),
        "unexpected validation body: {body}"
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );

    let after_get = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET after invalid PUT should complete");
    assert_eq!(policy_etag_header(&after_get), current_etag);
    assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
}

#[tokio::test]
async fn policy_put_rejects_relative_route_prefix_without_persisting_or_swapping() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let current_etag = policy_etag_header(&get_response);
    let mut invalid_policy = policy_document("relative-route", "test:new");
    invalid_policy["routes"][5]["path_prefix"] = json!("__test");

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(invalid_policy.to_string()),
            Some(&current_etag),
        ))
        .await
        .expect("relative route prefix PUT should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(false));
    assert!(
        body["errors"][0]
            .as_str()
            .unwrap_or_default()
            .contains("routes[5].path_prefix must start with '/'"),
        "unexpected validation body: {body}"
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );

    let after_get = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET after invalid PUT should complete");
    assert_eq!(policy_etag_header(&after_get), current_etag);
    assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
}

#[tokio::test]
async fn policy_put_missing_if_match_is_rejected_without_changes() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

    let response = router
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_string("updated-policy", "test:new")),
            None,
        ))
        .await
        .expect("missing If-Match policy PUT should complete");

    assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"If-Match header is required"}"#
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
}

#[tokio::test]
async fn policy_put_requires_write_permission() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let current_etag = policy_etag_header(&get_response);

    let response = router
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            Some(policy_document_string("updated-policy", "test:new")),
            Some(&current_etag),
        ))
        .await
        .expect("read-only policy PUT should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
}

#[tokio::test]
async fn policy_rule_create_without_id_generates_stable_id_that_survives_position_shift_and_emits_audit_event(
) {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([direct_rule_json(Some("seed"), &["GET"], "/seed", "allow")]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let (current_etag, _) = current_policy(&router).await;

    let create_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(
                json!({
                    "methods": ["GET"],
                    "path": "/created/a",
                    "action": "allow"
                })
                .to_string(),
            ),
            Some(&current_etag),
        ))
        .await
        .expect("rule POST should complete");

    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_etag = policy_etag_header(&create_response);
    let created_rule = json_body(create_response).await;
    let created_rule_id = created_rule["id"]
        .as_str()
        .expect("created rule id should be present")
        .to_owned();
    assert!(created_rule_id.starts_with("rule-"));
    assert_ne!(created_rule_id, "1");
    assert_eq!(created_rule["path"], json!("/created/a"));

    let event = captured_policy_change(&capture, "rule_created");
    assert_policy_change_actor(&event);
    assert_eq!(
        event.payload["diff_summary"],
        json!({
            "action": "rule_created",
            "rule_id": created_rule_id,
            "position": 1
        })
    );

    let delete_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::DELETE,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/seed"),
            Some(test_principal(&["admin"])),
            None,
            Some(&create_etag),
        ))
        .await
        .expect("seed DELETE should complete");
    assert_eq!(delete_response.status(), StatusCode::OK);
    let delete_etag = policy_etag_header(&delete_response);

    let patch_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PATCH,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/{created_rule_id}"),
            Some(test_principal(&["admin"])),
            Some(json!({ "action": "deny" }).to_string()),
            Some(&delete_etag),
        ))
        .await
        .expect("created rule PATCH should complete");

    assert_eq!(patch_response.status(), StatusCode::OK);
    let patched_rule = json_body(patch_response).await;
    assert_eq!(patched_rule["id"], json!(created_rule_id));
    assert_eq!(patched_rule["path"], json!("/created/a"));
    assert_eq!(patched_rule["action"], json!("deny"));

    let (_, live_policy) = current_policy(&router).await;
    assert_eq!(
        live_policy["rules"].as_array().unwrap_or(&Vec::new()).len(),
        1
    );
    assert_eq!(live_policy["rules"][0]["id"], json!(created_rule_id));
    assert_eq!(live_policy["rules"][0]["action"], json!("deny"));
}

#[tokio::test]
async fn policy_rule_create_rejects_explicit_id_collision() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([direct_rule_json(
            Some("existing-rule"),
            &["GET"],
            "/existing",
            "allow"
        )]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let (current_etag, _) = current_policy(&router).await;

    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(
                json!({
                    "id": "existing-rule",
                    "methods": ["GET"],
                    "path": "/new",
                    "action": "deny"
                })
                .to_string(),
            ),
            Some(&current_etag),
        ))
        .await
        .expect("colliding rule POST should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"rule id 'existing-rule' already exists"}"#
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
}

#[tokio::test]
async fn policy_rule_patch_updates_one_field_preserves_others_and_emits_audit_event() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([{
            "id": "managed-rule",
            "methods": ["GET"],
            "path": "/patch",
            "dispatch": {
                "kind": "legacy",
                "upstream_origin": "https://api.example.test"
            },
            "principal": { "roles": ["admin"] },
            "action": "allow"
        }]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let (current_etag, _) = current_policy(&router).await;

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PATCH,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
            Some(test_principal(&["admin"])),
            Some(json!({ "action": "deny" }).to_string()),
            Some(&current_etag),
        ))
        .await
        .expect("rule PATCH should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let new_etag = policy_etag_header(&response);
    assert_ne!(new_etag, current_etag);
    let patched_rule = json_body(response).await;
    assert_eq!(patched_rule["id"], json!("managed-rule"));
    assert_eq!(patched_rule["methods"], json!(["GET"]));
    assert_eq!(patched_rule["path"], json!("/patch"));
    assert_eq!(
        patched_rule["dispatch"]["upstream_origin"],
        json!("https://api.example.test")
    );
    assert_eq!(patched_rule["dispatch"]["kind"], json!("legacy"));
    assert_eq!(patched_rule["principal"]["roles"], json!(["admin"]));
    assert_eq!(patched_rule["action"], json!("deny"));

    let event = captured_policy_change(&capture, "rule_updated");
    assert_policy_change_actor(&event);
    assert_eq!(
        event.payload["diff_summary"],
        json!({
            "action": "rule_updated",
            "rule_id": "managed-rule",
            "changed_fields": ["action"]
        })
    );
}

#[tokio::test]
async fn policy_rule_patch_can_replace_path_matcher_with_tool_name_matcher() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([{
            "id": "managed-rule",
            "methods": ["GET"],
            "path": "/patch",
            "principal": { "roles": ["admin"] },
            "action": "allow"
        }]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let (current_etag, _) = current_policy(&router).await;

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PATCH,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
            Some(test_principal(&["admin"])),
            Some(
                json!({
                    "methods": [],
                    "path": null,
                    "tool_name": "reports.export",
                    "action": "deny"
                })
                .to_string(),
            ),
            Some(&current_etag),
        ))
        .await
        .expect("rule PATCH should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let patched_rule = json_body(response).await;
    assert_eq!(patched_rule["id"], json!("managed-rule"));
    assert_eq!(patched_rule.get("path"), None);
    assert_eq!(patched_rule["tool_name"], json!("reports.export"));
    assert_eq!(patched_rule["methods"], json!([]));
    assert_eq!(patched_rule["action"], json!("deny"));

    let event = captured_policy_change(&capture, "rule_updated");
    assert_policy_change_actor(&event);
    assert_eq!(
        event.payload["diff_summary"],
        json!({
            "action": "rule_updated",
            "rule_id": "managed-rule",
            "changed_fields": ["methods", "path", "tool_name", "action"]
        })
    );
}

#[tokio::test]
async fn policy_rule_patch_can_disable_rule_and_live_evaluation_skips_it() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([
            {
                "id": "deny-probe",
                "methods": ["GET"],
                "path": "/__test/principal",
                "action": "deny"
            },
            {
                "id": "allow-probe",
                "methods": ["GET"],
                "path": "/__test/principal",
                "action": "allow"
            }
        ]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);

    let before_probe = router
        .clone()
        .oneshot(audit_query_request(
            "/__test/principal",
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("pre-disable probe should complete");
    assert_eq!(before_probe.status(), StatusCode::FORBIDDEN);

    let (current_etag, _) = current_policy(&router).await;
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PATCH,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/deny-probe"),
            Some(test_principal(&["admin"])),
            Some(json!({ "enabled": false }).to_string()),
            Some(&current_etag),
        ))
        .await
        .expect("rule enabled PATCH should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let new_etag = policy_etag_header(&response);
    assert_ne!(new_etag, current_etag);
    let patched_rule = json_body(response).await;
    assert_eq!(patched_rule["id"], json!("deny-probe"));
    assert_eq!(patched_rule["enabled"], json!(false));
    assert_eq!(patched_rule["action"], json!("deny"));

    let after_probe = router
        .clone()
        .oneshot(audit_query_request(
            "/__test/principal",
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("post-disable probe should complete");
    assert_eq!(after_probe.status(), StatusCode::OK);
    assert_eq!(json_body(after_probe).await["user_id"], json!("user-123"));

    let (_, live_policy) = current_policy(&router).await;
    assert_eq!(live_policy["rules"][0]["enabled"], json!(false));

    let event = captured_policy_change(&capture, "rule_updated");
    assert_policy_change_actor(&event);
    assert_eq!(
        event.payload["diff_summary"],
        json!({
            "action": "rule_updated",
            "rule_id": "deny-probe",
            "changed_fields": ["enabled"]
        })
    );
}

#[tokio::test]
async fn policy_rule_patch_and_delete_unknown_id_return_not_found() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([direct_rule_json(
            Some("managed-rule"),
            &["GET"],
            "/managed",
            "allow"
        )]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let (current_etag, _) = current_policy(&router).await;

    let patch_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PATCH,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/missing-rule"),
            Some(test_principal(&["admin"])),
            Some(json!({ "action": "deny" }).to_string()),
            Some(&current_etag),
        ))
        .await
        .expect("missing rule PATCH should complete");
    assert_eq!(patch_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(patch_response).await,
        r#"{"error":"rule id 'missing-rule' was not found"}"#
    );

    let delete_response = router
        .oneshot(policy_admin_request(
            Method::DELETE,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/missing-rule"),
            Some(test_principal(&["admin"])),
            None,
            Some(&current_etag),
        ))
        .await
        .expect("missing rule DELETE should complete");
    assert_eq!(delete_response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(delete_response).await,
        r#"{"error":"rule id 'missing-rule' was not found"}"#
    );
}

#[tokio::test]
async fn policy_rule_delete_removes_rule_and_emits_audit_event() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([direct_rule_json(
            Some("managed-rule"),
            &["GET"],
            "/managed",
            "allow"
        )]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let (current_etag, _) = current_policy(&router).await;

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::DELETE,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
            Some(test_principal(&["admin"])),
            None,
            Some(&current_etag),
        ))
        .await
        .expect("rule DELETE should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(policy_etag_header(&response), current_etag);
    assert_eq!(
        json_body(response).await,
        json!({ "deleted_rule_id": "managed-rule" })
    );

    let (_, live_policy) = current_policy(&router).await;
    assert_eq!(live_policy["rules"], json!([]));

    let event = captured_policy_change(&capture, "rule_deleted");
    assert_policy_change_actor(&event);
    assert_eq!(
        event.payload["diff_summary"],
        json!({
            "action": "rule_deleted",
            "rule_id": "managed-rule",
            "position": 0
        })
    );
}

#[tokio::test]
async fn policy_rules_reorder_valid_permutation_changes_first_match_order_and_emits_audit_event() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([
            direct_rule_json(Some("deny-probe"), &["GET"], "/__test/principal", "deny"),
            direct_rule_json(Some("allow-probe"), &["GET"], "/__test/principal", "allow")
        ]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);

    let before_probe = router
        .clone()
        .oneshot(audit_query_request(
            "/__test/principal",
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("pre-reorder probe should complete");
    assert_eq!(before_probe.status(), StatusCode::FORBIDDEN);

    let (current_etag, _) = current_policy(&router).await;
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_RULES_ORDER_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(json!(["allow-probe", "deny-probe"]).to_string()),
            Some(&current_etag),
        ))
        .await
        .expect("rule order PUT should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let new_etag = policy_etag_header(&response);
    assert_ne!(new_etag, current_etag);
    assert_eq!(
        json_body(response).await,
        json!({ "order": ["allow-probe", "deny-probe"] })
    );

    let after_probe = router
        .clone()
        .oneshot(audit_query_request(
            "/__test/principal",
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("post-reorder probe should complete");
    assert_eq!(after_probe.status(), StatusCode::OK);
    assert_eq!(json_body(after_probe).await["user_id"], json!("user-123"));

    let (_, live_policy) = current_policy(&router).await;
    assert_eq!(live_policy["rules"][0]["id"], json!("allow-probe"));
    assert_eq!(live_policy["rules"][1]["id"], json!("deny-probe"));

    let event = captured_policy_change(&capture, "rules_reordered");
    assert_policy_change_actor(&event);
    assert_eq!(
        event.payload["diff_summary"],
        json!({
            "action": "rules_reordered",
            "new_order": ["allow-probe", "deny-probe"]
        })
    );
}

#[tokio::test]
async fn policy_rules_reorder_invalid_set_is_rejected_without_partial_reorder() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([
            direct_rule_json(Some("first-rule"), &["GET"], "/first", "allow"),
            direct_rule_json(Some("second-rule"), &["GET"], "/second", "deny")
        ]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let (current_etag, _) = current_policy(&router).await;

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_RULES_ORDER_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(json!(["second-rule", "second-rule", "unknown-rule"]).to_string()),
            Some(&current_etag),
        ))
        .await
        .expect("invalid rule order PUT should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    let errors = body["errors"]
        .as_array()
        .expect("errors should be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(errors.iter().any(|error| error.contains("length mismatch")));
    assert!(errors.iter().any(|error| error.contains("duplicate ids")));
    assert!(errors.iter().any(|error| error.contains("missing ids")));
    assert!(errors.iter().any(|error| error.contains("unknown ids")));
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );

    let (after_etag, live_policy) = current_policy(&router).await;
    assert_eq!(after_etag, current_etag);
    assert_eq!(live_policy["rules"][0]["id"], json!("first-rule"));
    assert_eq!(live_policy["rules"][1]["id"], json!("second-rule"));
}

#[tokio::test]
async fn policy_rule_mutations_require_write_permission() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([direct_rule_json(
            Some("managed-rule"),
            &["GET"],
            "/managed",
            "allow"
        )]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let (current_etag, _) = current_policy(&router).await;

    for (method, uri, body) in [
        (
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE.to_owned(),
            Some(json!({ "path": "/new", "action": "allow" }).to_string()),
        ),
        (
            Method::PATCH,
            format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
            Some(json!({ "action": "deny" }).to_string()),
        ),
        (
            Method::DELETE,
            format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
            None,
        ),
        (
            Method::PUT,
            POLICY_RULES_ORDER_ADMIN_ROUTE.to_owned(),
            Some(json!(["managed-rule"]).to_string()),
        ),
    ] {
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                method,
                &uri,
                Some(test_principal(&["policy-reader"])),
                body,
                Some(&current_etag),
            ))
            .await
            .expect("write-forbidden policy rule request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }

    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
}

#[tokio::test]
async fn policy_rule_mutations_require_fresh_if_match() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([direct_rule_json(
            Some("managed-rule"),
            &["GET"],
            "/managed",
            "allow"
        )]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let (current_etag, _) = current_policy(&router).await;

    for (method, uri, body) in [
        (
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE.to_owned(),
            Some(json!({ "path": "/new", "action": "allow" }).to_string()),
        ),
        (
            Method::PATCH,
            format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
            Some(json!({ "action": "deny" }).to_string()),
        ),
        (
            Method::DELETE,
            format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
            None,
        ),
        (
            Method::PUT,
            POLICY_RULES_ORDER_ADMIN_ROUTE.to_owned(),
            Some(json!(["managed-rule"]).to_string()),
        ),
    ] {
        let missing_response = router
            .clone()
            .oneshot(policy_admin_request(
                method.clone(),
                &uri,
                Some(test_principal(&["admin"])),
                body.clone(),
                None,
            ))
            .await
            .expect("missing If-Match policy rule request should complete");
        assert_eq!(
            missing_response.status(),
            StatusCode::PRECONDITION_REQUIRED,
            "{uri}"
        );
        assert_eq!(
            body_string(missing_response).await,
            r#"{"error":"If-Match header is required"}"#
        );

        let stale_response = router
            .clone()
            .oneshot(policy_admin_request(
                method,
                &uri,
                Some(test_principal(&["admin"])),
                body,
                Some("\"sha256:stale\""),
            ))
            .await
            .expect("stale If-Match policy rule request should complete");
        assert_eq!(
            stale_response.status(),
            StatusCode::PRECONDITION_FAILED,
            "{uri}"
        );
        assert_eq!(
            body_string(stale_response).await,
            r#"{"error":"If-Match does not match the current policy ETag"}"#
        );
    }

    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
    let (after_etag, _) = current_policy(&router).await;
    assert_eq!(after_etag, current_etag);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_policy_rule_patch_and_policy_put_with_same_if_match_allow_only_one_update() {
    let initial_policy = policy_document_with_rules_string(
        "initial-policy",
        json!([direct_rule_json(
            Some("managed-rule"),
            &["GET"],
            "/managed",
            "allow"
        )]),
    );
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let (current_etag, _) = current_policy(&router).await;

    let patch_body = json!({ "action": "deny" }).to_string();
    let whole_policy = policy_document("concurrent-put-policy", "test:old");
    let whole_policy_body =
        serde_json::to_string_pretty(&whole_policy).expect("test policy should serialize");
    let body_barrier = Arc::new(tokio::sync::Barrier::new(3));

    let patch_task = tokio::spawn({
        let router = router.clone();
        let current_etag = current_etag.clone();
        let body_barrier = Arc::clone(&body_barrier);

        async move {
            router
                .oneshot(synchronized_policy_admin_request(
                    Method::PATCH,
                    &format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                    patch_body,
                    &current_etag,
                    body_barrier,
                ))
                .await
                .expect("rule PATCH should complete")
        }
    });
    let put_task = tokio::spawn({
        let router = router.clone();
        let current_etag = current_etag.clone();
        let body_barrier = Arc::clone(&body_barrier);

        async move {
            router
                .oneshot(synchronized_policy_put_request(
                    whole_policy_body,
                    &current_etag,
                    body_barrier,
                ))
                .await
                .expect("policy PUT should complete")
        }
    });

    tokio::time::timeout(Duration::from_secs(2), body_barrier.wait())
        .await
        .expect("both policy mutation bodies should reach the release barrier");

    let (patch_response, put_response) = tokio::join!(patch_task, put_task);
    let patch_response = patch_response.expect("rule PATCH task should join");
    let put_response = put_response.expect("policy PUT task should join");

    let patch_status = patch_response.status();
    let patch_etag = (patch_status == StatusCode::OK).then(|| policy_etag_header(&patch_response));
    if patch_status == StatusCode::OK {
        assert_eq!(json_body(patch_response).await["action"], json!("deny"));
    } else {
        assert_eq!(patch_status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            body_string(patch_response).await,
            r#"{"error":"If-Match does not match the current policy ETag"}"#
        );
    }

    let put_status = put_response.status();
    let put_etag = (put_status == StatusCode::OK).then(|| policy_etag_header(&put_response));
    if put_status == StatusCode::OK {
        assert_eq!(
            json_body(put_response).await["id"],
            json!("concurrent-put-policy")
        );
    } else {
        assert_eq!(put_status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            body_string(put_response).await,
            r#"{"error":"If-Match does not match the current policy ETag"}"#
        );
    }

    assert_eq!(
        [patch_status, put_status]
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        [patch_status, put_status]
            .iter()
            .filter(|status| **status == StatusCode::PRECONDITION_FAILED)
            .count(),
        1
    );

    let (live_etag, live_policy) = current_policy(&router).await;
    if patch_status == StatusCode::OK {
        assert_eq!(live_etag, patch_etag.expect("PATCH should include ETag"));
        assert_eq!(live_policy["id"], json!("initial-policy"));
        assert_eq!(live_policy["rules"][0]["id"], json!("managed-rule"));
        assert_eq!(live_policy["rules"][0]["action"], json!("deny"));
    } else {
        assert_eq!(live_etag, put_etag.expect("PUT should include ETag"));
        assert_eq!(live_policy["id"], json!("concurrent-put-policy"));
        assert_eq!(live_policy["rules"], json!([]));
    }
}

#[tokio::test]
async fn policy_validate_accepts_valid_candidate_without_changing_live_policy_or_file() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let current_etag = policy_etag_header(&get_response);

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_VALIDATE_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            Some(policy_document_string("validated-only", "test:new")),
            None,
        ))
        .await
        .expect("policy validate should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let candidate = policy_document_string("validated-only", "test:new");
    let mut body = json_body(response).await;
    // The resources the cross-resource checks read: every one of them, so
    // the snapshot is complete and digested.
    let snapshot = body
        .as_object_mut()
        .and_then(|body| body.remove("resource_snapshot"))
        .expect("a document that parses is validated against a resource snapshot");
    assert_eq!(snapshot["complete"], json!(true), "{snapshot}");
    assert_eq!(snapshot["schema_version"], json!("1.0.0"));
    assert!(snapshot["digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71));
    for component in ["configuration", "egress", "tools", "connections"] {
        assert!(
            snapshot["components"][component].is_string(),
            "{component}: {snapshot}"
        );
    }
    // A 0.x document: valid, a source digest over the bytes sent, no
    // semantic digest (0.x defines no normalization), and the one stated
    // limitation of a document whose routes carry no stable id.
    assert_eq!(
        body,
        json!({
            "valid": true,
            "schema_version": "0.1.0",
            "diagnostics": [{
                "code": "stable_ids_unavailable",
                "severity": "warning",
                "pointer": "",
                "message": rbac::policy_document::IssueCode::StableIdsUnavailable.message(),
                "remediation": rbac::policy_document::IssueCode::StableIdsUnavailable.remediation(),
                "blocks": { "simulation": false, "tests": false, "publication": false, "evidence": true }
            }],
            "source_digest": canonical_json::source_digest(
                "application/json",
                "0.1.0",
                candidate.as_bytes()
            ),
        })
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == audit::event::POLICY_CHANGED));

    let after_get = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET after validate should complete");
    assert_eq!(policy_etag_header(&after_get), current_etag);
    assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
}

#[tokio::test]
async fn policy_validate_invalid_candidate_returns_errors_without_changes() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_VALIDATE_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            Some(r#"{ "schema_version": "2.0.0" }"#.to_owned()),
            None,
        ))
        .await
        .expect("invalid policy validate should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(false));
    assert!(
        body["errors"][0]
            .as_str()
            .unwrap_or_default()
            .contains("schema_version must start with"),
        "unexpected validation body: {body}"
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
}

#[tokio::test]
async fn policy_validate_rejects_relative_route_prefix_without_changes() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let mut invalid_policy = policy_document("relative-route", "test:new");
    invalid_policy["routes"][5]["path_prefix"] = json!("__test");

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_VALIDATE_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            Some(invalid_policy.to_string()),
            None,
        ))
        .await
        .expect("relative route prefix validation should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(false));
    assert!(
        body["errors"][0]
            .as_str()
            .unwrap_or_default()
            .contains("routes[5].path_prefix must start with '/'"),
        "unexpected validation body: {body}"
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );

    let after_get = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET after invalid validation should complete");
    assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
}

/// The test policy as policy v1: the same members, `schema_version`
/// `1.0.0`, and a stable id on every route.
fn v1_policy_document(id: &str, test_permission: &str) -> Value {
    let mut policy = policy_document(id, test_permission);
    policy["schema_version"] = json!("1.0.0");
    for (index, route) in policy["routes"]
        .as_array_mut()
        .expect("the test policy has routes")
        .iter_mut()
        .enumerate()
    {
        route["id"] = json!(format!("route-{index}"));
    }
    policy
}

#[tokio::test]
async fn policy_validate_reports_v1_diagnostics_and_both_digests() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let candidate = v1_policy_document("validated-v1", "test:new").to_string();

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_VALIDATE_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            Some(candidate.clone()),
            None,
        ))
        .await
        .expect("v1 validate should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(true));
    assert_eq!(body["schema_version"], json!("1.0.0"));
    assert_eq!(body["diagnostics"], json!([]));
    assert!(body.get("errors").is_none(), "{body}");
    assert_eq!(
        body["source_digest"],
        json!(canonical_json::source_digest(
            "application/json",
            "1.0.0",
            candidate.as_bytes()
        ))
    );
    let semantic = body["semantic_digest"]
        .as_str()
        .expect("a v1 document has a semantic digest")
        .to_owned();
    assert!(
        semantic.starts_with("sha256:") && semantic.len() == 71,
        "{semantic}"
    );

    // The same policy respelled -- other whitespace and member order -- has
    // another source digest and the same semantic one.
    let respelled = serde_json::to_string_pretty(&v1_policy_document("validated-v1", "test:new"))
        .expect("serialize");
    let body = json_body(
        router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(respelled),
                None,
            ))
            .await
            .expect("respelled validate should complete"),
    )
    .await;
    assert_eq!(body["semantic_digest"], json!(semantic));
    assert_ne!(
        body["source_digest"],
        json!(canonical_json::source_digest(
            "application/json",
            "1.0.0",
            candidate.as_bytes()
        ))
    );

    // Every structural problem is reported, each with its pointer, and the
    // errors list carries one detail per error diagnostic.
    let mut broken = v1_policy_document("broken-v1", "test:new");
    broken["routes"][1]["id"] = json!("route-0");
    broken["routes"][2]
        .as_object_mut()
        .expect("route")
        .remove("id");
    broken["routes"][3]["weight"] = json!(1);
    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_VALIDATE_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            Some(broken.to_string()),
            None,
        ))
        .await
        .expect("broken v1 validate should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(false));
    let found: Vec<(Value, Value)> = body["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|diagnostic| (diagnostic["code"].clone(), diagnostic["pointer"].clone()))
        .collect();
    assert_eq!(
        found,
        vec![
            (json!("element_id_duplicate"), json!("/routes/1/id")),
            (json!("element_id_missing"), json!("/routes/2/id")),
            (json!("unknown_member"), json!("/routes/3/weight")),
        ]
    );
    assert_eq!(body["diagnostics"][0]["element_id"], json!("route-0"));
    assert_eq!(body["errors"].as_array().map(Vec::len), Some(3));
    assert!(body.get("source_digest").is_none(), "{body}");
    assert!(body.get("semantic_digest").is_none(), "{body}");
}

/// The test policy with `admin` reduced to reading: no role grants
/// `admin:policy:write` any more.
fn policy_document_without_policy_write(id: &str) -> Value {
    let mut policy = policy_document(id, "test:new");
    policy["roles"]["admin"]["permissions"] = json!([ADMIN_POLICY_READ_PERMISSION]);
    policy
}

fn diagnostic_codes(body: &Value) -> Vec<(String, String)> {
    body["diagnostics"]
        .as_array()
        .map(|diagnostics| {
            diagnostics
                .iter()
                .map(|diagnostic| {
                    (
                        diagnostic["code"].as_str().unwrap_or_default().to_owned(),
                        diagnostic["pointer"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn policy_validate_reports_lockout_for_the_caller_and_everyone() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let candidate = policy_document_without_policy_write("locked-out").to_string();

    // The administrator would lose the permission, and so would everyone.
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_VALIDATE_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(candidate.clone()),
            None,
        ))
        .await
        .expect("policy validate should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(false));
    let codes = diagnostic_codes(&body);
    assert!(
        codes.contains(&("policy_write_unreachable".to_owned(), "/roles".to_owned())),
        "{body}"
    );
    assert!(
        codes.contains(&(
            "publisher_policy_write_lost".to_owned(),
            "/roles".to_owned()
        )),
        "{body}"
    );
    assert_eq!(body["errors"].as_array().map(Vec::len), Some(2), "{body}");
    let lockout = body["diagnostics"]
        .as_array()
        .and_then(|diagnostics| {
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic["code"] == json!("policy_write_unreachable"))
        })
        .expect("lockout diagnostic");
    assert_eq!(
        lockout["blocks"],
        json!({ "simulation": false, "tests": false, "publication": true, "evidence": false })
    );
    assert_eq!(body["resource_snapshot"]["complete"], json!(true));

    // A reader has no write to lose; nobody could write afterwards either way.
    // (The routes that required the permission are also reported, as
    // warnings: no role grants it any more.)
    let body = json_body(
        router
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(candidate),
                None,
            ))
            .await
            .expect("policy validate should complete"),
    )
    .await;
    let errors: Vec<&Value> = body["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|diagnostic| diagnostic["severity"] == json!("error"))
        .collect();
    assert_eq!(errors.len(), 1, "{body}");
    assert_eq!(errors[0]["code"], json!("policy_write_unreachable"));
    assert!(diagnostic_codes(&body).contains(&(
        "route_permission_ungranted".to_owned(),
        "/routes/1/permission".to_owned()
    )));
}

#[tokio::test]
async fn policy_put_refuses_an_administrator_lockout_without_writing_and_audits_it() {
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let (etag, _) = current_policy(&router).await;

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_without_policy_write("locked-out").to_string()),
            Some(&etag),
        ))
        .await
        .expect("policy PUT should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(false));
    assert_eq!(body["errors"].as_array().map(Vec::len), Some(2), "{body}");
    assert!(diagnostic_codes(&body)
        .iter()
        .any(|(code, _)| code == "publisher_policy_write_lost"));
    let snapshot_digest = body["resource_snapshot"]["digest"].clone();
    assert!(snapshot_digest.is_string(), "{body}");

    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
    let (after_etag, after_policy) = current_policy(&router).await;
    assert_eq!(after_etag, etag);
    assert_eq!(after_policy["id"], json!("initial-policy"));

    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::POLICY_PUBLICATION_REFUSED)
    });
    let events = capture.events();
    assert!(!events
        .iter()
        .any(|event| event.event_type == audit::event::POLICY_CHANGED));
    let refusal = events
        .iter()
        .find(|event| event.event_type == audit::event::POLICY_PUBLICATION_REFUSED)
        .expect("the refusal is audited");
    assert_eq!(
        refusal.payload,
        json!({
            "action": "policy_replaced",
            "codes": ["policy_write_unreachable", "publisher_policy_write_lost"],
            "policy_etag": etag,
            "resource_snapshot_digest": snapshot_digest,
        })
    );
    assert_eq!(
        refusal.actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("user-123")
    );
}

#[tokio::test]
async fn policy_put_refuses_a_rule_that_would_deny_the_publisher_its_own_put() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    // The policy route is judged by the RBAC route lane here, not exempt.
    let mut config = policy_admin_config_with_sqlite(Some(&policy), None);
    config
        .rbac_exempt_paths
        .retain(|path| path != POLICY_ADMIN_ROUTE);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let (etag, _) = current_policy(&router).await;

    let locking = policy_document_with_rules_string(
        "locking-policy",
        json!([direct_rule_json(
            Some("lock-admin"),
            &["PUT"],
            "/v1/admin/**",
            "deny"
        )]),
    );
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(locking),
            Some(&etag),
        ))
        .await
        .expect("policy PUT should complete");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    let lost = body["diagnostics"]
        .as_array()
        .and_then(|diagnostics| {
            diagnostics
                .iter()
                .find(|diagnostic| diagnostic["code"] == json!("publisher_policy_write_lost"))
        })
        .cloned()
        .unwrap_or_else(|| panic!("expected a publisher lockout: {body}"));
    assert_eq!(lost["pointer"], json!("/rules/0"));
    assert_eq!(lost["element_id"], json!("lock-admin"));
    assert_eq!(current_policy(&router).await.0, etag);

    // The same rule bound to another method takes nothing from the
    // publisher and is published.
    let harmless = policy_document_with_rules_string(
        "harmless-policy",
        json!([direct_rule_json(
            Some("lock-admin"),
            &["DELETE"],
            "/v1/admin/**",
            "deny"
        )]),
    );
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(harmless),
            Some(&etag),
        ))
        .await
        .expect("policy PUT should complete");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_policy_write_bound_to_a_resource_snapshot_is_refused_once_it_is_stale() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let (etag, _) = current_policy(&router).await;
    let candidate = policy_document_string("bound-policy", "test:new");
    let validated = json_body(
        router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(candidate.clone()),
                None,
            ))
            .await
            .expect("policy validate should complete"),
    )
    .await;
    let reviewed = validated["resource_snapshot"]["digest"]
        .as_str()
        .expect("a reviewed snapshot digest")
        .to_owned();
    let bound_put = |snapshot: &[&str], etag: &str| {
        let mut request = policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(candidate.clone()),
            Some(etag),
        );
        for value in snapshot {
            request.headers_mut().append(
                "x-greengateway-resource-snapshot",
                HeaderValue::from_str(value).expect("header value"),
            );
        }
        request
    };

    // A snapshot that is not the current one: refused, nothing written.
    let stale = format!("sha256:{}", "0".repeat(64));
    let response = router
        .clone()
        .oneshot(bound_put(&[&stale], &etag))
        .await
        .expect("policy PUT should complete");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("resource_snapshot_stale"));
    assert_eq!(body["resource_snapshot"]["digest"], json!(reviewed));
    assert_eq!(current_policy(&router).await.0, etag);
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::POLICY_PUBLICATION_REFUSED
                && event.payload["codes"] == json!(["resource_snapshot_stale"])
        })
    });

    // Naming it twice is ambiguous and refused before anything is judged.
    let response = router
        .clone()
        .oneshot(bound_put(&[&reviewed, &reviewed], &etag))
        .await
        .expect("policy PUT should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // The snapshot that was reviewed is still current: published.
    let response = router
        .clone()
        .oneshot(bound_put(&[&reviewed], &etag))
        .await
        .expect("policy PUT should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::POLICY_CHANGED
                && event.payload["resource_snapshot_digest"] == json!(reviewed)
        })
    });
}

#[tokio::test]
async fn policy_writes_record_their_risks_and_resource_snapshot_in_policy_changed() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let (etag, _) = current_policy(&router).await;
    let mut risky = policy_document("risky-policy", "test:new");
    risky["default_action"] = json!("allow");
    risky["roles"]["operator"] = json!({ "permissions": ["*"] });
    risky["tools"] = json!({ "unregistered-tool": {} });

    let validated = json_body(
        router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(risky.to_string()),
                None,
            ))
            .await
            .expect("policy validate should complete"),
    )
    .await;
    assert_eq!(validated["valid"], json!(true), "{validated}");
    // The live tool registry was asked, and holds no such tool.
    assert!(diagnostic_codes(&validated).contains(&(
        "tool_not_registered".to_owned(),
        "/tools/unregistered-tool".to_owned()
    )));
    let risks: Vec<(String, String)> = validated["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|diagnostic| diagnostic["severity"] == json!("risk"))
        .map(|diagnostic| {
            (
                diagnostic["code"].as_str().unwrap_or_default().to_owned(),
                diagnostic["pointer"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
        })
        .collect();
    assert_eq!(
        risks,
        vec![
            (
                "default_action_allow".to_owned(),
                "/default_action".to_owned()
            ),
            (
                "wildcard_permission".to_owned(),
                "/roles/operator/permissions/0".to_owned()
            ),
        ]
    );

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(risky.to_string()),
            Some(&etag),
        ))
        .await
        .expect("policy PUT should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let new_etag = policy_etag_header(&response);

    // A rule write is reviewed the same way.
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(json!({ "id": "reviewed", "path": "/reviewed", "action": "deny" }).to_string()),
            Some(&new_etag),
        ))
        .await
        .expect("rule POST should complete");
    assert_eq!(response.status(), StatusCode::CREATED);

    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .filter(|event| event.event_type == audit::event::POLICY_CHANGED)
            .count()
            == 2
    });
    let changes: Vec<Value> = capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == audit::event::POLICY_CHANGED)
        .map(|event| event.payload)
        .collect();
    assert_eq!(changes.len(), 2);
    for change in &changes {
        assert_eq!(
            change["risks"],
            json!(["default_action_allow", "wildcard_permission"])
        );
        assert_eq!(
            change["resource_snapshot_digest"],
            validated["resource_snapshot"]["digest"]
        );
    }
    assert_eq!(
        changes[0]["diff_summary"]["action"],
        json!("policy_replaced")
    );
    assert_eq!(changes[1]["diff_summary"]["action"], json!("rule_created"));
}

#[tokio::test]
async fn policy_convert_returns_the_v1_document_without_changing_the_live_policy() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let capture = audit::sink::tests::CaptureSink::new();
    let router = policy_admin_router(
        Some(&policy),
        audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>),
    );
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let etag = policy_etag_header(&get_response);
    let candidate = policy_document_string("converted", "test:new");

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_CONVERT_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            Some(candidate.clone()),
            None,
        ))
        .await
        .expect("policy convert should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["converted"], json!(true));
    assert_eq!(body["source_schema_version"], json!("0.1.0"));
    assert_eq!(body["schema_version"], json!("1.0.0"));
    assert_eq!(body["parity"], json!("verified"));
    assert_eq!(body["diagnostics"], json!([]));
    assert!(body.get("errors").is_none(), "{body}");
    assert_eq!(
        body["source_digest"],
        json!(canonical_json::source_digest(
            "application/json",
            "0.1.0",
            candidate.as_bytes()
        ))
    );
    // The test policy has routes and no rules or rate overrides: every route
    // gets `route-N`, and each assignment is listed after the version.
    let converted = body["policy"].clone();
    assert_eq!(converted["schema_version"], json!("1.0.0"));
    assert_eq!(converted["id"], json!("converted"));
    let routes = converted["routes"].as_array().expect("routes");
    let changes = body["changes"].as_array().expect("changes");
    assert_eq!(changes.len(), routes.len() + 1);
    assert_eq!(changes[0]["code"], json!("schema_version_set"));
    for (index, route) in routes.iter().enumerate() {
        assert_eq!(route["id"], json!(format!("route-{index}")));
        assert_eq!(
            changes[index + 1],
            json!({
                "code": "element_id_assigned",
                "pointer": format!("/routes/{index}/id"),
                "element_id": format!("route-{index}"),
                "message": rbac::policy_conversion::ChangeCode::ElementIdAssigned.message(),
            })
        );
    }

    // Converting changed nothing: same file, same ETag, no policy.changed.
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == audit::event::POLICY_CHANGED));

    // The converted document validates, with the semantic digest the
    // conversion reported, and can replace the live policy.
    let validated = json_body(
        router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(serde_json::to_string_pretty(&converted).expect("serialize")),
                None,
            ))
            .await
            .expect("validate should complete"),
    )
    .await;
    assert_eq!(validated["valid"], json!(true), "{validated}");
    assert_eq!(validated["semantic_digest"], body["semantic_digest"]);
    let put = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(converted.to_string()),
            Some(&etag),
        ))
        .await
        .expect("PUT should complete");
    assert_eq!(put.status(), StatusCode::OK);
    let live = json_body(
        router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete"),
    )
    .await;
    assert_eq!(live["schema_version"], json!("1.0.0"));
    assert_eq!(live["routes"], converted["routes"]);
}

#[tokio::test]
async fn policy_convert_refuses_without_permission_or_a_convertible_document() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let convert = |principal: Option<auth::Principal>, body: String| {
        router.clone().oneshot(policy_admin_request(
            Method::POST,
            POLICY_CONVERT_ADMIN_ROUTE,
            principal,
            Some(body),
            None,
        ))
    };
    let candidate = policy_document_string("converted", "test:new");

    let unauthenticated = convert(None, candidate.clone())
        .await
        .expect("convert should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let forbidden = convert(Some(test_principal(&["reader"])), candidate)
        .await
        .expect("convert should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    // A v1 document is not converted again.
    let response = convert(
        Some(test_principal(&["policy-reader"])),
        v1_policy_document("already-v1", "test:new").to_string(),
    )
    .await
    .expect("convert should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["converted"], json!(false));
    assert_eq!(body["source_schema_version"], json!("1.0.0"));
    assert_eq!(
        body["diagnostics"][0]["code"],
        json!("conversion_requires_v0")
    );
    assert_eq!(body["diagnostics"][0]["pointer"], json!("/schema_version"));
    assert_eq!(body["errors"].as_array().map(Vec::len), Some(1));
    assert!(body.get("policy").is_none(), "{body}");

    // An invalid 0.x document is refused in validation's own words.
    let mut invalid = policy_document("relative-route", "test:new");
    invalid["routes"][5]["path_prefix"] = json!("__test");
    let body = json_body(
        convert(
            Some(test_principal(&["policy-reader"])),
            invalid.to_string(),
        )
        .await
        .expect("convert should complete"),
    )
    .await;
    assert_eq!(body["converted"], json!(false));
    assert_eq!(body["diagnostics"][0]["code"], json!("path_not_absolute"));
    assert!(
        body["errors"][0]
            .as_str()
            .unwrap_or_default()
            .contains("routes[5].path_prefix must start with '/'"),
        "{body}"
    );
}

#[tokio::test]
async fn policy_put_accepts_a_v1_document_and_keeps_its_stable_ids() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let etag = policy_etag_header(&get_response);

    // A v1 document that repeats an id is refused with every problem named,
    // and nothing is written.
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let mut duplicate = v1_policy_document("duplicate-ids", "test:new");
    duplicate["routes"][5]["id"] = json!("route-4");
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(duplicate.to_string()),
            Some(&etag),
        ))
        .await
        .expect("duplicate-id PUT should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["valid"], json!(false));
    assert!(
        body["errors"][0]
            .as_str()
            .unwrap_or_default()
            .contains("/routes/5/id"),
        "{body}"
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(v1_policy_document("v1-policy", "test:new").to_string()),
            Some(&etag),
        ))
        .await
        .expect("v1 PUT should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let etag = policy_etag_header(&response);
    let body = json_body(response).await;
    assert_eq!(body["schema_version"], json!("1.0.0"));
    assert_eq!(body["routes"][5]["id"], json!("route-5"));

    // Persisted with its ids, and enforced: the new reader is admitted by the
    // route the v1 document now names.
    let persisted: Value =
        serde_json::from_str(&fs::read_to_string(&policy.path).expect("policy file should read"))
            .expect("persisted policy is JSON");
    assert_eq!(persisted["schema_version"], json!("1.0.0"));
    assert_eq!(persisted["routes"][0]["id"], json!("route-0"));
    let new_reader = router
        .clone()
        .oneshot(audit_query_request(
            "/__test/principal",
            Some(test_principal(&["new-reader"])),
        ))
        .await
        .expect("new-reader request should complete");
    assert_eq!(new_reader.status(), StatusCode::OK);

    // A rule created through the API in a v1 policy is given the stable id
    // v1 requires.
    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(json!({ "path": "/__test/blocked", "action": "deny" }).to_string()),
            Some(&etag),
        ))
        .await
        .expect("rule POST should complete");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = json_body(response).await;
    let rule_id = created["id"].as_str().expect("an assigned id").to_owned();
    assert!(
        rbac::policy_document::is_valid_element_id(&rule_id),
        "{rule_id}"
    );
    let reloaded = rbac::Policy::from_file(&policy.path).expect("the persisted v1 policy reloads");
    assert_eq!(reloaded.rules[0].id.as_deref(), Some(rule_id.as_str()));
}

#[tokio::test]
async fn policy_rule_preview_returns_matches_samples_and_does_not_mutate_policy() {
    let db = TempDb::new("rule-preview");
    create_audit_schema(&db.path);
    seed_rule_preview_events(&db.path);
    Connection::open(&db.path)
            .expect("audit database should open")
            .execute(
                "UPDATE audit_events SET actor_json = json_set(actor_json, '$.issuer', 'https://issuer.example')",
                [],
            )
            .expect("preview actor issuers should update");
    let initial_policy = policy_document_string("initial-policy", "test:old");
    let policy = TempPolicyFile::new(&initial_policy);
    let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router_with_sqlite(Some(&policy), audit_log, Some(&db.path));

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    let before_etag = policy_etag_header(&get_response);

    let preview_body = json!({
        "rule": {
            "methods": ["GET"],
            "path": "/api/items/{id}",
            "principal": {
                "roles": ["reader"],
                "issuers": ["https://issuer.example/"],
                "auth_methods": ["bearer_token"]
            },
            "action": "deny"
        },
        "from": "2024-06-01T12:00:00Z",
        "to": "2024-06-01T12:00:05Z",
        "sample_limit": 2
    })
    .to_string();
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULE_PREVIEW_ADMIN_ROUTE,
            Some(test_principal(&["policy-audit-reader"])),
            Some(preview_body),
            None,
        ))
        .await
        .expect("policy rule preview should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["match_count"], json!(2));
    assert_eq!(body["scanned_event_count"], json!(3));
    assert_eq!(body["unevaluated_event_count"], json!(0));
    assert_eq!(body["unevaluated_reasons"], json!({}));
    assert_eq!(body["scan_truncated"], json!(false));
    assert_eq!(body["complete"], json!(true));
    assert_eq!(body["sample_strategy"], json!("newest_matches"));
    assert_eq!(body["samples"][0]["event_id"], json!("match-new"));
    assert_eq!(body["samples"][0]["method"], json!("GET"));
    assert_eq!(body["samples"][0]["path"], json!("/api/items/4"));
    assert_eq!(body["samples"][0]["actor"]["user_id"], json!("reader-1"));
    assert_eq!(body["samples"][0]["policy_decision"], json!("allowed"));
    assert_eq!(body["samples"][1]["event_id"], json!("match-old"));

    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        before_contents
    );
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == audit::event::POLICY_CHANGED));

    let after_get = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET after preview should complete");
    assert_eq!(policy_etag_header(&after_get), before_etag);
    assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
}

#[tokio::test]
async fn policy_rule_preview_zero_matches_returns_empty_samples() {
    let db = TempDb::new("rule-preview-zero");
    create_audit_schema(&db.path);
    seed_rule_preview_events(&db.path);
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));

    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULE_PREVIEW_ADMIN_ROUTE,
            Some(test_principal(&["policy-audit-reader"])),
            Some(
                json!({
                    "rule": {
                        "methods": ["DELETE"],
                        "path": "/api/items/{id}",
                        "action": "deny"
                    },
                    "from": "2024-06-01T12:00:00Z",
                    "to": "2024-06-01T12:00:05Z"
                })
                .to_string(),
            ),
            None,
        ))
        .await
        .expect("policy rule preview should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["match_count"], json!(0));
    assert_eq!(body["samples"], json!([]));
}

#[tokio::test]
async fn policy_rule_preview_contextless_binding_excludes_unclassified_history() {
    let db = TempDb::new("rule-preview-contextless");
    create_audit_schema(&db.path);
    seed_rule_preview_events(&db.path);
    let connection = Connection::open(&db.path).expect("audit database should open");
    connection
            .execute(
                "UPDATE audit_events SET payload_json = json_remove(payload_json, '$.routing_context_known')",
                [],
            )
            .expect("legacy preview events should become unclassified");
    connection
        .execute(
            "UPDATE audit_events SET payload_json = ?1 WHERE event_id = 'match-new'",
            params![json!({
                "method": "GET",
                "path": "/api/items/4",
                "status": 200,
                "policy_decision": "allowed",
                "matched_rule_id": "existing-rule",
                "routing_context_known": true
            })
            .to_string()],
        )
        .expect("classified preview event should update");
    drop(connection);

    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));
    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULE_PREVIEW_ADMIN_ROUTE,
            Some(test_principal(&["policy-audit-reader"])),
            Some(
                json!({
                    "rule": {
                        "methods": ["GET"],
                        "path": "/api/items/{id}",
                        "dispatch": { "kind": "contextless" },
                        "principal": { "roles": ["reader"] },
                        "action": "deny"
                    }
                })
                .to_string(),
            ),
            None,
        ))
        .await
        .expect("contextless preview should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["match_count"], json!(1));
    assert_eq!(body["samples"][0]["event_id"], json!("match-new"));
    // The other three scanned observations were never classified, and the
    // rule is bound to a dispatch, so the evaluator cannot say whether it
    // matches them. They are reported rather than counted as non-matches, and
    // the count is a lower bound for the window.
    assert_eq!(body["scanned_event_count"], json!(4));
    assert_eq!(body["unevaluated_event_count"], json!(3));
    assert_eq!(
        body["unevaluated_reasons"],
        json!({"missing_dispatch_fact": 3})
    );
    assert_eq!(body["scan_truncated"], json!(false));
    assert_eq!(body["complete"], json!(false));
}

#[tokio::test]
async fn policy_rule_preview_requires_audit_store() {
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router(Some(&policy), test_audit_log());

    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULE_PREVIEW_ADMIN_ROUTE,
            Some(test_principal(&["policy-audit-reader"])),
            Some(
                json!({
                    "rule": {
                        "methods": ["GET"],
                        "path": "/api/items/{id}",
                        "action": "deny"
                    }
                })
                .to_string(),
            ),
            None,
        ))
        .await
        .expect("policy rule preview should complete");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(response).await,
        json!({
            "error": "policy rule preview requires an audit query store",
            "reason": "audit_evidence_unavailable"
        })
    );
}

#[tokio::test]
async fn policy_rule_preview_scan_ceiling_reports_a_truncated_incomplete_count() {
    let db = TempDb::new("rule-preview-scan-ceiling");
    create_audit_schema(&db.path);
    seed_rule_preview_events(&db.path);
    let store = storage::SqliteAuditEventStore::open(&db.path).expect("query store should open");
    let request = || {
        parse_rule_preview_body(&Bytes::from(
            json!({
                "rule": {
                    "methods": ["GET"],
                    "path": "/api/items/{id}",
                    "principal": { "roles": ["reader"] },
                    "action": "deny"
                },
                "from": "2024-06-01T12:00:00Z",
                "to": "2024-06-01T12:00:05Z"
            })
            .to_string(),
        ))
        .expect("preview request should parse")
    };

    // Three observations fall inside the window, newest first: match-new,
    // wrong-role, match-old. A two-row ceiling reads only the first two, so
    // the one match it saw is not the window's count.
    let truncated = preview_rule_with_scan_limit(&store, request(), 2)
        .await
        .expect("truncated preview should complete");
    assert_eq!(truncated.scanned_event_count, 2);
    assert_eq!(truncated.match_count, 1);
    assert!(truncated.scan_truncated);
    assert!(!truncated.complete);
    assert_eq!(truncated.samples.len(), 1);
    assert_eq!(truncated.samples[0].event_id, "match-new");

    // A ceiling the window exactly fills is not a truncation: every row was
    // read and nothing was left behind.
    let exact = preview_rule_with_scan_limit(&store, request(), 3)
        .await
        .expect("exact-ceiling preview should complete");
    assert_eq!(exact.scanned_event_count, 3);
    assert_eq!(exact.match_count, 2);
    assert!(!exact.scan_truncated);
    assert!(exact.complete);
}

#[tokio::test]
async fn policy_rule_preview_requires_policy_read_permission() {
    let db = TempDb::new("rule-preview-forbidden");
    create_audit_schema(&db.path);
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));

    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULE_PREVIEW_ADMIN_ROUTE,
            Some(test_principal(&["reader"])),
            Some(
                json!({
                    "rule": {
                        "methods": ["GET"],
                        "path": "/api/items/{id}",
                        "action": "deny"
                    }
                })
                .to_string(),
            ),
            None,
        ))
        .await
        .expect("policy rule preview should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn policy_rule_preview_requires_audit_read_permission() {
    let db = TempDb::new("rule-preview-audit-forbidden");
    create_audit_schema(&db.path);
    let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
    let capture = audit::sink::tests::CaptureSink::new();
    let log = audit::AuditLog::new(Arc::new(capture.clone()));
    let router = policy_admin_router_with_sqlite(Some(&policy), log.clone(), Some(&db.path));

    let response = router
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULE_PREVIEW_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            Some(
                json!({
                    "rule": {
                        "methods": ["GET"],
                        "path": "/api/items/{id}",
                        "action": "deny"
                    }
                })
                .to_string(),
            ),
            None,
        ))
        .await
        .expect("policy rule preview should complete");

    assert_admin_denial(&response, &log, &capture, ADMIN_AUDIT_READ_PERMISSION).await;
}

#[tokio::test]
async fn policy_rule_hits_count_real_rbac_observation_events() {
    let db = TempDb::new("rule-hits-real-middleware");
    let policy = TempPolicyFile::new(&direct_rule_policy_document());
    let mut config = policy_admin_config_with_sqlite(Some(&policy), Some(&db.path));
    config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let (audit_log, audit_event_sender) = audit_log_with_sqlite_and_broadcast(&db.path);
    let router =
        app(config, recorder.handle(), audit_log, audit_event_sender).expect("app should build");

    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(audit_query_request(
                "/__test/principal",
                Some(test_principal(&["member"])),
            ))
            .await
            .expect("direct allow request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }
    let denied = router
        .clone()
        .oneshot(audit_query_request(
            "/__test/blocked",
            Some(test_principal(&["member"])),
        ))
        .await
        .expect("direct deny request should complete");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let body = wait_for_rule_hits(router, |body| {
        rule_hit(body, "allow-principal-probe") == Some(2)
            && rule_hit(body, "deny-blocked") == Some(1)
    })
    .await;

    assert_eq!(rule_hit(&body, "allow-principal-probe"), Some(2));
    assert_eq!(rule_hit(&body, "deny-blocked"), Some(1));
}

#[tokio::test]
async fn policy_rule_hits_report_evidence_unavailable_when_sqlite_is_unset() {
    let policy = TempPolicyFile::new(&direct_rule_policy_document());
    let router = policy_admin_router(Some(&policy), test_audit_log());

    let response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_HITS_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy rule hits should complete");

    // No per-rule zeros: an unread audit store is not evidence that a rule
    // never matched.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(response).await,
        json!({
            "error": "policy rule hit counts require an audit query store",
            "reason": "audit_evidence_unavailable"
        })
    );
}

#[tokio::test]
async fn policy_rule_hits_return_real_zero_counts_from_an_empty_audit_store() {
    let db = TempDb::new("rule-hits-empty-store");
    create_audit_schema(&db.path);
    let policy = TempPolicyFile::new(&direct_rule_policy_document());
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));

    let response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_HITS_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy rule hits should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(rule_hit(&body, "allow-principal-probe"), Some(0));
    assert_eq!(rule_hit(&body, "deny-blocked"), Some(0));
}

#[tokio::test]
async fn policy_rule_shadow_review_returns_enabled_shadow_rules_with_would_deny_summaries() {
    let db = TempDb::new("policy-shadow-review");
    create_audit_schema(&db.path);
    insert_authz_event(
        &db.path,
        SeedAuthzEvent {
            event_id: "shadow-reports-1",
            event_type: "authz.would_deny",
            timestamp: "2024-06-01T12:00:00Z",
            actor_user_id: Some("analyst-1"),
            roles: &["analyst"],
            method: "GET",
            request_path: "/reports/1",
            matched_rule_id: Some("shadow-reports"),
        },
    );
    insert_authz_event(
        &db.path,
        SeedAuthzEvent {
            event_id: "allow-reports-1",
            event_type: "authz.would_deny",
            timestamp: "2024-06-01T12:00:01Z",
            actor_user_id: Some("analyst-2"),
            roles: &["analyst"],
            method: "GET",
            request_path: "/allow/1",
            matched_rule_id: Some("allow-reports"),
        },
    );
    insert_authz_event(
        &db.path,
        SeedAuthzEvent {
            event_id: "disabled-shadow-1",
            event_type: "authz.would_deny",
            timestamp: "2024-06-01T12:00:02Z",
            actor_user_id: Some("analyst-3"),
            roles: &["analyst"],
            method: "GET",
            request_path: "/disabled/1",
            matched_rule_id: Some("shadow-disabled"),
        },
    );
    insert_authz_event(
        &db.path,
        SeedAuthzEvent {
            event_id: "shadow-reports-2",
            event_type: "authz.would_deny",
            timestamp: "2024-06-01T12:00:03Z",
            actor_user_id: Some("analyst-2"),
            roles: &["analyst", "manager"],
            method: "DELETE",
            request_path: "/reports/2",
            matched_rule_id: Some("shadow-reports"),
        },
    );
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));

    let response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy shadow review should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(
        shadow_review_rule_ids(&body),
        vec!["shadow-reports".to_owned(), "shadow-exports".to_owned()]
    );
    let reports =
        shadow_review_rule(&body, "shadow-reports").expect("shadow reports rule should be present");
    assert_eq!(reports["rule"]["action"], json!("shadow"));
    assert_eq!(reports["would_deny_count"], json!(2));
    assert_eq!(
        reports["affected_principals"],
        json!([
            {
                "user_id": "analyst-2",
                "auth_mode": "bearer_token",
                "roles": ["analyst", "manager"]
            },
            {
                "user_id": "analyst-1",
                "auth_mode": "bearer_token",
                "roles": ["analyst"]
            }
        ])
    );
    assert_eq!(reports["samples"][0]["method"], json!("DELETE"));
    assert_eq!(reports["samples"][0]["path"], json!("/reports/2"));
    assert_eq!(
        reports["samples"][0]["actor"]["user_id"],
        json!("analyst-2")
    );

    // A real zero: the store was read in full and holds no would-deny events
    // for this rule.
    assert_eq!(body["scan_truncated"], json!(false));
    let exports =
        shadow_review_rule(&body, "shadow-exports").expect("shadow exports rule should be present");
    assert_eq!(exports["would_deny_count"], json!(0));
    assert_eq!(exports["affected_principals"], json!([]));
    assert_eq!(exports["samples"], json!([]));
}

#[tokio::test]
async fn policy_rule_shadow_review_requires_audit_read_permission() {
    let db = TempDb::new("shadow-review-audit-forbidden");
    create_audit_schema(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let log = audit::AuditLog::new(Arc::new(capture.clone()));
    let router = policy_admin_router_with_sqlite(Some(&policy), log.clone(), Some(&db.path));

    let response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            None,
            None,
        ))
        .await
        .expect("policy shadow review should complete");

    assert_admin_denial(&response, &log, &capture, ADMIN_AUDIT_READ_PERMISSION).await;
}

#[tokio::test]
async fn policy_rule_shadow_review_reports_evidence_unavailable_when_sqlite_is_unset() {
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let router = policy_admin_router(Some(&policy), test_audit_log());

    let response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy shadow review should complete");

    // No zero would-deny summaries: they would read as "safe to promote".
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(response).await,
        json!({
            "error": "policy shadow review requires an audit query store",
            "reason": "audit_evidence_unavailable"
        })
    );
}

#[tokio::test]
async fn policy_rule_shadow_review_checks_audit_read_before_evidence_availability() {
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let log = audit::AuditLog::new(Arc::new(capture.clone()));
    let router = policy_admin_router(Some(&policy), log.clone());

    let response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            None,
            None,
        ))
        .await
        .expect("policy shadow review should complete");

    assert_admin_denial(&response, &log, &capture, ADMIN_AUDIT_READ_PERMISSION).await;
}

#[tokio::test]
async fn policy_rule_shadow_review_binds_each_entry_to_revision_window_and_digest() {
    let db = TempDb::new("shadow-review-binding");
    create_audit_schema(&db.path);
    seed_shadow_reports_would_deny_events(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));
    let (policy_etag, _) = current_policy(&router).await;

    let body = shadow_review_body(&router).await;

    // The revision the review was read from is the one a write compares
    // against, so a client can send it straight back as If-Match.
    assert_eq!(body["policy_etag"], json!(policy_etag));
    let reports =
        shadow_review_rule(&body, "shadow-reports").expect("shadow reports rule should be present");
    assert_eq!(
        reports["evidence_window"],
        json!({"from": "2024-06-01T12:00:00Z", "to": "2024-06-01T12:00:03Z"})
    );
    let reports_digest = reports["evidence_digest"]
        .as_str()
        .expect("evidence digest should be a string");
    assert!(is_sha256_digest(reports_digest), "{reports_digest}");
    // No events read: the window says so rather than inventing bounds.
    let exports =
        shadow_review_rule(&body, "shadow-exports").expect("shadow exports rule should be present");
    assert_eq!(
        exports["evidence_window"],
        json!({"from": null, "to": null})
    );
    assert_ne!(exports["evidence_digest"], reports["evidence_digest"]);

    // Unchanged evidence and policy read back to an identical binding.
    assert_eq!(shadow_review_body(&router).await, body);
}

#[tokio::test]
async fn bound_shadow_promotion_applies_when_revision_window_and_digest_match() {
    let db = TempDb::new("shadow-promotion-match");
    create_audit_schema(&db.path);
    seed_shadow_reports_would_deny_events(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router_with_sqlite(Some(&policy), audit_log, Some(&db.path));
    let binding = shadow_review_binding(&router, "shadow-reports").await;
    let reviewed_etag = binding_policy_etag(&binding);

    let response = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-reports",
            json!({ "action": "deny" }),
            &binding,
            Some(&reviewed_etag),
        ))
        .await
        .expect("bound promotion should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(policy_etag_header(&response), reviewed_etag);
    let promoted = json_body(response).await;
    assert_eq!(promoted["id"], json!("shadow-reports"));
    assert_eq!(promoted["action"], json!("deny"));

    let event = captured_policy_change(&capture, "rule_updated");
    assert_policy_change_actor(&event);
    assert_eq!(
        event.payload["diff_summary"],
        json!({
            "action": "rule_updated",
            "rule_id": "shadow-reports",
            "changed_fields": ["action"],
            "shadow_review": {
                "transition": "promote",
                "policy_etag": reviewed_etag,
                "evidence_window": binding["evidence_window"],
                "evidence_digest": binding["evidence_digest"]
            }
        })
    );
    assert!(shadow_transition_refusals(&capture).is_empty());

    // An enforced rule is no longer in the shadow review queue.
    assert_eq!(
        shadow_review_rule_ids(&shadow_review_body(&router).await),
        vec!["shadow-exports".to_owned()]
    );
}

#[tokio::test]
async fn bound_shadow_disable_applies_and_the_next_change_needs_a_fresh_review() {
    let db = TempDb::new("shadow-disable-match");
    create_audit_schema(&db.path);
    seed_shadow_reports_would_deny_events(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));
    let exports_binding = shadow_review_binding(&router, "shadow-exports").await;
    let reports_binding = shadow_review_binding(&router, "shadow-reports").await;
    let reviewed_etag = binding_policy_etag(&exports_binding);

    let disabled = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-exports",
            json!({ "enabled": false }),
            &exports_binding,
            Some(&reviewed_etag),
        ))
        .await
        .expect("bound disable should complete");
    assert_eq!(disabled.status(), StatusCode::OK);
    let next_etag = policy_etag_header(&disabled);
    assert_eq!(json_body(disabled).await["enabled"], json!(false));

    // The other entry was reviewed under the revision the disable replaced.
    // A fresh If-Match does not make that review current again.
    for if_match in [next_etag.as_str(), reviewed_etag.as_str()] {
        let refused = router
            .clone()
            .oneshot(bound_shadow_patch(
                "shadow-reports",
                json!({ "action": "deny" }),
                &reports_binding,
                Some(if_match),
            ))
            .await
            .expect("stale bound promotion should complete");
        assert_shadow_refusal(
            refused,
            StatusCode::PRECONDITION_FAILED,
            "shadow_review_revision_stale",
        )
        .await;
    }

    let fresh_binding = shadow_review_binding(&router, "shadow-reports").await;
    assert_eq!(binding_policy_etag(&fresh_binding), next_etag);
    let promoted = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-reports",
            json!({ "action": "deny" }),
            &fresh_binding,
            Some(&next_etag),
        ))
        .await
        .expect("re-reviewed promotion should complete");
    assert_eq!(promoted.status(), StatusCode::OK);
}

#[tokio::test]
async fn bound_shadow_promotion_refuses_a_stale_revision() {
    let db = TempDb::new("shadow-promotion-stale-revision");
    create_audit_schema(&db.path);
    seed_shadow_reports_would_deny_events(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router_with_sqlite(Some(&policy), audit_log, Some(&db.path));
    let binding = shadow_review_binding(&router, "shadow-reports").await;
    let reviewed_etag = binding_policy_etag(&binding);

    // An unrelated edit lands after the review was read. The promoted rule
    // itself is untouched, but what reaches it, and what was reviewed, is
    // a property of the whole policy.
    let edit = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PATCH,
            &format!("{POLICY_RULES_ADMIN_ROUTE}/allow-reports"),
            Some(test_principal(&["admin"])),
            Some(json!({ "methods": ["GET", "HEAD"] }).to_string()),
            Some(&reviewed_etag),
        ))
        .await
        .expect("unrelated edit should complete");
    assert_eq!(edit.status(), StatusCode::OK);
    let current_etag = policy_etag_header(&edit);

    let refused = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-reports",
            json!({ "action": "deny" }),
            &binding,
            Some(&reviewed_etag),
        ))
        .await
        .expect("stale bound promotion should complete");

    assert_shadow_refusal(
        refused,
        StatusCode::PRECONDITION_FAILED,
        "shadow_review_revision_stale",
    )
    .await;
    assert_shadow_rule_unchanged(&router, "shadow-reports", &current_etag).await;
    let refusals = await_shadow_transition_refusals(&capture, 1);
    assert_eq!(
        refusals[0].payload,
        json!({
            "transition": "promote",
            "rule_id": "shadow-reports",
            "reason": "shadow_review_revision_stale",
            "reviewed_policy_etag": reviewed_etag,
            "reviewed_evidence_digest": binding["evidence_digest"],
            "current_policy_etag": current_etag
        })
    );
    assert_policy_change_actor(&refusals[0]);
}

#[tokio::test]
async fn bound_shadow_promotion_refuses_a_stale_evidence_window() {
    let db = TempDb::new("shadow-promotion-stale-window");
    create_audit_schema(&db.path);
    seed_shadow_reports_would_deny_events(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router_with_sqlite(Some(&policy), audit_log, Some(&db.path));
    let binding = shadow_review_binding(&router, "shadow-reports").await;
    let reviewed_etag = binding_policy_etag(&binding);

    // The rule would have denied another request after the review was read:
    // evidence the operator never saw.
    insert_authz_event(
        &db.path,
        shadow_would_deny_seed("shadow-reports-3", "2024-06-01T12:00:09Z", "shadow-reports"),
    );

    let refused = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-reports",
            json!({ "action": "deny" }),
            &binding,
            Some(&reviewed_etag),
        ))
        .await
        .expect("bound promotion should complete");

    assert_shadow_refusal(
        refused,
        StatusCode::CONFLICT,
        "shadow_evidence_window_stale",
    )
    .await;
    assert_shadow_rule_unchanged(&router, "shadow-reports", &reviewed_etag).await;
    let refusals = await_shadow_transition_refusals(&capture, 1);
    assert_eq!(
        refusals[0].payload["reason"],
        json!("shadow_evidence_window_stale")
    );
    assert_eq!(
        refusals[0].payload["current_policy_etag"],
        json!(reviewed_etag)
    );
    let current_digest = refusals[0].payload["current_evidence_digest"]
        .as_str()
        .expect("current digest should be recorded");
    assert!(is_sha256_digest(current_digest));
    assert_ne!(json!(current_digest), binding["evidence_digest"]);
}

#[tokio::test]
async fn bound_shadow_promotion_refuses_a_stale_evidence_digest() {
    let db = TempDb::new("shadow-promotion-stale-digest");
    create_audit_schema(&db.path);
    seed_shadow_reports_would_deny_events(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));
    let binding = shadow_review_binding(&router, "shadow-reports").await;
    let reviewed_etag = binding_policy_etag(&binding);

    // A late-arriving event recorded with the newest reviewed timestamp: the
    // window bounds read back the same, but the count, principals and
    // samples behind them do not.
    insert_authz_event(
        &db.path,
        SeedAuthzEvent {
            actor_user_id: Some("analyst-9"),
            ..shadow_would_deny_seed(
                "shadow-reports-late",
                "2024-06-01T12:00:03Z",
                "shadow-reports",
            )
        },
    );
    let current = shadow_review_body(&router).await;
    let current_reports = shadow_review_rule(&current, "shadow-reports")
        .expect("shadow reports rule should be present");
    assert_eq!(
        current_reports["evidence_window"],
        binding["evidence_window"]
    );
    assert_ne!(
        current_reports["evidence_digest"],
        binding["evidence_digest"]
    );

    let refused = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-reports",
            json!({ "action": "deny" }),
            &binding,
            Some(&reviewed_etag),
        ))
        .await
        .expect("bound promotion should complete");

    assert_shadow_refusal(
        refused,
        StatusCode::CONFLICT,
        "shadow_evidence_digest_stale",
    )
    .await;
    assert_shadow_rule_unchanged(&router, "shadow-reports", &reviewed_etag).await;

    // A digest the review never minted is refused the same way.
    let mut forged = binding.clone();
    forged["evidence_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    forged["evidence_window"] = current_reports["evidence_window"].clone();
    let refused = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-reports",
            json!({ "enabled": false }),
            &forged,
            Some(&reviewed_etag),
        ))
        .await
        .expect("bound disable should complete");
    assert_shadow_refusal(
        refused,
        StatusCode::CONFLICT,
        "shadow_evidence_digest_stale",
    )
    .await;
    assert_shadow_rule_unchanged(&router, "shadow-reports", &reviewed_etag).await;
}

#[tokio::test]
async fn bound_shadow_promotion_refuses_when_evidence_is_unavailable() {
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = policy_admin_router(Some(&policy), audit_log);
    let (current_etag, _) = current_policy(&router).await;
    // Shaped like a binding, but there is no evidence it could describe.
    let binding = json!({
        "policy_etag": current_etag,
        "evidence_window": {"from": null, "to": null},
        "evidence_digest": format!("sha256:{}", "a".repeat(64)),
    });

    for (attempt, (patch, transition)) in [
        (json!({ "action": "deny" }), "promote"),
        (json!({ "enabled": false }), "disable"),
    ]
    .into_iter()
    .enumerate()
    {
        let refused = router
            .clone()
            .oneshot(bound_shadow_patch(
                "shadow-reports",
                patch,
                &binding,
                Some(&current_etag),
            ))
            .await
            .expect("bound change should complete");
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            json_body(refused).await,
            json!({
                "error": "shadow rule promotion and disable require an audit query store",
                "reason": "audit_evidence_unavailable"
            })
        );
        let refusals = await_shadow_transition_refusals(&capture, attempt + 1);
        assert_eq!(refusals[attempt].payload["transition"], json!(transition));
    }

    assert_shadow_rule_unchanged(&router, "shadow-reports", &current_etag).await;
    let refusals = await_shadow_transition_refusals(&capture, 2);
    assert!(refusals
        .iter()
        .all(|event| event.payload["reason"] == json!("audit_evidence_unavailable")));
}

#[tokio::test]
async fn bound_shadow_change_requires_audit_read_permission() {
    let db = TempDb::new("shadow-promotion-audit-forbidden");
    create_audit_schema(&db.path);
    seed_shadow_reports_would_deny_events(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let capture = audit::sink::tests::CaptureSink::new();
    let log = audit::AuditLog::new(Arc::new(capture.clone()));
    let router = policy_admin_router_with_sqlite(Some(&policy), log.clone(), Some(&db.path));
    let binding = shadow_review_binding(&router, "shadow-reports").await;
    let reviewed_etag = binding_policy_etag(&binding);

    let mut request = bound_shadow_patch(
        "shadow-reports",
        json!({ "action": "deny" }),
        &binding,
        Some(&reviewed_etag),
    );
    request
        .extensions_mut()
        .insert(test_principal(&["policy-writer"]));
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("bound promotion should complete");

    assert_shadow_rule_unchanged(&router, "shadow-reports", &reviewed_etag).await;
    assert_admin_denial(&response, &log, &capture, ADMIN_AUDIT_READ_PERMISSION).await;
}

#[tokio::test]
async fn bound_shadow_change_accepts_only_a_reviewed_promotion_or_disable() {
    let db = TempDb::new("shadow-promotion-shape");
    create_audit_schema(&db.path);
    seed_shadow_reports_would_deny_events(&db.path);
    let policy = TempPolicyFile::new(&shadow_review_policy_document());
    let router = policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));
    let binding = shadow_review_binding(&router, "shadow-reports").await;
    let reviewed_etag = binding_policy_etag(&binding);

    // Anything but exactly a promotion or a disable changes the rule in a
    // way the review never showed.
    for patch in [
        json!({ "action": "allow" }),
        json!({ "action": "shadow" }),
        json!({ "enabled": true }),
        json!({ "action": "deny", "enabled": false }),
        json!({ "action": "deny", "path": "/reports/archive/**" }),
        json!({ "enabled": false, "principal": { "roles": [] } }),
    ] {
        let refused = router
            .clone()
            .oneshot(bound_shadow_patch(
                "shadow-reports",
                patch.clone(),
                &binding,
                Some(&reviewed_etag),
            ))
            .await
            .expect("bound change should complete");
        assert_shadow_refusal(
            refused,
            StatusCode::BAD_REQUEST,
            "shadow_review_transition_unsupported",
        )
        .await;
    }

    for (field, value) in [
        ("evidence_digest", json!("sha256:not-hex")),
        (
            "evidence_digest",
            json!(format!("SHA256:{}", "a".repeat(64))),
        ),
        ("policy_etag", json!("")),
        ("policy_etag", json!("x".repeat(257))),
        ("evidence_window", json!({"from": "", "to": null})),
    ] {
        let mut malformed = binding.clone();
        malformed[field] = value;
        let refused = router
            .clone()
            .oneshot(bound_shadow_patch(
                "shadow-reports",
                json!({ "action": "deny" }),
                &malformed,
                Some(&reviewed_etag),
            ))
            .await
            .expect("bound change should complete");
        assert_shadow_refusal(
            refused,
            StatusCode::BAD_REQUEST,
            "shadow_review_binding_invalid",
        )
        .await;
    }

    // Unknown binding fields are rejected like any unknown patch field.
    let mut unknown = binding.clone();
    unknown["force"] = json!(true);
    let refused = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-reports",
            json!({ "action": "deny" }),
            &unknown,
            Some(&reviewed_etag),
        ))
        .await
        .expect("bound change should complete");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

    // A rule outside the review has no evidence to be bound to.
    let refused = router
        .clone()
        .oneshot(bound_shadow_patch(
            "allow-reports",
            json!({ "action": "deny" }),
            &binding,
            Some(&reviewed_etag),
        ))
        .await
        .expect("bound change should complete");
    assert_shadow_refusal(
        refused,
        StatusCode::CONFLICT,
        "shadow_review_rule_not_shadow",
    )
    .await;

    // The binding adds to If-Match; it never replaces it.
    let refused = router
        .clone()
        .oneshot(bound_shadow_patch(
            "shadow-reports",
            json!({ "action": "deny" }),
            &binding,
            None,
        ))
        .await
        .expect("bound change should complete");
    assert_eq!(refused.status(), StatusCode::PRECONDITION_REQUIRED);

    assert_shadow_rule_unchanged(&router, "shadow-reports", &reviewed_etag).await;
}

#[tokio::test]
async fn policy_rule_preview_moderate_scale_completes_under_two_seconds() {
    let db = TempDb::new("rule-preview-performance");
    create_audit_schema(&db.path);
    let event_count = 50_000;
    bulk_insert_preview_events(&db.path, event_count);
    let store = storage::SqliteAuditEventStore::open(&db.path).expect("query store should open");
    let request = PolicyRulePreviewRequest {
        rule: rbac::Rule {
            id: None,
            enabled: true,
            methods: vec!["GET".to_owned()],
            path: "/load/{id}".to_owned(),
            tool_name: None,
            dispatch: None,
            principal: rbac::PrincipalMatcher {
                roles: vec!["reader".to_owned()],
                issuers: Vec::new(),
                auth_methods: vec!["bearer_token".to_owned()],
                principal_ids: Vec::new(),
            },
            action: rbac::RuleAction::Deny,
        },
        from: Some("2026-01-01T00:00:00Z".to_owned()),
        to: Some("2026-01-02T00:00:00Z".to_owned()),
        sample_limit: Some(5),
    };

    let started = Instant::now();
    let response = preview_rule(&store, request)
        .await
        .expect("preview should complete");
    let elapsed = started.elapsed();
    println!(
        "previewed {event_count} synthetic events in {elapsed:?}; scanned={}, matched={}",
        response.scanned_event_count, response.match_count
    );

    assert_eq!(response.match_count, 5_000);
    assert_eq!(response.samples.len(), 5);
    assert!(!response.scan_truncated);
    assert!(response.complete);
    assert!(
        elapsed < Duration::from_secs(2),
        "50k-row preview took {elapsed:?}"
    );
}

#[tokio::test]
async fn policy_admin_endpoints_return_not_found_when_policy_file_is_unset() {
    let router = policy_admin_router(None, test_audit_log());

    let get_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy GET without policy file should complete");
    assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

    let put_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_string("updated-policy", "test:new")),
            Some("\"sha256:anything\""),
        ))
        .await
        .expect("policy PUT without policy file should complete");
    assert_eq!(put_response.status(), StatusCode::NOT_FOUND);

    let validate_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_VALIDATE_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_string("updated-policy", "test:new")),
            None,
        ))
        .await
        .expect("policy validate without policy file should complete");
    assert_eq!(validate_response.status(), StatusCode::NOT_FOUND);

    let preview_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::POST,
            POLICY_RULE_PREVIEW_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(
                json!({
                    "rule": {
                        "methods": ["GET"],
                        "path": "/api/items/{id}",
                        "action": "deny"
                    }
                })
                .to_string(),
            ),
            None,
        ))
        .await
        .expect("policy preview without policy file should complete");
    assert_eq!(preview_response.status(), StatusCode::NOT_FOUND);

    let hits_response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_HITS_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy hits without policy file should complete");
    assert_eq!(hits_response.status(), StatusCode::NOT_FOUND);

    let shadow_review_response = router
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy shadow review without policy file should complete");
    assert_eq!(shadow_review_response.status(), StatusCode::NOT_FOUND);
}

fn policy_admin_router_with_history(
    policy: Option<&TempPolicyFile>,
    history_db: &TempDb,
) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        policy_admin_config_with_history(policy, Some(&history_db.path)),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
}

fn synchronized_policy_put_request(
    body: String,
    if_match: &str,
    barrier: Arc<tokio::sync::Barrier>,
) -> Request<Body> {
    synchronized_policy_admin_request(Method::PUT, POLICY_ADMIN_ROUTE, body, if_match, barrier)
}

fn synchronized_policy_admin_request(
    method: Method,
    uri: &str,
    body: String,
    if_match: &str,
    barrier: Arc<tokio::sync::Barrier>,
) -> Request<Body> {
    let chunks = stream::once(async move {
        barrier.wait().await;
        Ok::<Bytes, Infallible>(Bytes::from(body))
    });

    policy_admin_request_with_body(
        method,
        uri,
        Some(test_principal(&["admin"])),
        Body::from_stream(chunks),
        Some(if_match),
    )
}

async fn assert_history_versions(router: &Router, expected_actions: &[&str]) {
    let entries = policy_history_entries(router, None).await;
    assert_eq!(
        history_actions(&entries),
        expected_actions,
        "unexpected policy history actions"
    );
}

fn history_actions(entries: &[Value]) -> Vec<&str> {
    entries
        .iter()
        .map(|entry| {
            entry["diff_summary"]["action"]
                .as_str()
                .expect("history entry should include action")
        })
        .collect()
}

fn assert_rfc3339_timestamp(value: &str) {
    OffsetDateTime::parse(value, &Rfc3339)
        .unwrap_or_else(|err| panic!("timestamp should be RFC3339: {value}: {err}"));
}

fn policy_document_with_egress_string(id: &str, test_permission: &str, host: &str) -> String {
    let mut policy = policy_document(id, test_permission);
    policy["egress"] = json!({ "hosts": [host] });
    serde_json::to_string_pretty(&policy).expect("test policy should serialize")
}

fn direct_rule_policy_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "direct-rule-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION
                ]
            },
            "member": {
                "permissions": []
            }
        },
        "routes": [],
        "rules": [
            {
                "id": "allow-principal-probe",
                "methods": ["GET"],
                "path": "/__test/principal",
                "principal": {
                    "roles": ["member"],
                    "auth_methods": ["bearer_token"]
                },
                "action": "allow"
            },
            {
                "id": "deny-blocked",
                "methods": ["GET"],
                "path": "/__test/blocked",
                "action": "deny"
            }
        ]
    })
    .to_string()
}

fn shadow_review_policy_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "shadow-review-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [
                    ADMIN_POLICY_READ_PERMISSION,
                    ADMIN_POLICY_WRITE_PERMISSION,
                    ADMIN_AUDIT_READ_PERMISSION
                ]
            },
            "policy-reader": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION]
            },
            "policy-writer": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_WRITE_PERMISSION]
            },
            "reader": {
                "permissions": []
            }
        },
        "routes": [],
        "rules": [
            {
                "id": "shadow-reports",
                "methods": ["GET", "DELETE"],
                "path": "/reports/**",
                "principal": {
                    "roles": ["analyst"]
                },
                "action": "shadow"
            },
            {
                "id": "allow-reports",
                "methods": ["GET"],
                "path": "/allow/**",
                "action": "allow"
            },
            {
                "id": "shadow-disabled",
                "enabled": false,
                "methods": ["GET"],
                "path": "/disabled/**",
                "action": "shadow"
            },
            {
                "id": "shadow-exports",
                "methods": ["POST"],
                "path": "/exports/**",
                "principal": {
                    "roles": ["manager"]
                },
                "action": "shadow"
            }
        ]
    })
    .to_string()
}

fn captured_policy_change(
    capture: &audit::sink::tests::CaptureSink,
    action: &str,
) -> audit::AuditEvent {
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::POLICY_CHANGED
                && event.payload["diff_summary"]["action"] == json!(action)
        })
    });

    capture
        .events()
        .into_iter()
        .find(|event| {
            event.event_type == audit::event::POLICY_CHANGED
                && event.payload["diff_summary"]["action"] == json!(action)
        })
        .expect("policy.changed event should be captured")
}

fn assert_policy_change_actor(event: &audit::AuditEvent) {
    let actor = event.actor.as_ref().expect("actor should be set");
    assert_eq!(actor.user_id, "user-123");
    assert_eq!(actor.roles, Some(vec!["admin".to_owned()]));
}

async fn wait_for_rule_hits(router: Router, predicate: impl Fn(&Value) -> bool) -> Value {
    let started = Instant::now();

    loop {
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_RULE_HITS_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("rule hits request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        if predicate(&body) {
            return body;
        }

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "rule hits did not reach expected counts"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn rule_hit(body: &Value, rule_id: &str) -> Option<u64> {
    body["rules"]
        .as_array()?
        .iter()
        .find(|rule| rule["rule_id"] == json!(rule_id))
        .and_then(|rule| rule["hits"].as_u64())
}

fn shadow_review_rule_ids(body: &Value) -> Vec<String> {
    body["rules"]
        .as_array()
        .expect("shadow review rules should be an array")
        .iter()
        .map(|rule| {
            rule["rule_id"]
                .as_str()
                .expect("shadow review rule id should be a string")
                .to_owned()
        })
        .collect()
}

fn shadow_review_rule<'a>(body: &'a Value, rule_id: &str) -> Option<&'a Value> {
    body["rules"]
        .as_array()?
        .iter()
        .find(|rule| rule["rule_id"] == json!(rule_id))
}

/// Two would-deny events for `shadow-reports`, three seconds apart, and none
/// for `shadow-exports`.
fn seed_shadow_reports_would_deny_events(path: &PathBuf) {
    insert_authz_event(
        path,
        shadow_would_deny_seed("shadow-reports-1", "2024-06-01T12:00:00Z", "shadow-reports"),
    );
    insert_authz_event(
        path,
        SeedAuthzEvent {
            actor_user_id: Some("analyst-2"),
            method: "DELETE",
            request_path: "/reports/2",
            ..shadow_would_deny_seed("shadow-reports-2", "2024-06-01T12:00:03Z", "shadow-reports")
        },
    );
}

fn shadow_would_deny_seed<'a>(
    event_id: &'a str,
    timestamp: &'a str,
    matched_rule_id: &'a str,
) -> SeedAuthzEvent<'a> {
    SeedAuthzEvent {
        event_id,
        event_type: "authz.would_deny",
        timestamp,
        actor_user_id: Some("analyst-1"),
        roles: &["analyst"],
        method: "GET",
        request_path: "/reports/1",
        matched_rule_id: Some(matched_rule_id),
    }
}

async fn shadow_review_body(router: &Router) -> Value {
    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::GET,
            POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            None,
            None,
        ))
        .await
        .expect("policy shadow review should complete");
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

/// The binding one shadow-review entry carries, assembled the way a client
/// sends it back with a promotion or disable.
async fn shadow_review_binding(router: &Router, rule_id: &str) -> Value {
    let body = shadow_review_body(router).await;
    let entry = shadow_review_rule(&body, rule_id).expect("rule should be in the shadow review");
    json!({
        "policy_etag": body["policy_etag"],
        "evidence_window": entry["evidence_window"],
        "evidence_digest": entry["evidence_digest"],
    })
}

fn binding_policy_etag(binding: &Value) -> String {
    binding["policy_etag"]
        .as_str()
        .expect("binding should carry the reviewed policy ETag")
        .to_owned()
}

fn bound_shadow_patch(
    rule_id: &str,
    mut patch: Value,
    binding: &Value,
    if_match: Option<&str>,
) -> Request<Body> {
    patch["shadow_review"] = binding.clone();
    policy_admin_request(
        Method::PATCH,
        &format!("{POLICY_RULES_ADMIN_ROUTE}/{rule_id}"),
        Some(test_principal(&["admin"])),
        Some(patch.to_string()),
        if_match,
    )
}

async fn assert_shadow_refusal(response: Response, status: StatusCode, reason: &str) {
    assert_eq!(response.status(), status);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!(reason), "{body}");
    assert!(body["error"].is_string(), "{body}");
}

/// The rule is still an enabled shadow rule and the policy is still at
/// `expected_etag`: a refused change wrote nothing.
async fn assert_shadow_rule_unchanged(router: &Router, rule_id: &str, expected_etag: &str) {
    let (etag, policy) = current_policy(router).await;
    assert_eq!(etag, expected_etag);
    let rule = policy["rules"]
        .as_array()
        .expect("policy rules should be an array")
        .iter()
        .find(|rule| rule["id"] == json!(rule_id))
        .expect("rule should still exist");
    assert_eq!(rule["action"], json!("shadow"));
    assert_ne!(rule["enabled"], json!(false));
}

fn shadow_transition_refusals(capture: &audit::sink::tests::CaptureSink) -> Vec<audit::AuditEvent> {
    capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == audit::event::POLICY_SHADOW_TRANSITION_REFUSED)
        .collect()
}

fn await_shadow_transition_refusals(
    capture: &audit::sink::tests::CaptureSink,
    expected: usize,
) -> Vec<audit::AuditEvent> {
    // The audit worker thread delivers the event; give a loaded runner room
    // rather than fail on scheduling delay. A passing run returns at once.
    assert_eventually(Duration::from_secs(5), || {
        shadow_transition_refusals(capture).len() >= expected
    });
    let refusals = shadow_transition_refusals(capture);
    assert_eq!(refusals.len(), expected);
    refusals
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn seed_rule_preview_events(path: &PathBuf) {
    for event in [
        SeedObservationEvent {
            event_id: "outside-window",
            timestamp: "2024-06-01T11:59:59Z",
            actor_user_id: "reader-1",
            roles: &["reader"],
            method: "GET",
            request_path: "/api/items/0",
            status: 200,
            policy_decision: "allowed",
            matched_rule_id: Some("existing-rule"),
        },
        SeedObservationEvent {
            event_id: "match-old",
            timestamp: "2024-06-01T12:00:01Z",
            actor_user_id: "reader-1",
            roles: &["reader"],
            method: "GET",
            request_path: "/api/items/1",
            status: 200,
            policy_decision: "allowed",
            matched_rule_id: Some("existing-rule"),
        },
        SeedObservationEvent {
            event_id: "wrong-method",
            timestamp: "2024-06-01T12:00:02Z",
            actor_user_id: "reader-1",
            roles: &["reader"],
            method: "POST",
            request_path: "/api/items/2",
            status: 201,
            policy_decision: "allowed",
            matched_rule_id: None,
        },
        SeedObservationEvent {
            event_id: "wrong-role",
            timestamp: "2024-06-01T12:00:03Z",
            actor_user_id: "admin-1",
            roles: &["admin"],
            method: "GET",
            request_path: "/api/items/3",
            status: 200,
            policy_decision: "allowed",
            matched_rule_id: Some("existing-rule"),
        },
        SeedObservationEvent {
            event_id: "match-new",
            timestamp: "2024-06-01T12:00:04Z",
            actor_user_id: "reader-1",
            roles: &["reader"],
            method: "GET",
            request_path: "/api/items/4",
            status: 200,
            policy_decision: "allowed",
            matched_rule_id: Some("existing-rule"),
        },
        SeedObservationEvent {
            event_id: "wrong-path",
            timestamp: "2024-06-01T12:00:05Z",
            actor_user_id: "reader-1",
            roles: &["reader"],
            method: "GET",
            request_path: "/api/other",
            status: 404,
            policy_decision: "denied",
            matched_rule_id: Some("existing-rule"),
        },
    ] {
        insert_observation_event(path, event);
    }
}

struct SeedObservationEvent<'a> {
    event_id: &'a str,
    timestamp: &'a str,
    actor_user_id: &'a str,
    roles: &'a [&'a str],
    method: &'a str,
    request_path: &'a str,
    status: i64,
    policy_decision: &'a str,
    matched_rule_id: Option<&'a str>,
}

struct SeedAuthzEvent<'a> {
    event_id: &'a str,
    event_type: &'a str,
    timestamp: &'a str,
    actor_user_id: Option<&'a str>,
    roles: &'a [&'a str],
    method: &'a str,
    request_path: &'a str,
    matched_rule_id: Option<&'a str>,
}

fn insert_observation_event(path: &PathBuf, event: SeedObservationEvent<'_>) {
    let connection = Connection::open(path).expect("test database should open");
    let roles = event
        .roles
        .iter()
        .map(|role| json!(role))
        .collect::<Vec<_>>();
    let actor_json = json!({
        "user_id": event.actor_user_id,
        "roles": roles,
        "auth_mode": "bearer_token"
    })
    .to_string();
    let mut payload = json!({
        "method": event.method,
        "path": event.request_path,
        "status": event.status,
        "policy_decision": event.policy_decision,
        "policy_reason": "matched_rule",
        "routing_context_known": true
    });
    if let Some(matched_rule_id) = event.matched_rule_id {
        payload["matched_rule_id"] = json!(matched_rule_id);
    }
    let payload_json = payload.to_string();

    connection
            .execute(
                r#"
                INSERT INTO audit_events (
                    event_id,
                    event_type,
                    timestamp,
                    schema_version,
                    request_id,
                    source_ip,
                    actor_user_id,
                    actor_json,
                    payload_method,
                    payload_path,
                    payload_status,
                    payload_matched_rule_id,
                    payload_json
                ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    event.event_id,
                    event.timestamp,
                    format!("request-{}", event.event_id),
                    event.actor_user_id,
                    actor_json,
                    event.method,
                    event.request_path,
                    event.status,
                    event.matched_rule_id,
                    payload_json,
                ],
            )
            .expect("observation event should insert");
}

fn insert_authz_event(path: &PathBuf, event: SeedAuthzEvent<'_>) {
    let connection = Connection::open(path).expect("test database should open");
    let roles = event
        .roles
        .iter()
        .map(|role| json!(role))
        .collect::<Vec<_>>();
    let actor_json = event.actor_user_id.map(|user_id| {
        json!({
            "user_id": user_id,
            "roles": roles,
            "auth_mode": "bearer_token"
        })
        .to_string()
    });
    let mut payload = json!({
        "method": event.method,
        "path": event.request_path,
        "reason": "matched_rule"
    });
    if let Some(matched_rule_id) = event.matched_rule_id {
        payload["matched_rule_id"] = json!(matched_rule_id);
    }
    let payload_json = payload.to_string();

    connection
        .execute(
            r#"
                INSERT INTO audit_events (
                    event_id,
                    event_type,
                    timestamp,
                    schema_version,
                    request_id,
                    source_ip,
                    actor_user_id,
                    actor_json,
                    payload_method,
                    payload_path,
                    payload_status,
                    payload_matched_rule_id,
                    payload_json
                ) VALUES (?1, ?2, ?3, '0.1.0', ?4, '203.0.113.10', ?5, ?6, ?7, ?8, NULL, ?9, ?10)
                "#,
            params![
                event.event_id,
                event.event_type,
                event.timestamp,
                format!("request-{}", event.event_id),
                event.actor_user_id,
                actor_json,
                event.method,
                event.request_path,
                event.matched_rule_id,
                payload_json,
            ],
        )
        .expect("authz event should insert");
}

fn bulk_insert_preview_events(path: &PathBuf, event_count: usize) {
    let mut connection = Connection::open(path).expect("test database should open");
    connection
        .execute_batch(
            r#"
                PRAGMA synchronous=OFF;
                PRAGMA temp_store=MEMORY;
                "#,
        )
        .expect("bulk insert pragmas should apply");

    let chunk_size = 5_000;
    for chunk_start in (0..event_count).step_by(chunk_size) {
        let chunk_end = (chunk_start + chunk_size).min(event_count);
        let transaction = connection
            .transaction()
            .expect("bulk insert transaction should start");

        {
            let mut statement = transaction
                    .prepare_cached(
                        r#"
                        INSERT INTO audit_events (
                            event_id,
                            event_type,
                            timestamp,
                            schema_version,
                            request_id,
                            source_ip,
                            actor_user_id,
                            actor_json,
                            payload_method,
                            payload_path,
                            payload_status,
                            payload_matched_rule_id,
                            payload_json
                        ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', 'reader-1', ?4, ?5, ?6, 200, ?7, ?8)
                        "#,
                    )
                    .expect("bulk insert statement should prepare");

            for index in chunk_start..chunk_end {
                let method = if index % 2 == 0 { "GET" } else { "POST" };
                let request_path = if index % 10 == 0 {
                    format!("/load/{index}")
                } else {
                    format!("/other/{index}")
                };
                let matched_rule_id = (index % 10 == 0).then_some("existing-load-rule");
                let actor_json =
                    r#"{"user_id":"reader-1","roles":["reader"],"auth_mode":"bearer_token"}"#;
                let payload_json = json!({
                    "method": method,
                    "path": &request_path,
                    "status": 200,
                    "policy_decision": "allowed",
                    "matched_rule_id": matched_rule_id
                })
                .to_string();

                statement
                    .execute(params![
                        format!("preview-event-{index:05}"),
                        preview_timestamp(index),
                        format!("preview-request-{index:05}"),
                        actor_json,
                        method,
                        request_path,
                        matched_rule_id,
                        payload_json,
                    ])
                    .expect("bulk preview event should insert");
            }
        }

        transaction
            .commit()
            .expect("bulk insert transaction should commit");
    }
}

fn preview_timestamp(index: usize) -> String {
    let second = index % 60;
    let minute = (index / 60) % 60;
    let hour = (index / 3_600) % 24;

    format!("2026-01-01T{hour:02}:{minute:02}:{second:02}Z")
}

// ------------------------------------------------------------------
// Cluster-mode policy control plane (issue #241, PR 7): endpoint
// behavior and replica reconciliation against a real PostgreSQL.
// Docker-gated on the same locator as the storage suites.
// ------------------------------------------------------------------

#[cfg(feature = "postgres")]
mod cluster_policy_tests {
    use super::*;
    use crate::rbac::PolicyHistoryListFilters;
    use crate::security_cluster::{ClusterSecurityRuntime, PolicyResource};
    use crate::storage::postgres::PostgresFoundation;
    use crate::storage::postgres_policy::PostgresPolicyStore;
    use crate::storage::{
        self, migrations, PolicyCommitPrecondition, PolicyCommitRequest, PolicyControlPlane,
        PolicyHistory as _,
    };

    fn locator() -> Option<String> {
        let key = "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned();
        let file = std::env::var(&key).ok()?;
        if file.trim().is_empty() {
            return None;
        }
        let contents = std::fs::read_to_string(file).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    struct DsnFile {
        path: String,
        directory: std::path::PathBuf,
    }

    impl Drop for DsnFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn write_dsn_file(dsn: &str) -> DsnFile {
        let directory = std::env::temp_dir().join(format!(
            "greengateway-cluster-policy-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory should create");
        let path = directory.join("database-url");
        std::fs::write(&path, format!("{dsn}\n")).expect("DSN file should write");
        // The foundation's permission check is part of the contract:
        // credential material grants group/other nothing. On Unix CI
        // the default mode would be 0644, which the check (correctly)
        // refuses.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("DSN permissions should set");
        }
        DsnFile {
            path: path.display().to_string(),
            directory,
        }
    }

    /// One test's disposable database, dropped fire-and-forget on an
    /// admin connection (the same teardown contract the SSE tests
    /// use).
    struct TestDatabase {
        dsn: String,
        admin_dsn: String,
        name: String,
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let admin_dsn = self.admin_dsn.clone();
            let name = self.name.clone();
            std::thread::spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let Ok((client, connection)) =
                        tokio_postgres::connect(&admin_dsn, tokio_postgres::NoTls).await
                    else {
                        return;
                    };
                    let connection = tokio::spawn(connection);
                    let _ = client
                        .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                        .await;
                    let _ = connection.await;
                });
            });
        }
    }

    async fn create_test_database(admin_dsn: &str) -> TestDatabase {
        let name = format!("ggw_policy_test_{}", uuid::Uuid::new_v4().simple());
        // CREATE DATABASE cannot run inside a transaction block: take a
        // fresh admin connection, create, release it.
        let (client, connection) = tokio_postgres::connect(admin_dsn, tokio_postgres::NoTls)
            .await
            .expect("admin connection");
        let connection_task = tokio::spawn(connection);
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .expect("test database should create");
        drop(client);
        let _ = connection_task.await;
        let database_start = admin_dsn
            .rfind('/')
            .expect("locator DSN has a database path segment");
        let dsn = format!("{}/{}", &admin_dsn[..database_start], name);
        TestDatabase {
            dsn,
            admin_dsn: admin_dsn.to_owned(),
            name,
        }
    }

    async fn migrated_policy_foundation(
        dsn: &str,
    ) -> (Arc<PostgresPolicyStore>, deadpool_postgres::Pool) {
        let dsn_file = write_dsn_file(dsn);
        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-cluster-policy".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("schema should migrate");
        let pool = foundation.pool().clone();
        (Arc::new(PostgresPolicyStore::new(pool.clone())), pool)
    }

    fn cluster_policy_json(id: &str) -> String {
        format!(
            r#"{{
                    "schema_version": "0.1.0",
                    "id": "{id}",
                    "default_action": "deny",
                    "roles": {{
                        "admin": {{ "permissions": ["admin:policy:read", "admin:policy:write"] }}
                    }}
                }}"#
        )
    }

    fn cluster_policy(id: &str) -> rbac::Policy {
        parse_policy_body(&Bytes::from(cluster_policy_json(id)))
            .expect("cluster policy should parse")
    }

    static DIFF: std::sync::LazyLock<Value> =
        std::sync::LazyLock::new(|| json!({ "action": "test" }));

    async fn initialize(store: &PostgresPolicyStore, id: &str) -> storage::ActivePolicy {
        PolicyControlPlane::commit(
            store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &cluster_policy(id),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("deployment should initialize")
    }

    /// A minimal admin router wired like production's cluster mode:
    /// no policy file, the PostgreSQL control plane as the authority,
    /// the PG store as the history store, and the revision gate layered
    /// over the admin routes exactly as `add_admin_api_routes` does.
    /// The revision gate these admin-route tests put in front of their
    /// routers: the production gate, on the background budget instead
    /// of the 250 ms request deadline.
    ///
    /// That deadline is a fail-closed LATENCY policy, and none of the
    /// tests using this router asserts on it -- they assert the status
    /// the admin plane returns (200, 412, 403) and what the authority
    /// ends up holding. But a router built here starts cold, so the
    /// first request through it pays a full fetch-validate-compile
    /// pass, and against an authority shared with the rest of the
    /// suite that pass alone can spend a request's budget and turn the
    /// asserted status into a 503 -- a failure that says nothing about
    /// the property under test. Production replicas do not serve cold:
    /// the builder registers every resource and the reconciler primes
    /// the watermark before the listener accepts.
    ///
    /// The gate stays on the request path, so nothing is given up: a
    /// gate that served a stale snapshot, or refused one it should
    /// have served, still changes every status asserted below. Only
    /// the budget differs, and the budget has its own dedicated guard
    /// in `the_background_pass_outlives_the_request_deadline`.
    struct BackgroundBudgetGate(Arc<ClusterSecurityRuntime>);

    #[async_trait::async_trait]
    impl middleware::rbac::SecurityRevisionGate for BackgroundBudgetGate {
        async fn ensure_current_revision(
            &self,
        ) -> Result<i64, middleware::rbac::SecurityRevisionCheckError> {
            self.0
                .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
                .await
        }

        async fn admit(
            &self,
        ) -> Result<middleware::rbac::Admission, middleware::rbac::SecurityRevisionCheckError>
        {
            self.0
                .admit_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
                .await
        }
    }

    fn cluster_policy_router(
        store: Arc<PostgresPolicyStore>,
    ) -> (Router, middleware::rbac::RbacState) {
        cluster_policy_router_with(store, None, test_audit_log())
    }

    /// [`cluster_policy_router`] with a roster for the operation gate and
    /// an audit log a test can read back.
    fn cluster_policy_router_with(
        store: Arc<PostgresPolicyStore>,
        membership: Option<Arc<cluster_membership::ClusterMembership>>,
        audit: audit::AuditLog,
    ) -> (Router, middleware::rbac::RbacState) {
        let rbac_state = middleware::rbac::RbacState::new(
            cluster_policy("router-seed"),
            Vec::new(),
            false,
            test_audit_log(),
        );
        let runtime = ClusterSecurityRuntime::new(
            store.revision_source(),
            PolicyResource::new(store.clone(), rbac_state.clone()),
        );
        let gate: Arc<dyn middleware::rbac::SecurityRevisionGate> =
            Arc::new(BackgroundBudgetGate(runtime));
        let router = Router::new()
            .route(
                POLICY_ADMIN_ROUTE,
                get(policy_get_endpoint).put(policy_put_endpoint),
            )
            .route(POLICY_HISTORY_ADMIN_ROUTE, get(policy_history_endpoint))
            .route(POLICY_ROLLBACK_ADMIN_ROUTE, post(policy_rollback_endpoint))
            .route(
                POLICY_DRAFTS_ADMIN_ROUTE,
                get(policy_drafts_list_endpoint).post(policy_draft_create_endpoint),
            )
            .route(
                POLICY_DRAFT_ADMIN_ROUTE,
                get(policy_draft_get_endpoint)
                    .patch(policy_draft_patch_endpoint)
                    .delete(policy_draft_delete_endpoint),
            )
            .route(
                POLICY_DRAFT_PUBLISH_ADMIN_ROUTE,
                post(policy_draft_publish_endpoint),
            )
            .route(
                POLICY_SIMULATIONS_ADMIN_ROUTE,
                post(policy_simulations_endpoint).layer(Extension(Arc::new(
                    PolicyEvaluationLimiter::new(MAX_CONCURRENT_POLICY_SIMULATIONS),
                ))),
            )
            .with_state(PolicyAdminState {
                policy_file: None,
                rbac_state: Some(rbac_state.clone().with_revision_gate(gate.clone())),
                history_store: Some(store.clone() as Arc<dyn storage::PolicyHistory>),
                draft_store: Some(
                    Arc::new(store.draft_store()) as Arc<dyn storage::PolicyDraftStore>
                ),
                control_plane: Some(store as Arc<dyn storage::PolicyControlPlane>),
                membership,
                event_store: None,
                query_store: None,
                authority_evidence: authority_events::required::AuthorityEvidenceGate::best_effort(
                ),
                audit,
                client_ip_policy: client_ip::ClientIpPolicy::default(),
                max_body_size: 1024 * 1024,
            })
            .layer(axum::middleware::from_fn_with_state(
                gate,
                admin_revision_gate_middleware,
            ));
        (router, rbac_state)
    }

    fn admin_request(method: Method, uri: &str, body: Option<(&str, &str)>) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        let body = match body {
            Some((if_match, body)) => {
                builder = builder.header(header::IF_MATCH, if_match);
                Body::from(body.to_owned())
            }
            None => Body::empty(),
        };
        let mut request = builder.body(body).expect("admin request should build");
        request.extensions_mut().insert(admin_principal());
        request
    }

    fn admin_principal() -> auth::Principal {
        test_principal(&["admin"])
    }

    async fn etag_of(response: Response) -> String {
        assert_eq!(response.status(), StatusCode::OK);
        response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("ETag header")
            .to_owned()
    }

    fn described_cluster_policy_json(id: &str) -> String {
        format!(
            r#"{{
                    "schema_version": "0.1.0",
                    "id": "{id}",
                    "default_action": "deny",
                    "roles": {{
                        "admin": {{
                            "permissions": ["admin:policy:read", "admin:policy:write"],
                            "description": "Maintains the gateway policy"
                        }}
                    }}
                }}"#
        )
    }

    async fn policy_version_count(pool: &deadpool_postgres::Pool) -> i64 {
        pool.get()
            .await
            .expect("client")
            .query_one(
                "SELECT count(*)::bigint FROM greengateway.policy_documents",
                &[],
            )
            .await
            .expect("count policy versions")
            .get(0)
    }

    async fn refusal_of(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("refusal body");
        (
            status,
            serde_json::from_slice(&body).expect("refusal body is JSON"),
        )
    }

    /// Issue #426's registered operation through the policy API. A document
    /// whose roles carry a `description` is committed only while every live
    /// member advertises `policy_role_descriptions`: a refusal is a `409`
    /// with the stable reason, writes no version, and is audited; a control
    /// plane with no roster refuses with `503`; and a document without the
    /// feature never asks.
    #[tokio::test]
    async fn cluster_policy_role_descriptions_wait_for_every_live_member() {
        use crate::storage::{MemberRegistration, PostgresMembershipStore};

        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store, "gate-init").await;

        // No roster to ask: the gated write is refused, the plain one is not.
        let (router, rbac_state) = cluster_policy_router(store.clone());
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");
        let before = policy_version_count(&pool).await;
        let (status, body) = refusal_of(
            router
                .clone()
                .oneshot(admin_request(
                    Method::PUT,
                    POLICY_ADMIN_ROUTE,
                    Some((&active.etag, &described_cluster_policy_json("gate-orphan"))),
                ))
                .await
                .expect("PUT should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["reason"], "roster_unavailable");
        assert_eq!(policy_version_count(&pool).await, before);
        let plain_etag = etag_of(
            router
                .clone()
                .oneshot(admin_request(
                    Method::PUT,
                    POLICY_ADMIN_ROUTE,
                    Some((&active.etag, &cluster_policy_json("gate-plain"))),
                ))
                .await
                .expect("PUT should complete"),
        )
        .await;

        // A roster holding this replica and a prepared member: the
        // protocol, without role descriptions.
        let deployment = "deploy-cluster-policy";
        let membership = cluster_membership::ClusterMembership::new(
            PostgresMembershipStore::new(
                pool.clone(),
                deployment,
                crate::ha::InstanceIdentity::generate(),
            ),
            MemberRegistration {
                binary_version: env!("CARGO_PKG_VERSION").to_owned(),
                schema_version: migrations::schema_version_range(),
                document_version: cluster_membership::DOCUMENT_VERSION_RANGE,
                fingerprint: "b".repeat(64),
                capabilities: storage::compatibility::BINARY_CAPABILITIES.to_vec(),
            },
            Duration::from_secs(1),
            Duration::from_secs(30),
        );
        membership.register_boot().await.expect("boot row");
        let prepared = uuid::Uuid::new_v4();
        pool.get()
            .await
            .expect("client")
            .execute(
                "INSERT INTO greengateway.cluster_members
                     (deployment_id, instance_id, boot_id, binary_version,
                      schema_version_min, schema_version_max,
                      document_version_min, document_version_max, fingerprint,
                      capabilities)
                 VALUES ($1, $2::text::uuid, $3::text::uuid, '1.0.1', 18, 18, 0, 0,
                         repeat('b', 64), 'operation_requirements')",
                &[
                    &deployment,
                    &prepared.to_string(),
                    &uuid::Uuid::new_v4().to_string(),
                ],
            )
            .await
            .expect("a prepared member row inserts");

        let capture = audit::sink::tests::CaptureSink::new();
        let (router, rbac_state) = cluster_policy_router_with(
            store.clone(),
            Some(membership),
            audit::AuditLog::new(Arc::new(capture.clone())),
        );
        let current = store
            .active()
            .await
            .expect("active read")
            .expect("the deployment is initialized");
        assert_eq!(current.etag, plain_etag);
        rbac_state
            .install_revision_snapshot(current.policy.clone(), current.security_revision)
            .await
            .expect("the authority's revision should install");

        let before = policy_version_count(&pool).await;
        let (status, body) = refusal_of(
            router
                .clone()
                .oneshot(admin_request(
                    Method::PUT,
                    POLICY_ADMIN_ROUTE,
                    Some((&plain_etag, &described_cluster_policy_json("gate-held"))),
                ))
                .await
                .expect("PUT should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "capability_not_advertised");
        assert!(
            !body.to_string().contains(&prepared.to_string()),
            "a refusal names no member: {body}"
        );
        assert_eq!(
            policy_version_count(&pool).await,
            before,
            "a refused write commits nothing"
        );
        let started = std::time::Instant::now();
        while capture.len() < 1 && started.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let events = capture.events();
        assert_eq!(events.len(), 1, "one refusal, one audit event");
        assert_eq!(events[0].event_type, "cluster.operation_refused");
        assert_eq!(events[0].payload["operation"], "policy.role_descriptions");
        assert_eq!(events[0].payload["capability"], "policy_role_descriptions");
        assert_eq!(events[0].payload["lacking_members"], 1);
        assert_eq!(events[0].payload["live_members"], 2);

        // The prepared member's row goes stale on the database clock: the
        // same write is admitted and the description is served back.
        pool.get()
            .await
            .expect("client")
            .execute(
                "UPDATE greengateway.cluster_members
                 SET last_heartbeat_at = now() - interval '60 seconds'
                 WHERE instance_id = $1::text::uuid",
                &[&prepared.to_string()],
            )
            .await
            .expect("backdate the prepared member");
        let admitted = router
            .clone()
            .oneshot(admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some((&plain_etag, &described_cluster_policy_json("gate-admitted"))),
            ))
            .await
            .expect("PUT should complete");
        assert_eq!(admitted.status(), StatusCode::OK);
        let body = axum::body::to_bytes(admitted.into_body(), 1 << 20)
            .await
            .expect("admitted body");
        let served: Value = serde_json::from_slice(&body).expect("policy JSON");
        assert_eq!(
            served["roles"]["admin"]["description"],
            "Maintains the gateway policy"
        );
        assert_eq!(policy_version_count(&pool).await, before + 1);
        let started = std::time::Instant::now();
        while capture.len() < 2 && started.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let events = capture.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "cluster.operation_refused")
                .count(),
            1,
            "an admission is not audited as a refusal"
        );
        assert!(
            events
                .iter()
                .any(|event| event.event_type == audit::event::POLICY_CHANGED),
            "the admitted commit is audited as the policy change it is"
        );
    }

    /// Policy v1 is document format 1, and no replica of this build
    /// advertises it (`cluster_membership::DOCUMENT_VERSION_RANGE`), so the
    /// policy API refuses to commit one with a `400` and writes nothing. The
    /// store refuses the same candidate if a caller skips that check, and a
    /// 0.x document on the same path is committed as before.
    #[tokio::test]
    async fn cluster_policy_refuses_to_commit_a_v1_document() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store, "v1-init").await;
        let (router, rbac_state) = cluster_policy_router(store.clone());
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");
        let v1 = r#"{
            "schema_version": "1.0.0",
            "id": "v1-held",
            "default_action": "deny",
            "roles": { "admin": { "permissions": ["admin:policy:read", "admin:policy:write"] } }
        }"#;

        let before = policy_version_count(&pool).await;
        let (status, body) = refusal_of(
            router
                .clone()
                .oneshot(admin_request(
                    Method::PUT,
                    POLICY_ADMIN_ROUTE,
                    Some((&active.etag, v1)),
                ))
                .await
                .expect("PUT should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["valid"], json!(false));
        assert!(
            body["errors"][0]
                .as_str()
                .unwrap_or_default()
                .contains("cannot be committed in cluster mode"),
            "{body}"
        );
        assert_eq!(policy_version_count(&pool).await, before);

        let candidate = parse_policy_body(&Bytes::from(v1)).expect("a valid v1 document");
        let refused = PolicyControlPlane::commit(
            store.as_ref(),
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Expected {
                    etag: active.etag.clone(),
                },
                candidate: &candidate,
                change: crate::storage::DocumentChange::test_policy("test"),
                diff_summary: &DIFF,
            },
        )
        .await;
        assert!(
            matches!(refused, Err(storage::PolicyCommitError::Store(_))),
            "the store must refuse a document no replica reads"
        );
        assert_eq!(policy_version_count(&pool).await, before);

        let committed = router
            .oneshot(admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some((&active.etag, &cluster_policy_json("v0-after"))),
            ))
            .await
            .expect("PUT should complete");
        assert_eq!(committed.status(), StatusCode::OK);
        assert_eq!(policy_version_count(&pool).await, before + 1);
    }

    /// What cluster mode cannot commit it does not save or simulate either
    /// (issue #243 review). A draft whose candidate is policy v1 is refused
    /// on create and on patch with the `400` a `PUT` of the same document
    /// gets, and a simulation of an inline v1 candidate with the `422`
    /// `POST /policy/validate` and a test run give it, as soon as the
    /// candidate is read rather than when someone tries to commit it. Nothing
    /// is committed, and a 0.x candidate on the same paths still is
    /// accepted.
    #[tokio::test]
    async fn cluster_drafts_and_simulations_refuse_a_candidate_the_cluster_cannot_commit() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_foundation(&database.dsn).await;
        let simulating = r#"{
            "schema_version": "0.1.0",
            "id": "simulate-init",
            "default_action": "deny",
            "roles": { "admin": { "permissions":
                ["admin:policy:read", "admin:policy:write", "admin:policy:simulate"] } }
        }"#;
        let active = PolicyControlPlane::commit(
            store.as_ref(),
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &parse_policy_body(simulating.as_bytes())
                    .expect("seed policy should parse"),
                change: crate::storage::DocumentChange::test_policy("seed"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("deployment should initialize");
        let (router, rbac_state) = cluster_policy_router(store.clone());
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");
        let versions_before = policy_version_count(&pool).await;
        let v1 = r#"{"schema_version":"1.0.0","id":"v1-held","default_action":"deny"}"#;
        let refuses_format = |body: &Value| {
            body["errors"][0]
                .as_str()
                .is_some_and(|error| error.contains("cannot be committed in cluster mode"))
        };
        let request = |method: Method, uri: &str, if_match: &str, body: String| {
            let mut request = Request::builder()
                .method(method)
                .uri(uri)
                .header(header::IF_MATCH, if_match)
                .body(Body::from(body))
                .expect("request should build");
            request.extensions_mut().insert(admin_principal());
            request
        };

        let (status, body) = refusal_of(
            router
                .clone()
                .oneshot(request(
                    Method::POST,
                    POLICY_DRAFTS_ADMIN_ROUTE,
                    &active.etag,
                    format!(r#"{{"policy":{v1}}}"#),
                ))
                .await
                .expect("create should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(refuses_format(&body), "{body}");

        let created = router
            .clone()
            .oneshot(request(
                Method::POST,
                POLICY_DRAFTS_ADMIN_ROUTE,
                &active.etag,
                "{}".to_owned(),
            ))
            .await
            .expect("create should complete");
        assert_eq!(created.status(), StatusCode::CREATED);
        let draft_etag = created
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("draft ETag")
            .to_owned();
        let (_, draft) = refusal_of(created).await;
        let draft_uri = format!(
            "{POLICY_DRAFTS_ADMIN_ROUTE}/{}",
            draft["draft_id"].as_str().expect("draft id")
        );
        let (status, body) = refusal_of(
            router
                .clone()
                .oneshot(request(
                    Method::PATCH,
                    &draft_uri,
                    &draft_etag,
                    format!(r#"{{"policy":{v1}}}"#),
                ))
                .await
                .expect("patch should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(refuses_format(&body), "{body}");
        let (status, kept) = refusal_of(
            router
                .clone()
                .oneshot(request(Method::GET, &draft_uri, "*", String::new()))
                .await
                .expect("draft read should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(kept["revision"], 1, "the refused patch saved nothing");

        let simulation = |policy: &str| {
            format!(
                r#"{{"schema_version":"policy-simulation.v1","base_etag":{},"candidate":{{"source":"inline","policy":{policy}}},"cases":[{{"id":"anonymous","kind":"http","request":{{"method":"GET","path":"/x"}},"principal":"anonymous"}}]}}"#,
                json!(active.etag)
            )
        };
        let (status, body) = refusal_of(
            router
                .clone()
                .oneshot(request(
                    Method::POST,
                    POLICY_SIMULATIONS_ADMIN_ROUTE,
                    &active.etag,
                    simulation(v1),
                ))
                .await
                .expect("simulation should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["reason"], "policy_candidate_invalid");
        assert!(refuses_format(&body), "{body}");
        let simulated = router
            .clone()
            .oneshot(request(
                Method::POST,
                POLICY_SIMULATIONS_ADMIN_ROUTE,
                &active.etag,
                simulation(&cluster_policy_json("v0-simulated")),
            ))
            .await
            .expect("simulation should complete");
        assert_eq!(simulated.status(), StatusCode::OK);
        assert_eq!(policy_version_count(&pool).await, versions_before);
    }

    /// A draft publication the commit itself refuses is recorded like one
    /// refused before it (issue #243 review): here the candidate gives a
    /// role a `description`, the operation gate has no roster to ask, and
    /// the publication is the gate's `503` with nothing committed, the draft
    /// kept open, and a `policy.draft_publish_refused` naming
    /// `policy_operation_refused`.
    #[tokio::test]
    async fn cluster_draft_publications_the_commit_refuses_are_audited() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store, "refused-init").await;
        let capture = audit::sink::tests::CaptureSink::new();
        let (router, rbac_state) = cluster_policy_router_with(
            store.clone(),
            None,
            audit::AuditLog::new(Arc::new(capture.clone())),
        );
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");
        let versions_before = policy_version_count(&pool).await;

        let mut create = Request::builder()
            .method(Method::POST)
            .uri(POLICY_DRAFTS_ADMIN_ROUTE)
            .header(header::IF_MATCH, &active.etag)
            .body(Body::from(format!(
                r#"{{"policy":{}}}"#,
                described_cluster_policy_json("refused-described")
            )))
            .expect("request should build");
        create.extensions_mut().insert(admin_principal());
        let created = router
            .clone()
            .oneshot(create)
            .await
            .expect("create should complete");
        assert_eq!(created.status(), StatusCode::CREATED);
        let draft_etag = created
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("draft ETag")
            .to_owned();
        let (_, draft) = refusal_of(created).await;
        let draft_id = draft["draft_id"].as_str().expect("draft id").to_owned();

        let mut publish = Request::builder()
            .method(Method::POST)
            .uri(format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}/publish"))
            .header(POLICY_DRAFT_ETAG_HEADER, &draft_etag)
            .header(header::IF_MATCH, &active.etag)
            .body(Body::empty())
            .expect("request should build");
        publish.extensions_mut().insert(admin_principal());
        let (status, body) = refusal_of(
            router
                .clone()
                .oneshot(publish)
                .await
                .expect("publish should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(body["reason"], "roster_unavailable");
        assert_eq!(policy_version_count(&pool).await, versions_before);

        let refused = |capture: &audit::sink::tests::CaptureSink| {
            capture
                .events()
                .into_iter()
                .filter(|event| event.event_type == audit::event::POLICY_DRAFT_PUBLISH_REFUSED)
                .map(|event| event.payload)
                .collect::<Vec<_>>()
        };
        assert_eventually(Duration::from_secs(1), || refused(&capture).len() == 1);
        let refused = refused(&capture);
        assert_eq!(refused[0]["draft_id"], json!(draft_id));
        assert_eq!(refused[0]["reason"], "policy_operation_refused");
        assert_eq!(refused[0]["current_policy_etag"], json!(active.etag));
        assert!(!capture.events().into_iter().any(|event| {
            event.event_type == audit::event::POLICY_DRAFT_PUBLISHED
                || event.event_type == audit::event::POLICY_CHANGED
        }));
    }

    /// Issue #443's registered operation through the managed OpenAPI
    /// register endpoint, against a real roster: storing a catalog
    /// converted from a Swagger 2.0 document waits for every live member to
    /// advertise `openapi_swagger2_catalogs`. A refusal is a `409` with the
    /// stable reason, stores nothing and is audited; an OpenAPI 3.x
    /// registration never asks; and once the lacking member goes stale the
    /// same registration is admitted.
    #[tokio::test]
    async fn cluster_swagger2_catalogs_wait_for_every_live_member() {
        use crate::storage::{MemberRegistration, PostgresMembershipStore};

        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (_, pool) = migrated_policy_foundation(&database.dsn).await;
        let deployment = "deploy-cluster-swagger2";
        let membership = cluster_membership::ClusterMembership::new(
            PostgresMembershipStore::new(
                pool.clone(),
                deployment,
                crate::ha::InstanceIdentity::generate(),
            ),
            MemberRegistration {
                binary_version: env!("CARGO_PKG_VERSION").to_owned(),
                schema_version: migrations::schema_version_range(),
                document_version: cluster_membership::DOCUMENT_VERSION_RANGE,
                fingerprint: "b".repeat(64),
                capabilities: storage::compatibility::BINARY_CAPABILITIES.to_vec(),
            },
            Duration::from_secs(1),
            Duration::from_secs(30),
        );
        membership.register_boot().await.expect("boot row");
        // A member built before Swagger 2.0 import advertises what issue
        // #426's successor does, and nothing newer.
        let earlier = uuid::Uuid::new_v4();
        pool.get()
            .await
            .expect("client")
            .execute(
                "INSERT INTO greengateway.cluster_members
                     (deployment_id, instance_id, boot_id, binary_version,
                      schema_version_min, schema_version_max,
                      document_version_min, document_version_max, fingerprint,
                      capabilities)
                 VALUES ($1, $2::text::uuid, $3::text::uuid, '1.0.1', 18, 18, 0, 0,
                         repeat('b', 64), 'operation_requirements,policy_role_descriptions')",
                &[
                    &deployment,
                    &earlier.to_string(),
                    &uuid::Uuid::new_v4().to_string(),
                ],
            )
            .await
            .expect("an earlier member row inserts");

        let connection_db = TempDb::new("cluster-openapi-swagger2-gate");
        let policy = TempPolicyFile::new(&connection_policy_document_string());
        let capture = audit::sink::tests::CaptureSink::new();
        let router = gated_connection_admin_router(
            &connection_db,
            &policy,
            audit::AuditLog::new(Arc::new(capture.clone())),
            GatewayAppBuildOverrides {
                pg_membership: Some(membership),
                ..GatewayAppBuildOverrides::default()
            },
        );
        let (connection_id, connection_etag) =
            create_managed_openapi_connection(&router, "Cluster Swagger").await;
        let swagger_spec = json!({
            "swagger": "2.0",
            "info": { "title": "Widget API", "version": "1.0.0" },
            "paths": {
                "/widgets": {
                    "get": {
                        "operationId": "listWidgets",
                        "responses": { "200": { "description": "Widgets" } }
                    }
                }
            }
        })
        .to_string();
        let refusals = || {
            capture
                .events()
                .into_iter()
                .filter(|event| event.event_type == "cluster.operation_refused")
                .collect::<Vec<_>>()
        };

        let (status, body) = refusal_of(
            preview_and_register_managed_openapi(
                &router,
                &connection_id,
                &connection_etag,
                &swagger_spec,
                &["listWidgets"],
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "capability_not_advertised");
        assert!(
            !body.to_string().contains(&earlier.to_string()),
            "a refusal names no member: {body}"
        );
        let started = std::time::Instant::now();
        while refusals().is_empty() && started.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let refused = refusals();
        assert_eq!(refused.len(), 1, "one refusal, one gate audit event");
        assert_eq!(
            refused[0].payload["operation"],
            "connections.openapi_swagger2_catalog"
        );
        assert_eq!(
            refused[0].payload["capability"],
            "openapi_swagger2_catalogs"
        );
        assert_eq!(refused[0].payload["lacking_members"], 1);
        assert_eq!(refused[0].payload["live_members"], 2);

        let openapi = preview_and_register_managed_openapi(
            &router,
            &connection_id,
            &connection_etag,
            widget_openapi_spec(),
            &["createWidget"],
        )
        .await;
        assert_eq!(
            openapi.status(),
            StatusCode::CREATED,
            "an OpenAPI 3.x document never asks the gate"
        );

        // The earlier member's row goes stale on the database clock: the
        // same registration is admitted.
        pool.get()
            .await
            .expect("client")
            .execute(
                "UPDATE greengateway.cluster_members
                 SET last_heartbeat_at = now() - interval '60 seconds'
                 WHERE instance_id = $1::text::uuid",
                &[&earlier.to_string()],
            )
            .await
            .expect("backdate the earlier member");
        let admitted = preview_and_register_managed_openapi(
            &router,
            &connection_id,
            &connection_etag,
            &swagger_spec,
            &["listWidgets"],
        )
        .await;
        assert_eq!(admitted.status(), StatusCode::CREATED);
        assert_eq!(
            json_body(admitted).await["registered_tool_names"],
            json!(["listWidgets"])
        );
        assert_eq!(
            refusals().len(),
            1,
            "an admission is not audited as a refusal"
        );
    }

    /// Google Discovery catalogs (issue #443) through the register endpoint
    /// against a real roster: a member built with Swagger 2.0 import but
    /// before Discovery import advertises `openapi_swagger2_catalogs` only,
    /// which admits Swagger 2.0 catalogs and not Discovery ones.
    #[tokio::test]
    async fn cluster_discovery_catalogs_wait_for_members_built_before_discovery_import() {
        use crate::storage::{MemberRegistration, PostgresMembershipStore};

        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (_, pool) = migrated_policy_foundation(&database.dsn).await;
        let deployment = "deploy-cluster-discovery";
        let membership = cluster_membership::ClusterMembership::new(
            PostgresMembershipStore::new(
                pool.clone(),
                deployment,
                crate::ha::InstanceIdentity::generate(),
            ),
            MemberRegistration {
                binary_version: env!("CARGO_PKG_VERSION").to_owned(),
                schema_version: migrations::schema_version_range(),
                document_version: cluster_membership::DOCUMENT_VERSION_RANGE,
                fingerprint: "b".repeat(64),
                capabilities: storage::compatibility::BINARY_CAPABILITIES.to_vec(),
            },
            Duration::from_secs(1),
            Duration::from_secs(30),
        );
        membership.register_boot().await.expect("boot row");
        let swagger_only = uuid::Uuid::new_v4();
        pool.get()
            .await
            .expect("client")
            .execute(
                "INSERT INTO greengateway.cluster_members
                     (deployment_id, instance_id, boot_id, binary_version,
                      schema_version_min, schema_version_max,
                      document_version_min, document_version_max, fingerprint,
                      capabilities)
                 VALUES ($1, $2::text::uuid, $3::text::uuid, '1.0.1', 18, 18, 0, 0,
                         repeat('b', 64),
                         'openapi_swagger2_catalogs,operation_requirements,policy_role_descriptions')",
                &[
                    &deployment,
                    &swagger_only.to_string(),
                    &uuid::Uuid::new_v4().to_string(),
                ],
            )
            .await
            .expect("a Swagger-only member row inserts");

        let connection_db = TempDb::new("cluster-openapi-discovery-gate");
        let policy = TempPolicyFile::new(&connection_policy_document_string());
        let capture = audit::sink::tests::CaptureSink::new();
        let router = gated_connection_admin_router(
            &connection_db,
            &policy,
            audit::AuditLog::new(Arc::new(capture.clone())),
            GatewayAppBuildOverrides {
                pg_membership: Some(membership),
                ..GatewayAppBuildOverrides::default()
            },
        );
        let (connection_id, connection_etag) =
            create_managed_openapi_connection(&router, "Cluster Discovery").await;
        let refusals = || {
            capture
                .events()
                .into_iter()
                .filter(|event| event.event_type == "cluster.operation_refused")
                .collect::<Vec<_>>()
        };

        let swagger = preview_and_register_managed_openapi(
            &router,
            &connection_id,
            &connection_etag,
            &json!({
                "swagger": "2.0",
                "info": { "title": "Widget API", "version": "1.0.0" },
                "paths": {
                    "/widgets": {
                        "get": {
                            "operationId": "listWidgets",
                            "responses": { "200": { "description": "Widgets" } }
                        }
                    }
                }
            })
            .to_string(),
            &["listWidgets"],
        )
        .await;
        assert_eq!(
            swagger.status(),
            StatusCode::CREATED,
            "the Swagger-only member admits a Swagger 2.0 catalog"
        );

        let (status, body) = refusal_of(
            preview_and_register_managed_openapi(
                &router,
                &connection_id,
                &connection_etag,
                &widget_discovery_document(),
                &["widgets.widgets.get"],
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "capability_not_advertised");
        let started = std::time::Instant::now();
        while refusals().is_empty() && started.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let refused = refusals();
        assert_eq!(refused.len(), 1, "one refusal, one gate audit event");
        assert_eq!(
            refused[0].payload["operation"],
            "connections.openapi_discovery_catalog"
        );
        assert_eq!(
            refused[0].payload["capability"],
            "openapi_discovery_catalogs"
        );
        assert_eq!(refused[0].payload["lacking_members"], 1);

        pool.get()
            .await
            .expect("client")
            .execute(
                "UPDATE greengateway.cluster_members
                 SET last_heartbeat_at = now() - interval '60 seconds'
                 WHERE instance_id = $1::text::uuid",
                &[&swagger_only.to_string()],
            )
            .await
            .expect("backdate the Swagger-only member");
        let admitted = preview_and_register_managed_openapi(
            &router,
            &connection_id,
            &connection_etag,
            &widget_discovery_document(),
            &["widgets.widgets.get"],
        )
        .await;
        assert_eq!(admitted.status(), StatusCode::CREATED);
        assert_eq!(
            json_body(admitted).await["registered_tool_names"],
            json!(["widgets.widgets.get"])
        );
    }

    #[tokio::test]
    async fn cluster_policy_endpoints_commit_versions_and_reject_stale_preconditions() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store, "ep-init").await;
        let (router, rbac_state) = cluster_policy_router(store.clone());
        // The router's local snapshot starts unkeyed; install the
        // authority's revision like the production startup path does.
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");

        // GET serves the authoritative document and its verified ETag.
        let etag = etag_of(
            router
                .clone()
                .oneshot(admin_request(Method::GET, POLICY_ADMIN_ROUTE, None))
                .await
                .expect("GET should complete"),
        )
        .await;
        assert_eq!(etag, active.etag);

        // PUT with the current ETag commits a new version, advances the
        // revision, installs the snapshot, and reports the new ETag.
        let put = router
            .clone()
            .oneshot(admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some((&etag, &cluster_policy_json("ep-next"))),
            ))
            .await
            .expect("PUT should complete");
        let new_etag = etag_of(put).await;
        assert_ne!(etag, new_etag);
        assert_ne!(etag, new_etag);
        assert_eq!(
            rbac_state.snapshot_security_revision(),
            active.security_revision + 1,
            "a committed mutation must install the new snapshot before the response"
        );

        // The stale ETag is now a 412 that wrote nothing.
        let stale = router
            .clone()
            .oneshot(admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some((&etag, &cluster_policy_json("ep-race"))),
            ))
            .await
            .expect("stale PUT should complete");
        assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);

        // History lists both immutable versions through the same API
        // the standalone mode serves.
        let history = router
            .clone()
            .oneshot(admin_request(
                Method::GET,
                &format!("{POLICY_HISTORY_ADMIN_ROUTE}?limit=10&include_policy=false"),
                None,
            ))
            .await
            .expect("history should complete");
        assert_eq!(history.status(), StatusCode::OK);
        let body = axum::body::to_bytes(history.into_body(), 1 << 20)
            .await
            .expect("history body");
        let page: Value = serde_json::from_slice(&body).expect("history JSON");
        assert_eq!(page["versions"].as_array().map(Vec::len), Some(2));

        // Rollback to the first version commits it as a NEW version.
        // `list_versions` is newest-first: the oldest version is the
        // last entry of the full page.
        let full_page = store
            .list_versions(&PolicyHistoryListFilters {
                limit: 10,
                cursor: None,
                include_policy: false,
            })
            .await
            .expect("history list");
        let first_version = full_page
            .versions
            .last()
            .expect("history has versions")
            .version;
        let rollback = router
            .clone()
            .oneshot(admin_request(
                Method::POST,
                &format!("/v1/admin/policy/rollback/{first_version}"),
                Some((&new_etag, "")),
            ))
            .await
            .expect("rollback should complete");
        assert_eq!(rollback.status(), StatusCode::OK);

        let documents: i64 = {
            let client = pool.get().await.expect("count checkout");
            let row = client
                .query_one("SELECT count(*) FROM greengateway.policy_documents", &[])
                .await
                .expect("count");
            row.get(0)
        };
        assert_eq!(documents, 3, "two commits plus the rollback version");

        // Each committed change recorded itself (issue #425): the endpoint
        // named its operation and the authenticated principal that made it;
        // the stale PUT recorded nothing.
        let evidence: Vec<(String, String, String, Option<String>, String)> = pool
            .get()
            .await
            .expect("evidence checkout")
            .query(
                "SELECT action, actor_kind, actor_user_id, actor_issuer, actor_auth_mode \
                 FROM greengateway.document_change_evidence ORDER BY security_revision",
                &[],
            )
            .await
            .expect("evidence rows")
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
            .collect();
        let principal = admin_principal();
        let by_admin = |action: &str| {
            (
                action.to_owned(),
                "principal".to_owned(),
                principal.user_id.clone(),
                None,
                principal.auth_method.audit_mode().to_owned(),
            )
        };
        assert_eq!(
            evidence,
            vec![
                (
                    "policy.publish".to_owned(),
                    "principal".to_owned(),
                    "seed".to_owned(),
                    None,
                    "bearer_token".to_owned(),
                ),
                by_admin("policy.publish"),
                by_admin("policy.rollback"),
            ]
        );
    }

    /// Server-side drafts in cluster mode (issue #243, slice 9): a draft is
    /// shared state in migration 22's table, saving one commits nothing, and
    /// publishing one is exactly one control-plane commit, behind the draft
    /// ETag and the live `If-Match` both. A second draft pinned to the same
    /// base is then stale and is refused without a commit.
    #[tokio::test]
    async fn cluster_policy_drafts_publish_through_the_control_plane_transaction() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store, "draft-init").await;
        let (router, rbac_state) = cluster_policy_router(store.clone());
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");
        let versions_before = policy_version_count(&pool).await;

        let draft_request = |method: Method, uri: &str, headers: &[(&str, &str)], body: &str| {
            let mut builder = Request::builder().method(method).uri(uri);
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let mut request = builder
                .body(Body::from(body.to_owned()))
                .expect("draft request should build");
            request.extensions_mut().insert(admin_principal());
            request
        };
        let mut drafts = Vec::new();
        for id in ["draft-published", "draft-left-behind"] {
            let candidate: Value =
                serde_json::from_str(&cluster_policy_json(id)).expect("candidate JSON");
            let created = router
                .clone()
                .oneshot(draft_request(
                    Method::POST,
                    POLICY_DRAFTS_ADMIN_ROUTE,
                    &[("if-match", &active.etag)],
                    &json!({ "policy": candidate }).to_string(),
                ))
                .await
                .expect("create should complete");
            assert_eq!(created.status(), StatusCode::CREATED);
            let draft_etag = created
                .headers()
                .get(header::ETAG)
                .and_then(|value| value.to_str().ok())
                .expect("draft ETag")
                .to_owned();
            let (_, body) = refusal_of(created).await;
            drafts.push((
                body["draft_id"].as_str().expect("draft id").to_owned(),
                draft_etag,
            ));
        }
        assert_eq!(
            policy_version_count(&pool).await,
            versions_before,
            "saving drafts commits no policy version"
        );
        assert_eq!(
            rbac_state.snapshot_security_revision(),
            active.security_revision
        );

        let publish = |draft: &(String, String), if_match: &str| {
            draft_request(
                Method::POST,
                &format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{}/publish", draft.0),
                &[(POLICY_DRAFT_ETAG_HEADER, &draft.1), ("if-match", if_match)],
                "",
            )
        };
        let published = router
            .clone()
            .oneshot(publish(&drafts[0], &active.etag))
            .await
            .expect("publish should complete");
        let new_etag = etag_of(published).await;
        assert_eq!(policy_version_count(&pool).await, versions_before + 1);
        let now_active = store
            .active()
            .await
            .expect("active read")
            .expect("active document");
        assert_eq!(now_active.etag, new_etag);
        assert_eq!(now_active.policy.id.as_deref(), Some("draft-published"));
        assert_eq!(
            rbac_state.snapshot_security_revision(),
            active.security_revision + 1,
            "publication installs the committed revision like any policy write"
        );
        let (status, frozen) = refusal_of(
            router
                .clone()
                .oneshot(draft_request(
                    Method::GET,
                    &format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{}", drafts[0].0),
                    &[],
                    "",
                ))
                .await
                .expect("draft read should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(frozen["state"], "published");
        assert_eq!(frozen["published_etag"], json!(new_etag));

        // The other draft was pinned to the base that is no longer live.
        let (status, body) = refusal_of(
            router
                .clone()
                .oneshot(publish(&drafts[1], &new_etag))
                .await
                .expect("stale publish should complete"),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "policy_draft_base_stale");
        assert_eq!(policy_version_count(&pool).await, versions_before + 1);

        // The publication is a `policy.publish` like `PUT /policy` (issue
        // #425): it recorded the publishing principal in its own commit,
        // after the seed's row, and the refused stale publish recorded
        // nothing.
        let evidence: Vec<(String, String, String)> = pool
            .get()
            .await
            .expect("evidence checkout")
            .query(
                "SELECT action, actor_kind, actor_user_id \
                 FROM greengateway.document_change_evidence ORDER BY security_revision",
                &[],
            )
            .await
            .expect("evidence rows")
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect();
        assert_eq!(
            evidence,
            vec![
                (
                    "policy.publish".to_owned(),
                    "principal".to_owned(),
                    "seed".to_owned()
                ),
                (
                    "policy.publish".to_owned(),
                    "principal".to_owned(),
                    admin_principal().user_id
                ),
            ]
        );
    }

    #[tokio::test]
    async fn identical_if_match_puts_on_two_replicas_produce_exactly_one_winner() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        // Two routers over two separate pools: two replicas of one
        // deployment, sharing only the database.
        let (store_a, _pool_a) = migrated_policy_foundation(&database.dsn).await;
        let (store_b, pool_b) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store_a, "race-init").await;
        let (router_a, _) = cluster_policy_router(store_a.clone());
        let (router_b, _) = cluster_policy_router(store_b.clone());
        // Both replicas read the same current ETag.
        let etag = active.etag.clone();

        let body_a = cluster_policy_json("replica-a-wins");
        let body_b = cluster_policy_json("replica-b-wins");
        let (response_a, response_b) = tokio::join!(
            router_a.clone().oneshot(admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some((&etag, &body_a)),
            )),
            router_b.clone().oneshot(admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some((&etag, &body_b)),
            ))
        );
        let statuses = [
            response_a.expect("replica A PUT").status(),
            response_b.expect("replica B PUT").status(),
        ];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1,
            "exactly one replica's write commits: {statuses:?}"
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::PRECONDITION_FAILED)
                .count(),
            1,
            "the loser sees 412, not a silent overwrite: {statuses:?}"
        );

        // One new document, one new revision, one new outbox row.
        let client = pool_b.get().await.expect("count checkout");
        for (table, expected) in [
            ("policy_documents", 2),
            ("security_outbox", 2),
            ("policy_active", 1),
        ] {
            let row = client
                .query_one(&format!("SELECT count(*) FROM greengateway.{table}"), &[])
                .await
                .expect("count");
            let count: i64 = row.get(0);
            assert_eq!(count, expected, "{table}");
        }
    }

    /// The foundation binds a database to the first deployment that boots
    /// against it and refuses any other at startup.
    #[tokio::test]
    async fn a_database_bound_to_another_deployment_is_refused_at_startup() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let dsn_file = write_dsn_file(&database.dsn);
        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-first".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
        config.database.auto_migrate = true;
        PostgresFoundation::start_if_selected(&config)
            .await
            .expect("the first deployment boots and binds")
            .expect("postgres mode is selected");
        PostgresFoundation::start_if_selected(&config)
            .await
            .expect("the same deployment boots again");

        config.deployment_id = Some("deploy-second".to_owned());
        let refused = PostgresFoundation::start_if_selected(&config)
            .await
            .err()
            .unwrap_or_else(|| panic!("another deployment must be refused"));
        assert!(
            matches!(
                &refused,
                storage::postgres::PostgresFoundationError::DeploymentMismatch { bound }
                    if bound == "deploy-first"
            ),
            "{refused}"
        );
    }

    async fn commit_policy(store: &PostgresPolicyStore, id: &str) -> storage::ActivePolicy {
        let candidate = rbac::Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "id": id,
            "default_action": "deny",
            "roles": {
                "admin": { "permissions": ["data:read", "policy:write"] }
            }
        }))
        .expect("policy should validate");
        let current = PolicyControlPlane::active(store)
            .await
            .expect("active read")
            .expect("active row");
        PolicyControlPlane::commit(
            store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Expected { etag: current.etag },
                candidate: &candidate,
                change: crate::storage::DocumentChange::test_policy("other-replica"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("policy should commit")
    }

    /// A commit that lands after a pass reconciled its resources but
    /// before the watermark is published must move the watermark, not
    /// just the content: the pass re-reads the counter and goes again,
    /// so the published watermark never trails what is installed.
    #[tokio::test]
    async fn a_commit_that_lands_mid_pass_moves_the_watermark_not_just_the_content() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store, "mid-pass-init").await;
        let rbac_state = middleware::rbac::RbacState::new(
            active.policy.clone(),
            Vec::new(),
            false,
            test_audit_log(),
        );
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");
        let runtime = ClusterSecurityRuntime::new(
            store.revision_source(),
            PolicyResource::new(store.clone(), rbac_state.clone()),
        );
        // The background budget, not the 250 ms request deadline: what
        // is under test is which watermark a pass publishes, not how
        // fast a pass runs. This test is the most round-trip-hungry in
        // the module by construction -- the hook commits a whole new
        // policy mid-pass, so the pass re-reads the counter and goes
        // again -- and against a shared authority those round trips
        // alone can spend a request's budget. A
        // `ReconcileDeadlineExceeded` here would say nothing about the
        // watermark. The assertions below are budget-independent: a
        // pass that published the counter it read before the mid-pass
        // commit fails them however long it is given. The 250 ms
        // request deadline keeps its own dedicated guard in
        // `the_background_pass_outlives_the_request_deadline`.
        runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("the first pass compiles the initial revision");

        // One commit moves the counter; the pass that reconciles it is
        // interrupted by a second commit after the content fetch.
        let first = commit_policy(&store, "mid-pass-first").await;
        let hook_store = store.clone();
        runtime.set_before_publish_hook_for_test(Arc::new(move || {
            let store = hook_store.clone();
            Box::pin(async move {
                commit_policy(&store, "mid-pass-second").await;
            })
        }));
        let published = runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("the pass settles");
        let latest = PolicyControlPlane::active(&*store)
            .await
            .expect("active read")
            .expect("active row");
        assert!(latest.security_revision > first.security_revision);
        assert_eq!(
                published, latest.security_revision,
                "the watermark is the counter after the pass settled, not the one read before the mid-pass commit"
            );
        assert_eq!(
            rbac_state.current_policy().id.as_deref(),
            Some("mid-pass-second"),
            "the content installed is the one the published watermark describes"
        );
    }

    #[tokio::test]
    async fn admin_authorization_never_serves_under_a_stale_revision() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, _pool) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store, "stale-init").await;
        let (router, rbac_state) = cluster_policy_router(store.clone());
        // Production startup: the snapshot is keyed to the revision the
        // replica booted against.
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");

        // Sanity: the granted admin principal is authorized while the
        // snapshot is current.
        let response = router
            .clone()
            .oneshot(admin_request(Method::GET, POLICY_ADMIN_ROUTE, None))
            .await
            .expect("GET should complete");
        assert_eq!(response.status(), StatusCode::OK);

        // Another replica commits a revision that revokes every admin
        // permission. The local snapshot is now stale. Without the
        // admin-plane revision gate, this replica would keep
        // authorizing `admin:policy:*` under the old snapshot (an
        // RBAC-exempt route never reaches the data-plane gate) and the
        // PUT below would COMMIT at the authority, holding a correct
        // ETag against a stale authorization. The gate must reconcile
        // first and refuse.
        let revoked = rbac::Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "id": "stale-revoked",
            "default_action": "deny",
            "roles": {
                "nobody": { "permissions": ["data:read"] }
            }
        }))
        .expect("revocation policy should validate");
        let current = PolicyControlPlane::active(&*store)
            .await
            .expect("active read");
        PolicyControlPlane::commit(
            &*store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Expected {
                    etag: current.expect("active").etag,
                },
                candidate: &revoked,
                change: crate::storage::DocumentChange::test_policy("other-replica"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("revocation should commit");

        let fresh = PolicyControlPlane::active(&*store)
            .await
            .expect("active read after revoke")
            .expect("active row");
        let put = router
            .clone()
            .oneshot(admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some((
                    &fresh.etag,
                    &serde_json::to_string(&fresh.policy).expect("policy JSON"),
                )),
            ))
            .await
            .expect("PUT should complete");
        assert_eq!(
            put.status(),
            StatusCode::FORBIDDEN,
            "a revoked principal must not be authorized under the stale snapshot"
        );

        let get = router
            .clone()
            .oneshot(admin_request(Method::GET, POLICY_ADMIN_ROUTE, None))
            .await
            .expect("GET should complete");
        assert_eq!(get.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn revision_gate_reconciles_to_another_replicas_commit_and_fails_closed() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (store, pool) = migrated_policy_foundation(&database.dsn).await;
        let active = initialize(&store, "gate-init").await;

        // A replica boots with the runtime gate: its local snapshot is
        // keyed to the authority's revision at boot.
        let rbac_state = middleware::rbac::RbacState::new(
            active.policy.clone(),
            Vec::new(),
            false,
            test_audit_log(),
        );
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");
        let runtime = ClusterSecurityRuntime::new(
            store.revision_source(),
            PolicyResource::new(store.clone(), rbac_state.clone()),
        );

        // Current: the gate passes and reports the served revision.
        // On the background budget, not the request deadline: what is
        // under test is the revision a pass serves and the content it
        // installs, and both assertions hold or fail regardless of how
        // long the pass is given. Against a shared authority the round
        // trips a healthy pass makes can spend a request's 250 ms on
        // their own, which would fail this test for a reason it does
        // not guard. The request deadline keeps its own dedicated guard
        // in `the_background_pass_outlives_the_request_deadline`.
        let served = runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("gate should pass when current");
        assert_eq!(served, active.security_revision);

        // Another replica commits a new version. The local snapshot is
        // now behind; the next gate call must reconcile it (fetch,
        // validate, install) rather than serve the stale one.
        let mut updated = active.policy.clone();
        updated.id = Some("gate-updated".to_owned());
        PolicyControlPlane::commit(
            &*store,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Expected {
                    etag: active.etag.clone(),
                },
                candidate: &updated,
                change: crate::storage::DocumentChange::test_policy("other-replica"),
                diff_summary: &DIFF,
            },
        )
        .await
        .expect("other replica's commit should win");
        let served = runtime
            .ensure_current_revision_within(security_cluster::RECONCILE_BACKGROUND_DEADLINE)
            .await
            .expect("gate should reconcile");
        assert!(served > active.security_revision);
        assert_eq!(
            rbac_state.current_policy().id.as_deref(),
            Some("gate-updated")
        );

        // A document this binary cannot serve fails closed: the gate
        // refuses, and the compiled snapshot is not touched. The
        // tampered document is valid jsonb but an invalid policy
        // (`default_action` must be allow or deny), and its row still
        // carries the previous document's ETag -- either discrepancy
        // alone is enough; `active()` fails closed on both.
        let client = pool.get().await.expect("tamper checkout");
        client
            .batch_execute(
                r#"
                    UPDATE greengateway.policy_documents
                    SET document = '{"schema_version": "0.1.0", "default_action": "nope"}'::jsonb
                    WHERE version = (SELECT active_version FROM greengateway.policy_active);
                    "#,
            )
            .await
            .expect("tamper should apply");
        // Force a new revision so the gate must consult the tampered
        // document rather than answer from its current snapshot.
        client
            .batch_execute(
                "UPDATE greengateway.security_revision_state \
                     SET last_revision = last_revision + 1",
            )
            .await
            .expect("revision bump");
        drop(client);

        let probe =
            middleware::rbac::SecurityRevisionGate::ensure_current_revision(&*runtime).await;
        assert!(
            probe.is_err(),
            "an invalid authoritative document must fail closed, not serve stale"
        );
        assert_eq!(
            rbac_state.current_policy().id.as_deref(),
            Some("gate-updated"),
            "the last valid snapshot remains installed; nothing regressed"
        );
    }
}
