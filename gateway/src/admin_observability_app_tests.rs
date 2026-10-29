use super::*;

fn test_audit_log_with_broadcast() -> (audit::AuditLog, audit::AuditEventSender) {
    let (sender, _) = tokio::sync::broadcast::channel(16);
    let audit_log = audit::AuditLog::new(
        Arc::new(audit::sink::BroadcastSink::new(sender.clone())) as Arc<dyn audit::AuditSink>
    );

    (audit_log, sender)
}

#[tokio::test]
async fn authenticated_request_persists_principal_directory_row() {
    let jwks_addr = spawn_test_jwks_server().await;
    let principal_db = TempDb::new("principal-directory-full-stack");
    let mut config = test_config(Vec::new());
    config.principal_sqlite_path = Some(principal_db.path.to_string_lossy().into_owned());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let token = signed_token("directory-user", &["member"]);

    let response = authenticated_principal_probe(&router, &token).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eventually(Duration::from_secs(1), || {
        principal_directory_row_count(&principal_db.path) == 1
    });
    let row = principal_directory_row(
        &principal_db.path,
        "directory-user",
        "provider:legacy",
        "bearer",
    );
    assert_eq!(row.email.as_deref(), Some("directory-user@example.test"));
    assert_eq!(row.request_count, 1);
}

#[tokio::test]
async fn unset_principal_sqlite_path_leaves_directory_disabled() {
    let jwks_addr = spawn_test_jwks_server().await;
    let unused_db = TempDb::new("principal-directory-disabled");
    let mut config = test_config(Vec::new());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let token = signed_token("directory-disabled-user", &["member"]);

    let response = authenticated_principal_probe(&router, &token).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !unused_db.path.exists(),
        "unset PRINCIPAL_SQLITE_PATH should not create an unrelated SQLite file"
    );
}

#[tokio::test]
async fn principal_directory_list_filters_paginates_and_counts_anonymous_requests() {
    let principal_db = TempDb::new("principal-directory-list");
    let audit_db = TempDb::new("principal-directory-list-audit");
    create_principal_schema(&principal_db.path);
    create_audit_schema(&audit_db.path);
    seed_principal_directory_rows(&principal_db.path);
    insert_anonymous_observation_event(
        &audit_db.path,
        "anonymous-in-window",
        "2026-01-03T12:00:00Z",
        "/anonymous",
    );
    insert_anonymous_observation_event(
        &audit_db.path,
        "anonymous-outside-window",
        "2025-12-31T23:59:59Z",
        "/anonymous",
    );
    let (router, _policy) =
        principal_admin_router(Some(&principal_db.path), Some(&audit_db.path), None);

    let issuer = query_encode("https://issuer-a.example.test/");
    let first_page = principal_json(
        &router,
        &format!("/v1/admin/principals?issuer={issuer}&limit=2"),
        Some(test_principal(&["principal-reader"])),
    )
    .await;
    assert_eq!(
        principal_subjects(&first_page),
        vec!["alpha".to_owned(), "bravo".to_owned()]
    );
    let cursor = first_page["next_cursor"]
        .as_str()
        .expect("first principal page should include a cursor");
    let second_page = principal_json(
        &router,
        &format!("/v1/admin/principals?issuer={issuer}&limit=2&cursor={cursor}"),
        Some(test_principal(&["principal-reader"])),
    )
    .await;
    assert_eq!(principal_subjects(&second_page), vec!["delta".to_owned()]);
    assert!(second_page["next_cursor"].is_null());

    let service_tokens = principal_json(
        &router,
        "/v1/admin/principals?auth_method=service_token",
        Some(test_principal(&["principal-reader"])),
    )
    .await;
    assert_eq!(
        principal_subjects(&service_tokens),
        vec!["bravo".to_owned()]
    );

    let humans = principal_json(
        &router,
        "/v1/admin/principals?principal_type=human",
        Some(test_principal(&["principal-reader"])),
    )
    .await;
    assert_eq!(
        principal_subjects(&humans),
        vec!["alpha".to_owned(), "charlie".to_owned(), "delta".to_owned()]
    );

    let combined = principal_json(
            &router,
            &format!(
                "/v1/admin/principals?issuer={issuer}&auth_method=bearer&principal_type=human&last_seen_after=2026-01-01T12:00:00Z&last_seen_before=2026-01-04T12:00:00Z"
            ),
            Some(test_principal(&["principal-reader"])),
        )
        .await;
    assert_eq!(principal_subjects(&combined), vec!["alpha".to_owned()]);
    assert_eq!(combined["anonymous_request_count"], json!(1));
}

#[tokio::test]
async fn principal_directory_admin_requires_principals_read_permission() {
    let principal_db = TempDb::new("principal-directory-authz");
    create_principal_schema(&principal_db.path);
    insert_principal_directory_row(
        &principal_db.path,
        PrincipalDirectorySeed {
            subject: "alpha",
            issuer: "",
            auth_method: "bearer",
            email: None,
            org_id: None,
            first_seen: "2026-01-01T00:00:00Z",
            last_seen: "2026-01-01T00:00:00Z",
            request_count: 1,
        },
    );
    let (router, _policy) = principal_admin_router(Some(&principal_db.path), None, None);

    for uri in [
        "/v1/admin/principals",
        "/v1/admin/principal?subject=alpha&issuer=&auth_method=bearer",
    ] {
        let unauthenticated = router
            .clone()
            .oneshot(principal_admin_request(uri, None))
            .await
            .expect("principal admin request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let forbidden_response = router
            .clone()
            .oneshot(principal_admin_request(
                uri,
                Some(test_principal(&["reader"])),
            ))
            .await
            .expect("principal admin request should complete");
        assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_string(forbidden_response).await,
            r#"{"error":"forbidden"}"#
        );
    }
}

#[tokio::test]
async fn principal_directory_admin_reports_not_configured() {
    let (router, _policy) = principal_admin_router(None, None, None);

    for uri in [
        "/v1/admin/principals",
        "/v1/admin/principal?subject=missing&issuer=&auth_method=bearer",
    ] {
        let response = router
            .clone()
            .oneshot(principal_admin_request(
                uri,
                Some(test_principal(&["principal-reader"])),
            ))
            .await
            .expect("principal admin request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"principal directory requires PRINCIPAL_SQLITE_PATH to be configured"}"#
        );
    }
}

#[tokio::test]
async fn principal_delegated_token_revocation_needs_principals_write_and_a_well_formed_principal() {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(&principal_policy_document_string());
    let recorder = PrometheusBuilder::new().build_recorder();
    // No principal directory: the purge does not need one.
    let router = app(
        principal_admin_config(None, None, None, &policy),
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build");
    let request = |principal: Option<auth::Principal>, body: &str| {
        traffic_admin_json_request(
            Method::POST,
            PRINCIPAL_DELEGATED_TOKENS_REVOKE_ADMIN_ROUTE,
            principal,
            Some(body.to_owned()),
        )
    };
    let body = json!({ "issuer": "https://idp.example.test/", "subject": "alice" }).to_string();

    let unauthenticated = router
        .clone()
        .oneshot(request(None, &body))
        .await
        .expect("revocation request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    let read_only = router
        .clone()
        .oneshot(request(Some(test_principal(&["principal-reader"])), &body))
        .await
        .expect("revocation request should complete");
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

    let purged = router
        .clone()
        .oneshot(request(Some(test_principal(&["principal-writer"])), &body))
        .await
        .expect("revocation request should complete");
    assert_eq!(purged.status(), StatusCode::OK);
    assert_eq!(purged.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(json_body(purged).await, json!({ "purged_entries": 0 }));
    // An operator's purge is audited even when it finds nothing, naming the
    // operator and the canonical principal.
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::CONNECTION_DELEGATED_TOKEN_PURGE)
    });
    let purge = capture
        .events()
        .into_iter()
        .find(|event| event.event_type == audit::event::CONNECTION_DELEGATED_TOKEN_PURGE)
        .expect("the purge is audited");
    assert_eq!(
        purge.actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("user-123")
    );
    assert_eq!(purge.payload["trigger"], json!("operator"));
    assert_eq!(
        purge.payload["principal"],
        json!({ "issuer": "https://idp.example.test", "subject": "alice" })
    );
    assert_eq!(purge.payload["purged_entries"], json!(0));
    // Standalone mode has no other replica to tell.
    assert_eq!(purge.payload["replication"], json!(null));

    for malformed in [
        "not json".to_owned(),
        json!({ "issuer": "https://idp.example.test" }).to_string(),
        json!({ "issuer": "https://idp.example.test", "subject": "" }).to_string(),
        json!({ "issuer": " / ", "subject": "alice" }).to_string(),
        json!({ "issuer": "https://idp.example.test", "subject": "alice", "email": "a@b" })
            .to_string(),
        json!({ "issuer": "https://idp.example.test", "subject": "a".repeat(4097) }).to_string(),
    ] {
        let refused = router
            .clone()
            .oneshot(request(
                Some(test_principal(&["principal-writer"])),
                &malformed,
            ))
            .await
            .expect("revocation request should complete");
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST, "{malformed}");
    }
}

#[tokio::test]
async fn principal_delegated_token_revocation_is_refused_where_the_purge_cannot_reach_every_replica(
) {
    let policy = parse_policy_body(&Bytes::from(principal_policy_document_string()))
        .expect("principal policy should parse");
    let state = PrincipalAdminState {
        directory: auth::PrincipalDirectory::disabled(),
        audit_query_store: None,
        discovery_store: None,
        rbac_state: Some(middleware::rbac::RbacState::new(
            policy,
            Vec::new(),
            false,
            test_audit_log(),
        )),
        // What a cluster-mode build with no purge record builds.
        delegated_tokens: None,
        client_ip_policy: client_ip::ClientIpPolicy::from_config(&test_config(Vec::new())),
        max_body_size: 1_024,
    };
    let response = principal_delegated_tokens_revoke_endpoint(
        State(state),
        traffic_admin_json_request(
            Method::POST,
            PRINCIPAL_DELEGATED_TOKENS_REVOKE_ADMIN_ROUTE,
            Some(test_principal(&["principal-writer"])),
            Some(json!({ "issuer": "https://idp.example.test", "subject": "alice" }).to_string()),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(body_string(response)
        .await
        .contains("cannot record the purge for the other replicas"));
}

/// A purge ledger that answers as `answer` says: what the endpoint sees of
/// cluster mode's record, without a roster or a database behind it.
struct ScriptedPurgeLedger {
    answer: Result<i64, connections::token_exchange::PurgeNotRecorded>,
}

#[async_trait::async_trait]
impl connections::token_exchange::DelegatedTokenPurgeLedger for ScriptedPurgeLedger {
    async fn record(
        &self,
        _purge_key: &str,
        _origin: &connections::token_exchange::DelegatedTokenPurgeTrigger,
    ) -> Result<i64, connections::token_exchange::PurgeNotRecorded> {
        self.answer.clone()
    }
}

/// Cluster mode's contract (issue #441): `200` names the shared security
/// revision every replica applies the purge at; a purge that could not be
/// recorded for the other replicas is `409` while a live replica predates
/// the record and `503` when the authority did not answer, each saying how
/// many entries the answering replica purged anyway.
#[tokio::test]
async fn principal_delegated_token_revocation_in_cluster_mode_reports_the_record() {
    use connections::token_exchange::PurgeNotRecorded;

    let policy = parse_policy_body(&Bytes::from(principal_policy_document_string()))
        .expect("principal policy should parse");
    let state_with = |answer: Result<i64, PurgeNotRecorded>| {
        let egress = egress::EgressConfig::default();
        let client =
            Arc::new(egress::EgressClient::new(egress.clone()).expect("egress client builds"));
        PrincipalAdminState {
            directory: auth::PrincipalDirectory::disabled(),
            audit_query_store: None,
            discovery_store: None,
            rbac_state: Some(middleware::rbac::RbacState::new(
                policy.clone(),
                Vec::new(),
                false,
                test_audit_log(),
            )),
            delegated_tokens: Some(
                connections::http::ConnectionHttpRuntime::new(
                    connections::control_plane::ConnectionControlPlane::from_config(&test_config(
                        Vec::new(),
                    ))
                    .expect("control plane builds"),
                    egress,
                    client,
                )
                .with_delegated_token_purge_ledger(
                    Arc::new(ScriptedPurgeLedger { answer }),
                    "deploy-endpoint",
                ),
            ),
            client_ip_policy: client_ip::ClientIpPolicy::from_config(&test_config(Vec::new())),
            max_body_size: 1_024,
        }
    };
    let purge = |state: PrincipalAdminState| {
        principal_delegated_tokens_revoke_endpoint(
            State(state),
            traffic_admin_json_request(
                Method::POST,
                PRINCIPAL_DELEGATED_TOKENS_REVOKE_ADMIN_ROUTE,
                Some(test_principal(&["principal-writer"])),
                Some(
                    json!({ "issuer": "https://idp.example.test", "subject": "alice" }).to_string(),
                ),
            ),
        )
    };

    let recorded = purge(state_with(Ok(42))).await;
    assert_eq!(recorded.status(), StatusCode::OK);
    assert_eq!(recorded.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        json_body(recorded).await,
        json!({ "purged_entries": 0, "security_revision": 42 })
    );

    let lacking = purge(state_with(Err(PurgeNotRecorded::Refused {
        reason: "capability_not_advertised",
        detail: "a live member does not advertise delegated_token_purges".to_owned(),
        members_lack_capability: true,
    })))
    .await;
    assert_eq!(lacking.status(), StatusCode::CONFLICT);
    assert_eq!(lacking.headers()[header::CACHE_CONTROL], "no-store");
    let body = json_body(lacking).await;
    assert_eq!(body["reason"], json!("capability_not_advertised"));
    assert_eq!(body["purged_entries"], json!(0));
    assert!(body["error"]
        .as_str()
        .is_some_and(|error| error.contains("not recorded for the other replicas")));

    let roster = purge(state_with(Err(PurgeNotRecorded::Refused {
        reason: "roster_unavailable",
        detail: "cluster membership could not be read".to_owned(),
        members_lack_capability: false,
    })))
    .await;
    assert_eq!(roster.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(roster).await["reason"],
        json!("roster_unavailable")
    );

    let unavailable = purge(state_with(Err(PurgeNotRecorded::Unavailable))).await;
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(unavailable).await["reason"],
        json!("purge_not_recorded")
    );
}

#[tokio::test]
async fn principal_directory_detail_returns_404_for_missing_composite_key() {
    let principal_db = TempDb::new("principal-directory-detail-missing");
    create_principal_schema(&principal_db.path);
    let (router, _policy) = principal_admin_router(Some(&principal_db.path), None, None);

    let response = router
        .oneshot(principal_admin_request(
            "/v1/admin/principal?subject=missing&issuer=&auth_method=bearer",
            Some(test_principal(&["principal-reader"])),
        ))
        .await
        .expect("principal detail request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"principal was not found"}"#
    );
}

#[tokio::test]
async fn principal_directory_detail_enriches_authenticated_request_from_audit() {
    let jwks_addr = spawn_test_jwks_server().await;
    let principal_db = TempDb::new("principal-directory-detail-full-stack");
    let audit_db = TempDb::new("principal-directory-detail-audit");
    let policy = TempPolicyFile::new(&principal_full_stack_policy_document_string());
    let mut config = test_config(Vec::new());
    config.principal_sqlite_path = Some(principal_db.path.to_string_lossy().into_owned());
    config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push("/v1/admin/principals".to_owned());
    config
        .rbac_exempt_paths
        .push("/v1/admin/principal".to_owned());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let (audit_log, audit_event_sender) = audit_log_with_sqlite_and_broadcast(&audit_db.path);
    let router =
        app(config, recorder.handle(), audit_log, audit_event_sender).expect("app should build");
    let user_token = signed_token("directory-detail-user", &["member"]);
    let admin_token = signed_token("directory-admin", &["principal-reader"]);

    let response = authenticated_principal_probe(&router, &user_token).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eventually(Duration::from_secs(1), || {
        principal_directory_row_count(&principal_db.path) == 1
    });

    let detail_uri = "/v1/admin/principal?subject=directory-detail-user&issuer=provider%3Alegacy&auth_method=bearer";
    let body = wait_for_principal_detail_json(&router, detail_uri, &admin_token, |body| {
        principal_detail_endpoint_paths(body)
            .contains(&("GET".to_owned(), "/__test/principal".to_owned()))
            && principal_detail_rule_ids(body).contains(&"allow-probe".to_owned())
    })
    .await;

    assert_eq!(body["principal"]["subject"], json!("directory-detail-user"));
    assert_eq!(body["principal"]["auth_method"], json!("bearer"));
    assert_eq!(body["tools_called"], json!([]));
}

#[tokio::test]
async fn principal_directory_detail_filters_principal_endpoint_signal_history_exactly() {
    let principal_db = TempDb::new("principal-directory-signals");
    let discovery_db = TempDb::new("principal-directory-signals-discovery");
    create_principal_schema(&principal_db.path);
    create_discovery_schema(&discovery_db.path);
    for (subject, issuer, auth_method) in [
        ("bob", "https://issuer-a.example", "bearer"),
        ("bob", "https://issuer-b.example", "bearer"),
        ("bob", "https://issuer-a.example", "cookie"),
        ("alice bob", "https://issuer-a.example", "bearer"),
        ("charlie", "https://issuer-a.example", "bearer"),
    ] {
        insert_principal_directory_row(
            &principal_db.path,
            PrincipalDirectorySeed {
                subject,
                issuer,
                auth_method,
                email: None,
                org_id: None,
                first_seen: "2026-01-01T00:00:00Z",
                last_seen: "2026-01-01T00:00:00Z",
                request_count: 1,
            },
        );
    }
    insert_principal_endpoint_signal(
        &discovery_db.path,
        PrincipalEndpointSignalSeed {
            id: "sig-bob",
            method: "POST",
            endpoint_template: "/principal-pairs/{id}",
            principal: "bob",
            issuer: Some("https://issuer-a.example"),
            auth_method: "bearer_token",
            created_at: "2026-01-02T00:00:00Z",
        },
    );
    insert_principal_endpoint_signal(
        &discovery_db.path,
        PrincipalEndpointSignalSeed {
            id: "sig-bob-other-issuer",
            method: "POST",
            endpoint_template: "/principal-pairs/{id}",
            principal: "bob",
            issuer: Some("https://issuer-b.example"),
            auth_method: "bearer_token",
            created_at: "2026-01-03T00:00:00Z",
        },
    );
    insert_principal_endpoint_signal(
        &discovery_db.path,
        PrincipalEndpointSignalSeed {
            id: "sig-bob-other-auth",
            method: "POST",
            endpoint_template: "/principal-pairs/{id}",
            principal: "bob",
            issuer: Some("https://issuer-a.example"),
            auth_method: "session_cookie",
            created_at: "2026-01-04T00:00:00Z",
        },
    );
    insert_principal_endpoint_signal(
        &discovery_db.path,
        PrincipalEndpointSignalSeed {
            id: "sig-alice-bob",
            method: "POST",
            endpoint_template: "/principal-pairs/{id}",
            principal: "alice bob",
            issuer: Some("https://issuer-a.example"),
            auth_method: "bearer_token",
            created_at: "2026-01-05T00:00:00Z",
        },
    );
    let (router, _policy) =
        principal_admin_router(Some(&principal_db.path), None, Some(&discovery_db.path));

    let bob = principal_json(
        &router,
        "/v1/admin/principal?subject=bob&issuer=https%3A%2F%2Fissuer-a.example&auth_method=bearer",
        Some(test_principal(&["principal-reader"])),
    )
    .await;
    assert_eq!(
        principal_detail_signal_ids(&bob),
        vec!["sig-bob".to_owned()]
    );

    let charlie = principal_json(
            &router,
            "/v1/admin/principal?subject=charlie&issuer=https%3A%2F%2Fissuer-a.example&auth_method=bearer",
            Some(test_principal(&["principal-reader"])),
        )
        .await;
    assert!(principal_detail_signal_ids(&charlie).is_empty());
}

#[tokio::test]
async fn principal_directory_list_counts_failed_auth_without_creating_principal_row() {
    let jwks_addr = spawn_test_jwks_server().await;
    let principal_db = TempDb::new("principal-directory-anonymous");
    let audit_db = TempDb::new("principal-directory-anonymous-audit");
    let mut config = test_config(Vec::new());
    config.principal_sqlite_path = Some(principal_db.path.to_string_lossy().into_owned());
    config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let (audit_log, audit_event_sender) = audit_log_with_sqlite_and_broadcast(&audit_db.path);
    let router =
        app(config, recorder.handle(), audit_log, audit_event_sender).expect("app should build");
    let window_start = (OffsetDateTime::now_utc() - time::Duration::seconds(10))
        .format(&Rfc3339)
        .expect("window start should format");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .body(Body::empty())
                .expect("anonymous request should build"),
        )
        .await
        .expect("anonymous request should complete");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eventually(Duration::from_secs(1), || {
        anonymous_observation_count(&audit_db.path) == 1
    });
    assert_eq!(principal_directory_row_count(&principal_db.path), 0);

    let window_end = (OffsetDateTime::now_utc() + time::Duration::seconds(10))
        .format(&Rfc3339)
        .expect("window end should format");
    let (query_router, _policy) =
        principal_admin_router(Some(&principal_db.path), Some(&audit_db.path), None);
    let body = principal_json(
        &query_router,
        &format!(
            "/v1/admin/principals?last_seen_after={window_start}&last_seen_before={window_end}"
        ),
        Some(test_principal(&["principal-reader"])),
    )
    .await;

    assert_eq!(body["principals"], json!([]));
    assert_eq!(body["anonymous_request_count"], json!(1));
}

#[tokio::test]
async fn audit_query_without_principal_returns_unauthorized() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        audit_query_config(None),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(audit_query_request(AUDIT_ADMIN_ROUTE, None))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
}

#[tokio::test]
async fn audit_query_non_admin_principal_returns_forbidden_without_store_leak() {
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        audit_query_config_with_policy(None, &policy),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(audit_query_request(
        AUDIT_ADMIN_ROUTE,
        Some(test_principal(&["reader"])),
    ))
    .await
    .expect("request should complete");

    let body = body_string(response).await;
    assert_eq!(body, r#"{"error":"forbidden"}"#);
    assert!(!body.contains("audit query store"));
}

#[tokio::test]
async fn audit_events_stream_without_principal_returns_unauthorized() {
    let (router, _, _policy) = audit_events_router();

    let response = router
        .oneshot(audit_query_request(AUDIT_EVENTS_STREAM_ROUTE, None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
}

#[tokio::test]
async fn audit_events_stream_non_admin_principal_returns_forbidden() {
    let (router, _, _policy) = audit_events_router();

    let response = router
        .oneshot(audit_stream_request(
            AUDIT_EVENTS_STREAM_ROUTE,
            test_principal(&["reader"]),
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn status_without_principal_returns_unauthorized() {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let router = status_router(config, Instant::now());

    let response = router
        .oneshot(audit_query_request(STATUS_ADMIN_ROUTE, None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
}

#[tokio::test]
async fn status_non_admin_principal_returns_forbidden() {
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let config = status_config_with_policy(config, &policy);
    let router = status_router(config, Instant::now());

    let response = router
        .oneshot(audit_query_request(
            STATUS_ADMIN_ROUTE,
            Some(test_principal(&["reader"])),
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn audit_and_status_principals_without_policy_return_not_configured() {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let router = status_router(config, Instant::now());

    for (uri, expected_body) in [
        (
            AUDIT_ADMIN_ROUTE,
            r#"{"error":"audit API requires POLICY_FILE to be configured"}"#,
        ),
        (
            AUDIT_EVENTS_STREAM_ROUTE,
            r#"{"error":"audit API requires POLICY_FILE to be configured"}"#,
        ),
        (
            STATUS_ADMIN_ROUTE,
            r#"{"error":"status API requires POLICY_FILE to be configured"}"#,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_string(response).await, expected_body);
    }
}

#[tokio::test]
async fn status_admin_response_reflects_running_config_values() {
    let sqlite_db = TempDb::new("status-sqlite");
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "id": "status-policy",
                "default_action": "allow",
                "roles": {
                    "admin": { "permissions": ["*"] }
                }
            }"#,
    );
    let mut rich_config = test_config(vec!["https://example.test", "https://ops.example.test"]);
    rich_config.listen_addr = "127.0.0.1:18181"
        .parse()
        .expect("listen address should parse");
    rich_config.audit_log_file = Some("audit-a.jsonl".to_owned());
    rich_config.audit_sqlite_path = Some(sqlite_db.path.to_string_lossy().into_owned());
    rich_config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    rich_config.rate_limit_read_rps = 17.5;
    rich_config.rate_limit_read_burst = 31;
    rich_config.rate_limit_write_rps = 4.25;
    rich_config.rate_limit_write_burst = 9;
    rich_config.trust_proxy_headers = true;
    rich_config.trusted_proxy_cidrs = vec!["10.0.0.0/8"
        .parse()
        .expect("trusted proxy CIDR should parse")];
    rich_config.auth_enabled = true;
    rich_config
        .auth_exempt_paths
        .push(STATUS_ADMIN_ROUTE.to_owned());
    rich_config.csrf_enabled = false;
    rich_config.egress_allowed_hosts = vec![
        "api.example.test".to_owned(),
        "tiles.example.test".to_owned(),
    ];
    rich_config.egress_nat64_prefixes = vec!["2001:db8:122:344::/64"
        .parse()
        .expect("test NAT64 prefix should parse")];
    rich_config.egress_deny_private_ips = false;

    let rich = status_json(
        status_router(rich_config, Instant::now() - Duration::from_secs(42)),
        Some(test_principal(&["admin"])),
    )
    .await;

    assert_eq!(rich["version"], env!("CARGO_PKG_VERSION"));
    assert!(rich["uptime_seconds"].as_u64().unwrap_or_default() >= 42);
    assert_eq!(rich["listen_addr"], "127.0.0.1:18181");
    assert_eq!(rich["auth_enabled"], true);
    assert_eq!(rich["rbac"]["policy_loaded"], true);
    assert_eq!(rich["rbac"]["policy_id"], "status-policy");
    assert_eq!(rich["audit_sinks"]["stdout"], true);
    assert_eq!(rich["audit_sinks"]["file"], true);
    assert_eq!(rich["audit_sinks"]["sqlite"], true);
    assert_eq!(rich["audit_sinks"]["broadcast"], true);
    assert_eq!(
        rich["rate_limits"]["read"]["requests_per_second"].as_f64(),
        Some(17.5)
    );
    assert_eq!(rich["rate_limits"]["read"]["burst"], 31);
    assert_eq!(
        rich["rate_limits"]["write"]["requests_per_second"].as_f64(),
        Some(4.25)
    );
    assert_eq!(rich["rate_limits"]["write"]["burst"], 9);
    assert_eq!(
        rich["cors_allow_origins"],
        json!(["https://example.test", "https://ops.example.test"])
    );
    assert_eq!(rich["trust_proxy_headers"], true);
    assert_eq!(rich["csrf_enabled"], false);
    assert_eq!(rich["egress"]["allowed_hosts_count"], 2);
    assert_eq!(rich["egress"]["nat64_prefixes_count"], 1);
    assert_eq!(rich["egress"]["deny_private_ips"], false);

    let minimal_policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "id": "status-minimal-policy",
                "default_action": "deny",
                "roles": {
                    "status-reader": { "permissions": ["admin:status:read"] }
                }
            }"#,
    );
    let mut minimal_config = test_config(Vec::new());
    minimal_config.listen_addr = "127.0.0.1:18182"
        .parse()
        .expect("listen address should parse");
    minimal_config.auth_enabled = false;
    minimal_config.rate_limit_read_rps = 61.25;
    minimal_config.rate_limit_read_burst = 77;
    minimal_config.rate_limit_write_rps = 8.5;
    minimal_config.rate_limit_write_burst = 12;
    let minimal_config = status_config_with_policy(minimal_config, &minimal_policy);

    let minimal = status_json(
        status_router(minimal_config, Instant::now() - Duration::from_secs(5)),
        Some(test_principal(&["status-reader"])),
    )
    .await;

    assert_eq!(minimal["listen_addr"], "127.0.0.1:18182");
    assert_eq!(minimal["auth_enabled"], false);
    assert_eq!(minimal["rbac"]["policy_loaded"], true);
    assert_eq!(minimal["rbac"]["policy_id"], "status-minimal-policy");
    assert_eq!(minimal["audit_sinks"]["file"], false);
    assert_eq!(minimal["audit_sinks"]["sqlite"], false);
    assert_eq!(
        minimal["rate_limits"]["read"]["requests_per_second"].as_f64(),
        Some(61.25)
    );
    assert_eq!(minimal["rate_limits"]["read"]["burst"], 77);
    assert_eq!(
        minimal["rate_limits"]["write"]["requests_per_second"].as_f64(),
        Some(8.5)
    );
    assert_eq!(minimal["rate_limits"]["write"]["burst"], 12);
    assert_eq!(minimal["cors_allow_origins"], json!([]));
    assert_eq!(minimal["egress"]["allowed_hosts_count"], 0);
    assert_eq!(minimal["egress"]["nat64_prefixes_count"], 0);
    assert_eq!(minimal["egress"]["deny_private_ips"], true);
}

#[tokio::test]
async fn status_reports_effective_egress_allowlist_count() {
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.auth_exempt_paths.push(STATUS_ADMIN_ROUTE.to_owned());
    config.egress_allowed_hosts = vec!["api.example.test".to_owned()];
    config.upstream_url = Some("https://upstream.example.test/base".to_owned());
    let config = status_config_with_policy(config, &policy);
    let router = status_router(config, Instant::now());

    let status = status_json(router, Some(test_principal(&["status-reader"]))).await;

    assert_eq!(status["egress"]["allowed_hosts_count"], 2);
}

#[tokio::test]
async fn schema_coverage_reports_undocumented_endpoints_and_unused_operations() {
    let discovery_db = TempDb::new("schema-coverage");
    create_discovery_schema(&discovery_db.path);
    seed_discovery_endpoint(&discovery_db.path, "GET", "/users/{id}");
    seed_discovery_endpoint(&discovery_db.path, "POST", "/users");
    seed_discovery_endpoint(&discovery_db.path, "GET", "/internal/health");
    seed_discovery_endpoint(&discovery_db.path, "GET", "/reports/{id}/summary/details");
    for (host, origin) in [
        ("api.example.test", "https://api.internal"),
        ("admin.example.test", "https://admin.internal"),
    ] {
        insert_discovery_routing_context(
            &discovery_db.path,
            "GET",
            "/internal/health",
            host,
            "/internal",
            origin,
            1,
            0,
        );
    }
    let spec = TempSpecFile::new(
        "coverage",
        r#"
openapi: 3.0.3
info:
  title: Coverage API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      operationId: getUser
      summary: Fetch a user
    patch:
      operationId: updateUser
      summary: Update a user
  /users:
    post:
      operationId: createUser
  /reports/{reportId}/summary:
    get:
      operationId: reportSummary
"#,
    );
    let policy = TempPolicyFile::new(&schema_policy_document());
    let router = schema_coverage_router(Some(&spec), Some(&discovery_db), &policy);

    let response = router
        .oneshot(audit_query_request(
            SCHEMA_COVERAGE_ADMIN_ROUTE,
            Some(test_principal(&["schema-reader"])),
        ))
        .await
        .expect("schema coverage request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["spec_configured"], true);
    assert_eq!(body["discovery_configured"], true);
    assert_eq!(
        body["undocumented_endpoints"],
        json!([
            {
                "method": "GET",
                "endpoint_template": "/internal/health"
            },
            {
                "method": "GET",
                "endpoint_template": "/reports/{id}/summary/details"
            }
        ])
    );
    assert_eq!(
        body["unused_operations"],
        json!([
            {
                "method": "GET",
                "path_template": "/reports/{reportId}/summary",
                "operation_id": "reportSummary",
                "source": spec.path.to_string_lossy()
            },
            {
                "method": "PATCH",
                "path_template": "/users/{userId}",
                "operation_id": "updateUser",
                "summary": "Update a user",
                "source": spec.path.to_string_lossy()
            }
        ])
    );
}

#[tokio::test]
async fn schema_coverage_without_spec_returns_not_found() {
    let discovery_db = TempDb::new("schema-no-spec");
    seed_discovery_endpoint(&discovery_db.path, "GET", "/users/{id}");
    let policy = TempPolicyFile::new(&schema_policy_document());
    let router = schema_coverage_router(None, Some(&discovery_db), &policy);

    let response = router
        .oneshot(audit_query_request(
            SCHEMA_COVERAGE_ADMIN_ROUTE,
            Some(test_principal(&["schema-reader"])),
        ))
        .await
        .expect("schema coverage request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"schema coverage requires OPENAPI_SPEC_PATH or UPSTREAM_ROUTES[].openapi_spec_path to be configured","spec_configured":false}"#
    );
}

#[tokio::test]
async fn schema_coverage_without_discovery_store_returns_service_unavailable() {
    let spec = TempSpecFile::new(
        "no-discovery",
        r#"
openapi: 3.0.3
info:
  title: Coverage API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      operationId: getUser
"#,
    );
    let policy = TempPolicyFile::new(&schema_policy_document());
    let router = schema_coverage_router(Some(&spec), None, &policy);

    let response = router
        .oneshot(audit_query_request(
            SCHEMA_COVERAGE_ADMIN_ROUTE,
            Some(test_principal(&["schema-reader"])),
        ))
        .await
        .expect("schema coverage request should complete");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"schema coverage requires DISCOVERY_SQLITE_PATH to be configured","discovery_configured":false}"#
    );
}

#[tokio::test]
async fn schema_coverage_requires_schema_read_permission() {
    let discovery_db = TempDb::new("schema-authz");
    seed_discovery_endpoint(&discovery_db.path, "GET", "/users/{id}");
    let spec = TempSpecFile::new(
        "authz",
        r#"
openapi: 3.0.3
info:
  title: Coverage API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      operationId: getUser
"#,
    );
    let policy = TempPolicyFile::new(&schema_policy_document());
    let router = schema_coverage_router(Some(&spec), Some(&discovery_db), &policy);

    let unauthenticated = router
        .clone()
        .oneshot(audit_query_request(SCHEMA_COVERAGE_ADMIN_ROUTE, None))
        .await
        .expect("unauthenticated request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_string(unauthenticated).await,
        r#"{"error":"unauthorized"}"#
    );

    let forbidden_response = router
        .oneshot(audit_query_request(
            SCHEMA_COVERAGE_ADMIN_ROUTE,
            Some(test_principal(&["reader"])),
        ))
        .await
        .expect("forbidden request should complete");
    assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_string(forbidden_response).await,
        r#"{"error":"forbidden"}"#
    );
}

#[tokio::test]
async fn schema_endpoint_denials_emit_one_audit_event_with_required_permission() {
    let policy = TempPolicyFile::new(&schema_policy_document());
    for route in [SCHEMA_COVERAGE_ADMIN_ROUTE, SCHEMA_INFERRED_ADMIN_ROUTE] {
        let capture = audit::sink::tests::CaptureSink::new();
        let log = audit::AuditLog::new(Arc::new(capture.clone()));
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.rbac_exempt_paths.push(route.to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            log.clone(),
            test_audit_event_sender(),
        )
        .expect("app should build");
        let response = router
            .oneshot(audit_query_request(
                route,
                Some(test_principal(&["reader"])),
            ))
            .await
            .expect("schema denial should complete");
        assert_admin_denial(&response, &log, &capture, ADMIN_SCHEMA_READ_PERMISSION).await;
    }
}

#[test]
fn openapi_overlay_secret_denial_preserves_required_permission() {
    let response = openapi_overlay_operation_error_response(
        connections::openapi::OpenApiOverlayOperationError::SecretsWriteRequired,
        "overlay update",
    );
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<middleware::decision::PolicyDecision>()
        .expect("permission denial should preserve its decision");
    assert_eq!(
        decision.permission.as_deref(),
        Some(ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION)
    );
}

#[tokio::test]
async fn schema_inference_returns_inferred_payload_shape_schema() {
    let discovery_db = TempDb::new("schema-inferred");
    seed_payload_shape_samples(
        &discovery_db.path,
        "POST",
        "/users/{id}",
        &[
            json!({
                "query_params": [
                    { "name": "page", "redacted": false, "value_type": "number" },
                    { "name": "search", "redacted": false, "value_type": "string" }
                ],
                "json_body": {
                    "top_level_keys": [
                        { "name": "display_name", "redacted": false },
                        { "name_hash": "sha256:redacted-body-key", "redacted": true }
                    ]
                }
            }),
            json!({
                "query_params": [
                    { "name": "page", "redacted": false, "value_type": "number" }
                ],
                "json_body": {
                    "top_level_keys": [
                        { "name": "display_name", "redacted": false }
                    ]
                }
            }),
        ],
    );
    let policy = TempPolicyFile::new(&schema_policy_document());
    let router = schema_inference_router(Some(&discovery_db), true, &policy);
    let template = query_encode("/users/{id}");

    let response = router
        .oneshot(audit_query_request(
            &format!("/v1/admin/schema/inferred?method=POST&endpoint_template={template}"),
            Some(test_principal(&["schema-reader"])),
        ))
        .await
        .expect("schema inference request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["method"], json!("POST"));
    assert_eq!(body["endpoint_template"], json!("/users/{id}"));
    assert_eq!(body["sample_count"], json!(2));
    assert_eq!(body["required_threshold"], json!(0.95));
    assert_eq!(
        body["query_params"],
        json!([
            {
                "name": "page",
                "redacted": false,
                "present_count": 2,
                "frequency": 1.0,
                "required": true,
                "value_types": [
                    { "value_type": "number", "count": 2 }
                ]
            },
            {
                "name": "search",
                "redacted": false,
                "present_count": 1,
                "frequency": 0.5,
                "required": false,
                "value_types": [
                    { "value_type": "string", "count": 1 }
                ]
            }
        ])
    );
    assert_eq!(
        body["json_body_keys"],
        json!([
            {
                "name": "display_name",
                "redacted": false,
                "present_count": 2,
                "frequency": 1.0,
                "required": true
            },
            {
                "name_hash": "sha256:redacted-body-key",
                "redacted": true,
                "present_count": 1,
                "frequency": 0.5,
                "required": false
            }
        ])
    );
}

#[tokio::test]
async fn schema_inference_distinguishes_payload_capture_disabled_from_no_samples() {
    let discovery_db = TempDb::new("schema-inferred-empty");
    let policy = TempPolicyFile::new(&schema_policy_document());
    let configured_router = schema_inference_router(Some(&discovery_db), true, &policy);
    let template = query_encode("/users/{id}");

    let no_samples = configured_router
        .oneshot(audit_query_request(
            &format!("/v1/admin/schema/inferred?method=POST&endpoint_template={template}"),
            Some(test_principal(&["schema-reader"])),
        ))
        .await
        .expect("schema inference no-samples request should complete");

    assert_eq!(no_samples.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(no_samples).await,
        r#"{"error":"inferred schema has no captured payload samples for method and endpoint_template","schema_inferred":false}"#
    );

    let disabled_router = schema_inference_router(Some(&discovery_db), false, &policy);
    let disabled = disabled_router
        .oneshot(audit_query_request(
            &format!("/v1/admin/schema/inferred?method=POST&endpoint_template={template}"),
            Some(test_principal(&["schema-reader"])),
        ))
        .await
        .expect("schema inference disabled request should complete");

    assert_eq!(disabled.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(disabled).await,
        r#"{"error":"inferred schema requires PAYLOAD_CAPTURE_ENABLED=true","payload_capture_configured":false}"#
    );
}

#[tokio::test]
async fn schema_inference_requires_schema_read_permission() {
    let discovery_db = TempDb::new("schema-inferred-authz");
    seed_payload_shape_samples(
        &discovery_db.path,
        "GET",
        "/users",
        &[json!({
            "query_params": [
                { "name": "page", "redacted": false, "value_type": "number" }
            ]
        })],
    );
    let policy = TempPolicyFile::new(&schema_policy_document());
    let router = schema_inference_router(Some(&discovery_db), true, &policy);

    let unauthenticated = router
        .clone()
        .oneshot(audit_query_request(
            "/v1/admin/schema/inferred?method=GET&endpoint_template=%2Fusers",
            None,
        ))
        .await
        .expect("unauthenticated schema inference request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_string(unauthenticated).await,
        r#"{"error":"unauthorized"}"#
    );

    let forbidden_response = router
        .oneshot(audit_query_request(
            "/v1/admin/schema/inferred?method=GET&endpoint_template=%2Fusers",
            Some(test_principal(&["reader"])),
        ))
        .await
        .expect("forbidden schema inference request should complete");
    assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_string(forbidden_response).await,
        r#"{"error":"forbidden"}"#
    );
}

#[test]
fn missing_openapi_spec_file_returns_actionable_startup_error() {
    let mut config = test_config(Vec::new());
    config.openapi_spec_path =
        Some(std::env::temp_dir().join(format!("missing-openapi-{}.yaml", uuid::Uuid::new_v4())));
    let recorder = PrometheusBuilder::new().build_recorder();

    let error = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect_err("app startup should reject missing OpenAPI spec file");
    let message = error.to_string();

    assert!(
        message.contains("OpenAPI schema configuration is invalid"),
        "unexpected startup error: {message}"
    );
    assert!(
        message.contains("OPENAPI_SPEC_PATH"),
        "startup error should name OPENAPI_SPEC_PATH: {message}"
    );
}

#[test]
fn broken_openapi_spec_file_returns_actionable_startup_error() {
    let spec = TempSpecFile::new("broken", "openapi: 2.0\npaths: {}\n");
    let mut config = test_config(Vec::new());
    config.openapi_spec_path = Some(spec.path.clone());
    let recorder = PrometheusBuilder::new().build_recorder();

    let error = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect_err("app startup should reject broken OpenAPI spec file");
    let message = error.to_string();

    assert!(
        message.contains("OpenAPI schema configuration is invalid"),
        "unexpected startup error: {message}"
    );
    assert!(
        message.contains("OPENAPI_SPEC_PATH"),
        "startup error should name OPENAPI_SPEC_PATH: {message}"
    );
    assert!(
        message.contains("OpenAPI 3.x"),
        "startup error should explain the expected spec version: {message}"
    );
}

#[tokio::test]
async fn status_uptime_increases_between_requests() {
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let config = status_config_with_policy(config, &policy);
    let router = status_router(config, Instant::now() - Duration::from_secs(30));

    let first = status_json(router.clone(), Some(test_principal(&["status-reader"]))).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let second = status_json(router, Some(test_principal(&["status-reader"]))).await;

    let first_uptime = first["uptime_seconds"]
        .as_u64()
        .expect("uptime should be an integer");
    let second_uptime = second["uptime_seconds"]
        .as_u64()
        .expect("uptime should be an integer");

    assert!(first_uptime >= 30);
    assert!(
        second_uptime > first_uptime,
        "expected uptime to increase, got {first_uptime} then {second_uptime}"
    );
}

#[tokio::test]
async fn audit_events_stream_admin_principal_receives_emitted_event() {
    let (router, audit_log, _policy) = audit_events_router();
    let response = router
        .oneshot(audit_stream_request(
            AUDIT_EVENTS_STREAM_ROUTE,
            test_principal(&["audit-streamer"]),
        ))
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);

    let event = test_stream_event("audit.sse.direct", "/direct");
    audit_log.emit(event.clone());

    let body = read_sse_until(response.into_body(), |body| {
        contains_event_id(body, &event.event_id)
    })
    .await;

    assert!(body.contains("event: audit.sse.direct"));
    assert!(body.contains(r#""path":"/direct""#));
}

#[tokio::test]
async fn audit_events_stream_filters_by_event_type_and_path() {
    let (router, audit_log, _policy) = audit_events_router();
    let response = router
        .oneshot(audit_stream_request(
            &format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type=audit.sse.match&path=/match"),
            test_principal(&["audit-streamer"]),
        ))
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);

    let wrong_type = test_stream_event("audit.sse.skip", "/match");
    let wrong_path = test_stream_event("audit.sse.match", "/skip");
    let matching = test_stream_event("audit.sse.match", "/match");
    audit_log.emit(wrong_type.clone());
    audit_log.emit(wrong_path.clone());
    audit_log.emit(matching.clone());

    let body = read_sse_until(response.into_body(), |body| {
        contains_event_id(body, &matching.event_id)
    })
    .await;

    assert!(contains_event_id(&body, &matching.event_id));
    assert!(!contains_event_id(&body, &wrong_type.event_id));
    assert!(!contains_event_id(&body, &wrong_path.event_id));
}

#[tokio::test]
async fn audit_events_stream_delivers_request_event_within_latency_budget() {
    let (router, _, _policy) = audit_events_router();
    let response = router
        .clone()
        .oneshot(audit_stream_request(
            &format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type=http.request_observed&path=/health"),
            test_principal(&["audit-streamer"]),
        ))
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);

    let started = Instant::now();
    let health_response = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("health request should complete");
    assert_eq!(health_response.status(), StatusCode::OK);

    let body = read_sse_until(response.into_body(), |body| {
        body.contains(r#""event_type":"http.request_observed""#)
            && body.contains(r#""path":"/health""#)
    })
    .await;

    assert!(body.contains(r#""status":200"#));
    // The issue target is roughly 100ms; this keeps CI stable while still
    // proving the audit writer and in-process broadcast do not add seconds
    // of delay.
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "streamed audit event arrived after {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn audit_events_stream_delivers_signal_opened_events_from_discovery() {
    let discovery_db = TempDb::new("signal-opened-stream");
    let (upstream_addr, _upstream_rx) = spawn_capture_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.auth_enabled = false;
    config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(AUDIT_EVENTS_STREAM_ROUTE.to_owned());
    config
        .rbac_exempt_paths
        .push("/signal-stream-opened".to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    // No audit store of record here: this test is not about durability,
    // so it runs the explicit best-effort opt-out (issue #425).
    config.audit_durability = config::AuditDurability::BestEffort;
    let (audit_log, audit_event_sender) =
        audit::AuditLog::from_config(&config).expect("audit log should build");
    // Keep a handle on the audit pipeline so the observation can be driven
    // to the discovery aggregator on demand instead of by racing it. The
    // request's `http.request_observed` event only reaches the aggregator
    // once the audit writer thread dequeues it, and the aggregator only
    // announces the signal when it flushes -- on a 250ms batch tick.
    // Neither the writer thread's turn nor that tick is the property under
    // test, so neither belongs inside the stream read budget.
    let audit_pipeline = audit_log.clone();
    let router =
        app(config, recorder.handle(), audit_log, audit_event_sender).expect("app should build");

    let stream_response = router
        .clone()
        .oneshot(audit_stream_request(
            &format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type=signal.opened"),
            test_principal(&["audit-streamer"]),
        ))
        .await
        .expect("stream request should complete");
    assert_eq!(stream_response.status(), StatusCode::OK);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/signal-stream-opened")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("data request should complete");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Draining is the observable condition the read below used to wait on
    // by hope: it closes admission and joins the audit writer, which emits
    // every queued event and then flushes every sink. When it returns, the
    // discovery flush has happened, so `signal.opened` has already been
    // published to the broadcast channel and the read observes a delivered
    // event rather than the scheduler. A gateway that stops announcing
    // opened signals -- or announces the wrong ones -- still fails this
    // test: the stream then ends with no matching event at all.
    audit_pipeline
        .close_and_drain(Duration::from_secs(10))
        .await
        .expect("audit pipeline should drain");

    let body = read_sse_until(stream_response.into_body(), |body| {
        body.contains(r#""event_type":"signal.opened""#)
            && body.contains(r#""signal_type":"new_endpoint_seen""#)
            && body.contains(r#""endpoint_template":"/signal-stream-opened""#)
    })
    .await;

    assert!(body.contains("event: signal.opened"));
    assert!(body.contains(r#""state":"open""#));
    assert!(body.contains(r#""target":"#));
    assert!(body.contains(r#""kind":"endpoint""#));
    assert!(body.contains(r#""explanation":"New endpoint observed: GET /signal-stream-opened"#));
}

#[tokio::test]
async fn audit_events_stream_delivers_signal_lifecycle_transitions() {
    let discovery_db = TempDb::new("signal-transition-stream");
    create_signal_schema(&discovery_db.path);
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-stream-ack",
            signal_type: "new_endpoint_seen",
            method: "GET",
            endpoint_template: "/stream/{id}",
            explanation:
                "New endpoint observed: GET /stream/{id} was first seen at 2024-06-01T00:00:00Z.",
            evidence: json!({
                "first_seen": "2024-06-01T00:00:00Z",
                "initial_call_count": 1
            }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );
    let policy = TempPolicyFile::new(&signals_policy_document_string());
    let recorder = PrometheusBuilder::new().build_recorder();
    let (audit_log, audit_event_sender) = test_audit_log_with_broadcast();
    let mut config = signals_admin_config(Some(&discovery_db.path), &policy);
    config
        .rbac_exempt_paths
        .push(AUDIT_EVENTS_STREAM_ROUTE.to_owned());
    let router =
        app(config, recorder.handle(), audit_log, audit_event_sender).expect("app should build");

    let stream_response = router
        .clone()
        .oneshot(audit_stream_request(
            &format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type=signal.lifecycle_changed"),
            test_principal(&["admin"]),
        ))
        .await
        .expect("stream request should complete");
    assert_eq!(stream_response.status(), StatusCode::OK);

    let transition_response = router
        .oneshot(signals_admin_json_request(
            Method::POST,
            "/v1/admin/signals/sig-stream-ack/acknowledge",
            Some(test_principal(&["signals-writer"])),
        ))
        .await
        .expect("signals transition request should complete");
    assert_eq!(transition_response.status(), StatusCode::OK);

    let body = read_sse_until(stream_response.into_body(), |body| {
        body.contains(r#""event_type":"signal.lifecycle_changed""#)
            && body.contains(r#""id":"sig-stream-ack""#)
    })
    .await;

    assert!(body.contains("event: signal.lifecycle_changed"));
    assert!(body.contains(r#""signal_type":"new_endpoint_seen""#));
    assert!(body.contains(r#""state":"acknowledged""#));
    assert!(body.contains(r#""transitioned_by":"user-123""#));
}

#[tokio::test]
async fn shadow_would_deny_events_are_queryable_and_streamable() {
    let db = TempDb::new("shadow-would-deny");
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "enforcement_mode": "shadow",
                "roles": {
                    "admin": {
                        "permissions": [
                            "admin:audit:read",
                            "admin:audit:stream"
                        ]
                    }
                },
                "routes": [
                    {
                        "path_prefix": "/__test",
                        "permission": "test:read"
                    }
                ]
            }"#,
    );
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.audit_sqlite_path = Some(db.path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push("/v1/admin".to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let (audit_log, audit_event_sender) = audit_log_with_sqlite_and_broadcast(&db.path);
    let router =
        app(config, recorder.handle(), audit_log, audit_event_sender).expect("app should build");
    let request_id = "request-shadow-would-deny";
    let stream_response = router
        .clone()
        .oneshot(audit_stream_request(
            &format!(
                "{AUDIT_EVENTS_STREAM_ROUTE}?event_type=authz.would_deny&path=/__test/principal"
            ),
            test_principal(&["admin"]),
        ))
        .await
        .expect("stream request should complete");
    assert_eq!(stream_response.status(), StatusCode::OK);

    let shadow_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(REQUEST_ID_HEADER, request_id)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("shadow request should complete");
    assert_eq!(shadow_response.status(), StatusCode::NO_CONTENT);

    let stream_body = read_sse_until(stream_response.into_body(), |body| {
        body.contains(r#""event_type":"authz.would_deny""#)
            && body.contains(&format!(r#""request_id":"{request_id}""#))
    })
    .await;
    assert!(stream_body.contains("event: authz.would_deny"));
    assert!(stream_body.contains(r#""path":"/__test/principal""#));
    assert!(stream_body.contains(r#""path_prefix":"/__test""#));
    assert!(stream_body.contains(r#""permission":"test:read""#));
    assert!(stream_body.contains(r#""reason":"missing_principal""#));

    let body = wait_for_audit_query_event(
        router,
        "/v1/admin/audit?event_type=authz.would_deny",
        request_id,
    )
    .await;
    let event = body["events"]
        .as_array()
        .expect("events should be an array")
        .iter()
        .find(|event| event["request_id"] == json!(request_id))
        .expect("queried would-deny event should be present");
    assert_eq!(event["event_type"], json!("authz.would_deny"));
    assert_eq!(event["payload"]["path"], json!("/__test/principal"));
    assert_eq!(event["payload"]["path_prefix"], json!("/__test"));
    assert_eq!(event["payload"]["permission"], json!("test:read"));
    assert_eq!(event["payload"]["reason"], json!("missing_principal"));
}

// ------------------------------------------------------------------
// Durable audit SSE (issue #241, PR 6): the endpoint reads committed
// events from the stream cursor in cluster mode. Docker-gated on the
// same locator as the storage suites.
// ------------------------------------------------------------------

#[cfg(feature = "postgres")]
mod durable_sse_tests {
    use super::*;
    use crate::storage::{
        migrations,
        postgres::PostgresFoundation,
        postgres_audit::{IngestIdentity, PostgresAuditEventStore},
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
        let directory =
            std::env::temp_dir().join(format!("greengateway-durable-sse-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("temp directory should create");
        let path = directory.join("database-url");
        std::fs::write(&path, format!("{dsn}\n")).expect("DSN file should write");
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

    /// One test's disposable database: each SSE test streams from its
    /// own database because an abandoned stream's background polls can
    /// hold table locks that a sibling test's TRUNCATE would deadlock
    /// against (a real failure under shared-database testing).
    struct TestDatabase {
        dsn: String,
        admin_dsn: String,
        name: String,
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let admin_dsn = self.admin_dsn.clone();
            let name = self.name.clone();
            // Fire-and-forget: joining here deadlocks under some
            // runtimes (the drop thread's own runtime can stall on
            // socket wakeup once the test runtime is gone), and a
            // leaked per-test database costs nothing on a disposable
            // test server. Each run sweeps stale databases first, so
            // nothing accumulates across runs.
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

    /// The segment that names this test process's run in every
    /// database it creates, so the sweep can tell an earlier run's
    /// leftovers from a sibling test's fresh database.
    fn run_epoch() -> &'static str {
        static RUN_EPOCH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
            let seconds = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0);
            format!("{seconds:x}p{:x}", std::process::id())
        });
        RUN_EPOCH.as_str()
    }

    /// Drop any databases leaked by earlier runs of these tests, so a
    /// long-lived development database server does not accumulate them.
    /// Only databases from OTHER runs are swept, never this run's: a
    /// sibling test that has just created its database and not yet
    /// connected has no active connections either, and dropping it out
    /// from under the sibling (WITH FORCE) was exactly the flake this
    /// guard exists to prevent -- "database does not exist; it seems
    /// to have just been dropped" at the sibling's first checkout.
    async fn sweep_stale_test_databases(admin_dsn: &str) {
        let Ok((client, connection)) =
            tokio_postgres::connect(admin_dsn, tokio_postgres::NoTls).await
        else {
            return;
        };
        let connection = tokio::spawn(connection);
        let rows = client
            .query(
                r#"
                    SELECT datname FROM pg_database
                    WHERE datname LIKE 'ggw_sse_test_%'
                      AND datname NOT LIKE $1
                      AND NOT EXISTS (
                          SELECT 1 FROM pg_stat_activity
                          WHERE pg_stat_activity.datname = pg_database.datname
                      )
                    "#,
                &[&format!("ggw_sse_test_{}_%", run_epoch())],
            )
            .await;
        if let Ok(rows) = rows {
            for row in rows {
                let name: String = row.get(0);
                let _ = client
                    .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .await;
            }
        }
        drop(client);
        let _ = connection.await;
    }

    async fn create_test_database(admin_dsn: &str) -> TestDatabase {
        use std::str::FromStr as _;
        sweep_stale_test_databases(admin_dsn).await;
        let name = format!(
            "ggw_sse_test_{}_{}",
            run_epoch(),
            uuid::Uuid::new_v4().simple()
        );
        let parsed = tokio_postgres::Config::from_str(admin_dsn).expect("admin DSN should parse");
        let admin_pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
            parsed,
            tokio_postgres::NoTls,
        ))
        .config({
            let mut pool_config = deadpool_postgres::PoolConfig::new(2);
            pool_config.timeouts.create = Some(std::time::Duration::from_millis(5_000));
            pool_config
        })
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .build()
        .expect("admin pool should build");
        admin_pool
            .get()
            .await
            .expect("admin checkout")
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap_or_else(|error| panic!("test database should create: {error}"));
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

    async fn migrated_store(dsn: &str) -> PostgresAuditEventStore {
        let dsn_file = write_dsn_file(dsn);
        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-durable-sse".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("schema should migrate");
        foundation
            .pool()
            .get()
            .await
            .expect("cleanup checkout")
            .batch_execute(
                "TRUNCATE greengateway.audit_stream, greengateway.audit_events \
                     RESTART IDENTITY CASCADE; \
                     UPDATE greengateway.audit_stream_state SET last_position = 0;",
            )
            .await
            .expect("audit tables should reset");
        PostgresAuditEventStore::new(
            foundation.pool().clone(),
            Some(IngestIdentity {
                instance_id: uuid::Uuid::new_v4(),
                boot_id: uuid::Uuid::new_v4(),
            }),
        )
    }

    fn durable_stream_router(store: PostgresAuditEventStore) -> (Router, audit::AuditEventSender) {
        durable_stream_router_with(store, AuditStreamLimits::SERVED)
    }

    fn durable_stream_router_with(
        store: PostgresAuditEventStore,
        stream_limits: AuditStreamLimits,
    ) -> (Router, audit::AuditEventSender) {
        let policy = middleware::rbac::RbacState::new(
            parse_policy_body(&Bytes::from(
                r#"{
                        "schema_version": "0.1.0",
                        "default_action": "deny",
                        "roles": {
                            "streamer": { "permissions": ["admin:audit:stream"] },
                            "other": { "permissions": ["admin:audit:read"] }
                        }
                    }"#,
            ))
            .expect("stream policy should parse"),
            Vec::new(),
            false,
            test_audit_log(),
        );
        let (event_sender, _) = tokio::sync::broadcast::channel(8);
        let router = Router::new()
            .route(AUDIT_EVENTS_STREAM_ROUTE, get(audit_events_stream_endpoint))
            .with_state(AuditAdminState {
                query_store: None,
                event_sender: event_sender.clone(),
                rbac_state: Some(policy),
                stream_limits,
                pg_audit: Some(std::sync::Arc::new(store)),
            });
        (router, event_sender)
    }

    fn stream_request(
        last_event_id: Option<&str>,
        principal: Option<auth::Principal>,
    ) -> Request<Body> {
        stream_request_filtered(last_event_id, principal, None)
    }

    fn stream_request_filtered(
        last_event_id: Option<&str>,
        principal: Option<auth::Principal>,
        event_type: Option<&str>,
    ) -> Request<Body> {
        let uri = match event_type {
            Some(event_type) => format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type={event_type}"),
            None => AUDIT_EVENTS_STREAM_ROUTE.to_owned(),
        };
        let mut builder = Request::builder().uri(uri);
        if let Some(last_event_id) = last_event_id {
            builder = builder.header("last-event-id", last_event_id);
        }
        let mut request = builder
            .body(Body::empty())
            .expect("stream request should build");
        if let Some(principal) = principal {
            request
                .extensions_mut()
                .insert(accepted_reauthentication(principal.clone()));
            request.extensions_mut().insert(principal);
        }
        request
    }

    fn streamer_principal(role: &str) -> auth::Principal {
        test_principal(&[role])
    }

    fn sse_event(event_type: &str, path: &str) -> audit::AuditEvent {
        audit::AuditEvent::new(
            event_type,
            "request-sse",
            "127.0.0.1",
            None,
            json!({ "path": path, "status": 200 }),
        )
    }

    #[tokio::test]
    async fn durable_sse_replays_filtered_events_without_repeating_frames() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database.dsn).await;
        // Alternating event types: the filter excludes half. An
        // adversarial review reintroduced the shadowed-cursor defect
        // (a fully filtered batch never advancing the poll cursor) and
        // the shipped suite stayed green; this test pins both the
        // filter and the no-repeat/no-stall behavior.
        for index in 0..6 {
            let event_type = if index % 2 == 0 {
                "audit.sse.wanted"
            } else {
                "audit.sse.excluded"
            };
            store
                .insert_events(&[sse_event(event_type, &format!("/filtered/{index}"))])
                .await
                .expect("seed event should commit");
        }
        let (router, _sender) = durable_stream_router(store);

        let response = router
            .clone()
            .oneshot(stream_request_filtered(
                Some("0"),
                Some(streamer_principal("streamer")),
                Some("audit.sse.wanted"),
            ))
            .await
            .expect("filtered replay should start");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_sse_until(response.into_body(), |body| {
            // Count the frame lines, not the JSON payloads: each framed
            // event carries the type twice (event: line + data JSON),
            // so matching the bare type would stop after two frames.
            body.matches("event: audit.sse.wanted").count() >= 3
        })
        .await;

        assert_eq!(
            body.matches("event: audit.sse.wanted").count(),
            3,
            "exactly the wanted events must be framed: {body}"
        );
        assert_eq!(
            body.matches("event: audit.sse.excluded").count(),
            0,
            "filtered events must never be framed: {body}"
        );
        // Each framed position appears exactly once: the cursor
        // advanced past the excluded positions rather than re-fetching
        // them.
        for position in [1, 3, 5] {
            assert_eq!(
                body.matches(&format!("id: {position}")).count(),
                1,
                "position {position} must be framed exactly once: {body}"
            );
        }
    }

    #[tokio::test]
    async fn durable_sse_boundary_cursors_do_not_panic() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database.dsn).await;
        store
            .insert_events(&[sse_event("audit.sse.boundary", "/boundary")])
            .await
            .expect("seed event should commit");
        let (router, _sender) = durable_stream_router(store);

        // i64::MAX once overflowed the expiry comparison and panicked
        // the request task; it must answer like any other not-expired
        // cursor (a live tail from an absurd position).
        let response = router
            .clone()
            .oneshot(stream_request(
                Some("9223372036854775807"),
                Some(streamer_principal("streamer")),
            ))
            .await
            .expect("i64::MAX cursor must not panic");
        assert_eq!(response.status(), StatusCode::OK);
        drop(response.into_body());

        // The head itself: replay from head delivers nothing (live
        // tail), not an error.
        let response = router
            .oneshot(stream_request(
                Some("1"),
                Some(streamer_principal("streamer")),
            ))
            .await
            .expect("head cursor should start");
        assert_eq!(response.status(), StatusCode::OK);
        drop(response.into_body());
    }

    #[tokio::test]
    async fn durable_sse_replays_from_last_event_id_with_position_ids() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database.dsn).await;
        for path in ["/one", "/two", "/three"] {
            store
                .insert_events(&[sse_event("audit.sse.replay", path)])
                .await
                .expect("seed event should commit");
        }
        let (router, _sender) = durable_stream_router(store);

        // The client saw position 1 (/one); replay must deliver
        // exactly positions 2 and 3, each framed with id: so a further
        // reconnect resumes after the last one received.
        let response = router
            .oneshot(stream_request(
                Some("1"),
                Some(streamer_principal("streamer")),
            ))
            .await
            .expect("replay request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let body = read_sse_until(response.into_body(), |body| body.contains("/three")).await;
        assert!(body.contains("/two"), "{body}");
        assert!(body.contains("/three"), "{body}");
        assert!(
            !body.contains("/one"),
            "replay must start after the cursor: {body}"
        );
        assert!(
            body.contains("id: 2"),
            "frames must carry stream positions for reconnect: {body}"
        );
        assert!(body.contains("id: 3"), "{body}");
    }

    #[tokio::test]
    async fn durable_sse_expired_cursor_returns_410() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database.dsn).await;
        for path in ["/kept-a", "/kept-b"] {
            store
                .insert_events(&[sse_event("audit.sse.expiry", path)])
                .await
                .expect("seed event should commit");
        }
        // Simulate retention removing the oldest row: a client at
        // cursor 0 has missed position 1 forever (first_available
        // becomes 2).
        {
            let dsn_file = write_dsn_file(&database.dsn);
            let mut config = test_config(Vec::new());
            config.state_backend = config::StateBackend::Postgres;
            config.deployment_id = Some("deploy-durable-sse".to_owned());
            config.database.url_file = Some(dsn_file.path.clone());
            config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
            let foundation = PostgresFoundation::establish(&config)
                .await
                .expect("expiry connection should establish");
            foundation
                .pool()
                .get()
                .await
                .expect("expiry checkout")
                .batch_execute("DELETE FROM greengateway.audit_stream WHERE position = 1")
                .await
                .expect("expiry delete should run");
        }

        let (router, _sender) = durable_stream_router(store);
        let response = router
            .oneshot(stream_request(
                Some("0"),
                Some(streamer_principal("streamer")),
            ))
            .await
            .expect("expired request should complete");
        assert_eq!(response.status(), StatusCode::GONE);
        let body = body_string(response).await;
        assert!(
            body.contains("older than the earliest retained event"),
            "{body}"
        );
        assert!(
            body.contains("reconnect without Last-Event-ID"),
            "the response must say how to resynchronize: {body}"
        );
    }

    #[tokio::test]
    async fn durable_sse_invalid_last_event_id_returns_400() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database.dsn).await;
        let (router, _sender) = durable_stream_router(store);
        let response = router
            .oneshot(stream_request(
                Some("not-a-position"),
                Some(streamer_principal("streamer")),
            ))
            .await
            .expect("invalid request should complete");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    /// An authority that accepts the stream's credential until it is told
    /// the session has ended.
    struct EndingAuthority {
        principal: auth::Principal,
        ended: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl auth::SessionValidator for EndingAuthority {
        async fn validate_session(
            &self,
            _credential: &auth::SessionCredential,
        ) -> Result<auth::Principal, auth::AuthError> {
            if self.ended.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(auth::AuthError::InvalidSession("logged out".to_owned()));
            }
            Ok(self.principal.clone())
        }
    }

    #[tokio::test]
    async fn durable_sse_ends_on_a_lost_session_without_moving_the_resume_cursor() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database.dsn).await;
        store
            .insert_events(&[sse_event("audit.sse.before", "/before")])
            .await
            .expect("seed event should commit");
        let (router, _sender) = durable_stream_router_with(
            store,
            AuditStreamLimits {
                recheck_interval: Duration::from_millis(50),
                max_lifetime: Duration::from_secs(60),
            },
        );
        let principal = streamer_principal("streamer");
        let authority = Arc::new(EndingAuthority {
            principal: principal.clone(),
            ended: std::sync::atomic::AtomicBool::new(false),
        });
        let mut request = stream_request(Some("0"), None);
        request.extensions_mut().insert(principal);
        request.extensions_mut().insert(auth::Reauthentication::new(
            auth::CredentialJudge::Validator(
                Arc::clone(&authority) as Arc<dyn auth::SessionValidator>
            ),
            auth::SessionCredential::Bearer(format!("test-{}", uuid::Uuid::new_v4())),
            None,
        ));

        let response = router
            .oneshot(request)
            .await
            .expect("replay request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body().into_data_stream();
        let mut received = String::new();
        while !received.contains("id: 1") {
            let chunk = tokio::time::timeout(Duration::from_secs(5), body.next())
                .await
                .expect("the seeded event should be replayed")
                .expect("stream should not end before the seeded event")
                .expect("stream chunk should read");
            received.push_str(std::str::from_utf8(&chunk).expect("UTF-8"));
        }
        authority
            .ended
            .store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(chunk) = body.next().await {
                let chunk = chunk.expect("stream chunk should read");
                received.push_str(std::str::from_utf8(&chunk).expect("UTF-8"));
            }
        })
        .await
        .expect("the gateway should end the stream");

        let last = received
            .rsplit("\n\n")
            .find(|frame| !frame.trim().is_empty())
            .expect("the stream sent frames");
        assert!(
            last.contains("event: stream.closed")
                && last.contains(r#"data: {"reason":"session_ended"}"#),
            "the stream must end with its closing frame: {received}"
        );
        // A client that reconnects resumes after the last event it was sent,
        // not after the closing frame.
        assert!(!last.contains("id:"), "{received}");
        assert_eq!(received.matches("id: ").count(), 1, "{received}");
    }

    #[tokio::test]
    async fn durable_sse_requires_the_stream_permission() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let store = migrated_store(&database.dsn).await;
        let (router, _sender) = durable_stream_router(store);
        // A principal whose role lacks admin:audit:stream is refused
        // before any stream work happens.
        let response = router
            .oneshot(stream_request(None, Some(streamer_principal("other"))))
            .await
            .expect("unauthorized request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[test]
fn stalled_sse_consumer_does_not_slow_audit_emit_burst() {
    const BURST_EVENTS: usize = 20_000;

    let event = test_stream_event("audit.sse.backpressure", "/burst");
    let baseline_log = test_audit_log();
    let baseline = emit_burst(&baseline_log, &event, BURST_EVENTS);

    let (audit_log, sender) = test_audit_log_with_broadcast();
    let _stalled_consumer = sender.subscribe();
    let stalled = emit_burst(&audit_log, &event, BURST_EVENTS);

    let allowed = baseline.mul_f64(20.0).max(Duration::from_millis(200));
    assert!(
        stalled < allowed,
        "stalled subscriber burst took {stalled:?}, baseline was {baseline:?}, allowed {allowed:?}"
    );
    assert!(
        stalled < Duration::from_secs(1),
        "stalled subscriber burst took {stalled:?}"
    );
}

#[tokio::test]
async fn audit_query_admin_principal_filters_events() {
    let db = TempDb::new("audit-query-filters");
    create_audit_schema(&db.path);
    seed_filter_events(&db.path);
    let (router, _policy) = audit_query_router(Some(&db.path));

    assert_eq!(
        audit_event_ids(router.clone(), "/v1/admin/audit?event_type=audit.policy").await,
        vec!["fractionally-newer-event".to_owned()]
    );
    assert_eq!(
        audit_event_ids(router.clone(), "/v1/admin/audit?actor=bob").await,
        vec!["fractionally-newer-event".to_owned()]
    );
    assert_eq!(
        audit_event_ids(router.clone(), "/v1/admin/audit?path=/admin").await,
        vec!["fractionally-newer-event".to_owned()]
    );
    assert_eq!(
        audit_event_ids(router.clone(), "/v1/admin/audit?status=403").await,
        vec!["fractionally-newer-event".to_owned()]
    );
    assert_eq!(
        audit_event_ids(
            router,
            "/v1/admin/audit?from=2024-06-01T12:00:00Z&to=2024-06-01T12:00:00.5Z",
        )
        .await,
        vec![
            "fractionally-newer-event".to_owned(),
            "cutoff-event".to_owned()
        ]
    );
}

#[tokio::test]
async fn audit_query_reason_filter_reaches_storage_and_preserves_pagination() {
    let db = TempDb::new("audit-query-reason");
    create_audit_schema(&db.path);
    for (event_id, event_type, mut payload) in [
        (
            "direct",
            "tool.invoke_failure",
            json!({"reason": "invalid_params"}),
        ),
        (
            "detailed",
            "tool.invoke_failure",
            json!({"reason": "work_error", "failure_reason": "invalid_params"}),
        ),
        (
            "both",
            "tool.invoke_failure",
            json!({"reason": "invalid_params", "failure_reason": "invalid_params"}),
        ),
        ("missing", "tool.invoke_failure", json!({})),
        (
            "unrelated",
            "tool.invoke_failure",
            json!({"message": "invalid_params", "data": {"reason": "invalid_params"}}),
        ),
        (
            "other-type",
            "audit.other",
            json!({"failure_reason": "invalid_params"}),
        ),
    ] {
        insert_audit_event(
            &db.path,
            SeedAuditEvent {
                event_id,
                event_type,
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "admin-user",
                path: "/tools",
                status: 400,
            },
        );
        payload["path"] = json!("/tools");
        payload["status"] = json!(400);
        Connection::open(&db.path)
            .expect("test database should open")
            .execute(
                "UPDATE audit_events SET payload_json = ?1 WHERE event_id = ?2",
                params![payload.to_string(), event_id],
            )
            .expect("reason payload should update");
    }
    let (router, _policy) = audit_query_router(Some(&db.path));
    let query = "/v1/admin/audit?event_type=tool.invoke_failure&reason=invalid_params&limit=2";
    let first = router
        .clone()
        .oneshot(audit_query_request(query, Some(test_principal(&["admin"]))))
        .await
        .expect("first reason-filtered request should complete");
    assert_eq!(first.status(), StatusCode::OK);
    let first = json_body(first).await;
    assert_eq!(event_ids_from_body(&first), ["both", "detailed"]);
    let cursor = first["next_cursor"]
        .as_i64()
        .expect("first page has a cursor");

    let second = router
        .clone()
        .oneshot(audit_query_request(
            &format!("{query}&before_id={cursor}"),
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("second reason-filtered request should complete");
    assert_eq!(second.status(), StatusCode::OK);
    let second = json_body(second).await;
    assert_eq!(event_ids_from_body(&second), ["direct"]);
    assert!(second["next_cursor"].is_null());
    assert_eq!(
        audit_event_ids(router.clone(), "/v1/admin/audit?reason=work_error").await,
        ["detailed"]
    );
    for reason in ["invalid", "a", &"a".repeat(64), "upstream_http_4xx"] {
        assert!(
            audit_event_ids(router.clone(), &format!("/v1/admin/audit?reason={reason}"))
                .await
                .is_empty()
        );
    }
}

#[tokio::test]
async fn audit_query_paginates_with_keyset_cursor_without_gaps() {
    let db = TempDb::new("audit-query-pagination");
    create_audit_schema(&db.path);
    for index in 0..25 {
        insert_audit_event(
            &db.path,
            SeedAuditEvent {
                event_id: &format!("page-event-{index:02}"),
                event_type: "audit.page",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "admin-user",
                path: "/page",
                status: 200,
            },
        );
    }
    let (router, _policy) = audit_query_router(Some(&db.path));
    let mut next_cursor = None;
    let mut returned = Vec::new();
    let mut seen = HashSet::new();

    loop {
        let uri = match next_cursor {
            Some(cursor) => format!("/v1/admin/audit?limit=10&before_id={cursor}"),
            None => "/v1/admin/audit?limit=10".to_owned(),
        };
        let response = router
            .clone()
            .oneshot(audit_query_request(&uri, Some(test_principal(&["admin"]))))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let body = json_body(response).await;
        let ids = event_ids_from_body(&body);
        for id in ids {
            assert!(seen.insert(id.clone()), "duplicate event id {id}");
            returned.push(id);
        }

        next_cursor = body["next_cursor"].as_i64();
        if next_cursor.is_none() {
            break;
        }
    }

    let expected = (0..25)
        .rev()
        .map(|index| format!("page-event-{index:02}"))
        .collect::<Vec<_>>();
    assert_eq!(returned, expected);
}

#[tokio::test]
async fn audit_query_admin_principal_without_store_returns_service_unavailable() {
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        audit_query_config_with_policy(None, &policy),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(audit_query_request(
        AUDIT_ADMIN_ROUTE,
        Some(test_principal(&["admin"])),
    ))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"audit query store not configured"}"#
    );
}

#[tokio::test]
async fn audit_query_malformed_params_return_bad_request() {
    let db = TempDb::new("audit-query-malformed");
    create_audit_schema(&db.path);
    let (router, _policy) = audit_query_router(Some(&db.path));

    for (uri, parameter) in [
        ("/v1/admin/audit?status=not-a-number", "status"),
        ("/v1/admin/audit?from=not-a-date", "from"),
        ("/v1/admin/audit?before_id=-1", "before_id"),
        ("/v1/admin/audit?before_id=not-a-number", "before_id"),
        ("/v1/admin/audit?limit=0", "limit"),
        ("/v1/admin/audit?reason=", "reason"),
        ("/v1/admin/audit?reason=INVALID_PARAMS", "reason"),
        ("/v1/admin/audit?reason=invalid%20params", "reason"),
        ("/v1/admin/audit?reason=invalid%0Aparams", "reason"),
        ("/v1/admin/audit?reason=%C3%A9", "reason"),
        (
            "/v1/admin/audit?reason=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "reason",
        ),
    ] {
        let response = router
            .clone()
            .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_string(response).await,
            format!(r#"{{"error":"invalid query parameter: {parameter}"}}"#)
        );
    }
}

#[tokio::test]
async fn traffic_endpoint_list_filters_sorts_and_paginates() {
    let discovery_db = TempDb::new("traffic-list");
    create_discovery_schema(&discovery_db.path);
    seed_list_discovery_endpoints(&discovery_db.path);
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);

    let call_count_page = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?method=GET&sort=call_count&limit=2",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&call_count_page),
        vec!["/reports/{id}".to_owned(), "/users/{id}".to_owned()]
    );
    let next_cursor = call_count_page["next_cursor"]
        .as_str()
        .expect("list response should include next cursor");

    let second_page = traffic_json(
        &router,
        &format!(
            "/v1/admin/traffic/endpoints?method=GET&sort=call_count&limit=2&cursor={next_cursor}"
        ),
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&second_page),
        vec!["/admin/status".to_owned()]
    );
    assert!(second_page["next_cursor"].is_null());

    let substring = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?endpoint_template=users&sort=last_seen",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&substring),
        vec!["/users/{id}".to_owned(), "/users".to_owned()]
    );

    let prefix = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?endpoint_template_prefix=/admin",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&prefix),
        vec!["/admin/status".to_owned()]
    );

    let last_seen_window = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?last_seen_after=2024-06-02T00:00:00Z&last_seen_before=2024-06-03T23:59:59Z",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
    assert_eq!(
        endpoint_templates(&last_seen_window),
        vec!["/users/{id}".to_owned(), "/users".to_owned()]
    );

    let min_call_count = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?min_call_count=20&sort=call_count",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&min_call_count),
        vec!["/reports/{id}".to_owned(), "/users/{id}".to_owned()]
    );

    let first_seen = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?sort=first_seen",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        first_seen["endpoints"][0]["endpoint_template"],
        json!("/admin/status")
    );
    assert_eq!(
        first_seen["endpoints"][0]["status_counts"][0]["status"],
        json!(204)
    );
    assert_eq!(first_seen["endpoints"][0]["latency"]["p95_ms"], json!(5));
}

#[tokio::test]
async fn traffic_endpoint_inventory_surfaces_schema_mismatch_count() {
    let discovery_db = TempDb::new("traffic-schema-mismatch-count");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/users/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 3,
            latency_count: 3,
            latency_p50_ms: 10,
            latency_p95_ms: 20,
            latency_p99_ms: 30,
            distinct_principal_count: 1,
            status_counts: &[(200, 3)],
        },
    );
    set_schema_mismatch_count(&discovery_db.path, "GET", "/users/{id}", 2);
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);

    let list = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?method=GET",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(list["endpoints"][0]["schema_mismatch_count"], json!(2));

    let template = query_encode("/users/{id}");
    let detail = traffic_json(
        &router,
        &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}"),
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(detail["endpoint"]["schema_mismatch_count"], json!(2));
}

#[tokio::test]
async fn traffic_endpoint_inventory_includes_open_signal_summary_without_signal_n_plus_one() {
    let discovery_db = TempDb::new("traffic-open-signals");
    create_discovery_schema(&discovery_db.path);
    for index in 0..25 {
        let endpoint_template = format!("/bulk/{index}");
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: &endpoint_template,
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 10,
                latency_p99_ms: 10,
                distinct_principal_count: 1,
                status_counts: &[(200, 1)],
            },
        );
        let signal_id = format!("sig-bulk-{index}");
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: &signal_id,
                signal_type: "new_endpoint_seen",
                method: "GET",
                endpoint_template: &endpoint_template,
                explanation: "New endpoint observed during signal summary query-count test.",
                evidence: json!({ "first_seen": "2024-06-01T00:00:00Z" }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );
    }
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-bulk-extra-type",
            signal_type: "schema_mismatch",
            method: "GET",
            endpoint_template: "/bulk/0",
            explanation: "Schema mismatch for GET /bulk/0.",
            evidence: json!({ "reason": "body_shape_changed" }),
            state: "open",
            created_at: "2024-06-01T00:10:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-bulk-acknowledged",
            signal_type: "principal_new_to_endpoint",
            method: "GET",
            endpoint_template: "/bulk/1",
            explanation: "Acknowledged signal should not count as open.",
            evidence: json!({ "principal": "alice" }),
            state: "acknowledged",
            created_at: "2024-06-01T00:15:00Z",
            transitioned_at: Some("2024-06-01T00:16:00Z"),
            transitioned_by: Some("reviewer"),
        },
    );

    let store = discovery::query::DiscoveryQueryStore::open(&discovery_db.path)
        .expect("discovery query store should open");
    let page = store
        .list_endpoints(&discovery::query::EndpointListFilters {
            method: Some("GET".to_owned()),
            endpoint_template_contains: None,
            endpoint_template_prefix: None,
            first_seen_after: None,
            first_seen_before: None,
            last_seen_after: None,
            last_seen_before: None,
            min_call_count: None,
            new_since_hours: discovery::query::DEFAULT_NEW_SINCE_HOURS,
            is_new: None,
            reviewed: None,
            sort: discovery::query::EndpointSort::LastSeen,
            limit: 50,
            cursor: None,
        })
        .expect("endpoint page should load");
    assert_eq!(page.endpoints.len(), 25);
    assert_eq!(
        store.open_signal_summary_query_count_for_test(),
        1,
        "endpoint page should load all open-signal summaries with one set-based query"
    );
    let first = page
        .endpoints
        .iter()
        .find(|endpoint| endpoint.endpoint_template == "/bulk/0")
        .expect("/bulk/0 endpoint should be present");
    let first_open_signals = first
        .open_signals
        .as_ref()
        .expect("open signal summary should be loaded by default");
    assert_eq!(first_open_signals.count, 2);
    assert_eq!(
        first_open_signals.signal_types,
        vec!["new_endpoint_seen".to_owned(), "schema_mismatch".to_owned()]
    );
    assert!(page.endpoints.iter().all(|endpoint| {
        endpoint.endpoint_template == "/bulk/0"
            || endpoint
                .open_signals
                .as_ref()
                .expect("open signal summary should be loaded by default")
                .count
                == 1
    }));

    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
    let list = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?method=GET&endpoint_template_prefix=/bulk&sort=last_seen&limit=50",
            Some(test_principal(&["traffic-and-signals-reader"])),
        )
        .await;
    let bulk_zero = list["endpoints"]
        .as_array()
        .expect("endpoints should be an array")
        .iter()
        .find(|endpoint| endpoint["endpoint_template"] == json!("/bulk/0"))
        .expect("/bulk/0 should be returned");
    assert_eq!(bulk_zero["open_signals"]["count"], json!(2));
    assert_eq!(
        bulk_zero["open_signals"]["signal_types"],
        json!(["new_endpoint_seen", "schema_mismatch"])
    );

    let detail = traffic_json(
        &router,
        "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fbulk%2F0",
        Some(test_principal(&["traffic-and-signals-reader"])),
    )
    .await;
    assert_eq!(detail["endpoint"]["open_signals"]["count"], json!(2));
    assert_eq!(
        detail["endpoint"]["open_signals"]["signal_types"],
        json!(["new_endpoint_seen", "schema_mismatch"])
    );
}

#[tokio::test]
async fn traffic_endpoint_inventory_omits_open_signal_summary_without_signals_read() {
    let discovery_db = TempDb::new("traffic-open-signals-hidden");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/hidden-signals",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 1,
            status_counts: &[(200, 1)],
        },
    );
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-hidden",
            signal_type: "security_anomaly",
            method: "GET",
            endpoint_template: "/hidden-signals",
            explanation: "Signal type should not leak to traffic-only readers.",
            evidence: json!({ "category": "authorization" }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );

    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
    let list = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?method=GET&endpoint_template_prefix=/hidden",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert!(
        list["endpoints"][0].get("open_signals").is_none(),
        "open_signals should be absent from list responses for traffic-only readers: {list}"
    );

    let detail = traffic_json(
        &router,
        "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fhidden-signals",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert!(
        detail["endpoint"].get("open_signals").is_none(),
        "open_signals should be absent from detail responses for traffic-only readers: {detail}"
    );
}

#[test]
fn endpoint_queries_can_skip_open_signal_summary_lookup() {
    let discovery_db = TempDb::new("traffic-open-signals-query-skipped");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/skip-signals",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 1,
            status_counts: &[(200, 1)],
        },
    );
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-skip",
            signal_type: "security_anomaly",
            method: "GET",
            endpoint_template: "/skip-signals",
            explanation: "Signal type should not be queried when hidden.",
            evidence: json!({ "category": "authorization" }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );

    let store = discovery::query::DiscoveryQueryStore::open(&discovery_db.path)
        .expect("discovery query store should open");
    let page = store
        .list_endpoints_with_open_signal_summaries(
            &discovery::query::EndpointListFilters {
                method: Some("GET".to_owned()),
                endpoint_template_contains: None,
                endpoint_template_prefix: Some("/skip".to_owned()),
                first_seen_after: None,
                first_seen_before: None,
                last_seen_after: None,
                last_seen_before: None,
                min_call_count: None,
                new_since_hours: discovery::query::DEFAULT_NEW_SINCE_HOURS,
                is_new: None,
                reviewed: None,
                sort: discovery::query::EndpointSort::LastSeen,
                limit: 50,
                cursor: None,
            },
            false,
        )
        .expect("endpoint page should load");
    assert_eq!(page.endpoints.len(), 1);
    assert!(page.endpoints[0].open_signals.is_none());
    assert_eq!(
        store.open_signal_summary_query_count_for_test(),
        0,
        "endpoint page should not run the open-signal summary query when summaries are hidden"
    );

    let detail = store
        .get_endpoint_with_open_signal_summaries("GET", "/skip-signals", 24, false)
        .expect("endpoint detail should load")
        .expect("endpoint should exist");
    assert!(detail.open_signals.is_none());
    assert_eq!(
        store.open_signal_summary_query_count_for_test(),
        0,
        "endpoint detail should not run the open-signal summary query when summaries are hidden"
    );
}

#[tokio::test]
async fn spec_conformance_mismatch_is_visible_in_traffic_inventory() {
    let discovery_db = TempDb::new("traffic-spec-conformance");
    let spec = TempSpecFile::new(
        "traffic-conformance",
        r#"
openapi: 3.0.3
info:
  title: Traffic Conformance API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      parameters:
        - in: query
          name: page
          required: true
"#,
    );
    let policy = TempPolicyFile::new(&traffic_policy_document_string());
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
    config.openapi_spec_path = Some(spec.path.clone());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(TRAFFIC_ENDPOINTS_ADMIN_ROUTE.to_owned());
    config
        .rbac_exempt_paths
        .push(TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE.to_owned());
    // No audit store of record here: this test is not about durability,
    // so it runs the explicit best-effort opt-out (issue #425).
    config.audit_durability = config::AuditDurability::BestEffort;
    // The configured sinks, then a capture sink: an event it holds has
    // already been handed to the discovery aggregator.
    let (sink, audit_event_sender) =
        audit::sink::build_sink_from_config(&config).expect("audit sink should build");
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(audit::sink::CompositeSink::new(vec![
        sink,
        Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>,
    ])) as Arc<dyn audit::AuditSink>);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router =
        app(config, recorder.handle(), audit_log, audit_event_sender).expect("app should build");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/users/123")
                .header(REQUEST_ID_HEADER, "request-spec-conformance-missing")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // The 2 s window below is the aggregator's flush, so the observation
    // must have reached the aggregator before it starts.
    wait_for_delivered_audit_events(&capture, "the request observation", |events| {
        events.iter().any(|event| {
            event.event_type == "http.request_observed"
                && event.request_id == "request-spec-conformance-missing"
        })
    })
    .await;
    let body = wait_for_traffic_json(&router, "/v1/admin/traffic/endpoints?method=GET", |body| {
        body["endpoints"].as_array().is_some_and(|endpoints| {
            endpoints.iter().any(|endpoint| {
                endpoint["endpoint_template"] == json!("/users/{id}")
                    && endpoint["schema_mismatch_count"] == json!(1)
            })
        })
    })
    .await;
    let users_endpoint = body["endpoints"]
        .as_array()
        .expect("endpoints should be an array")
        .iter()
        .find(|endpoint| endpoint["endpoint_template"] == json!("/users/{id}"))
        .expect("users endpoint should be present");
    assert_eq!(users_endpoint["schema_mismatch_count"], json!(1));
}

#[tokio::test]
async fn migrated_traffic_endpoint_reports_unknown_context_and_no_rule_coverage() {
    let discovery_db = TempDb::new("traffic-migrated-unknown-context");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/legacy/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 4,
            latency_count: 4,
            latency_p50_ms: 10,
            latency_p95_ms: 20,
            latency_p99_ms: 20,
            distinct_principal_count: 1,
            status_counts: &[(200, 4)],
        },
    );
    clear_discovery_routing_classification(&discovery_db.path, "GET", "/legacy/{id}");

    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
    let body = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?method=GET",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    let endpoint = &body["endpoints"][0];

    assert_eq!(endpoint["routing_context_known"], json!(false));
    assert_eq!(endpoint["routing_context_known_since"], Value::Null);
    assert_eq!(endpoint["coverage_scope"], json!("unknown"));
    assert_eq!(endpoint["covered_by_rule"], json!(false));
}

#[tokio::test]
async fn mixed_legacy_and_classified_history_remains_unknown_and_uncovered() {
    let discovery_db = TempDb::new("traffic-mixed-unknown-context");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/mixed/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T02:00:00Z",
            call_count: 5,
            latency_count: 5,
            latency_p50_ms: 10,
            latency_p95_ms: 20,
            latency_p99_ms: 20,
            distinct_principal_count: 1,
            status_counts: &[(200, 5)],
        },
    );
    insert_discovery_routing_context(
        &discovery_db.path,
        "GET",
        "/mixed/{id}",
        "",
        "",
        "https://legacy.internal",
        1,
        1,
    );
    let connection =
        Connection::open(&discovery_db.path).expect("test discovery database should open");
    connection
        .execute(
            r#"
                UPDATE discovery_endpoint_routing_classifications
                SET first_classified_at = '2024-06-01T01:00:00Z'
                WHERE method = 'GET' AND endpoint_template = '/mixed/{id}'
                "#,
            [],
        )
        .expect("classification timestamp should update");
    connection
        .execute(
            r#"
                UPDATE discovery_endpoint_routing_contexts
                SET first_seen = '2024-06-01T01:00:00Z'
                WHERE method = 'GET' AND endpoint_template = '/mixed/{id}'
                "#,
            [],
        )
        .expect("routing context timestamp should update");
    drop(connection);

    let policy = TempPolicyFile::new(&traffic_policy_document_with_rules(json!([{
        "methods": ["GET"],
        "path": "/mixed/{id}",
        "dispatch": {
            "kind": "legacy",
            "upstream_origin": "https://legacy.internal"
        },
        "action": "allow"
    }])));
    let router = traffic_admin_router_with_policy(Some(&discovery_db.path), None, &policy);
    let body = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?method=GET",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    let endpoint = &body["endpoints"][0];

    assert_eq!(endpoint["routing_context_known"], json!(false));
    assert_eq!(
        endpoint["routing_context_known_since"],
        json!("2024-06-01T01:00:00Z")
    );
    assert_eq!(endpoint["routing_contexts"].as_array().unwrap().len(), 1);
    assert_eq!(endpoint["coverage_scope"], json!("unknown"));
    assert_eq!(endpoint["covered_by_rule"], json!(false));
}

#[tokio::test]
async fn traffic_endpoint_lifecycle_flags_rule_coverage_and_hot_reload() {
    let discovery_db = TempDb::new("traffic-lifecycle-coverage");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/covered/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 3,
            latency_count: 3,
            latency_p50_ms: 10,
            latency_p95_ms: 20,
            latency_p99_ms: 30,
            distinct_principal_count: 1,
            status_counts: &[(200, 3)],
        },
    );
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/open/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 2,
            latency_count: 2,
            latency_p50_ms: 10,
            latency_p95_ms: 20,
            latency_p99_ms: 30,
            distinct_principal_count: 1,
            status_counts: &[(200, 2)],
        },
    );
    // Classified traffic without a proxy dispatch, as the aggregator records
    // it. Coverage is judged in that routing context; with none recorded at
    // all the evaluator would be missing the dispatch fact.
    for (endpoint_template, call_count) in [("/covered/{id}", 3), ("/open/{id}", 2)] {
        insert_discovery_routing_context(
            &discovery_db.path,
            "GET",
            endpoint_template,
            "",
            "",
            "",
            call_count,
            1,
        );
    }
    let policy = TempPolicyFile::new(&traffic_policy_document_with_rules(json!([
        {
            "id": "cover-id-endpoint",
            "methods": ["GET"],
            "path": "/covered/{id}",
            "action": "allow"
        }
    ])));
    let router = traffic_admin_router_with_policy(Some(&discovery_db.path), None, &policy);

    let body = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?sort=first_seen",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_coverage(&body),
        HashMap::from([
            ("/covered/{id}".to_owned(), true),
            ("/open/{id}".to_owned(), false)
        ])
    );

    let uncovered = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?covered_by_rule=false&sort=first_seen",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&uncovered),
        vec!["/open/{id}".to_owned()]
    );

    let uncovered_limited = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?covered_by_rule=false&sort=first_seen&limit=1",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&uncovered_limited),
        vec!["/open/{id}".to_owned()]
    );

    policy.write(&traffic_policy_document_with_rules(json!([
        {
            "id": "cover-id-endpoint",
            "methods": ["GET"],
            "path": "/covered/{id}",
            "action": "allow"
        },
        {
            "id": "cover-open-endpoint",
            "methods": ["GET"],
            "path": "/open/{id}",
            "principal": {
                "roles": ["traffic-reader"],
                "auth_methods": ["bearer_token"]
            },
            "action": "shadow"
        }
    ])));

    let reloaded = wait_for_traffic_json(&router, "/v1/admin/traffic/endpoints", |body| {
        endpoint_coverage_scopes(body).get("/open/{id}") == Some(&"principal".to_owned())
    })
    .await;
    assert_eq!(
        endpoint_coverage(&reloaded),
        HashMap::from([
            ("/covered/{id}".to_owned(), true),
            ("/open/{id}".to_owned(), false)
        ])
    );
    assert_eq!(
        endpoint_coverage_scopes(&reloaded),
        HashMap::from([
            ("/covered/{id}".to_owned(), "endpoint".to_owned()),
            ("/open/{id}".to_owned(), "principal".to_owned())
        ])
    );
}

#[tokio::test]
async fn traffic_inventory_reports_route_variants_and_mixed_principal_coverage() {
    let discovery_db = TempDb::new("traffic-routing-coverage");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/data/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 4,
            latency_count: 4,
            latency_p50_ms: 10,
            latency_p95_ms: 20,
            latency_p99_ms: 30,
            distinct_principal_count: 2,
            status_counts: &[(200, 4)],
        },
    );
    insert_discovery_routing_context(
        &discovery_db.path,
        "GET",
        "/data/{id}",
        "api.example.test",
        "/data",
        "https://api.internal",
        3,
        2,
    );
    insert_discovery_routing_context(
        &discovery_db.path,
        "GET",
        "/data/{id}",
        "admin.example.test",
        "/data",
        "https://admin.internal",
        1,
        1,
    );
    let policy = TempPolicyFile::new(
        &serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": {
                "traffic-reader": {
                    "permissions": [ADMIN_TRAFFIC_READ_PERMISSION]
                },
                "api-reader": {
                    "permissions": ["api:read"]
                }
            },
            "routes": [{
                "methods": ["GET"],
                "hosts": ["api.example.test"],
                "path_prefix": "/data",
                "permission": "api:read"
            }]
        }))
        .expect("traffic routing policy should serialize"),
    );
    let router = traffic_admin_router_with_policy(Some(&discovery_db.path), None, &policy);

    let body = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    let endpoint = &body["endpoints"][0];
    assert_eq!(endpoint["coverage_scope"], json!("mixed"));
    assert_eq!(endpoint["covered_by_rule"], json!(false));
    assert_eq!(
        endpoint["routing_contexts"],
        json!([
            {
                "route_host": "admin.example.test",
                "route_path_prefix": "/data",
                "upstream_origin": "https://admin.internal",
                "first_seen": "2024-06-01T00:00:00Z",
                "last_seen": "2024-06-01T01:00:00Z",
                "call_count": 1,
                "distinct_principal_count": 1,
                "covered_by_rule": false,
                "coverage_scope": "none"
            },
            {
                "route_host": "api.example.test",
                "route_path_prefix": "/data",
                "upstream_origin": "https://api.internal",
                "first_seen": "2024-06-01T00:00:00Z",
                "last_seen": "2024-06-01T01:00:00Z",
                "call_count": 3,
                "distinct_principal_count": 2,
                "covered_by_rule": false,
                "coverage_scope": "principal"
            }
        ])
    );
}

#[tokio::test]
async fn traffic_endpoint_new_flag_uses_configurable_window() {
    let discovery_db = TempDb::new("traffic-lifecycle-new");
    create_discovery_schema(&discovery_db.path);
    let recent = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current timestamp should format");
    let old = (OffsetDateTime::now_utc() - time::Duration::hours(48))
        .format(&Rfc3339)
        .expect("old timestamp should format");
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/recent",
            first_seen: &recent,
            last_seen: &recent,
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 1,
            latency_p95_ms: 1,
            latency_p99_ms: 1,
            distinct_principal_count: 0,
            status_counts: &[(200, 1)],
        },
    );
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/old",
            first_seen: &old,
            last_seen: &old,
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 1,
            latency_p95_ms: 1,
            latency_p99_ms: 1,
            distinct_principal_count: 0,
            status_counts: &[(200, 1)],
        },
    );
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);

    let body = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?new_since_hours=24&sort=first_seen",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_new_flags(&body),
        HashMap::from([("/recent".to_owned(), true), ("/old".to_owned(), false)])
    );

    let only_new = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?is_new=true&new_since_hours=24",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(endpoint_templates(&only_new), vec!["/recent".to_owned()]);
}

#[tokio::test]
async fn traffic_endpoint_new_since_hours_rejects_out_of_range_values_instead_of_panicking() {
    let discovery_db = TempDb::new("traffic-lifecycle-new-since-bounds");
    create_discovery_schema(&discovery_db.path);
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
    let principal = Some(test_principal(&["traffic-reader"]));
    let template = query_encode("/users/{id}");

    for uri in [
            "/v1/admin/traffic/endpoints?new_since_hours=1000000000".to_owned(),
            format!(
                "/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&new_since_hours=1000000000"
            ),
        ] {
            let response = router
                .clone()
                .oneshot(traffic_admin_request(&uri, principal.clone()))
                .await
                .expect("traffic request should complete");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                body_string(response).await,
                r#"{"error":"invalid query parameter: new_since_hours"}"#
            );
        }
}

#[tokio::test]
async fn traffic_endpoint_review_mark_clear_and_write_permission() {
    let discovery_db = TempDb::new("traffic-lifecycle-review");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/reviewed/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 0,
            status_counts: &[(200, 1)],
        },
    );
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let policy = TempPolicyFile::new(&traffic_policy_document_string());
    let router = traffic_admin_router_with_policy_and_audit(
        Some(&discovery_db.path),
        None,
        &policy,
        audit_log,
    );
    let body = json!({
        "method": "GET",
        "endpoint_template": "/reviewed/{id}",
        "reviewed": true
    })
    .to_string();

    let unauthenticated = router
        .clone()
        .oneshot(traffic_admin_json_request(
            Method::POST,
            TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
            None,
            Some(body.clone()),
        ))
        .await
        .expect("traffic review request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let read_only = router
        .clone()
        .oneshot(traffic_admin_json_request(
            Method::POST,
            TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["traffic-reader"])),
            Some(body.clone()),
        ))
        .await
        .expect("traffic review request should complete");
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

    let marked = router
        .clone()
        .oneshot(traffic_admin_json_request(
            Method::POST,
            TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["traffic-writer"])),
            Some(body),
        ))
        .await
        .expect("traffic review request should complete");
    assert_eq!(marked.status(), StatusCode::OK);
    let marked_body = json_body(marked).await;
    assert_eq!(marked_body["reviewed"], json!(true));
    assert!(marked_body["reviewed_at"].as_str().is_some());
    assert_eq!(marked_body["reviewed_by"], json!("user-123"));

    let template = query_encode("/reviewed/{id}");
    let detail = traffic_json(
        &router,
        &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}"),
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(detail["endpoint"]["reviewed"], json!(true));
    assert_eq!(
        detail["endpoint"]["reviewed_at"],
        marked_body["reviewed_at"]
    );
    assert_eq!(detail["endpoint"]["reviewed_by"], json!("user-123"));

    let reviewed_list = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?reviewed=true",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&reviewed_list),
        vec!["/reviewed/{id}".to_owned()]
    );
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::TRAFFIC_ENDPOINT_REVIEW_CHANGED)
    });

    let cleared = router
        .clone()
        .oneshot(traffic_admin_json_request(
            Method::POST,
            TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["traffic-writer"])),
            Some(
                json!({
                    "method": "GET",
                    "endpoint_template": "/reviewed/{id}",
                    "reviewed": false
                })
                .to_string(),
            ),
        ))
        .await
        .expect("traffic review clear request should complete");
    assert_eq!(cleared.status(), StatusCode::OK);
    let cleared_body = json_body(cleared).await;
    assert_eq!(cleared_body["reviewed"], json!(false));
    assert!(cleared_body["reviewed_at"].is_null());
    assert!(cleared_body["reviewed_by"].is_null());

    let unreviewed_list = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?reviewed=false",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&unreviewed_list),
        vec!["/reviewed/{id}".to_owned()]
    );
}

#[tokio::test]
async fn traffic_review_filter_tracks_routing_context_invalidation() {
    let discovery_db = TempDb::new("traffic-review-routing-invalidation");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/review-invalidated/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 0,
            status_counts: &[(200, 1)],
        },
    );
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
    let marked = router
        .clone()
        .oneshot(traffic_admin_json_request(
            Method::POST,
            TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
            Some(test_principal(&["traffic-writer"])),
            Some(
                json!({
                    "method": "GET",
                    "endpoint_template": "/review-invalidated/{id}",
                    "reviewed": true
                })
                .to_string(),
            ),
        ))
        .await
        .expect("traffic review request should complete");
    assert_eq!(marked.status(), StatusCode::OK);

    insert_discovery_routing_context(
        &discovery_db.path,
        "GET",
        "/review-invalidated/{id}",
        "api.example.test",
        "/review-invalidated",
        "https://api.internal",
        1,
        0,
    );
    Connection::open(&discovery_db.path)
        .expect("test discovery database should open")
        .execute(
            r#"
                UPDATE discovery_endpoint_routing_contexts
                SET first_seen = '2099-01-01T00:00:00Z',
                    last_seen = '2099-01-01T00:00:00Z'
                WHERE method = 'GET'
                  AND endpoint_template = '/review-invalidated/{id}'
                "#,
            [],
        )
        .expect("routing context timestamp should update");

    let reviewed = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?reviewed=true",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert!(endpoint_templates(&reviewed).is_empty());

    let unreviewed = traffic_json(
        &router,
        "/v1/admin/traffic/endpoints?reviewed=false",
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(
        endpoint_templates(&unreviewed),
        vec!["/review-invalidated/{id}".to_owned()]
    );
    assert_eq!(unreviewed["endpoints"][0]["reviewed"], json!(false));
}

#[tokio::test]
async fn signals_admin_list_filters_paginates_and_explains() {
    let discovery_db = TempDb::new("signals-list");
    create_signal_schema(&discovery_db.path);
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-open-newer",
            signal_type: "new_endpoint_seen",
            method: "POST",
            endpoint_template: "/widgets",
            explanation:
                "New endpoint observed: POST /widgets was first seen at 2024-06-03T00:00:00Z.",
            evidence: json!({
                "first_seen": "2024-06-03T00:00:00Z",
                "initial_call_count": 1,
                "initial_principal": "alice"
            }),
            state: "open",
            created_at: "2024-06-03T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );
    insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-acknowledged",
                signal_type: "new_endpoint_seen",
                method: "DELETE",
                endpoint_template: "/widgets/{id}",
                explanation: "New endpoint observed: DELETE /widgets/{id} was first seen at 2024-06-02T00:00:00Z.",
                evidence: json!({
                    "first_seen": "2024-06-02T00:00:00Z",
                    "initial_call_count": 1,
                    "initial_principal": "bob"
                }),
                state: "acknowledged",
                created_at: "2024-06-02T00:00:00Z",
                transitioned_at: Some("2024-06-02T01:00:00Z"),
                transitioned_by: Some("reviewer"),
            },
        );
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-open-older",
            signal_type: "new_endpoint_seen",
            method: "GET",
            endpoint_template: "/widgets/{id}",
            explanation:
                "New endpoint observed: GET /widgets/{id} was first seen at 2024-06-01T00:00:00Z.",
            evidence: json!({
                "first_seen": "2024-06-01T00:00:00Z",
                "initial_call_count": 1,
                "initial_principal": "carol"
            }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );
    let (router, _policy) = signals_admin_router(Some(&discovery_db.path));

    let first_page = signals_json(
        &router,
        "/v1/admin/signals?state=open&limit=1",
        Some(test_principal(&["signals-reader"])),
    )
    .await;
    assert_eq!(signal_ids(&first_page), vec!["sig-open-newer".to_owned()]);
    assert!(first_page["next_cursor"].as_str().is_some());
    assert_eq!(first_page["signals"][0]["state"], json!("open"));
    assert_eq!(
        first_page["signals"][0]["target"],
        json!({
            "kind": "endpoint",
            "identity": {
                "method": "POST",
                "endpoint_template": "/widgets"
            }
        })
    );
    assert!(
        first_page["signals"][0]["explanation"]
            .as_str()
            .expect("signal explanation should be a string")
            .contains("POST /widgets"),
        "signal explanation should describe what fired"
    );

    let cursor = first_page["next_cursor"]
        .as_str()
        .expect("first page should include next cursor");
    let second_page = signals_json(
        &router,
        &format!("/v1/admin/signals?state=open&limit=1&cursor={cursor}"),
        Some(test_principal(&["signals-reader"])),
    )
    .await;
    assert_eq!(signal_ids(&second_page), vec!["sig-open-older".to_owned()]);
    assert!(second_page["next_cursor"].is_null());

    let acknowledged = signals_json(
        &router,
        "/v1/admin/signals?state=acknowledged",
        Some(test_principal(&["signals-reader"])),
    )
    .await;
    assert_eq!(
        signal_ids(&acknowledged),
        vec!["sig-acknowledged".to_owned()]
    );

    let target_key = query_encode("GET /widgets/{id}");
    let target_filtered = signals_json(
        &router,
        &format!("/v1/admin/signals?target_kind=endpoint&target_key={target_key}"),
        Some(test_principal(&["signals-reader"])),
    )
    .await;
    assert_eq!(
        signal_ids(&target_filtered),
        vec!["sig-open-older".to_owned()]
    );

    let forbidden = router
        .clone()
        .oneshot(signals_admin_request(
            "/v1/admin/signals",
            Some(test_principal(&["reader"])),
        ))
        .await
        .expect("signals request should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let unauthenticated = router
        .clone()
        .oneshot(signals_admin_request("/v1/admin/signals", None))
        .await
        .expect("signals request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn signals_admin_lifecycle_transitions_persist_and_require_write_permission() {
    let discovery_db = TempDb::new("signals-lifecycle");
    create_signal_schema(&discovery_db.path);
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-ack",
            signal_type: "new_endpoint_seen",
            method: "GET",
            endpoint_template: "/ack/{id}",
            explanation:
                "New endpoint observed: GET /ack/{id} was first seen at 2024-06-01T00:00:00Z.",
            evidence: json!({
                "first_seen": "2024-06-01T00:00:00Z",
                "initial_call_count": 1
            }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-dismiss",
            signal_type: "new_endpoint_seen",
            method: "GET",
            endpoint_template: "/dismiss/{id}",
            explanation:
                "New endpoint observed: GET /dismiss/{id} was first seen at 2024-06-01T01:00:00Z.",
            evidence: json!({
                "first_seen": "2024-06-01T01:00:00Z",
                "initial_call_count": 1
            }),
            state: "open",
            created_at: "2024-06-01T01:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );
    let (router, _policy) = signals_admin_router(Some(&discovery_db.path));

    let unauthenticated = router
        .clone()
        .oneshot(signals_admin_json_request(
            Method::POST,
            "/v1/admin/signals/sig-ack/acknowledge",
            None,
        ))
        .await
        .expect("signals transition request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let read_only = router
        .clone()
        .oneshot(signals_admin_json_request(
            Method::POST,
            "/v1/admin/signals/sig-ack/acknowledge",
            Some(test_principal(&["signals-reader"])),
        ))
        .await
        .expect("signals transition request should complete");
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

    let acknowledged = router
        .clone()
        .oneshot(signals_admin_json_request(
            Method::POST,
            "/v1/admin/signals/sig-ack/acknowledge",
            Some(test_principal(&["signals-writer"])),
        ))
        .await
        .expect("signals transition request should complete");
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let acknowledged_body = json_body(acknowledged).await;
    assert_eq!(acknowledged_body["state"], json!("acknowledged"));
    assert_eq!(acknowledged_body["transitioned_by"], json!("user-123"));
    assert!(acknowledged_body["transitioned_at"].as_str().is_some());

    let dismissed = router
        .clone()
        .oneshot(signals_admin_json_request(
            Method::POST,
            "/v1/admin/signals/sig-dismiss/dismiss",
            Some(test_principal(&["signals-writer"])),
        ))
        .await
        .expect("signals transition request should complete");
    assert_eq!(dismissed.status(), StatusCode::OK);
    let dismissed_body = json_body(dismissed).await;
    assert_eq!(dismissed_body["state"], json!("dismissed"));
    assert_eq!(dismissed_body["transitioned_by"], json!("user-123"));
    assert!(dismissed_body["transitioned_at"].as_str().is_some());

    let acknowledged_page = signals_json(
        &router,
        "/v1/admin/signals?state=acknowledged",
        Some(test_principal(&["signals-reader"])),
    )
    .await;
    assert_eq!(signal_ids(&acknowledged_page), vec!["sig-ack".to_owned()]);
    assert_eq!(
        acknowledged_page["signals"][0]["transitioned_by"],
        json!("user-123")
    );

    let dismissed_page = signals_json(
        &router,
        "/v1/admin/signals?state=dismissed",
        Some(test_principal(&["signals-reader"])),
    )
    .await;
    assert_eq!(signal_ids(&dismissed_page), vec!["sig-dismiss".to_owned()]);
}

/// Dismissal is reachable from `acknowledged`, not only from `open`
/// (issue #241, PR 12): an operator who acknowledged a signal and then
/// decides to clear it must not be told the signal is not open, which
/// would strand it in `acknowledged` forever. The conditional
/// transition still gives exactly one winner -- the second dismiss is
/// refused -- and a stale `If-Match` is still refused.
#[tokio::test]
async fn an_acknowledged_signal_can_still_be_dismissed_and_only_once() {
    let discovery_db = TempDb::new("signals-ack-then-dismiss");
    create_signal_schema(&discovery_db.path);
    insert_signal(
        &discovery_db.path,
        SignalSeed {
            id: "sig-ack",
            signal_type: "new_endpoint_seen",
            method: "GET",
            endpoint_template: "/ack/{id}",
            explanation:
                "New endpoint observed: GET /ack/{id} was first seen at 2024-06-01T00:00:00Z.",
            evidence: json!({
                "first_seen": "2024-06-01T00:00:00Z",
                "initial_call_count": 1
            }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
        },
    );
    let (router, _policy) = signals_admin_router(Some(&discovery_db.path));
    let request = |uri: &str, if_match: Option<&str>| {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-token");
        if let Some(if_match) = if_match {
            builder = builder.header(header::IF_MATCH, if_match);
        }
        let mut request = builder.body(Body::empty()).expect("request should build");
        request
            .extensions_mut()
            .insert(test_principal(&["signals-writer"]));
        request
    };

    let acknowledged = router
        .clone()
        .oneshot(request("/v1/admin/signals/sig-ack/acknowledge", Some("1")))
        .await
        .expect("acknowledge should complete");
    assert_eq!(acknowledged.status(), StatusCode::OK);
    let acknowledged = json_body(acknowledged).await;
    assert_eq!(acknowledged["state"], json!("acknowledged"));
    assert_eq!(acknowledged["revision"], json!(2));

    // The revision predicate still holds over the second from-state.
    let stale = router
        .clone()
        .oneshot(request("/v1/admin/signals/sig-ack/dismiss", Some("1")))
        .await
        .expect("stale dismiss should complete");
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let stale = json_body(stale).await;
    assert_eq!(stale["reason"], json!("signal_revision_mismatch"));
    assert_eq!(stale["signal"]["state"], json!("acknowledged"));
    assert_eq!(stale["signal"]["revision"], json!(2));

    let dismissed = router
        .clone()
        .oneshot(request("/v1/admin/signals/sig-ack/dismiss", Some("2")))
        .await
        .expect("dismiss should complete");
    assert_eq!(dismissed.status(), StatusCode::OK);
    let dismissed = json_body(dismissed).await;
    assert_eq!(dismissed["state"], json!("dismissed"));
    assert_eq!(dismissed["revision"], json!(3));
    assert_eq!(dismissed["transitioned_by"], json!("user-123"));

    // Dismissed is terminal: the predicate accepts open and
    // acknowledged, and nothing else.
    let repeat = router
        .clone()
        .oneshot(request("/v1/admin/signals/sig-ack/dismiss", None))
        .await
        .expect("repeat dismiss should complete");
    assert_eq!(repeat.status(), StatusCode::CONFLICT);
    let repeat = json_body(repeat).await;
    assert_eq!(repeat["reason"], json!("signal_not_open"));
    assert_eq!(repeat["signal"]["revision"], json!(3));

    // Acknowledge still leaves only `open`.
    let reacknowledge = router
        .clone()
        .oneshot(request("/v1/admin/signals/sig-ack/acknowledge", None))
        .await
        .expect("acknowledge of a dismissed signal should complete");
    assert_eq!(reacknowledge.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(reacknowledge).await["reason"],
        json!("signal_not_open")
    );

    let dismissed_page = signals_json(
        &router,
        "/v1/admin/signals?state=dismissed",
        Some(test_principal(&["signals-reader"])),
    )
    .await;
    assert_eq!(signal_ids(&dismissed_page), vec!["sig-ack".to_owned()]);
}

#[tokio::test]
async fn suggestions_admin_list_filters_paginates_and_requires_read_permission() {
    let discovery_db = TempDb::new("suggestions-list");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-open-newer",
            suggestion_type: "baseline_allow",
            method: "POST",
            path_pattern: "/widgets",
            role: Some("writer"),
            action: "allow",
            rationale: "Observed writer calls to POST /widgets.",
            evidence: json!({ "observation_count": 3 }),
            state: "open",
            created_at: "2024-06-03T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-dismissed",
            suggestion_type: "signal_shadow_error_rate_spike",
            method: "GET",
            path_pattern: "/widgets/{id}",
            role: None,
            action: "shadow",
            rationale: "Open error-rate signal targets GET /widgets/{id}.",
            evidence: json!({ "source_signal_id": "sig-error" }),
            state: "dismissed",
            created_at: "2024-06-02T00:00:00Z",
            transitioned_at: Some("2024-06-02T01:00:00Z"),
            transitioned_by: Some("reviewer"),
            source_signal_id: Some("sig-error"),
        },
    );
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-open-older",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/widgets/{id}",
            role: Some("reader"),
            action: "allow",
            rationale: "Observed reader calls to GET /widgets/{id}.",
            evidence: json!({ "observation_count": 5 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let (router, _policy) = suggestions_admin_router(Some(&discovery_db.path), None);

    let first_page = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=open&suggestion_type=baseline_allow&limit=1",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(
        suggestion_ids(&first_page),
        vec!["sug-open-newer".to_owned()]
    );
    assert!(first_page["next_cursor"].as_str().is_some());
    assert_eq!(first_page["suggestions"][0]["state"], json!("open"));
    assert_eq!(
        first_page["suggestions"][0]["proposed_rule"],
        json!({
            "methods": ["POST"],
            "path": "/widgets",
            "principal": {
                "roles": ["writer"],
                "issuers": ["provider:test"],
                "auth_methods": ["bearer_token"],
                "principal_ids": []
            },
            "action": "allow"
        })
    );
    assert_eq!(
        first_page["suggestions"][0]["rationale"],
        json!("Observed writer calls to POST /widgets.")
    );
    assert_eq!(
        first_page["suggestions"][0]["evidence"],
        json!({ "observation_count": 3 })
    );

    let cursor = first_page["next_cursor"]
        .as_str()
        .expect("first page should include next cursor");
    let second_page = suggestions_json(
            &router,
            &format!(
                "/v1/admin/suggestions?state=open&suggestion_type=baseline_allow&limit=1&cursor={cursor}"
            ),
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
    assert_eq!(
        suggestion_ids(&second_page),
        vec!["sug-open-older".to_owned()]
    );
    assert!(second_page["next_cursor"].is_null());

    let dismissed = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=dismissed",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(suggestion_ids(&dismissed), vec!["sug-dismissed".to_owned()]);

    let forbidden = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::GET,
            "/v1/admin/suggestions",
            Some(test_principal(&["reader"])),
            None,
            None,
        ))
        .await
        .expect("suggestions request should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let unauthenticated = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::GET,
            "/v1/admin/suggestions",
            None,
            None,
            None,
        ))
        .await
        .expect("suggestions request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
}

/// Without a suggestion engine (no discovery store configured), the
/// read routes and `generate` answer "not configured" -- after
/// authorization, so nothing leaks to a caller who may not generate.
/// Cluster mode no longer has a separate refusal: its engine is the
/// PostgreSQL one (issue #241, PR 12), exercised by the cluster
/// discovery tests.
#[tokio::test]
async fn suggestions_admin_without_engine_answers_not_configured() {
    let policy = parse_policy_body(&axum::body::Bytes::from(
        suggestions_policy_document_string(),
    ))
    .expect("suggestions policy should parse");
    let rbac_state = middleware::rbac::RbacState::new(policy, Vec::new(), false, test_audit_log());
    let router = Router::new()
        .route(SUGGESTIONS_ADMIN_ROUTE, get(rule_suggestions_list_endpoint))
        .route(
            SUGGESTIONS_GENERATE_ADMIN_ROUTE,
            post(rule_suggestions_generate_endpoint),
        )
        .with_state(SuggestionsAdminState {
            suggestion_engine: None,
            policy: PolicyAdminState {
                policy_file: None,
                rbac_state: Some(rbac_state.clone()),
                history_store: None,
                draft_store: None,
                #[cfg(feature = "postgres")]
                control_plane: None,
                #[cfg(feature = "postgres")]
                membership: None,
                event_store: None,
                query_store: None,
                authority_evidence: authority_events::required::AuthorityEvidenceGate::best_effort(
                ),
                audit: test_audit_log(),
                client_ip_policy: client_ip::ClientIpPolicy::default(),
                max_body_size: 1024 * 1024,
            },
            lifecycle_guard: Arc::new(tokio::sync::Mutex::new(())),
        });
    let not_configured_error = "suggestions API requires DISCOVERY_SQLITE_PATH to be configured";

    let listed = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::GET,
            SUGGESTIONS_ADMIN_ROUTE,
            Some(test_principal(&["suggestions-reader"])),
            None,
            None,
        ))
        .await
        .expect("list request should complete");
    assert_eq!(listed.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(listed).await["error"],
        json!(not_configured_error)
    );

    let forbidden = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            SUGGESTIONS_GENERATE_ADMIN_ROUTE,
            Some(test_principal(&["suggestions-reader"])),
            None,
            None,
        ))
        .await
        .expect("generate request should complete");
    assert_eq!(
        forbidden.status(),
        StatusCode::FORBIDDEN,
        "authorization is judged before the engine is consulted"
    );

    let generated = router
        .oneshot(suggestions_admin_request(
            Method::POST,
            SUGGESTIONS_GENERATE_ADMIN_ROUTE,
            Some(test_principal(&["suggestions-writer"])),
            None,
            None,
        ))
        .await
        .expect("generate request should complete");
    assert_eq!(generated.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(generated).await["error"],
        json!(not_configured_error)
    );
}

#[tokio::test]
async fn suggestions_admin_generate_is_explicit_and_list_does_not_refresh() {
    let discovery_db = TempDb::new("suggestions-generate-discovery");
    let audit_db = TempDb::new("suggestions-generate-audit");
    seed_suggestion_generation_observation(
        &discovery_db.path,
        &audit_db.path,
        "first",
        "GET",
        "/generated/{id}",
        "reader",
        "2024-06-01T12:00:00Z",
    );
    let (router, _policy) =
        suggestions_admin_router(Some(&discovery_db.path), Some(&audit_db.path));

    let initially_empty = suggestions_json(
        &router,
        "/v1/admin/suggestions",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(suggestion_ids(&initially_empty), Vec::<String>::new());

    let generated = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/generate",
            Some(test_principal(&["suggestions-writer"])),
            None,
            None,
        ))
        .await
        .expect("suggestion generation request should complete");
    assert_eq!(generated.status(), StatusCode::OK);
    let generated_body = json_body(generated).await;
    assert_eq!(generated_body["inserted_count"], json!(1));

    seed_suggestion_generation_observation(
        &discovery_db.path,
        &audit_db.path,
        "second",
        "POST",
        "/generated/{id}",
        "writer",
        "2024-06-01T12:01:00Z",
    );
    let after_list_only = suggestions_json(
        &router,
        "/v1/admin/suggestions",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(suggestion_ids(&after_list_only).len(), 1);

    let regenerated = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/generate",
            Some(test_principal(&["suggestions-writer"])),
            None,
            None,
        ))
        .await
        .expect("second generation request should complete");
    assert_eq!(regenerated.status(), StatusCode::OK);
    let regenerated_body = json_body(regenerated).await;
    assert_eq!(regenerated_body["inserted_count"], json!(1));

    let refreshed = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=open",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(suggestion_ids(&refreshed).len(), 2);
}

#[tokio::test]
async fn suggestions_admin_accept_creates_real_rule_requires_both_permissions_and_audits() {
    let discovery_db = TempDb::new("suggestions-accept");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-accept",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/accepted/{id}",
            role: Some("accepted-reader"),
            action: "allow",
            rationale: "Observed accepted-reader calls to GET /accepted/{id}.",
            evidence: json!({ "observation_count": 4 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let router =
        suggestions_admin_router_with_policy(Some(&discovery_db.path), None, &policy, audit_log);

    let current_etag = suggestions_policy_etag(&router).await;

    let suggestion_only = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-accept/accept",
            Some(test_principal(&["suggestions-writer"])),
            None,
            Some(&current_etag),
        ))
        .await
        .expect("suggestion-only accept request should complete");
    assert_eq!(suggestion_only.status(), StatusCode::FORBIDDEN);

    let policy_only = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-accept/accept",
            Some(test_principal(&["policy-writer"])),
            None,
            Some(&current_etag),
        ))
        .await
        .expect("policy-only accept request should complete");
    assert_eq!(policy_only.status(), StatusCode::FORBIDDEN);

    let accepted = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-accept/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&current_etag),
        ))
        .await
        .expect("accept request should complete");
    assert_eq!(accepted.status(), StatusCode::CREATED);
    let accepted_etag = policy_etag_header(&accepted);
    let accepted_body = json_body(accepted).await;
    assert_eq!(accepted_body["suggestion"]["state"], json!("accepted"));
    assert_eq!(accepted_body["rule"]["path"], json!("/accepted/{id}"));
    assert_eq!(accepted_body["rule"]["action"], json!("allow"));
    assert_eq!(
        accepted_body["rule"]["dispatch"],
        json!({ "kind": "contextless" })
    );
    assert_eq!(
        accepted_body["rule"]["principal"]["roles"],
        json!(["accepted-reader"])
    );
    assert_eq!(
        accepted_body["rule"]["principal"]["issuers"],
        json!(["provider:test"])
    );
    assert_eq!(
        accepted_body["rule"]["principal"]["auth_methods"],
        json!(["bearer_token"])
    );
    assert!(accepted_body["rule"]["id"].as_str().is_some());

    let policy_response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            None,
            None,
        ))
        .await
        .expect("policy GET should complete");
    assert_eq!(policy_response.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&policy_response), accepted_etag);
    let policy_body = json_body(policy_response).await;
    assert_eq!(policy_body["rules"].as_array().unwrap().len(), 1);
    assert_eq!(policy_body["rules"][0], accepted_body["rule"]);

    let accepted_page = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=accepted",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(
        suggestion_ids(&accepted_page),
        vec!["sug-accept".to_owned()]
    );
    assert_eq!(
        accepted_page["suggestions"][0]["transitioned_by"],
        json!("user-123")
    );

    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        events
            .iter()
            .any(|event| event.event_type == audit::event::POLICY_CHANGED)
            && events
                .iter()
                .any(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
    });
    let events = capture.events();
    let policy_event = events
        .iter()
        .find(|event| event.event_type == audit::event::POLICY_CHANGED)
        .expect("policy.changed should be emitted");
    assert_eq!(
        policy_event.payload["diff_summary"]["action"],
        json!("rule_created")
    );
    let suggestion_event = events
        .iter()
        .find(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
        .expect("suggestion lifecycle event should be emitted");
    assert_eq!(suggestion_event.payload["id"], json!("sug-accept"));
    assert_eq!(suggestion_event.payload["state"], json!("accepted"));
}

#[tokio::test]
async fn suggestions_admin_dismisses_legacy_unbound_baseline_before_acceptance() {
    let discovery_db = TempDb::new("suggestions-legacy-unbound");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_legacy_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-legacy-unbound",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/legacy/{id}",
            role: Some("legacy-reader"),
            action: "allow",
            rationale: "Legacy role-only baseline suggestion.",
            evidence: json!({ "observation_count": 3 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let before_contents = fs::read_to_string(&policy.path).expect("policy should read");
    let router = suggestions_admin_router_with_policy(
        Some(&discovery_db.path),
        None,
        &policy,
        test_audit_log(),
    );
    let current_etag = suggestions_policy_etag(&router).await;

    let response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-legacy-unbound/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&current_etag),
        ))
        .await
        .expect("legacy suggestion accept request should complete");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    // The refusal carries the row as it is now and a stable reason
    // (issue #241, PR 12), so the caller can see who moved it.
    let refusal = json_body(response).await;
    assert_eq!(refusal["error"], json!("suggestion is not open"));
    assert_eq!(refusal["reason"], json!("suggestion_not_open"));
    assert_eq!(refusal["suggestion"]["state"], json!("dismissed"));
    assert_eq!(refusal["suggestion"]["id"], json!("sug-legacy-unbound"));
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy should read"),
        before_contents
    );
    let dismissed = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=dismissed",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(
        suggestion_ids(&dismissed),
        vec!["sug-legacy-unbound".to_owned()]
    );
    assert_eq!(
        dismissed["suggestions"][0]["transitioned_by"],
        json!("system:issuer-bound-migration")
    );
}

#[tokio::test]
async fn suggestions_admin_accepts_mcp_tool_rule_with_http_fallback_configured() {
    let discovery_db = TempDb::new("suggestions-tool-accept-http-fallback");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-tool-http-fallback",
            suggestion_type: "signal_shadow_schema_mismatch",
            method: "MCP",
            path_pattern: "/mcp/tools/echo",
            role: None,
            action: "shadow",
            rationale: "Observed schema mismatches for the echo tool.",
            evidence: json!({ "schema_mismatch_count": 4 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let mut config = suggestions_admin_config(Some(&discovery_db.path), None, &policy);
    config.upstream_url = Some("https://http-fallback.internal".to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let etag = suggestions_policy_etag(&router).await;

    let accepted = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-tool-http-fallback/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&etag),
        ))
        .await
        .expect("tool suggestion accept should complete");

    assert_eq!(accepted.status(), StatusCode::CREATED);
    let body = json_body(accepted).await;
    assert_eq!(body["suggestion"]["state"], json!("accepted"));
    assert_eq!(body["rule"]["tool_name"], json!("echo"));
    assert!(body["rule"].get("dispatch").is_none());
    assert!(body["rule"].get("path").is_none());
}

#[tokio::test]
async fn accepted_contextless_suggestion_does_not_authorize_new_path_upstream_after_restart() {
    let discovery_db = TempDb::new("suggestions-contextless-restart");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-contextless-restart",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/reports/{id}",
            role: Some("reader"),
            action: "allow",
            rationale: "Observed contextless report traffic.",
            evidence: json!({ "observation_count": 4 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let accepting_router = suggestions_admin_router_with_policy(
        Some(&discovery_db.path),
        None,
        &policy,
        test_audit_log(),
    );
    let etag = suggestions_policy_etag(&accepting_router).await;

    let accepted = accepting_router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-contextless-restart/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&etag),
        ))
        .await
        .expect("contextless suggestion accept should complete");
    assert_eq!(accepted.status(), StatusCode::CREATED);
    let accepted_body = json_body(accepted).await;
    assert_eq!(
        accepted_body["rule"]["dispatch"],
        json!({ "kind": "contextless" })
    );
    drop(accepting_router);

    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut restarted_config = suggestions_admin_config(Some(&discovery_db.path), None, &policy);
    restarted_config.upstream_routes = vec![path_route("/reports", upstream_addr)];
    restarted_config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let restarted_router = app(
        restarted_config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("gateway should restart with the new path dispatch");

    let response = restarted_router
        .oneshot(suggestions_admin_request(
            Method::GET,
            "/reports/123",
            Some(test_principal(&["reader"])),
            None,
            None,
        ))
        .await
        .expect("path-routed request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_upstream_receives_no_request(
        &mut captured,
        "a contextless suggestion rule must not authorize a newly routed upstream",
    )
    .await;
}

#[tokio::test]
async fn accepted_legacy_suggestion_does_not_authorize_same_origin_path_route_after_restart() {
    let discovery_db = TempDb::new("suggestions-legacy-same-origin-restart");
    create_discovery_schema(&discovery_db.path);
    create_rule_suggestion_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/reports/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 1,
            status_counts: &[(200, 1)],
        },
    );
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let upstream_origin = format!("http://{upstream_addr}");
    insert_discovery_routing_context(
        &discovery_db.path,
        "GET",
        "/reports/{id}",
        "",
        "",
        &upstream_origin,
        1,
        1,
    );
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-legacy-same-origin-restart",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/reports/{id}",
            role: Some("reader"),
            action: "allow",
            rationale: "Observed report traffic through the legacy fallback.",
            evidence: json!({ "observation_count": 1 }),
            state: "open",
            created_at: "2024-06-02T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let mut accepting_config = suggestions_admin_config(Some(&discovery_db.path), None, &policy);
    accepting_config.upstream_url = Some(upstream_origin.clone());
    accepting_config.egress_deny_private_ips = false;
    let accepting_recorder = PrometheusBuilder::new().build_recorder();
    let accepting_router = app(
        accepting_config,
        accepting_recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("gateway should start with the legacy fallback");
    let etag = suggestions_policy_etag(&accepting_router).await;

    let accepted = accepting_router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-legacy-same-origin-restart/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&etag),
        ))
        .await
        .expect("legacy suggestion accept should complete");
    assert_eq!(accepted.status(), StatusCode::CREATED);
    let accepted_body = json_body(accepted).await;
    assert_eq!(
        accepted_body["rule"]["dispatch"],
        json!({
            "kind": "legacy",
            "upstream_origin": upstream_origin
        })
    );
    drop(accepting_router);

    let mut restarted_config = suggestions_admin_config(Some(&discovery_db.path), None, &policy);
    restarted_config.upstream_routes = vec![path_route("/reports", upstream_addr)];
    restarted_config.egress_deny_private_ips = false;
    let restarted_recorder = PrometheusBuilder::new().build_recorder();
    let restarted_router = app(
        restarted_config,
        restarted_recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("gateway should restart with a same-origin path route");

    let response = restarted_router
        .oneshot(suggestions_admin_request(
            Method::GET,
            "/reports/123",
            Some(test_principal(&["reader"])),
            None,
            None,
        ))
        .await
        .expect("same-origin path-routed request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_upstream_receives_no_request(
        &mut captured,
        "a legacy suggestion rule must not authorize a path route at the same origin",
    )
    .await;
}

#[tokio::test]
async fn suggestions_admin_rejects_pre_context_open_suggestion_without_policy_mutation() {
    let discovery_db = TempDb::new("suggestions-pre-context-accept");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-pre-context",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/legacy/{id}",
            role: Some("legacy-reader"),
            action: "allow",
            rationale: "Legacy observation without routing classification.",
            evidence: json!({ "observation_count": 4 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    clear_discovery_routing_classification(&discovery_db.path, "GET", "/legacy/{id}");
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let before = fs::read_to_string(&policy.path).expect("policy should read");
    let router = suggestions_admin_router_with_policy(
        Some(&discovery_db.path),
        None,
        &policy,
        test_audit_log(),
    );
    let etag = suggestions_policy_etag(&router).await;

    let response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-pre-context/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&etag),
        ))
        .await
        .expect("pre-context accept request should complete");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await,
        json!({
            "error": "suggestion predates trusted routing context and cannot be accepted; dismiss it and review newly classified traffic"
        })
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy should read"),
        before
    );
    let open_page = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=open",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(
        suggestion_ids(&open_page),
        vec!["sug-pre-context".to_owned()]
    );
}

#[tokio::test]
async fn suggestions_admin_rejects_path_dispatch_without_policy_mutation() {
    let discovery_db = TempDb::new("suggestions-path-dispatch-accept");
    create_discovery_schema(&discovery_db.path);
    create_rule_suggestion_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/tenants/{id}/records",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 1,
            status_counts: &[(200, 1)],
        },
    );
    insert_discovery_routing_context(
        &discovery_db.path,
        "GET",
        "/tenants/{id}/records",
        "",
        "/tenants/1",
        "http://127.0.0.1:41001",
        1,
        1,
    );
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-path-dispatch",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/tenants/{id}/records",
            role: Some("tenant-reader"),
            action: "allow",
            rationale: "Observed tenant reader traffic.",
            evidence: json!({ "observation_count": 1 }),
            state: "open",
            created_at: "2024-06-02T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );

    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let before = fs::read_to_string(&policy.path).expect("policy should read");
    let mut config = suggestions_admin_config(Some(&discovery_db.path), None, &policy);
    config.upstream_routes = vec![path_route(
        "/tenants/1",
        "127.0.0.1:41001"
            .parse()
            .expect("route address should parse"),
    )];
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let etag = suggestions_policy_etag(&router).await;

    let response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-path-dispatch/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&etag),
        ))
        .await
        .expect("path-dispatch accept request should complete");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await,
        json!({
            "error": "suggestion targets path-routed traffic and cannot be accepted as a direct rule"
        })
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy should read"),
        before
    );
    let open_page = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=open",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(
        suggestion_ids(&open_page),
        vec!["sug-path-dispatch".to_owned()]
    );
}

#[tokio::test]
async fn suggestions_admin_rejects_changed_legacy_upstream_without_policy_mutation() {
    let discovery_db = TempDb::new("suggestions-changed-legacy-accept");
    create_discovery_schema(&discovery_db.path);
    create_rule_suggestion_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/reports/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 1,
            status_counts: &[(200, 1)],
        },
    );
    insert_discovery_routing_context(
        &discovery_db.path,
        "GET",
        "/reports/{id}",
        "",
        "",
        "http://127.0.0.1:41001",
        1,
        1,
    );
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-changed-legacy",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/reports/{id}",
            role: Some("report-reader"),
            action: "allow",
            rationale: "Observed report reader traffic on the prior upstream.",
            evidence: json!({ "observation_count": 1 }),
            state: "open",
            created_at: "2024-06-02T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );

    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let before = fs::read_to_string(&policy.path).expect("policy should read");
    let mut config = suggestions_admin_config(Some(&discovery_db.path), None, &policy);
    config.upstream_url = Some("http://127.0.0.1:41002".to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build after legacy upstream change");
    let etag = suggestions_policy_etag(&router).await;

    let response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-changed-legacy/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&etag),
        ))
        .await
        .expect("changed-legacy accept request should complete");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(response).await,
        json!({
            "error": "suggestion spans multiple upstream routing contexts and cannot be accepted as a direct rule"
        })
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy should read"),
        before
    );
    let open_page = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=open",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(
        suggestion_ids(&open_page),
        vec!["sug-changed-legacy".to_owned()]
    );
}

#[tokio::test]
async fn suggestions_admin_accept_surfaces_policy_etag_conflict_without_transition() {
    let discovery_db = TempDb::new("suggestions-accept-conflict");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-stale",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/stale/{id}",
            role: Some("stale-reader"),
            action: "allow",
            rationale: "Observed stale-reader calls to GET /stale/{id}.",
            evidence: json!({ "observation_count": 2 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let router = suggestions_admin_router_with_policy(
        Some(&discovery_db.path),
        None,
        &policy,
        test_audit_log(),
    );
    let stale_etag = suggestions_policy_etag(&router).await;

    let manual_rule = json!({
        "methods": ["POST"],
        "path": "/manual",
        "action": "deny"
    })
    .to_string();
    let manual_response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            Some(test_principal(&["policy-writer"])),
            Some(manual_rule),
            Some(&stale_etag),
        ))
        .await
        .expect("manual policy rule create should complete");
    assert_eq!(manual_response.status(), StatusCode::CREATED);

    let conflict = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-stale/accept",
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            Some(&stale_etag),
        ))
        .await
        .expect("stale accept request should complete");
    assert_eq!(conflict.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        body_string(conflict).await,
        r#"{"error":"If-Match does not match the current policy ETag"}"#
    );

    let open_page = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=open",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(suggestion_ids(&open_page), vec!["sug-stale".to_owned()]);
    assert!(open_page["suggestions"][0]["transitioned_at"].is_null());
}

/// Standalone acceptance and a concurrent dismissal of the same
/// suggestion cannot produce a partial success (issue #241, PR 12; the
/// HA state model's rule 7). One process serves both requests at once,
/// and acceptance is a read, a long policy write, and a transition, so
/// without a lock the dismissal lands in the middle and the deployment
/// keeps an access-granting rule whose suggestion reads `dismissed`.
/// Whichever request wins, the rule and the suggestion agree.
#[tokio::test]
async fn a_concurrent_dismiss_never_leaves_the_rule_installed_for_a_dismissed_suggestion() {
    let discovery_db = TempDb::new("suggestions-accept-dismiss-race");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-race",
            suggestion_type: "baseline_allow",
            method: "GET",
            path_pattern: "/raced/{id}",
            role: Some("raced-reader"),
            action: "allow",
            rationale: "Observed raced-reader calls to GET /raced/{id}.",
            evidence: json!({ "observation_count": 4 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: None,
        },
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let router = suggestions_admin_router_with_policy(
        Some(&discovery_db.path),
        None,
        &policy,
        test_audit_log(),
    );
    let current_etag = suggestions_policy_etag(&router).await;

    let accept = router.clone().oneshot(suggestions_admin_request(
        Method::POST,
        "/v1/admin/suggestions/sug-race/accept",
        Some(test_principal(&["suggestions-policy-writer"])),
        None,
        Some(&current_etag),
    ));
    let dismiss = router.clone().oneshot(suggestions_admin_request(
        Method::POST,
        "/v1/admin/suggestions/sug-race/dismiss",
        Some(test_principal(&["suggestions-writer"])),
        None,
        None,
    ));
    let (accept, dismiss) = tokio::join!(accept, dismiss);
    let accept = accept.expect("accept request should complete");
    let dismiss = dismiss.expect("dismiss request should complete");
    let accept_status = accept.status();
    let dismiss_status = dismiss.status();
    assert!(
        accept_status == StatusCode::CREATED || dismiss_status == StatusCode::OK,
        "one of the two must win: accept={accept_status} dismiss={dismiss_status}"
    );
    assert!(
        accept_status != StatusCode::CREATED || dismiss_status != StatusCode::OK,
        "both cannot win: accept={accept_status} dismiss={dismiss_status}"
    );

    let policy_body = json_body(
        router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete"),
    )
    .await;
    let rules = policy_body["rules"]
        .as_array()
        .expect("rules should be an array");
    let listed = suggestions_json(
        &router,
        "/v1/admin/suggestions",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    let state = listed["suggestions"][0]["state"]
        .as_str()
        .expect("the suggestion should still be listed")
        .to_owned();

    if accept_status == StatusCode::CREATED {
        assert_eq!(state, "accepted");
        assert_eq!(rules.len(), 1, "{policy_body}");
        assert_eq!(rules[0]["path"], json!("/raced/{id}"));
        assert_eq!(dismiss_status, StatusCode::CONFLICT);
    } else {
        assert_eq!(state, "dismissed");
        assert!(
            rules.is_empty(),
            "a dismissed suggestion must not leave its rule installed: {policy_body}"
        );
        assert_eq!(accept_status, StatusCode::CONFLICT);
    }
}

#[tokio::test]
async fn suggestions_admin_dismiss_transitions_requires_write_only_and_audits() {
    let discovery_db = TempDb::new("suggestions-dismiss");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-dismiss",
            suggestion_type: "signal_shadow_schema_mismatch",
            method: "PATCH",
            path_pattern: "/dismiss/{id}",
            role: None,
            action: "shadow",
            rationale: "Open schema mismatch signal targets PATCH /dismiss/{id}.",
            evidence: json!({ "source_signal_id": "sig-schema" }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: Some("sig-schema"),
        },
    );
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let router =
        suggestions_admin_router_with_policy(Some(&discovery_db.path), None, &policy, audit_log);

    let unauthenticated = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-dismiss/dismiss",
            None,
            None,
            None,
        ))
        .await
        .expect("dismiss request should complete");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let read_only = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-dismiss/dismiss",
            Some(test_principal(&["suggestions-reader"])),
            None,
            None,
        ))
        .await
        .expect("dismiss request should complete");
    assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

    let dismissed = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-dismiss/dismiss",
            Some(test_principal(&["suggestions-writer"])),
            None,
            None,
        ))
        .await
        .expect("dismiss request should complete");
    assert_eq!(dismissed.status(), StatusCode::OK);
    let dismissed_body = json_body(dismissed).await;
    assert_eq!(dismissed_body["state"], json!("dismissed"));
    assert_eq!(dismissed_body["transitioned_by"], json!("user-123"));
    assert!(dismissed_body["transitioned_at"].as_str().is_some());

    let dismissed_page = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=dismissed",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(
        suggestion_ids(&dismissed_page),
        vec!["sug-dismiss".to_owned()]
    );

    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
    });
    let event = capture
        .events()
        .into_iter()
        .find(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
        .expect("suggestion lifecycle event should be emitted");
    assert_eq!(event.payload["id"], json!("sug-dismiss"));
    assert_eq!(event.payload["state"], json!("dismissed"));
}

#[tokio::test]
async fn suggestions_admin_dismiss_rejects_non_open_suggestion_without_overwriting_state() {
    let discovery_db = TempDb::new("suggestions-dismiss-non-open");
    create_rule_suggestion_schema(&discovery_db.path);
    insert_rule_suggestion(
        &discovery_db.path,
        RuleSuggestionSeed {
            id: "sug-already-dismissed",
            suggestion_type: "signal_shadow_schema_mismatch",
            method: "PATCH",
            path_pattern: "/dismiss/{id}",
            role: None,
            action: "shadow",
            rationale: "Open schema mismatch signal targets PATCH /dismiss/{id}.",
            evidence: json!({ "source_signal_id": "sig-schema" }),
            state: "dismissed",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: Some("2024-06-02T00:00:00Z"),
            transitioned_by: Some("original-dismisser"),
            source_signal_id: Some("sig-schema"),
        },
    );
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let router =
        suggestions_admin_router_with_policy(Some(&discovery_db.path), None, &policy, audit_log);

    let response = router
        .clone()
        .oneshot(suggestions_admin_request(
            Method::POST,
            "/v1/admin/suggestions/sug-already-dismissed/dismiss",
            Some(test_principal(&["suggestions-writer"])),
            None,
            None,
        ))
        .await
        .expect("dismiss request should complete");
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let page = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=dismissed",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    let suggestion = page["suggestions"]
        .as_array()
        .expect("suggestions array should exist")
        .iter()
        .find(|suggestion| suggestion["id"] == json!("sug-already-dismissed"))
        .expect("suggestion should still exist");
    assert_eq!(
        suggestion["transitioned_by"],
        json!("original-dismisser"),
        "rejected dismiss must not overwrite the original transition metadata"
    );
    assert_eq!(suggestion["transitioned_at"], json!("2024-06-02T00:00:00Z"));

    assert!(
        capture
            .events()
            .iter()
            .all(|event| event.event_type != audit::event::SUGGESTION_LIFECYCLE_CHANGED),
        "a rejected dismiss must not emit a lifecycle-changed audit event"
    );
}

#[test]
fn endpoint_rule_coverage_without_rules_is_none() {
    let policy = policy_eval::CompiledPolicy::for_analysis(
        serde_json::from_value(json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": {}
        }))
        .expect("policy should parse"),
    );
    let contextless = discovery::query::EndpointRoutingContext {
        route_host: None,
        route_path_prefix: None,
        upstream_origin: None,
        first_seen: "2024-06-01T12:00:00Z".to_owned(),
        last_seen: "2024-06-01T12:00:00Z".to_owned(),
        call_count: 1,
        distinct_principal_count: 1,
        covered_by_rule: false,
        coverage_scope: discovery::query::EndpointCoverageScope::None,
    };
    assert_eq!(
        endpoint_coverage_scope(&policy, "GET", "/anything/{id}", Some(&contextless)),
        discovery::query::EndpointCoverageScope::None
    );
    // With no routing context recorded at all the evaluator is missing the
    // dispatch fact, so coverage is unknown rather than none.
    assert_eq!(
        endpoint_coverage_scope(&policy, "GET", "/anything/{id}", None),
        discovery::query::EndpointCoverageScope::Unknown
    );
}

#[tokio::test]
async fn traffic_endpoint_detail_paginates_principals() {
    let discovery_db = TempDb::new("traffic-principals");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/users/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-03T00:00:00Z",
            call_count: 75,
            latency_count: 75,
            latency_p50_ms: 10,
            latency_p95_ms: 30,
            latency_p99_ms: 50,
            distinct_principal_count: 75,
            status_counts: &[(200, 75)],
        },
    );
    for index in 0..75 {
        insert_discovery_principal(
            &discovery_db.path,
            "GET",
            "/users/{id}",
            &format!("user-{index:03}"),
            "2024-06-01T00:00:00Z",
            &format!("2024-06-03T00:{:02}:00Z", index % 60),
        );
    }
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
    let template = query_encode("/users/{id}");

    let first_page = traffic_json(
        &router,
        &format!(
            "/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&principal_limit=10"
        ),
        Some(test_principal(&["traffic-reader"])),
    )
    .await;
    assert_eq!(first_page["endpoint"]["call_count"], json!(75));
    let first_principals = principal_ids(&first_page);
    assert_eq!(first_principals.len(), 10);
    assert_eq!(first_principals[0], "user-059");
    assert_eq!(first_principals[9], "user-050");
    assert!(first_page["principals"]["next_cursor"].as_str().is_some());
    assert_eq!(first_page["audit"]["available"], json!(false));
    assert!(first_page["audit"].get("time_series").is_none());
    assert!(first_page["audit"].get("recent_events").is_none());

    let cursor = first_page["principals"]["next_cursor"]
        .as_str()
        .expect("principal page should include next cursor");
    let second_page = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&principal_limit=10&principal_cursor={cursor}"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
    let second_principals = principal_ids(&second_page);
    assert_eq!(second_principals[0], "user-049");
    assert_eq!(second_principals[9], "user-040");
}

#[tokio::test]
async fn traffic_endpoint_detail_enriches_from_audit_for_stateless_id_templates() {
    let discovery_db = TempDb::new("traffic-detail-discovery");
    let audit_db = TempDb::new("traffic-detail-audit");
    emit_observed_events_to_discovery_and_audit(
        &discovery_db.path,
        &audit_db.path,
        &[
            observed_request_event(
                "GET",
                "/users/123",
                200,
                10,
                Some("alice"),
                "2024-06-01T00:05:00Z",
            ),
            observed_request_event(
                "GET",
                "/users/456",
                404,
                20,
                Some("bob"),
                "2024-06-01T00:40:00Z",
            ),
            observed_request_event(
                "GET",
                "/users/789",
                200,
                30,
                Some("alice"),
                "2024-06-01T01:10:00Z",
            ),
            observed_request_event(
                "POST",
                "/users/123",
                201,
                40,
                Some("alice"),
                "2024-06-01T01:20:00Z",
            ),
        ],
    );
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), Some(&audit_db.path));
    let template = query_encode("/users/{id}");

    let body = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&from=2024-06-01T00:00:00Z&to=2024-06-01T02:00:00Z&bucket=hour&events_limit=2"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;

    assert_eq!(body["endpoint"]["call_count"], json!(3));
    assert_eq!(body["endpoint"]["status_counts"][0]["status"], json!(200));
    assert_eq!(body["endpoint"]["status_counts"][0]["count"], json!(2));
    assert_eq!(
        body["principals"]["principals"].as_array().unwrap().len(),
        2
    );
    assert_eq!(body["audit"]["available"], json!(true));
    assert_eq!(
        body["audit"]["match_strategy"],
        json!(audit::query::ENDPOINT_AUDIT_MATCH_STRATEGY)
    );
    assert_eq!(
        body["audit"]["time_series"],
        json!([
            { "bucket_start": "2024-06-01T00:00:00Z", "count": 2 },
            { "bucket_start": "2024-06-01T01:00:00Z", "count": 1 }
        ])
    );
    assert_eq!(body["audit"]["time_series_truncated"], json!(false));
    let recent_paths = body["audit"]["recent_events"]
        .as_array()
        .expect("recent events should be present")
        .iter()
        .map(|event| event["path"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        recent_paths,
        vec!["/users/789".to_owned(), "/users/456".to_owned()]
    );
    assert_eq!(body["audit"]["recent_events_scan_truncated"], json!(false));
    assert!(body["audit"]["recent_events_next_cursor"]
        .as_i64()
        .is_some());
}

#[tokio::test]
async fn traffic_endpoint_detail_documents_learned_param_reverse_mapping_limit() {
    let discovery_db = TempDb::new("traffic-learned-discovery");
    let audit_db = TempDb::new("traffic-learned-audit");
    emit_observed_events_to_discovery_and_audit(
        &discovery_db.path,
        &audit_db.path,
        &["apple", "banana", "cherry", "date"]
            .into_iter()
            .enumerate()
            .map(|(index, slug)| {
                observed_request_event(
                    "GET",
                    &format!("/catalog/{slug}"),
                    200,
                    10,
                    Some("alice"),
                    &format!("2024-06-01T00:0{index}:00Z"),
                )
            })
            .collect::<Vec<_>>(),
    );
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), Some(&audit_db.path));
    let template = query_encode("/catalog/{param}");

    let body = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&from=2024-06-01T00:00:00Z&to=2024-06-01T01:00:00Z"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;

    assert_eq!(body["endpoint"]["call_count"], json!(4));
    assert_eq!(body["audit"]["available"], json!(true));
    assert_eq!(body["audit"]["time_series"], json!([]));
    assert_eq!(body["audit"]["recent_events"], json!([]));
    assert!(body["audit"]["match_limitations"]
        .as_str()
        .expect("match limitation should be present")
        .contains("learned slug templates"));
}

#[tokio::test]
async fn traffic_endpoint_inventory_requires_discovery_sqlite_path() {
    let (router, _policy) = traffic_admin_router(None, None);
    let principal = Some(test_principal(&["traffic-reader"]));

    for uri in [
        "/v1/admin/traffic/endpoints",
        "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D",
    ] {
        let response = router
            .clone()
            .oneshot(traffic_admin_request(uri, principal.clone()))
            .await
            .expect("traffic request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"traffic endpoint inventory requires DISCOVERY_SQLITE_PATH to be configured"}"#
        );
    }
}

#[tokio::test]
async fn traffic_endpoint_detail_omits_audit_enrichment_when_audit_sqlite_path_is_unset() {
    let discovery_db = TempDb::new("traffic-no-audit");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/users/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 0,
            status_counts: &[(200, 1)],
        },
    );
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
    let template = query_encode("/users/{id}");

    let body = traffic_json(
        &router,
        &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}"),
        Some(test_principal(&["traffic-reader"])),
    )
    .await;

    assert_eq!(body["endpoint"]["call_count"], json!(1));
    assert_eq!(body["audit"]["available"], json!(false));
    assert_eq!(
        body["audit"]["omitted_reason"],
        json!("AUDIT_SQLITE_PATH not configured")
    );
    assert!(body["audit"].get("time_series").is_none());
    assert!(body["audit"].get("recent_events").is_none());
}

#[tokio::test]
async fn traffic_endpoint_admin_reports_rbac_not_configured() {
    let discovery_db = TempDb::new("traffic-rbac-unconfigured");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/users/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 0,
            status_counts: &[(200, 1)],
        },
    );
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let detail_uri = "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D";

    for uri in ["/v1/admin/traffic/endpoints", detail_uri] {
        let response = router
            .clone()
            .oneshot(traffic_admin_request(
                uri,
                Some(test_principal(&["traffic-reader"])),
            ))
            .await
            .expect("traffic request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"traffic endpoint inventory requires POLICY_FILE to be configured"}"#
        );
    }
}

#[tokio::test]
async fn traffic_endpoint_admin_requires_traffic_read_permission() {
    let discovery_db = TempDb::new("traffic-authz");
    create_discovery_schema(&discovery_db.path);
    insert_discovery_endpoint(
        &discovery_db.path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/users/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-01T01:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 0,
            status_counts: &[(200, 1)],
        },
    );
    let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
    let detail_uri = "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D";

    for uri in ["/v1/admin/traffic/endpoints", detail_uri] {
        let unauthenticated = router
            .clone()
            .oneshot(traffic_admin_request(uri, None))
            .await
            .expect("traffic request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let forbidden_response = router
            .clone()
            .oneshot(traffic_admin_request(
                uri,
                Some(test_principal(&["reader"])),
            ))
            .await
            .expect("traffic request should complete");
        assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
    }
}

fn audit_query_config(sqlite_path: Option<&PathBuf>) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.audit_sqlite_path = sqlite_path.map(|path| path.to_string_lossy().into_owned());
    config
}

fn audit_query_config_with_policy(
    sqlite_path: Option<&PathBuf>,
    policy: &TempPolicyFile,
) -> config::Config {
    let mut config = audit_query_config(sqlite_path);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push(AUDIT_ADMIN_ROUTE.to_owned());
    config
        .rbac_exempt_paths
        .push(AUDIT_EVENTS_STREAM_ROUTE.to_owned());

    config
}

fn audit_query_router(sqlite_path: Option<&PathBuf>) -> (Router, TempPolicyFile) {
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        audit_query_config_with_policy(sqlite_path, &policy),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    (router, policy)
}

fn principal_admin_config(
    principal_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
    discovery_path: Option<&PathBuf>,
    policy: &TempPolicyFile,
) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.principal_sqlite_path = principal_path.map(|path| path.to_string_lossy().into_owned());
    config.audit_sqlite_path = audit_path.map(|path| path.to_string_lossy().into_owned());
    config.discovery_sqlite_path = discovery_path.map(|path| path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push("/v1/admin/principals".to_owned());
    config
        .rbac_exempt_paths
        .push("/v1/admin/principal".to_owned());
    config
}

fn principal_admin_router(
    principal_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
    discovery_path: Option<&PathBuf>,
) -> (Router, TempPolicyFile) {
    let policy = TempPolicyFile::new(&principal_policy_document_string());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        principal_admin_config(principal_path, audit_path, discovery_path, &policy),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    (router, policy)
}

fn principal_admin_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

fn principal_admin_bearer_request(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("principal admin bearer request should build")
}

async fn principal_json(router: &Router, uri: &str, principal: Option<auth::Principal>) -> Value {
    let response = router
        .clone()
        .oneshot(principal_admin_request(uri, principal))
        .await
        .expect("principal admin request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn wait_for_principal_detail_json(
    router: &Router,
    uri: &str,
    token: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Value {
    let started = Instant::now();

    loop {
        let response = router
            .clone()
            .oneshot(principal_admin_bearer_request(uri, token))
            .await
            .expect("principal detail request should complete");
        let status = response.status();
        if status != StatusCode::OK {
            panic!(
                "principal detail request returned {status}: {}",
                body_string(response).await
            );
        }
        let body = json_body(response).await;
        if predicate(&body) {
            return body;
        }

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "principal detail did not match condition within async flush window: {body}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn principal_policy_document_string() -> String {
    serde_json::to_string_pretty(&json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "principal-reader": {
                "permissions": ["admin:principals:read"]
            },
            "principal-writer": {
                "permissions": [ADMIN_PRINCIPALS_WRITE_PERMISSION]
            },
            "reader": {
                "permissions": []
            }
        },
        "rules": []
    }))
    .expect("principal policy should serialize")
}

fn principal_full_stack_policy_document_string() -> String {
    serde_json::to_string_pretty(&json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "principal-reader": {
                "permissions": ["admin:principals:read"]
            },
            "member": {
                "permissions": []
            }
        },
        "rules": [
            direct_rule_json(Some("allow-probe"), &["GET"], "/__test/principal", "allow")
        ]
    }))
    .expect("principal full-stack policy should serialize")
}

fn traffic_admin_config(
    discovery_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
    policy: &TempPolicyFile,
) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.discovery_sqlite_path = discovery_path.map(|path| path.to_string_lossy().into_owned());
    config.audit_sqlite_path = audit_path.map(|path| path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(TRAFFIC_ENDPOINTS_ADMIN_ROUTE.to_owned());
    config
        .rbac_exempt_paths
        .push(TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE.to_owned());
    config
        .rbac_exempt_paths
        .push(TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE.to_owned());
    config
}

fn traffic_admin_router(
    discovery_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
) -> (Router, TempPolicyFile) {
    let policy = TempPolicyFile::new(&traffic_policy_document_string());
    let router = traffic_admin_router_with_policy(discovery_path, audit_path, &policy);

    (router, policy)
}

fn traffic_admin_router_with_policy(
    discovery_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
    policy: &TempPolicyFile,
) -> Router {
    traffic_admin_router_with_policy_and_audit(discovery_path, audit_path, policy, test_audit_log())
}

fn traffic_admin_router_with_policy_and_audit(
    discovery_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        traffic_admin_config(discovery_path, audit_path, policy),
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
}

fn traffic_admin_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

fn traffic_admin_json_request(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Option<String>,
) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        builder = builder
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-token");
    }

    let mut request = builder
        .body(Body::from(body.unwrap_or_default()))
        .expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

async fn traffic_json(router: &Router, uri: &str, principal: Option<auth::Principal>) -> Value {
    let response = router
        .clone()
        .oneshot(traffic_admin_request(uri, principal))
        .await
        .expect("traffic request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn wait_for_traffic_json(
    router: &Router,
    uri: &str,
    condition: impl Fn(&Value) -> bool,
) -> Value {
    let started = Instant::now();

    loop {
        let body = traffic_json(router, uri, Some(test_principal(&["traffic-reader"]))).await;
        if condition(&body) {
            return body;
        }

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "traffic response did not match condition within reload window: {body}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn traffic_policy_document_string() -> String {
    traffic_policy_document_with_rules(json!([]))
}

fn traffic_policy_document_with_rules(rules: Value) -> String {
    serde_json::to_string_pretty(&json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "traffic-reader": {
                "permissions": [ADMIN_TRAFFIC_READ_PERMISSION]
            },
            "traffic-and-signals-reader": {
                "permissions": [
                    ADMIN_TRAFFIC_READ_PERMISSION,
                    ADMIN_SIGNALS_READ_PERMISSION
                ]
            },
            "traffic-writer": {
                "permissions": [
                    ADMIN_TRAFFIC_READ_PERMISSION,
                    ADMIN_TRAFFIC_WRITE_PERMISSION
                ]
            },
            "reader": {
                "permissions": []
            }
        },
        "rules": rules
    }))
    .expect("traffic policy should serialize")
}

fn signals_admin_config(
    discovery_path: Option<&PathBuf>,
    policy: &TempPolicyFile,
) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.discovery_sqlite_path = discovery_path.map(|path| path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push("/v1/admin/signals".to_owned());
    config
}

fn signals_admin_router(discovery_path: Option<&PathBuf>) -> (Router, TempPolicyFile) {
    let policy = TempPolicyFile::new(&signals_policy_document_string());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        signals_admin_config(discovery_path, &policy),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    (router, policy)
}

fn signals_admin_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
    let mut request = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

fn signals_admin_json_request(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer test-token")
        .body(Body::empty())
        .expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }

    request
}

async fn signals_json(router: &Router, uri: &str, principal: Option<auth::Principal>) -> Value {
    let response = router
        .clone()
        .oneshot(signals_admin_request(uri, principal))
        .await
        .expect("signals request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

fn signal_ids(body: &Value) -> Vec<String> {
    body["signals"]
        .as_array()
        .expect("signals should be an array")
        .iter()
        .map(|signal| {
            signal["id"]
                .as_str()
                .expect("signal id should be a string")
                .to_owned()
        })
        .collect()
}

fn signals_policy_document_string() -> String {
    serde_json::to_string_pretty(&json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "admin": {
                "permissions": [ADMIN_AUDIT_STREAM_PERMISSION]
            },
            "signals-reader": {
                "permissions": ["admin:signals:read"]
            },
            "signals-writer": {
                "permissions": [
                    "admin:signals:read",
                    "admin:signals:write"
                ]
            },
            "reader": {
                "permissions": []
            }
        },
        "rules": []
    }))
    .expect("signals policy should serialize")
}

fn suggestions_admin_router(
    discovery_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
) -> (Router, TempPolicyFile) {
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let router =
        suggestions_admin_router_with_policy(discovery_path, audit_path, &policy, test_audit_log());

    (router, policy)
}

fn suggestions_admin_router_with_policy(
    discovery_path: Option<&PathBuf>,
    audit_path: Option<&PathBuf>,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        suggestions_admin_config(discovery_path, audit_path, policy),
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
}

fn audit_events_router() -> (Router, audit::AuditLog, TempPolicyFile) {
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(AUDIT_EVENTS_STREAM_ROUTE.to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let (audit_log, audit_event_sender) = test_audit_log_with_broadcast();
    let router = app(
        config,
        recorder.handle(),
        audit_log.clone(),
        audit_event_sender,
    )
    .expect("app should build");

    (router, audit_log, policy)
}

fn schema_coverage_router(
    spec: Option<&TempSpecFile>,
    discovery_db: Option<&TempDb>,
    policy: &TempPolicyFile,
) -> Router {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(SCHEMA_COVERAGE_ADMIN_ROUTE.to_owned());
    config.openapi_spec_path = spec.map(|spec| spec.path.clone());
    config.discovery_sqlite_path = discovery_db.map(|db| db.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();

    app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
}

fn schema_inference_router(
    discovery_db: Option<&TempDb>,
    payload_capture_enabled: bool,
    policy: &TempPolicyFile,
) -> Router {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(SCHEMA_INFERRED_ADMIN_ROUTE.to_owned());
    config.discovery_sqlite_path = discovery_db.map(|db| db.path.to_string_lossy().into_owned());
    config.payload_capture_enabled = payload_capture_enabled;
    let recorder = PrometheusBuilder::new().build_recorder();

    app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
}

/// A stream request as the authentication middleware passes it on: the
/// principal, and beside it the credential the stream re-checks for as long
/// as it stays open -- here one whose authority keeps accepting it.
fn audit_stream_request(uri: &str, principal: auth::Principal) -> Request<Body> {
    let mut request = audit_query_request(uri, Some(principal.clone()));
    request
        .extensions_mut()
        .insert(accepted_reauthentication(principal));
    request
}

/// An authority that accepts every credential as `principal`.
struct AcceptingAuthority(auth::Principal);

#[async_trait::async_trait]
impl auth::SessionValidator for AcceptingAuthority {
    async fn validate_session(
        &self,
        _credential: &auth::SessionCredential,
    ) -> Result<auth::Principal, auth::AuthError> {
        Ok(self.0.clone())
    }
}

fn accepted_reauthentication(principal: auth::Principal) -> auth::Reauthentication {
    auth::Reauthentication::new(
        auth::CredentialJudge::Validator(Arc::new(AcceptingAuthority(principal))),
        auth::SessionCredential::Bearer(format!("test-{}", uuid::Uuid::new_v4())),
        None,
    )
}

fn schema_policy_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "schema-policy",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "schema-reader": {
                "permissions": [ADMIN_SCHEMA_READ_PERMISSION]
            },
            "reader": {
                "permissions": []
            }
        }
    })
    .to_string()
}

async fn status_json(router: Router, principal: Option<auth::Principal>) -> Value {
    let response = router
        .oneshot(audit_query_request(STATUS_ADMIN_ROUTE, principal))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await
}

async fn read_sse_until(body: Body, predicate: impl Fn(&str) -> bool) -> String {
    let mut stream = body.into_data_stream();

    tokio::time::timeout(Duration::from_secs(2), async move {
        let mut body = String::new();

        while body.len() < 65_536 {
            let Some(chunk) = stream.next().await else {
                panic!("SSE stream ended before expected event arrived");
            };
            let chunk = chunk.expect("SSE chunk should read");
            body.push_str(std::str::from_utf8(&chunk).expect("SSE chunk should be UTF-8"));

            if predicate(&body) {
                return body;
            }
        }

        panic!("SSE stream exceeded bounded read without expected event");
    })
    .await
    .expect("SSE event should arrive before timeout")
}

fn emit_burst(audit_log: &audit::AuditLog, event: &audit::AuditEvent, count: usize) -> Duration {
    let started = Instant::now();

    for _ in 0..count {
        audit_log.emit(event.clone());
    }

    started.elapsed()
}

async fn audit_event_ids(router: Router, uri: &str) -> Vec<String> {
    let response = router
        .oneshot(audit_query_request(
            uri,
            Some(test_principal(&["audit-reader"])),
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    event_ids_from_body(&json_body(response).await)
}

async fn wait_for_audit_query_event(router: Router, uri: &str, request_id: &str) -> Value {
    let started = Instant::now();

    loop {
        let response = router
            .clone()
            .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
            .await
            .expect("audit query request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let found = body["events"]
            .as_array()
            .expect("events should be an array")
            .iter()
            .any(|event| event["request_id"] == json!(request_id));
        if found {
            return body;
        }

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "audit query did not return event with request_id {request_id}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn event_ids_from_body(body: &Value) -> Vec<String> {
    body["events"]
        .as_array()
        .expect("events should be an array")
        .iter()
        .map(|event| {
            event["event_id"]
                .as_str()
                .expect("event_id should be a string")
                .to_owned()
        })
        .collect()
}

fn endpoint_templates(body: &Value) -> Vec<String> {
    body["endpoints"]
        .as_array()
        .expect("endpoints should be an array")
        .iter()
        .map(|endpoint| {
            endpoint["endpoint_template"]
                .as_str()
                .expect("endpoint_template should be a string")
                .to_owned()
        })
        .collect()
}

fn endpoint_coverage(body: &Value) -> HashMap<String, bool> {
    body["endpoints"]
        .as_array()
        .expect("endpoints should be an array")
        .iter()
        .map(|endpoint| {
            (
                endpoint["endpoint_template"]
                    .as_str()
                    .expect("endpoint_template should be a string")
                    .to_owned(),
                endpoint["covered_by_rule"]
                    .as_bool()
                    .expect("covered_by_rule should be a boolean"),
            )
        })
        .collect()
}

fn endpoint_coverage_scopes(body: &Value) -> HashMap<String, String> {
    body["endpoints"]
        .as_array()
        .expect("endpoints should be an array")
        .iter()
        .map(|endpoint| {
            (
                endpoint["endpoint_template"]
                    .as_str()
                    .expect("endpoint_template should be a string")
                    .to_owned(),
                endpoint["coverage_scope"]
                    .as_str()
                    .expect("coverage_scope should be a string")
                    .to_owned(),
            )
        })
        .collect()
}

fn endpoint_new_flags(body: &Value) -> HashMap<String, bool> {
    body["endpoints"]
        .as_array()
        .expect("endpoints should be an array")
        .iter()
        .map(|endpoint| {
            (
                endpoint["endpoint_template"]
                    .as_str()
                    .expect("endpoint_template should be a string")
                    .to_owned(),
                endpoint["is_new"]
                    .as_bool()
                    .expect("is_new should be a boolean"),
            )
        })
        .collect()
}

fn principal_subjects(body: &Value) -> Vec<String> {
    body["principals"]
        .as_array()
        .expect("principals should be an array")
        .iter()
        .map(|principal| {
            principal["subject"]
                .as_str()
                .expect("subject should be a string")
                .to_owned()
        })
        .collect()
}

fn principal_detail_endpoint_paths(body: &Value) -> Vec<(String, String)> {
    body["endpoints_touched"]
        .as_array()
        .expect("endpoints_touched should be an array")
        .iter()
        .map(|endpoint| {
            (
                endpoint["method"]
                    .as_str()
                    .expect("endpoint method should be a string")
                    .to_owned(),
                endpoint["path"]
                    .as_str()
                    .expect("endpoint path should be a string")
                    .to_owned(),
            )
        })
        .collect()
}

fn principal_detail_rule_ids(body: &Value) -> Vec<String> {
    body["rules_hit"]
        .as_array()
        .expect("rules_hit should be an array")
        .iter()
        .map(|rule_id| {
            rule_id
                .as_str()
                .expect("rule id should be a string")
                .to_owned()
        })
        .collect()
}

fn principal_detail_signal_ids(body: &Value) -> Vec<String> {
    body["anomaly_history"]
        .as_array()
        .expect("anomaly_history should be an array")
        .iter()
        .map(|signal| {
            signal["id"]
                .as_str()
                .expect("signal id should be a string")
                .to_owned()
        })
        .collect()
}

fn create_signal_schema(path: &PathBuf) {
    let connection = Connection::open(path).expect("test discovery database should open");
    connection
        .execute_batch(
            r#"
                CREATE TABLE IF NOT EXISTS discovery_signals (
                    id TEXT PRIMARY KEY,
                    signal_type TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    target_identity_json TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    transitioned_at TEXT,
                    transitioned_by TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_signals_identity
                ON discovery_signals(signal_type, target_kind, target_key);

                CREATE INDEX IF NOT EXISTS idx_discovery_signals_state_created
                ON discovery_signals(state, created_at, id);
                "#,
        )
        .expect("signal schema should create");
}

fn insert_legacy_rule_suggestion(path: &PathBuf, suggestion: RuleSuggestionSeed<'_>) {
    insert_rule_suggestion_with_identity_binding(path, suggestion, false);
}

fn seed_suggestion_generation_observation(
    discovery_path: &PathBuf,
    audit_path: &PathBuf,
    event_id: &str,
    method: &str,
    endpoint_template: &str,
    role: &str,
    timestamp: &str,
) {
    create_discovery_schema(discovery_path);
    insert_discovery_endpoint(
        discovery_path,
        SeedEndpoint {
            method,
            endpoint_template,
            first_seen: timestamp,
            last_seen: timestamp,
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 10,
            latency_p95_ms: 10,
            latency_p99_ms: 10,
            distinct_principal_count: 1,
            status_counts: &[(200, 1)],
        },
    );
    create_audit_schema(audit_path);
    let connection = Connection::open(audit_path).expect("test audit database should open");
    let actor_json = json!({
        "user_id": format!("user-{event_id}"),
        "issuer": "provider:test",
        "roles": [role],
        "auth_mode": "bearer_token"
    })
    .to_string();
    let payload_json = json!({
        "method": method,
        "path": concrete_path_for_template(endpoint_template),
        "status": 200,
        "policy_decision": "allowed",
        "routing_context_known": true
    })
    .to_string();

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
                    payload_json
                ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', ?4, ?5, ?6, ?7, 200, ?8)
                "#,
                params![
                    event_id,
                    timestamp,
                    format!("request-{event_id}"),
                    format!("user-{event_id}"),
                    actor_json,
                    method,
                    concrete_path_for_template(endpoint_template),
                    payload_json,
                ],
            )
            .expect("audit observation should insert");
}

fn concrete_path_for_template(endpoint_template: &str) -> String {
    endpoint_template.replace("{id}", "123")
}

fn seed_list_discovery_endpoints(path: &PathBuf) {
    insert_discovery_endpoint(
        path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/users/{id}",
            first_seen: "2024-06-01T00:00:00Z",
            last_seen: "2024-06-03T12:00:00Z",
            call_count: 25,
            latency_count: 25,
            latency_p50_ms: 12,
            latency_p95_ms: 40,
            latency_p99_ms: 60,
            distinct_principal_count: 2,
            status_counts: &[(200, 20), (404, 5)],
        },
    );
    insert_discovery_endpoint(
        path,
        SeedEndpoint {
            method: "POST",
            endpoint_template: "/users",
            first_seen: "2024-06-02T00:00:00Z",
            last_seen: "2024-06-02T12:00:00Z",
            call_count: 5,
            latency_count: 5,
            latency_p50_ms: 20,
            latency_p95_ms: 30,
            latency_p99_ms: 30,
            distinct_principal_count: 1,
            status_counts: &[(201, 5)],
        },
    );
    insert_discovery_endpoint(
        path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/reports/{id}",
            first_seen: "2024-05-30T00:00:00Z",
            last_seen: "2024-05-31T12:00:00Z",
            call_count: 100,
            latency_count: 100,
            latency_p50_ms: 50,
            latency_p95_ms: 90,
            latency_p99_ms: 120,
            distinct_principal_count: 3,
            status_counts: &[(200, 80), (500, 20)],
        },
    );
    insert_discovery_endpoint(
        path,
        SeedEndpoint {
            method: "GET",
            endpoint_template: "/admin/status",
            first_seen: "2024-06-04T00:00:00Z",
            last_seen: "2024-06-04T12:00:00Z",
            call_count: 1,
            latency_count: 1,
            latency_p50_ms: 5,
            latency_p95_ms: 5,
            latency_p99_ms: 5,
            distinct_principal_count: 1,
            status_counts: &[(204, 1)],
        },
    );
}

struct SignalSeed<'a> {
    id: &'a str,
    signal_type: &'a str,
    method: &'a str,
    endpoint_template: &'a str,
    explanation: &'a str,
    evidence: Value,
    state: &'a str,
    created_at: &'a str,
    transitioned_at: Option<&'a str>,
    transitioned_by: Option<&'a str>,
}

fn insert_signal(path: &PathBuf, signal: SignalSeed<'_>) {
    let connection = Connection::open(path).expect("test discovery database should open");
    let target_identity_json = serde_json::to_string(&json!({
        "method": signal.method,
        "endpoint_template": signal.endpoint_template,
    }))
    .expect("target identity should serialize");
    let evidence_json = serde_json::to_string(&signal.evidence).expect("evidence should serialize");
    let target_key = format!("{} {}", signal.method, signal.endpoint_template);

    connection
        .execute(
            r#"
                INSERT INTO discovery_signals (
                    id,
                    signal_type,
                    target_kind,
                    target_key,
                    target_identity_json,
                    explanation,
                    evidence_json,
                    state,
                    created_at,
                    updated_at,
                    transitioned_at,
                    transitioned_by
                ) VALUES (?1, ?2, 'endpoint', ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10)
                "#,
            params![
                signal.id,
                signal.signal_type,
                target_key,
                target_identity_json,
                signal.explanation,
                evidence_json,
                signal.state,
                signal.created_at,
                signal.transitioned_at,
                signal.transitioned_by,
            ],
        )
        .expect("signal should insert");
}

struct SeedEndpoint<'a> {
    method: &'a str,
    endpoint_template: &'a str,
    first_seen: &'a str,
    last_seen: &'a str,
    call_count: i64,
    latency_count: i64,
    latency_p50_ms: i64,
    latency_p95_ms: i64,
    latency_p99_ms: i64,
    distinct_principal_count: i64,
    status_counts: &'a [(i64, i64)],
}

fn insert_discovery_endpoint(path: &PathBuf, endpoint: SeedEndpoint<'_>) {
    let connection = Connection::open(path).expect("test discovery database should open");
    let latency_samples_json = serde_json::to_string(&[
        endpoint.latency_p50_ms,
        endpoint.latency_p95_ms,
        endpoint.latency_p99_ms,
    ])
    .expect("latency samples should serialize");

    connection
        .execute(
            r#"
                INSERT INTO discovery_endpoint_aggregates (
                    method,
                    endpoint_template,
                    first_seen,
                    last_seen,
                    call_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, '2024-06-05T00:00:00Z')
                "#,
            params![
                endpoint.method,
                endpoint.endpoint_template,
                endpoint.first_seen,
                endpoint.last_seen,
                endpoint.call_count,
                endpoint.latency_count,
                endpoint.latency_p50_ms,
                endpoint.latency_p95_ms,
                endpoint.latency_p99_ms,
                latency_samples_json,
                endpoint.distinct_principal_count,
            ],
        )
        .expect("endpoint aggregate should insert");

    connection
        .execute(
            r#"
                INSERT INTO discovery_endpoint_routing_classifications (
                    method, endpoint_template, first_classified_at
                ) VALUES (?1, ?2, ?3)
                "#,
            params![
                endpoint.method,
                endpoint.endpoint_template,
                endpoint.first_seen,
            ],
        )
        .expect("endpoint routing classification should insert");

    for (status, count) in endpoint.status_counts {
        connection
            .execute(
                r#"
                    INSERT INTO discovery_endpoint_status_counts (
                        method, endpoint_template, status, count
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                params![endpoint.method, endpoint.endpoint_template, status, count,],
            )
            .expect("endpoint status count should insert");
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_discovery_routing_context(
    path: &PathBuf,
    method: &str,
    endpoint_template: &str,
    route_host: &str,
    route_path_prefix: &str,
    upstream_origin: &str,
    call_count: i64,
    distinct_principal_count: i64,
) {
    let connection = Connection::open(path).expect("test discovery database should open");
    connection
        .execute(
            r#"
                INSERT INTO discovery_endpoint_routing_contexts (
                    method,
                    endpoint_template,
                    route_host,
                    route_path_prefix,
                    upstream_origin,
                    first_seen,
                    last_seen,
                    call_count,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?7)
                "#,
            params![
                method,
                endpoint_template,
                route_host,
                route_path_prefix,
                upstream_origin,
                "2024-06-01T00:00:00Z",
                "2024-06-01T01:00:00Z",
                call_count,
                distinct_principal_count,
            ],
        )
        .expect("routing context should insert");
}

fn clear_discovery_routing_classification(path: &PathBuf, method: &str, endpoint_template: &str) {
    let connection = Connection::open(path).expect("test discovery database should open");
    connection
        .execute(
            r#"
                DELETE FROM discovery_endpoint_routing_classifications
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
            params![method, endpoint_template],
        )
        .expect("routing classification should clear");
}

fn set_schema_mismatch_count(path: &PathBuf, method: &str, endpoint_template: &str, count: i64) {
    let connection = Connection::open(path).expect("test discovery database should open");
    connection
        .execute(
            r#"
                UPDATE discovery_endpoint_aggregates
                SET schema_mismatch_count = ?3
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
            params![method, endpoint_template, count],
        )
        .expect("schema mismatch count should update");
}

fn create_principal_schema(path: &PathBuf) {
    let connection = Connection::open(path).expect("test principal database should open");
    connection
        .execute_batch(
            r#"
                CREATE TABLE IF NOT EXISTS principal_directory (
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    auth_method TEXT NOT NULL,
                    email TEXT,
                    org_id TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    PRIMARY KEY (subject, issuer, auth_method)
                );
                "#,
        )
        .expect("principal directory schema should create");
}

fn seed_principal_directory_rows(path: &PathBuf) {
    for principal in [
        PrincipalDirectorySeed {
            subject: "alpha",
            issuer: "https://issuer-a.example.test/",
            auth_method: "bearer",
            email: Some("alpha@example.test"),
            org_id: Some("org-a"),
            first_seen: "2026-01-01T00:00:00Z",
            last_seen: "2026-01-04T00:00:00Z",
            request_count: 4,
        },
        PrincipalDirectorySeed {
            subject: "bravo",
            issuer: "https://issuer-a.example.test/",
            auth_method: "service_token",
            email: None,
            org_id: Some("org-a"),
            first_seen: "2026-01-01T00:00:00Z",
            last_seen: "2026-01-03T00:00:00Z",
            request_count: 3,
        },
        PrincipalDirectorySeed {
            subject: "charlie",
            issuer: "https://issuer-b.example.test/",
            auth_method: "cookie",
            email: Some("charlie@example.test"),
            org_id: Some("org-b"),
            first_seen: "2026-01-01T00:00:00Z",
            last_seen: "2026-01-02T00:00:00Z",
            request_count: 2,
        },
        PrincipalDirectorySeed {
            subject: "delta",
            issuer: "https://issuer-a.example.test/",
            auth_method: "bearer",
            email: None,
            org_id: None,
            first_seen: "2026-01-01T00:00:00Z",
            last_seen: "2026-01-01T00:00:00Z",
            request_count: 1,
        },
    ] {
        insert_principal_directory_row(path, principal);
    }
}

struct PrincipalDirectorySeed<'a> {
    subject: &'a str,
    issuer: &'a str,
    auth_method: &'a str,
    email: Option<&'a str>,
    org_id: Option<&'a str>,
    first_seen: &'a str,
    last_seen: &'a str,
    request_count: i64,
}

fn insert_principal_directory_row(path: &PathBuf, principal: PrincipalDirectorySeed<'_>) {
    let connection = Connection::open(path).expect("test principal database should open");
    connection
        .execute(
            r#"
                INSERT INTO principal_directory (
                    subject,
                    issuer,
                    auth_method,
                    email,
                    org_id,
                    first_seen,
                    last_seen,
                    request_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
            params![
                principal.subject,
                principal.issuer,
                principal.auth_method,
                principal.email,
                principal.org_id,
                principal.first_seen,
                principal.last_seen,
                principal.request_count,
            ],
        )
        .expect("principal directory row should insert");
}

fn insert_anonymous_observation_event(
    path: &PathBuf,
    event_id: &str,
    timestamp: &str,
    request_path: &str,
) {
    let connection = Connection::open(path).expect("test audit database should open");
    let payload_json = json!({
        "method": "GET",
        "path": request_path,
        "status": 401,
        "auth_outcome": "anonymous_or_failed"
    })
    .to_string();
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
                    payload_json
                ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', NULL, NULL, 'GET', ?4, 401, ?5)
                "#,
                params![
                    event_id,
                    timestamp,
                    format!("request-{event_id}"),
                    request_path,
                    payload_json,
                ],
            )
            .expect("anonymous observation should insert");
}

fn anonymous_observation_count(path: &PathBuf) -> i64 {
    let connection = Connection::open(path).expect("test audit database should open");
    connection
        .query_row(
            r#"
                SELECT COUNT(*)
                FROM audit_events
                WHERE event_type = 'http.request_observed'
                  AND actor_user_id IS NULL
                "#,
            [],
            |row| row.get(0),
        )
        .expect("anonymous observation count should query")
}

struct PrincipalEndpointSignalSeed<'a> {
    id: &'a str,
    method: &'a str,
    endpoint_template: &'a str,
    principal: &'a str,
    issuer: Option<&'a str>,
    auth_method: &'a str,
    created_at: &'a str,
}

fn insert_principal_endpoint_signal(path: &PathBuf, signal: PrincipalEndpointSignalSeed<'_>) {
    let connection = Connection::open(path).expect("test discovery database should open");
    let target_identity_json = serde_json::to_string(&json!({
        "method": signal.method,
        "endpoint_template": signal.endpoint_template,
        "principal": signal.principal,
        "issuer": signal.issuer,
        "auth_method": signal.auth_method,
    }))
    .expect("target identity should serialize");
    let evidence_json = serde_json::to_string(&json!({
        "observed_at": signal.created_at,
        "principal": signal.principal,
        "prior_distinct_principal_count": 1,
        "threshold": 1
    }))
    .expect("evidence should serialize");
    let target_key = discovery::signals::principal_identity_endpoint_target_key(
        signal.method,
        signal.endpoint_template,
        signal.principal,
        signal.issuer,
        signal.auth_method,
    );

    connection
        .execute(
            r#"
                INSERT INTO discovery_signals (
                    id,
                    signal_type,
                    target_kind,
                    target_key,
                    target_identity_json,
                    explanation,
                    evidence_json,
                    state,
                    created_at,
                    updated_at,
                    transitioned_at,
                    transitioned_by
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8, ?8, NULL, NULL)
                "#,
            params![
                signal.id,
                discovery::signals::PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_TYPE,
                discovery::signals::PRINCIPAL_ENDPOINT_TARGET_KIND,
                target_key,
                target_identity_json,
                format!("Principal new to endpoint: {}", signal.principal),
                evidence_json,
                signal.created_at,
            ],
        )
        .expect("principal endpoint signal should insert");
}

#[derive(Debug)]
struct PrincipalDirectoryRow {
    email: Option<String>,
    request_count: i64,
}

fn principal_directory_row_count(path: &PathBuf) -> i64 {
    let connection = Connection::open(path).expect("test principal database should open");
    connection
        .query_row("SELECT COUNT(*) FROM principal_directory", [], |row| {
            row.get(0)
        })
        .expect("principal directory count should query")
}

fn principal_directory_row(
    path: &PathBuf,
    subject: &str,
    issuer: &str,
    auth_method: &str,
) -> PrincipalDirectoryRow {
    let connection = Connection::open(path).expect("test principal database should open");
    connection
        .query_row(
            r#"
                SELECT email, request_count
                FROM principal_directory
                WHERE subject = ?1 AND issuer = ?2 AND auth_method = ?3
                "#,
            params![subject, issuer, auth_method],
            |row| {
                Ok(PrincipalDirectoryRow {
                    email: row.get(0)?,
                    request_count: row.get(1)?,
                })
            },
        )
        .expect("principal directory row should query")
}

fn insert_discovery_principal(
    path: &PathBuf,
    method: &str,
    endpoint_template: &str,
    user_id: &str,
    first_seen: &str,
    last_seen: &str,
) {
    let connection = Connection::open(path).expect("test discovery database should open");
    connection
        .execute(
            r#"
                INSERT INTO discovery_endpoint_principals (
                    method, endpoint_template, user_id, first_seen, last_seen
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
            params![method, endpoint_template, user_id, first_seen, last_seen],
        )
        .expect("endpoint principal should insert");
}

fn emit_observed_events_to_discovery_and_audit(
    discovery_path: &FsPath,
    audit_path: &FsPath,
    events: &[audit::AuditEvent],
) {
    let discovery_sink = discovery::aggregator::EndpointAggregatorSink::new(
        discovery::aggregator::EndpointAggregatorSinkConfig {
            path: discovery_path.to_path_buf(),
            payload_capture_enabled: false,
            endpoint_limit: config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            signal_event_sender: None,
            signal_detector_config: discovery::signals::SignalDetectorConfig::default(),
        },
    )
    .expect("discovery aggregator should build");
    let audit_sink = audit::sqlite_sink::SqliteSink::new(audit::sqlite_sink::SqliteSinkConfig {
        path: audit_path.to_path_buf(),
        retention_days: None,
    })
    .expect("audit SQLite sink should build");

    for event in events {
        audit::AuditSink::emit(&discovery_sink, event);
        audit::AuditSink::emit(&audit_sink, event);
    }
    drop(discovery_sink);
    drop(audit_sink);
}

fn observed_request_event(
    method: &str,
    path: &str,
    status: u16,
    latency_ms: u64,
    user_id: Option<&str>,
    timestamp: &str,
) -> audit::AuditEvent {
    let actor = user_id.map(|user_id| audit::Actor {
        user_id: user_id.to_owned(),
        issuer: None,
        email: None,
        roles: Some(vec!["reader".to_owned()]),
        auth_mode: "bearer_token".to_owned(),
    });
    let mut event = audit::AuditEvent::new(
        "http.request_observed",
        "request-traffic-test",
        "203.0.113.10",
        actor,
        json!({
            "method": method,
            "path": path,
            "status": status,
            "latency_ms": latency_ms
        }),
    );
    event.timestamp = timestamp.to_owned();
    event
}

fn seed_filter_events(path: &PathBuf) {
    insert_audit_event(
        path,
        SeedAuditEvent {
            event_id: "older-event",
            event_type: "audit.auth",
            timestamp: "2024-06-01T11:59:59.5Z",
            actor_user_id: "alice",
            path: "/login",
            status: 200,
        },
    );
    insert_audit_event(
        path,
        SeedAuditEvent {
            event_id: "cutoff-event",
            event_type: "audit.auth",
            timestamp: "2024-06-01T12:00:00Z",
            actor_user_id: "alice",
            path: "/login",
            status: 200,
        },
    );
    insert_audit_event(
        path,
        SeedAuditEvent {
            event_id: "fractionally-newer-event",
            event_type: "audit.policy",
            timestamp: "2024-06-01T12:00:00.5Z",
            actor_user_id: "bob",
            path: "/admin",
            status: 403,
        },
    );
    insert_audit_event(
        path,
        SeedAuditEvent {
            event_id: "later-event",
            event_type: "audit.egress",
            timestamp: "2024-06-01T12:00:01Z",
            actor_user_id: "carol",
            path: "/upstream",
            status: 502,
        },
    );
}

struct SeedAuditEvent<'a> {
    event_id: &'a str,
    event_type: &'a str,
    timestamp: &'a str,
    actor_user_id: &'a str,
    path: &'a str,
    status: i64,
}

fn insert_audit_event(path: &PathBuf, event: SeedAuditEvent<'_>) {
    let connection = Connection::open(path).expect("test database should open");
    let actor_json = json!({
        "user_id": event.actor_user_id,
        "roles": ["admin"],
        "auth_mode": "bearer_token"
    })
    .to_string();
    let payload_json = json!({
        "path": event.path,
        "status": event.status
    })
    .to_string();

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
                    payload_path,
                    payload_status,
                    payload_json
                ) VALUES (?1, ?2, ?3, '0.1.0', 'request-test', '203.0.113.10', ?4, ?5, ?6, ?7, ?8)
                "#,
            params![
                event.event_id,
                event.event_type,
                event.timestamp,
                event.actor_user_id,
                actor_json,
                event.path,
                event.status,
                payload_json
            ],
        )
        .expect("event should insert");
}

struct TempSpecFile {
    path: PathBuf,
}

impl TempSpecFile {
    fn new(test_name: &str, contents: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-openapi-{test_name}-{}.yaml",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

        Self { path }
    }
}

impl Drop for TempSpecFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn seed_discovery_endpoint(path: &PathBuf, method: &str, endpoint_template: &str) {
    let connection = Connection::open(path).expect("test database should open");
    connection
        .execute_batch(
            r#"
                CREATE TABLE IF NOT EXISTS discovery_endpoint_aggregates (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    call_count INTEGER NOT NULL,
                    latency_count INTEGER NOT NULL,
                    latency_p50_ms INTEGER NOT NULL,
                    latency_p95_ms INTEGER NOT NULL,
                    latency_p99_ms INTEGER NOT NULL,
                    latency_samples_json TEXT NOT NULL,
                    distinct_principal_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template)
                );
                "#,
        )
        .expect("discovery schema should create");
    connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_aggregates (
                    method,
                    endpoint_template,
                    first_seen,
                    last_seen,
                    call_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 1, 1, 1, 1, '[]', 0, '2024-06-01T12:00:00Z')
                "#,
                params![method, endpoint_template],
            )
            .expect("endpoint aggregate should insert");
}

fn seed_payload_shape_samples(
    path: &PathBuf,
    method: &str,
    endpoint_template: &str,
    shapes: &[Value],
) {
    let connection = Connection::open(path).expect("test database should open");
    connection
        .execute_batch(
            r#"
                CREATE TABLE IF NOT EXISTS discovery_payload_shape_stats (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    shape_observation_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template)
                );

                CREATE TABLE IF NOT EXISTS discovery_payload_shape_samples (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    sample_slot INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    shape_hash TEXT NOT NULL,
                    shape_json TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template, sample_slot)
                );
                "#,
        )
        .expect("payload shape schema should create");
    connection
        .execute(
            r#"
                INSERT INTO discovery_payload_shape_stats (
                    method,
                    endpoint_template,
                    shape_observation_count,
                    updated_at
                ) VALUES (?1, ?2, ?3, '2024-06-01T12:00:00Z')
                "#,
            params![
                method,
                endpoint_template,
                i64::try_from(shapes.len()).expect("shape count should fit i64")
            ],
        )
        .expect("payload shape stats should insert");

    for (index, shape) in shapes.iter().enumerate() {
        connection
            .execute(
                r#"
                    INSERT INTO discovery_payload_shape_samples (
                        method,
                        endpoint_template,
                        sample_slot,
                        observed_at,
                        shape_hash,
                        shape_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    "#,
                params![
                    method,
                    endpoint_template,
                    i64::try_from(index).expect("sample slot should fit i64"),
                    format!("2024-06-01T12:00:0{index}Z"),
                    format!("sha256:test-shape-{index}"),
                    shape.to_string(),
                ],
            )
            .expect("payload shape sample should insert");
    }
}

// ------------------------------------------------------------------
// Cluster-mode discovery wiring (issue #241, PR 11): the app builder
// spawns the fenced projector from the discovery seed and serves the
// read store from the same pool, with no SQLite sink in the way.
// Docker-gated on the same locator as the storage suites.
// ------------------------------------------------------------------

#[cfg(feature = "postgres")]
mod cluster_discovery_tests {
    use super::*;
    use crate::audit::Actor;
    use crate::discovery::query::DiscoveryReadStore as _;
    use crate::rbac::PolicyHistoryListFilters;
    use crate::storage::migrations;
    use crate::storage::postgres::PostgresFoundation;
    use crate::storage::postgres_audit::{IngestIdentity, PostgresAuditEventStore};
    use crate::storage::postgres_discovery::PostgresDiscoveryStore;
    use crate::storage::postgres_discovery_read::PostgresDiscoveryReadStore;
    use crate::storage::postgres_policy::PostgresPolicyStore;
    use crate::storage::PolicyControlPlane;

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
            "greengateway-cluster-discovery-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory should create");
        let path = directory.join("database-url");
        std::fs::write(&path, format!("{dsn}\n")).expect("DSN file should write");
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
        let name = format!("ggw_discovery_test_{}", uuid::Uuid::new_v4().simple());
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

    const CLUSTER_DISCOVERY_DEPLOYMENT_ID: &str = "deploy-cluster-discovery";

    async fn migrated_pool(dsn: &str) -> deadpool_postgres::Pool {
        let dsn_file = write_dsn_file(dsn);
        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some(CLUSTER_DISCOVERY_DEPLOYMENT_ID.to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("schema should migrate");
        foundation.pool().clone()
    }

    fn observed_event(index: usize, method: &str, path: &str) -> audit::AuditEvent {
        let mut event = audit::AuditEvent::new(
            "http.request_observed",
            format!("request-{index}"),
            "203.0.113.10",
            Some(Actor {
                user_id: "alice".to_owned(),
                issuer: Some("https://issuer.example/".to_owned()),
                email: None,
                roles: Some(vec!["reader".to_owned()]),
                auth_mode: "bearer_token".to_owned(),
            }),
            json!({
                "method": method,
                "path": path,
                "status": 200,
                "latency_ms": 12,
                "routing_context_known": true,
                "upstream_origin": "http://upstream.internal:8080",
                "upstream_route_host": "api.example",
                "upstream_route_path_prefix": "/",
            }),
        );
        event.event_id = format!("wiring-{index:06}");
        event
    }

    async fn wait_for_checkpoint(store: &PostgresDiscoveryStore, position: i64) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let checkpoint = store
                .checkpoint()
                .await
                .expect("the projector state should read");
            if checkpoint.checkpoint_position >= position {
                return;
            }
            assert!(
                    Instant::now() < deadline,
                    "the projector spawned by the app builder never reached position {position}: {checkpoint:?}"
                );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn postgres_app_serves_historical_audit_and_rule_preview_without_sqlite() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database.dsn).await;
        let audit_store = cluster_audit_store(&pool).await;
        audit_store
            .insert_events(&[
                observed_event(1, "GET", "/orders"),
                observed_event(2, "GET", "/orders"),
                observed_event(3, "POST", "/other"),
            ])
            .await
            .expect("peer events ingest");
        let policy = parse_policy_body(&Bytes::from(policy_document_string(
            "audit-test",
            "test:old",
        )))
        .expect("policy parses");
        let store = Arc::new(PostgresPolicyStore::new(pool.clone()));
        let active = store
            .commit(storage::PolicyCommitRequest {
                precondition: storage::PolicyCommitPrecondition::Initialize,
                candidate: &policy,
                change: crate::storage::DocumentChange::test_policy("installer"),
                diff_summary: &json!({"action": "seed"}),
            })
            .await
            .expect("policy initializes");
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some(CLUSTER_DISCOVERY_DEPLOYMENT_ID.to_owned());
        config
            .rbac_exempt_paths
            .extend([AUDIT_ADMIN_ROUTE.to_owned(), POLICY_ADMIN_ROUTE.to_owned()]);
        assert!(config.audit_sqlite_path.is_none());
        assert!(config.policy_file.is_none());
        let lifecycle = GatewayLifecycle::new();
        let recorder = PrometheusBuilder::new().build_recorder();
        let app = gateway_app_with_process_started_at_and_overrides(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
            Instant::now(),
            GatewayAppBuildOverrides {
                lifecycle: Some(lifecycle.clone()),
                pg_audit: Some(audit_store),
                pg_policy: Some(ClusterPolicySeed { store, active }),
                disable_proxy_health_checks: true,
                ..GatewayAppBuildOverrides::default()
            },
        )
        .expect("cluster app builds");
        let router = match app.http {
            GatewayApp::Unified(router) => router,
            GatewayApp::Split { .. } => panic!("expected unified router"),
        };
        let first = router
                .clone()
                .oneshot(audit_query_request(
                    "/v1/admin/audit?path=/orders&from=2020-01-01T00:00:00Z&to=2099-01-01T00:00:00Z&limit=1",
                    Some(test_principal(&["policy-audit-reader"])),
                ))
                .await
                .expect("history request");
        assert_eq!(first.status(), StatusCode::OK);
        let first = json_body(first).await;
        assert_eq!(event_ids_from_body(&first), ["wiring-000002"]);
        let cursor = first["next_cursor"].as_i64().expect("cursor");
        let next = router
                .clone()
                .oneshot(audit_query_request(
                    &format!("/v1/admin/audit?path=/orders&from=2020-01-01T00:00:00Z&to=2099-01-01T00:00:00Z&limit=1&before_id={cursor}"),
                    Some(test_principal(&["policy-audit-reader"])),
                ))
                .await
                .expect("next history request");
        assert_eq!(
            event_ids_from_body(&json_body(next).await),
            ["wiring-000001"]
        );
        let preview_body = json!({"rule": {"methods": ["GET"], "path": "/orders",
                "principal": {"roles": ["reader"]}, "action": "deny"}, "sample_limit": 1})
        .to_string();
        for (roles, expected) in [
            (vec!["policy-audit-reader"], StatusCode::OK),
            (vec!["policy-reader"], StatusCode::FORBIDDEN),
        ] {
            let response = router
                .clone()
                .oneshot(policy_admin_request(
                    Method::POST,
                    POLICY_RULE_PREVIEW_ADMIN_ROUTE,
                    Some(test_principal(&roles)),
                    Some(preview_body.clone()),
                    None,
                ))
                .await
                .expect("preview request");
            assert_eq!(response.status(), expected);
            if expected == StatusCode::OK {
                let body = json_body(response).await;
                assert_eq!(body["match_count"], 2);
                assert_eq!(body["scanned_event_count"], 2);
                assert_eq!(body["scan_truncated"], false);
                assert_eq!(body["complete"], true);
                assert_eq!(body["samples"][0]["event_id"], "wiring-000002");
                assert_eq!(body["samples"].as_array().expect("samples").len(), 1);
            }
        }
        // Hit counts and shadow review still read only the SQLite query
        // surface, which cluster mode never has: they must say so rather
        // than answer zeros the shared store was never asked for.
        for route in [
            POLICY_RULE_HITS_ADMIN_ROUTE,
            POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
        ] {
            let response = router
                .clone()
                .oneshot(policy_admin_request(
                    Method::GET,
                    route,
                    Some(test_principal(&["policy-audit-reader"])),
                    None,
                    None,
                ))
                .await
                .expect("evidence request");
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{route}"
            );
            assert_eq!(
                json_body(response).await["reason"],
                "audit_evidence_unavailable",
                "{route}"
            );
        }
        let denied = router
            .oneshot(audit_query_request(
                "/v1/admin/audit",
                Some(test_principal(&["policy-reader"])),
            ))
            .await
            .expect("denied history");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        lifecycle.background_cancellation().cancel();
        lifecycle.shutdown_background_tasks().await;
    }

    /// The builder, handed the discovery seed, runs the projector as a
    /// registered background task and answers discovery reads from the
    /// projected tables: events ingested before boot and after it both
    /// reach the inventory, and shutdown stops the task.
    #[tokio::test]
    async fn the_app_builder_spawns_the_projector_and_serves_the_read_store() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database.dsn).await;
        let instance_id = uuid::Uuid::new_v4();
        let audit_store = Arc::new(PostgresAuditEventStore::new(
            pool.clone(),
            Some(IngestIdentity {
                instance_id,
                boot_id: uuid::Uuid::new_v4(),
            }),
        ));
        // Traffic a peer replica observed before this one booted.
        audit_store
            .insert_events(&[
                observed_event(1, "GET", "/orders"),
                observed_event(2, "GET", "/orders"),
                observed_event(3, "POST", "/orders"),
            ])
            .await
            .expect("pre-boot observations should ingest");

        let lifecycle = GatewayLifecycle::new();
        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some(CLUSTER_DISCOVERY_DEPLOYMENT_ID.to_owned());
        config.discovery_projector_poll_ms = 50;
        let recorder = PrometheusBuilder::new().build_recorder();
        let app = gateway_app_with_process_started_at_and_overrides(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
            Instant::now(),
            GatewayAppBuildOverrides {
                lifecycle: Some(lifecycle.clone()),
                pg_audit: Some(audit_store.clone()),
                pg_discovery: Some(ClusterDiscoverySeed {
                    pool: pool.clone(),
                    deployment_id: CLUSTER_DISCOVERY_DEPLOYMENT_ID.to_owned(),
                    instance_id,
                    audit: audit_store.clone(),
                }),
                disable_proxy_health_checks: true,
                ..GatewayAppBuildOverrides::default()
            },
        )
        .expect("a cluster-mode app with the discovery seed should build");

        let store = PostgresDiscoveryStore::new(pool.clone());
        wait_for_checkpoint(&store, 3).await;
        let checkpoint = store.checkpoint().await.expect("checkpoint");
        assert_eq!(checkpoint.projected_events, 3);
        assert!(
            checkpoint.fence >= 1,
            "leadership was claimed: {checkpoint:?}"
        );

        // Traffic observed while this replica leads is projected as it
        // arrives, and the read store every replica serves sees it.
        audit_store
            .insert_events(&[
                observed_event(4, "GET", "/users/42"),
                observed_event(5, "GET", "/users/43"),
            ])
            .await
            .expect("post-boot observations should ingest");
        wait_for_checkpoint(&store, 5).await;

        let read_store = PostgresDiscoveryReadStore::new(pool.clone());
        let mut observed = read_store
            .observed_endpoints()
            .await
            .expect("the read store should answer")
            .into_iter()
            .map(|endpoint| (endpoint.method, endpoint.endpoint_template))
            .collect::<Vec<_>>();
        observed.sort();
        observed.dedup();
        assert_eq!(
            observed,
            vec![
                ("GET".to_owned(), "/orders".to_owned()),
                ("GET".to_owned(), "/users/{id}".to_owned()),
                ("POST".to_owned(), "/orders".to_owned()),
            ]
        );

        // The projector is a registered background task: shutdown ends
        // it rather than leaving a leader behind.
        lifecycle.background_cancellation().cancel();
        tokio::time::timeout(
            Duration::from_secs(10),
            lifecycle.shutdown_background_tasks(),
        )
        .await
        .expect("the projector should stop on shutdown");
        drop(app);
    }

    /// One classified endpoint and one observation of it by a role the
    /// policy does not cover: the smallest fixture that makes an
    /// explicit generation run produce exactly one identity-bound
    /// baseline suggestion for `GET /orders/{id}`.
    async fn seed_baseline_generation_fixture(
        pool: &deadpool_postgres::Pool,
        audit_store: &PostgresAuditEventStore,
    ) {
        let client = pool.get().await.expect("client");
        client
            .execute(
                "INSERT INTO greengateway.discovery_endpoint_aggregates
                         (method, endpoint_template, first_seen, last_seen, call_count,
                          latency_count, latency_p50_ms, latency_p95_ms, latency_p99_ms,
                          latency_samples_json, distinct_principal_count, updated_at)
                     VALUES ('GET', '/orders/{id}', '2024-06-01T12:00:00Z',
                             '2024-06-01T12:00:00Z', 1, 1, 1, 1, 1, '[]', 1,
                             '2024-06-01T12:00:00Z')",
                &[],
            )
            .await
            .expect("the aggregate seeds");
        client
            .execute(
                "INSERT INTO greengateway.discovery_endpoint_routing_classifications
                         (method, endpoint_template, first_classified_at)
                     VALUES ('GET', '/orders/{id}', '2024-05-31T00:00:00Z')",
                &[],
            )
            .await
            .expect("the classification seeds");
        drop(client);

        let mut observed = audit::AuditEvent::new(
            "http.request_observed",
            "request-cluster-generate".to_owned(),
            "203.0.113.10",
            Some(Actor {
                user_id: "alice".to_owned(),
                issuer: Some("provider:test".to_owned()),
                email: None,
                roles: Some(vec!["orders-reader".to_owned()]),
                auth_mode: "bearer_token".to_owned(),
            }),
            json!({
                "method": "GET",
                "path": "/orders/42",
                "status": 200,
                "policy_decision": "allowed",
                "routing_context_known": true,
            }),
        );
        observed.timestamp = "2024-06-01T12:00:00Z".to_owned();
        audit_store
            .insert_events(&[observed])
            .await
            .expect("the observation ingests");
    }

    /// A cluster-mode suggestions router wired the way production
    /// wires one: no policy file, the PostgreSQL control plane as the
    /// policy authority and history store, and the cluster suggestion
    /// engine over the same pool.
    struct ClusterSuggestionsHarness {
        router: Router,
        rbac_state: middleware::rbac::RbacState,
        policy_store: Arc<PostgresPolicyStore>,
        audit: audit::sink::tests::CaptureSink,
    }

    async fn cluster_suggestions_harness(
        pool: &deadpool_postgres::Pool,
        audit_store: Arc<PostgresAuditEventStore>,
    ) -> ClusterSuggestionsHarness {
        let policy = parse_policy_body(&axum::body::Bytes::from(
            suggestions_policy_document_string(),
        ))
        .expect("suggestions policy should parse");
        let policy_store = Arc::new(PostgresPolicyStore::new(pool.clone()));
        let seed_diff = json!({ "action": "seed" });
        let active = PolicyControlPlane::commit(
            policy_store.as_ref(),
            storage::PolicyCommitRequest {
                precondition: storage::PolicyCommitPrecondition::Initialize,
                candidate: &policy,
                change: crate::storage::DocumentChange::test_policy("installer"),
                diff_summary: &seed_diff,
            },
        )
        .await
        .expect("the deployment should initialize");

        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
        let rbac_state =
            middleware::rbac::RbacState::new(policy, Vec::new(), false, audit_log.clone());
        // Startup installs the authority's revision; without it the
        // handler's snapshot is unkeyed.
        rbac_state
            .install_revision_snapshot(active.policy.clone(), active.security_revision)
            .await
            .expect("the authority's revision should install");

        let engine = discovery::cluster_suggestions::ClusterRuleSuggestionEngine::new(
            Arc::new(PostgresDiscoveryReadStore::new(pool.clone())),
            audit_store,
            storage::postgres_discovery_lifecycle::PostgresDiscoveryLifecycleStore::new(
                pool.clone(),
            ),
            discovery::suggestions::RuleSuggestionConfig {
                baseline_window_hours: 876_000,
            },
        );
        let router = Router::new()
            .route(SUGGESTIONS_ADMIN_ROUTE, get(rule_suggestions_list_endpoint))
            .route(
                SUGGESTIONS_GENERATE_ADMIN_ROUTE,
                post(rule_suggestions_generate_endpoint),
            )
            .route(
                SUGGESTION_DISMISS_ADMIN_ROUTE,
                post(rule_suggestion_dismiss_endpoint),
            )
            .route(
                SUGGESTION_ACCEPT_ADMIN_ROUTE,
                post(rule_suggestion_accept_endpoint),
            )
            .with_state(SuggestionsAdminState {
                suggestion_engine: Some(discovery::suggestions::SuggestionEngineHandle::Cluster(
                    Arc::new(engine),
                )),
                policy: PolicyAdminState {
                    policy_file: None,
                    rbac_state: Some(rbac_state.clone()),
                    history_store: Some(policy_store.clone() as Arc<dyn storage::PolicyHistory>),
                    draft_store: None,
                    control_plane: Some(
                        policy_store.clone() as Arc<dyn storage::PolicyControlPlane>
                    ),
                    membership: None,
                    event_store: None,
                    query_store: None,
                    authority_evidence:
                        authority_events::required::AuthorityEvidenceGate::best_effort(),
                    audit: audit_log,
                    client_ip_policy: client_ip::ClientIpPolicy::default(),
                    max_body_size: 1024 * 1024,
                },
                lifecycle_guard: Arc::new(tokio::sync::Mutex::new(())),
            });

        ClusterSuggestionsHarness {
            router,
            rbac_state,
            policy_store,
            audit: capture,
        }
    }

    async fn cluster_audit_store(pool: &deadpool_postgres::Pool) -> Arc<PostgresAuditEventStore> {
        Arc::new(PostgresAuditEventStore::new(
            pool.clone(),
            Some(IngestIdentity {
                instance_id: uuid::Uuid::new_v4(),
                boot_id: uuid::Uuid::new_v4(),
            }),
        ))
    }

    /// Generate once and return the single open suggestion's id.
    async fn generate_one_suggestion(router: &Router) -> String {
        let generated = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                SUGGESTIONS_GENERATE_ADMIN_ROUTE,
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("generate request should complete");
        assert_eq!(generated.status(), StatusCode::OK);
        assert_eq!(json_body(generated).await["inserted_count"], json!(1));

        let listed = suggestions_json(
            router,
            "/v1/admin/suggestions?state=open",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        let ids = suggestion_ids(&listed);
        assert_eq!(ids.len(), 1, "{listed}");
        ids.into_iter().next().expect("one suggestion")
    }

    /// An accept request: `If-Match` is the policy ETag, and the
    /// suggestion's own expected revision rides its own header.
    fn accept_request(
        id: &str,
        policy_etag: Option<&str>,
        suggestion_revision: Option<&str>,
    ) -> Request<Body> {
        let mut request = suggestions_admin_request(
            Method::POST,
            &format!("/v1/admin/suggestions/{id}/accept"),
            Some(test_principal(&["suggestions-policy-writer"])),
            None,
            policy_etag,
        );
        if let Some(revision) = suggestion_revision {
            request.headers_mut().insert(
                HeaderName::from_static(SUGGESTION_REVISION_HEADER),
                HeaderValue::from_str(revision).expect("revision header should build"),
            );
        }
        request
    }

    async fn count_rows(pool: &deadpool_postgres::Pool, table: &str) -> i64 {
        let client = pool.get().await.expect("client");
        client
            .query_one(
                &format!("SELECT count(*)::bigint FROM greengateway.{table}"),
                &[],
            )
            .await
            .expect("count should read")
            .get(0)
    }

    /// Everything an acceptance would change on the policy side, plus
    /// the suggestion row: byte-for-byte equality means nothing was
    /// written.
    #[derive(Debug, Eq, PartialEq)]
    struct AcceptanceFootprint {
        active_version: i64,
        active_etag: String,
        security_revision: i64,
        rule_count: usize,
        document_rows: i64,
        outbox_rows: i64,
        suggestion_state: String,
        suggestion_revision: i64,
    }

    async fn acceptance_footprint(
        store: &PostgresPolicyStore,
        pool: &deadpool_postgres::Pool,
        suggestion_id: &str,
    ) -> AcceptanceFootprint {
        let active = PolicyControlPlane::active(store)
            .await
            .expect("active policy reads")
            .expect("a policy is active");
        let suggestion =
            storage::postgres_discovery_lifecycle::PostgresDiscoveryLifecycleStore::new(
                pool.clone(),
            )
            .get_suggestion(suggestion_id)
            .await
            .expect("the suggestion reads")
            .expect("the suggestion exists");
        AcceptanceFootprint {
            active_version: active.version,
            active_etag: active.etag,
            security_revision: active.security_revision,
            rule_count: active.policy.rules.len(),
            document_rows: count_rows(pool, "policy_documents").await,
            outbox_rows: count_rows(pool, "security_outbox").await,
            suggestion_state: suggestion.state.as_str().to_owned(),
            suggestion_revision: suggestion.revision,
        }
    }

    /// The signal routes in cluster mode (issue #241, PR 12): the
    /// admin router over the PostgreSQL read store, exercising the
    /// same conditional lifecycle transitions the SQLite variant
    /// covers -- the revision on every read, `If-Match` as the
    /// precondition, and a `409` that carries the row as it stands.
    #[tokio::test]
    async fn cluster_mode_signal_routes_transition_conditionally_from_postgres() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database.dsn).await;

        let client = pool.get().await.expect("client");
        for (id, endpoint_template) in [("sig-ack", "/ack/{id}"), ("sig-dismiss", "/dismiss/{id}")]
        {
            client
                .execute(
                    "INSERT INTO greengateway.discovery_signals
                             (id, signal_type, target_kind, target_key, target_identity_json,
                              explanation, evidence_json, state, created_at, updated_at)
                         VALUES ($1, 'new_endpoint_seen', 'endpoint', $2, $3,
                                 'New endpoint observed.', '{}', 'open',
                                 '2024-06-01T00:00:00Z', '2024-06-01T00:00:00Z')",
                    &[
                        &id,
                        &discovery::signals::endpoint_target_key("GET", endpoint_template),
                        &json!({
                            "method": "GET",
                            "endpoint_template": endpoint_template,
                        })
                        .to_string(),
                    ],
                )
                .await
                .expect("the open signal seeds");
        }
        drop(client);

        let policy = parse_policy_body(&axum::body::Bytes::from(signals_policy_document_string()))
            .expect("signals policy should parse");
        let router = Router::new()
            .route(SIGNALS_ADMIN_ROUTE, get(signals_list_endpoint))
            .route(
                SIGNAL_ACKNOWLEDGE_ADMIN_ROUTE,
                post(signal_acknowledge_endpoint),
            )
            .route(SIGNAL_DISMISS_ADMIN_ROUTE, post(signal_dismiss_endpoint))
            .with_state(SignalsAdminState {
                discovery_store: Some(Arc::new(PostgresDiscoveryReadStore::new(pool.clone()))),
                rbac_state: Some(middleware::rbac::RbacState::new(
                    policy,
                    Vec::new(),
                    false,
                    test_audit_log(),
                )),
                audit: test_audit_log(),
                client_ip_policy: client_ip::ClientIpPolicy::default(),
            });

        let signal_request = |method: Method, uri: &str, role: &str, if_match: Option<&str>| {
            let mut builder = Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(if_match) = if_match {
                builder = builder.header(header::IF_MATCH, if_match);
            }
            let mut request = builder.body(Body::empty()).expect("request should build");
            request
                .extensions_mut()
                .insert(test_principal(&[role.to_owned().as_str()]));
            request
        };

        // Reads carry the revision an `If-Match` must present.
        let listed = router
            .clone()
            .oneshot(signal_request(
                Method::GET,
                "/v1/admin/signals?state=open",
                "signals-reader",
                None,
            ))
            .await
            .expect("list request should complete");
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = json_body(listed).await;
        let signals = listed["signals"].as_array().expect("signals is an array");
        assert_eq!(signals.len(), 2, "{listed}");
        assert!(signals
            .iter()
            .all(|signal| signal["revision"] == json!(1) && signal["state"] == json!("open")));

        let forbidden = router
            .clone()
            .oneshot(signal_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/acknowledge",
                "signals-reader",
                None,
            ))
            .await
            .expect("read-only acknowledge should complete");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let stale = router
            .clone()
            .oneshot(signal_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/acknowledge",
                "signals-writer",
                Some("4"),
            ))
            .await
            .expect("stale acknowledge should complete");
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let stale = json_body(stale).await;
        assert_eq!(stale["reason"], json!("signal_revision_mismatch"));
        assert_eq!(stale["signal"]["state"], json!("open"));
        assert_eq!(stale["signal"]["revision"], json!(1));

        let acknowledged = router
            .clone()
            .oneshot(signal_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/acknowledge",
                "signals-writer",
                Some("1"),
            ))
            .await
            .expect("acknowledge should complete");
        assert_eq!(acknowledged.status(), StatusCode::OK);
        let acknowledged = json_body(acknowledged).await;
        assert_eq!(acknowledged["state"], json!("acknowledged"));
        assert_eq!(acknowledged["revision"], json!(2));
        assert_eq!(acknowledged["transitioned_by"], json!("user-123"));

        // The from-state predicate stands on its own: an
        // unconditional repeat is refused, not re-applied.
        let repeat = router
            .clone()
            .oneshot(signal_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/acknowledge",
                "signals-writer",
                None,
            ))
            .await
            .expect("repeat acknowledge should complete");
        assert_eq!(repeat.status(), StatusCode::CONFLICT);
        let repeat = json_body(repeat).await;
        assert_eq!(repeat["reason"], json!("signal_not_open"));
        assert_eq!(repeat["signal"]["revision"], json!(2));

        // Dismissal leaves `acknowledged` too, so an acknowledged
        // signal is not stranded; it is still refused a second time.
        let dismissed_after_acknowledge = router
            .clone()
            .oneshot(signal_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/dismiss",
                "signals-writer",
                Some("2"),
            ))
            .await
            .expect("dismiss after acknowledge should complete");
        assert_eq!(dismissed_after_acknowledge.status(), StatusCode::OK);
        let dismissed_after_acknowledge = json_body(dismissed_after_acknowledge).await;
        assert_eq!(dismissed_after_acknowledge["state"], json!("dismissed"));
        assert_eq!(dismissed_after_acknowledge["revision"], json!(3));
        let repeat_dismiss = router
            .clone()
            .oneshot(signal_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/dismiss",
                "signals-writer",
                None,
            ))
            .await
            .expect("repeat dismiss should complete");
        assert_eq!(repeat_dismiss.status(), StatusCode::CONFLICT);
        assert_eq!(
            json_body(repeat_dismiss).await["reason"],
            json!("signal_not_open")
        );

        let dismissed = router
            .clone()
            .oneshot(signal_request(
                Method::POST,
                "/v1/admin/signals/sig-dismiss/dismiss",
                "signals-writer",
                None,
            ))
            .await
            .expect("dismiss should complete");
        assert_eq!(dismissed.status(), StatusCode::OK);
        let dismissed = json_body(dismissed).await;
        assert_eq!(dismissed["state"], json!("dismissed"));
        assert_eq!(dismissed["revision"], json!(2));

        let missing = router
            .oneshot(signal_request(
                Method::POST,
                "/v1/admin/signals/sig-missing/dismiss",
                "signals-writer",
                None,
            ))
            .await
            .expect("unknown-signal dismiss should complete");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    /// The traffic endpoint-review route in cluster mode (issue #241,
    /// PR 12). The review is a conditional write against the shared
    /// table: reads carry the stored row's `review_revision`, `If-Match:
    /// 0` marks only an endpoint still unreviewed, a stale expectation
    /// is refused with the review as it stands, and clearing deletes the
    /// row only at its revision, which puts the endpoint back at
    /// revision 0.
    #[tokio::test]
    async fn cluster_mode_traffic_review_route_writes_conditionally_from_postgres() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database.dsn).await;

        let client = pool.get().await.expect("client");
        client
            .execute(
                "INSERT INTO greengateway.discovery_endpoint_aggregates
                         (method, endpoint_template, first_seen, last_seen, call_count,
                          latency_count, latency_p50_ms, latency_p95_ms, latency_p99_ms,
                          latency_samples_json, distinct_principal_count, updated_at)
                     VALUES ('GET', '/reviewed/{id}', '2024-06-01T00:00:00Z',
                             '2024-06-01T01:00:00Z', 1, 1, 10, 10, 10, '[]', 0,
                             '2024-06-01T01:00:00Z')",
                &[],
            )
            .await
            .expect("the aggregate seeds");
        drop(client);

        let policy = parse_policy_body(&axum::body::Bytes::from(traffic_policy_document_string()))
            .expect("traffic policy should parse");
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = Router::new()
            .route(
                TRAFFIC_ENDPOINTS_ADMIN_ROUTE,
                get(traffic_endpoint_list_endpoint),
            )
            .route(
                TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
                post(traffic_endpoint_review_endpoint),
            )
            .with_state(TrafficAdminState {
                discovery_store: Some(Arc::new(PostgresDiscoveryReadStore::new(pool.clone()))),
                audit_query_store: None,
                rbac_state: Some(middleware::rbac::RbacState::new(
                    policy,
                    Vec::new(),
                    false,
                    test_audit_log(),
                )),
                audit: audit_log,
                client_ip_policy: client_ip::ClientIpPolicy::default(),
                max_body_size: 64 * 1024,
            });

        let review_request =
            |role: &str, template: &str, reviewed: bool, if_match: Option<&str>| {
                let mut builder = Request::builder()
                    .method(Method::POST)
                    .uri(TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE)
                    .header(header::CONTENT_TYPE, "application/json");
                if let Some(if_match) = if_match {
                    builder = builder.header(header::IF_MATCH, if_match);
                }
                let body = json!({
                    "method": "GET",
                    "endpoint_template": template,
                    "reviewed": reviewed,
                })
                .to_string();
                let mut request = builder
                    .body(Body::from(body))
                    .expect("request should build");
                request
                    .extensions_mut()
                    .insert(test_principal(&[role.to_owned().as_str()]));
                request
            };
        let listed_endpoint = |router: Router| async move {
            let mut request = Request::builder()
                .uri(TRAFFIC_ENDPOINTS_ADMIN_ROUTE)
                .body(Body::empty())
                .expect("request should build");
            request
                .extensions_mut()
                .insert(test_principal(&["traffic-reader"]));
            let response = router
                .oneshot(request)
                .await
                .expect("endpoint list should complete");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            body["endpoints"][0].clone()
        };

        // Reads carry the revision a conditional write must present.
        let endpoint = listed_endpoint(router.clone()).await;
        assert_eq!(endpoint["endpoint_template"], json!("/reviewed/{id}"));
        assert_eq!(endpoint["reviewed"], json!(false));
        assert_eq!(endpoint["review_revision"], json!(0));

        let forbidden = router
            .clone()
            .oneshot(review_request(
                "traffic-reader",
                "/reviewed/{id}",
                true,
                None,
            ))
            .await
            .expect("read-only review should complete");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        // Expecting a revision no review row has ever had writes nothing.
        let stale = router
            .clone()
            .oneshot(review_request(
                "traffic-writer",
                "/reviewed/{id}",
                true,
                Some("3"),
            ))
            .await
            .expect("stale mark should complete");
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let stale = json_body(stale).await;
        assert_eq!(stale["reason"], json!("review_revision_mismatch"));
        assert_eq!(stale["review"]["reviewed"], json!(false));
        assert_eq!(stale["review"]["revision"], json!(0));

        let marked = router
            .clone()
            .oneshot(review_request(
                "traffic-writer",
                "/reviewed/{id}",
                true,
                Some("0"),
            ))
            .await
            .expect("mark should complete");
        assert_eq!(marked.status(), StatusCode::OK);
        let marked = json_body(marked).await;
        assert_eq!(marked["reviewed"], json!(true));
        assert_eq!(marked["revision"], json!(1));
        assert_eq!(marked["reviewed_by"], json!("user-123"));

        // The second replica's "mark it if nobody has" loses.
        let raced = router
            .clone()
            .oneshot(review_request(
                "traffic-writer",
                "/reviewed/{id}",
                true,
                Some("0"),
            ))
            .await
            .expect("raced mark should complete");
        assert_eq!(raced.status(), StatusCode::CONFLICT);
        let raced = json_body(raced).await;
        assert_eq!(raced["reason"], json!("review_revision_mismatch"));
        assert_eq!(raced["review"]["reviewed"], json!(true));
        assert_eq!(raced["review"]["revision"], json!(1));

        let endpoint = listed_endpoint(router.clone()).await;
        assert_eq!(endpoint["reviewed"], json!(true));
        assert_eq!(endpoint["review_revision"], json!(1));
        assert_eq!(endpoint["reviewed_by"], json!("user-123"));

        let stale_clear = router
            .clone()
            .oneshot(review_request(
                "traffic-writer",
                "/reviewed/{id}",
                false,
                Some("9"),
            ))
            .await
            .expect("stale clear should complete");
        assert_eq!(stale_clear.status(), StatusCode::CONFLICT);
        let stale_clear = json_body(stale_clear).await;
        assert_eq!(stale_clear["reason"], json!("review_revision_mismatch"));
        assert_eq!(stale_clear["review"]["revision"], json!(1));

        let cleared = router
            .clone()
            .oneshot(review_request(
                "traffic-writer",
                "/reviewed/{id}",
                false,
                Some("1"),
            ))
            .await
            .expect("clear should complete");
        assert_eq!(cleared.status(), StatusCode::OK);
        let cleared = json_body(cleared).await;
        assert_eq!(cleared["reviewed"], json!(false));
        // The review row outlives the review, so the revision goes UP;
        // it never returns to 1 for a later review of this endpoint.
        assert_eq!(cleared["revision"], json!(2));

        let endpoint = listed_endpoint(router.clone()).await;
        assert_eq!(endpoint["reviewed"], json!(false));
        assert_eq!(endpoint["review_revision"], json!(2));

        // An admin still holding the cleared review's revision -- or
        // one that believes the endpoint was never reviewed -- cannot
        // mark it: the conditional write refuses the stale generation
        // instead of silently overwriting the next one.
        for stale_expectation in ["1", "0"] {
            let stale_remark = router
                .clone()
                .oneshot(review_request(
                    "traffic-writer",
                    "/reviewed/{id}",
                    true,
                    Some(stale_expectation),
                ))
                .await
                .expect("stale re-mark should complete");
            assert_eq!(stale_remark.status(), StatusCode::CONFLICT);
            let stale_remark = json_body(stale_remark).await;
            assert_eq!(stale_remark["reason"], json!("review_revision_mismatch"));
            assert_eq!(stale_remark["review"]["revision"], json!(2));
        }
        let remarked = router
            .clone()
            .oneshot(review_request(
                "traffic-writer",
                "/reviewed/{id}",
                true,
                Some("2"),
            ))
            .await
            .expect("re-mark should complete");
        assert_eq!(remarked.status(), StatusCode::OK);
        let remarked = json_body(remarked).await;
        assert_eq!(remarked["reviewed"], json!(true));
        assert_eq!(remarked["revision"], json!(3));

        let missing = router
            .clone()
            .oneshot(review_request("traffic-writer", "/absent/{id}", true, None))
            .await
            .expect("unknown-endpoint review should complete");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        assert_eventually(Duration::from_secs(1), || {
            capture
                .events()
                .iter()
                .filter(|event| event.event_type == audit::event::TRAFFIC_ENDPOINT_REVIEW_CHANGED)
                .count()
                == 3
        });
    }

    /// The suggestion routes in cluster mode (issue #241, PR 12):
    /// `generate` runs against PostgreSQL instead of being refused,
    /// the list shows what it stored (with its revision), and dismissal
    /// is the conditional transition with `If-Match`. Acceptance needs
    /// the policy authority and has its own tests below.
    #[tokio::test]
    async fn cluster_mode_suggestion_routes_generate_list_and_dismiss_from_postgres() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database.dsn).await;
        let audit_store = cluster_audit_store(&pool).await;
        seed_baseline_generation_fixture(&pool, &audit_store).await;
        let router = cluster_suggestions_harness(&pool, audit_store).await.router;

        let forbidden = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                SUGGESTIONS_GENERATE_ADMIN_ROUTE,
                Some(test_principal(&["suggestions-reader"])),
                None,
                None,
            ))
            .await
            .expect("generate request should complete");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let generated = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                SUGGESTIONS_GENERATE_ADMIN_ROUTE,
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("generate request should complete");
        assert_eq!(generated.status(), StatusCode::OK);
        let generated = json_body(generated).await;
        assert_eq!(generated["inserted_count"], json!(1), "{generated}");
        assert_eq!(generated["baseline"]["available"], json!(true));
        assert_eq!(
            generated["baseline"]["observed_role_endpoint_count"],
            json!(1)
        );

        let regenerated = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                SUGGESTIONS_GENERATE_ADMIN_ROUTE,
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("second generate request should complete");
        assert_eq!(regenerated.status(), StatusCode::OK);
        assert_eq!(json_body(regenerated).await["inserted_count"], json!(0));

        let listed = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::GET,
                "/v1/admin/suggestions?state=open",
                Some(test_principal(&["suggestions-reader"])),
                None,
                None,
            ))
            .await
            .expect("list request should complete");
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = json_body(listed).await;
        let suggestions = listed["suggestions"]
            .as_array()
            .expect("suggestions is an array");
        assert_eq!(suggestions.len(), 1, "{listed}");
        let suggestion = &suggestions[0];
        assert_eq!(suggestion["suggestion_type"], json!("baseline_allow"));
        assert_eq!(suggestion["method"], json!("GET"));
        assert_eq!(suggestion["path_pattern"], json!("/orders/{id}"));
        assert_eq!(
            suggestion["proposed_rule"]["principal"]["roles"],
            json!(["orders-reader"])
        );
        assert_eq!(suggestion["evidence"]["source"], json!("audit_postgres"));
        assert_eq!(suggestion["revision"], json!(1));
        let id = suggestion["id"].as_str().expect("id").to_owned();

        let stale = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                &format!("/v1/admin/suggestions/{id}/dismiss"),
                Some(test_principal(&["suggestions-writer"])),
                None,
                Some("7"),
            ))
            .await
            .expect("stale dismiss request should complete");
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let stale = json_body(stale).await;
        assert_eq!(stale["reason"], json!("suggestion_revision_mismatch"));
        assert_eq!(stale["suggestion"]["revision"], json!(1));

        let dismissed = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                &format!("/v1/admin/suggestions/{id}/dismiss"),
                Some(test_principal(&["suggestions-writer"])),
                None,
                Some("1"),
            ))
            .await
            .expect("dismiss request should complete");
        assert_eq!(dismissed.status(), StatusCode::OK);
        let dismissed = json_body(dismissed).await;
        assert_eq!(dismissed["state"], json!("dismissed"));
        assert_eq!(dismissed["revision"], json!(2));
        assert_eq!(dismissed["transitioned_by"], json!("user-123"));

        let not_open = router
            .oneshot(suggestions_admin_request(
                Method::POST,
                &format!("/v1/admin/suggestions/{id}/dismiss"),
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("repeat dismiss request should complete");
        assert_eq!(not_open.status(), StatusCode::CONFLICT);
        let not_open = json_body(not_open).await;
        assert_eq!(not_open["reason"], json!("suggestion_not_open"));
        assert_eq!(not_open["suggestion"]["revision"], json!(2));
    }

    /// Generation filters against the policy AUTHORITY, not this
    /// replica's snapshot (issue #241, PR 12). Another replica commits
    /// a rule that covers the observed traffic; this replica has not
    /// installed that revision yet. Generating here must still see the
    /// endpoint as covered -- a suggestion minted from the stale
    /// snapshot is stored by identity and never re-evaluated, so it
    /// would stay open forever and accepting it would append a
    /// duplicate rule.
    #[tokio::test]
    async fn cluster_generation_filters_against_the_authority_not_the_replica_snapshot() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database.dsn).await;
        let audit_store = cluster_audit_store(&pool).await;
        seed_baseline_generation_fixture(&pool, &audit_store).await;
        let harness = cluster_suggestions_harness(&pool, audit_store).await;

        // Another replica commits the covering rule. Nothing installs
        // it here: this replica's snapshot still has no rules, exactly
        // as it stands between a commit elsewhere and the security
        // revision reconciler catching up.
        let mut document: Value = serde_json::from_str(&suggestions_policy_document_string())
            .expect("the seed policy should parse as JSON");
        document["rules"] = json!([{
            "methods": ["GET"],
            "path": "/orders/{id}",
            "principal": { "roles": ["orders-reader"] },
            "action": "allow"
        }]);
        let covering = parse_policy_body(&axum::body::Bytes::from(document.to_string()))
            .expect("the covering policy should parse");
        let active = PolicyControlPlane::active(harness.policy_store.as_ref())
            .await
            .expect("active reads")
            .expect("a policy is active");
        let diff_summary = json!({ "action": "rule_created" });
        PolicyControlPlane::commit(
            harness.policy_store.as_ref(),
            storage::PolicyCommitRequest {
                precondition: storage::PolicyCommitPrecondition::Expected {
                    etag: active.etag.clone(),
                },
                candidate: &covering,
                change: crate::storage::DocumentChange::test_policy("other-replica"),
                diff_summary: &diff_summary,
            },
        )
        .await
        .expect("the other replica's commit should apply");
        assert!(
            harness.rbac_state.current_policy().rules.is_empty(),
            "this replica must still be on the pre-commit snapshot"
        );

        let generated = harness
            .router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                SUGGESTIONS_GENERATE_ADMIN_ROUTE,
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("generate request should complete");
        assert_eq!(generated.status(), StatusCode::OK);
        let generated = json_body(generated).await;
        assert_eq!(
            generated["inserted_count"],
            json!(0),
            "the authority already covers this endpoint: {generated}"
        );

        let listed = suggestions_json(
            &harness.router,
            "/v1/admin/suggestions?state=open",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert!(
            suggestion_ids(&listed).is_empty(),
            "no suggestion may be stored for covered traffic: {listed}"
        );
    }

    /// Cluster-mode acceptance end to end (issue #241, PR 12): one
    /// request installs the rule, moves the suggestion, writes the
    /// immutable history version and the outbox row, installs the new
    /// security revision locally, and emits both audit events -- and a
    /// second acceptance of the same suggestion is refused with the row
    /// as it now stands.
    #[tokio::test]
    async fn cluster_mode_accept_commits_the_rule_the_transition_and_the_history_row() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database.dsn).await;
        let audit_store = cluster_audit_store(&pool).await;
        seed_baseline_generation_fixture(&pool, &audit_store).await;
        let harness = cluster_suggestions_harness(&pool, audit_store).await;
        let id = generate_one_suggestion(&harness.router).await;

        let before = acceptance_footprint(&harness.policy_store, &pool, &id).await;
        assert_eq!(before.active_version, 1);
        assert_eq!(before.rule_count, 0);
        assert_eq!(before.suggestion_state, "open");
        assert_eq!(before.suggestion_revision, 1);

        // The suggestion's expected revision is its own precondition:
        // a stale one is refused before anything is written.
        let stale_revision = harness
            .router
            .clone()
            .oneshot(accept_request(&id, Some(&before.active_etag), Some("9")))
            .await
            .expect("stale-revision accept should complete");
        assert_eq!(stale_revision.status(), StatusCode::CONFLICT);
        let stale_revision = json_body(stale_revision).await;
        assert_eq!(
            stale_revision["reason"],
            json!("suggestion_revision_mismatch")
        );
        assert_eq!(stale_revision["suggestion"]["revision"], json!(1));
        assert_eq!(
            acceptance_footprint(&harness.policy_store, &pool, &id).await,
            before,
            "a refused precondition must write nothing"
        );

        let accepted = harness
            .router
            .clone()
            .oneshot(accept_request(&id, Some(&before.active_etag), Some("1")))
            .await
            .expect("accept request should complete");
        assert_eq!(accepted.status(), StatusCode::CREATED);
        let accepted_etag = policy_etag_header(&accepted);
        assert_ne!(accepted_etag, before.active_etag);
        let accepted_body = json_body(accepted).await;
        assert_eq!(accepted_body["suggestion"]["state"], json!("accepted"));
        assert_eq!(accepted_body["suggestion"]["revision"], json!(2));
        assert_eq!(
            accepted_body["suggestion"]["transitioned_by"],
            json!("user-123")
        );
        assert_eq!(accepted_body["rule"]["path"], json!("/orders/{id}"));
        assert_eq!(accepted_body["rule"]["action"], json!("allow"));
        assert_eq!(
            accepted_body["rule"]["principal"]["roles"],
            json!(["orders-reader"])
        );
        assert_eq!(
            accepted_body["rule"]["principal"]["issuers"],
            json!(["provider:test"])
        );
        assert_eq!(
            accepted_body["rule"]["principal"]["auth_methods"],
            json!(["bearer_token"])
        );

        // Both halves are durable, and so is everything the policy
        // commit writes alongside them.
        let after = acceptance_footprint(&harness.policy_store, &pool, &id).await;
        assert_eq!(
            after,
            AcceptanceFootprint {
                active_version: 2,
                active_etag: accepted_etag.clone(),
                security_revision: before.security_revision + 1,
                rule_count: 1,
                document_rows: 2,
                outbox_rows: 2,
                suggestion_state: "accepted".to_owned(),
                suggestion_revision: 2,
            }
        );
        let active = PolicyControlPlane::active(harness.policy_store.as_ref())
            .await
            .expect("active reads")
            .expect("a policy is active");
        assert_eq!(
            serde_json::to_value(&active.policy.rules[0]).expect("rule serializes"),
            accepted_body["rule"]
        );
        // The replica answered with the revision it had already
        // installed, as every cluster-mode policy mutation does.
        assert_eq!(
            harness.rbac_state.snapshot_security_revision(),
            after.security_revision
        );

        // The immutable version the same transaction wrote is the
        // history row.
        let history = storage::PolicyHistory::list_versions(
            harness.policy_store.as_ref(),
            &PolicyHistoryListFilters {
                limit: 10,
                cursor: None,
                include_policy: false,
            },
        )
        .await
        .expect("history should list");
        assert_eq!(history.versions.len(), 2, "{history:?}");
        assert_eq!(history.versions[0].version, 2);
        assert_eq!(
            history.versions[0].diff_summary["action"],
            json!("rule_created")
        );
        assert_eq!(history.versions[0].actor_user_id, "user-123");

        // Both events are emitted after COMMIT, describing changes
        // that really happened.
        assert_eventually(Duration::from_secs(2), || {
            let events = harness.audit.events();
            events
                .iter()
                .any(|event| event.event_type == audit::event::POLICY_CHANGED)
                && events
                    .iter()
                    .any(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
        });
        let events = harness.audit.events();
        let policy_event = events
            .iter()
            .find(|event| event.event_type == audit::event::POLICY_CHANGED)
            .expect("policy.changed should be emitted");
        assert_eq!(
            policy_event.payload["diff_summary"]["action"],
            json!("rule_created")
        );
        let lifecycle_event = events
            .iter()
            .find(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
            .expect("suggestion.lifecycle_changed should be emitted");
        assert_eq!(lifecycle_event.payload["id"], json!(id));
        assert_eq!(lifecycle_event.payload["state"], json!("accepted"));

        // The transition is the precondition: accepting again is
        // refused with the row as it stands, not re-applied.
        let repeat = harness
            .router
            .clone()
            .oneshot(accept_request(&id, Some(&accepted_etag), None))
            .await
            .expect("repeat accept should complete");
        assert_eq!(repeat.status(), StatusCode::CONFLICT);
        let repeat = json_body(repeat).await;
        assert_eq!(repeat["reason"], json!("suggestion_not_open"));
        assert_eq!(repeat["suggestion"]["state"], json!("accepted"));
        assert_eq!(repeat["suggestion"]["revision"], json!(2));
        assert_eq!(
            acceptance_footprint(&harness.policy_store, &pool, &id).await,
            after,
            "a refused acceptance must write nothing"
        );
    }

    /// An acceptance whose policy commit loses its compare-and-swap
    /// INSIDE the transaction writes neither half (issue #241, PR 12).
    ///
    /// The race is made deterministic: an external transaction holds
    /// the suggestion row `FOR UPDATE`, so the acceptance blocks after
    /// it has already read the policy ETag and built its candidate.
    /// While it waits, another writer commits a policy version, which
    /// invalidates that ETag. When the lock is released, the
    /// acceptance's own transaction reaches the policy precondition,
    /// fails it, and rolls back -- the suggestion stays open and the
    /// proposed rule is nowhere.
    #[tokio::test]
    async fn a_cluster_acceptance_that_loses_the_policy_race_writes_neither_half() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database.dsn).await;
        let audit_store = cluster_audit_store(&pool).await;
        seed_baseline_generation_fixture(&pool, &audit_store).await;
        let harness = cluster_suggestions_harness(&pool, audit_store).await;
        let id = generate_one_suggestion(&harness.router).await;
        let before = acceptance_footprint(&harness.policy_store, &pool, &id).await;

        // Hold the suggestion row exactly as a peer replica's
        // acceptance would.
        let blocker = pool.get().await.expect("blocker client");
        blocker.batch_execute("BEGIN").await.expect("BEGIN");
        blocker
            .query_one(
                "SELECT id FROM greengateway.discovery_rule_suggestions
                     WHERE id = $1 FOR UPDATE",
                &[&id.as_str()],
            )
            .await
            .expect("the row locks");

        let request = accept_request(&id, Some(&before.active_etag), Some("1"));
        let router = harness.router.clone();
        let accepting = tokio::spawn(async move {
            router
                .oneshot(request)
                .await
                .expect("accept request should complete")
        });

        // It is blocked on the row, having written nothing.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            !accepting.is_finished(),
            "the acceptance must wait for the suggestion row"
        );
        assert_eq!(
            acceptance_footprint(&harness.policy_store, &pool, &id).await,
            before,
            "a blocked acceptance must not have written its policy"
        );

        // Another writer commits a policy version: the ETag the
        // blocked acceptance is holding is now stale.
        let interfering_diff = json!({ "action": "interfering_commit" });
        let mut interfering_candidate = PolicyControlPlane::active(harness.policy_store.as_ref())
            .await
            .expect("active reads")
            .expect("a policy is active")
            .policy;
        interfering_candidate.id = Some("interfering".to_owned());
        let interfering = PolicyControlPlane::commit(
            harness.policy_store.as_ref(),
            storage::PolicyCommitRequest {
                precondition: storage::PolicyCommitPrecondition::Expected {
                    etag: before.active_etag.clone(),
                },
                candidate: &interfering_candidate,
                change: crate::storage::DocumentChange::test_policy("peer"),
                diff_summary: &interfering_diff,
            },
        )
        .await
        .expect("the interfering commit should win");
        assert_ne!(interfering.etag, before.active_etag);

        blocker.batch_execute("COMMIT").await.expect("COMMIT");
        drop(blocker);

        let refused = accepting.await.expect("the acceptance task should finish");
        assert_eq!(refused.status(), StatusCode::PRECONDITION_FAILED);

        // Neither half landed: the only new version is the interfering
        // one, and the suggestion is untouched.
        assert_eq!(
            acceptance_footprint(&harness.policy_store, &pool, &id).await,
            AcceptanceFootprint {
                active_version: 2,
                active_etag: interfering.etag.clone(),
                security_revision: interfering.security_revision,
                rule_count: 0,
                document_rows: 2,
                outbox_rows: 2,
                suggestion_state: "open".to_owned(),
                suggestion_revision: 1,
            }
        );
        assert!(
            !harness
                .audit
                .events()
                .iter()
                .any(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED),
            "a rolled-back acceptance must emit no lifecycle event"
        );

        // The suggestion is still acceptable: retrying against the
        // current ETag commits both halves.
        let retried = harness
            .router
            .clone()
            .oneshot(accept_request(&id, Some(&interfering.etag), Some("1")))
            .await
            .expect("retry should complete");
        assert_eq!(retried.status(), StatusCode::CREATED);
        let retried = acceptance_footprint(&harness.policy_store, &pool, &id).await;
        assert_eq!(retried.rule_count, 1);
        assert_eq!(retried.suggestion_state, "accepted");
        assert_eq!(retried.suggestion_revision, 2);
    }
}
